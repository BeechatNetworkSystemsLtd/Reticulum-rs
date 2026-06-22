#![cfg(feature = "python-tests")]

use std::process::Stdio;
use std::sync::{atomic, LazyLock, Once};

use tokio::process::Command;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time;

use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::destination::DestinationName;
use reticulum::destination::link::LinkEvent;
use reticulum::transport::TransportConfig;

static RETICULUM_PYTHON_DIR: LazyLock<String> =
    LazyLock::new(|| std::env::var("RETICULUM_TEST_PYTHON_DIR").unwrap());

static INIT: Once = Once::new();
/// Only one test can be running at a time
static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn setup() {
    INIT.call_once(||
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init()
    );
}

#[tokio::test]
/// Spawn Python Reticulum Example/Announce.py and listen for announce
async fn python_announce() {
    use tokio::io::AsyncWriteExt;
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let script_path = format!("{}/Examples/Announce.py", *RETICULUM_PYTHON_DIR);
    // the Python example will send application data with the announce from one of these lists:
    // fruits = ["Peach", "Quince", "Date", "Tangerine", "Pomelo", "Carambola", "Grape"]
    // noble_gases = ["Helium", "Neon", "Argon", "Krypton", "Xenon", "Radon", "Oganesson"]
    let get_list = |name| -> Vec<String> {
        let starts_with = format!("{name} = ");
        let content = std::fs::read_to_string(&script_path).expect("failed to read Python script");
        let line = content.lines()
            .find(|l| l.starts_with(&starts_with))
            .expect("could not find fruits list in script");
        let json = &line[starts_with.len()..];
        serde_json::from_str(json).expect("failed to parse fruits list as JSON")
    };
    let fruits = get_list ("fruits");
    let noble_gases = get_list ("noble_gases");

    let mut child = Command::new("python3")
        .arg("-u")  // make sure output is not buffered
        .arg(script_path)
        .arg("--config")
        .arg("tests/rns-py-configs/udp")
        .stdin(Stdio::piped())  // to be able to send to stdin
        .spawn()
        .expect("failed to start {script_path}");

    let transport = TransportConfig::default().build();
    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4242", Some("127.0.0.1:4243"), false),
        UdpInterface::spawn);
    let mut recv_announces = transport.recv_announces().await;
    let handle = tokio::spawn(async move {
        let mut counter = 0;
        while counter < 2 {
            // wait for 10 seconds to receive announce, otherwise exit with error
            let result = time::timeout(time::Duration::from_secs(10), recv_announces.recv()).await;
            match result {
                Ok(Ok(announce)) => {
                    let app_data = str::from_utf8(announce.app_data.as_slice()).unwrap().to_string();
                    log::info!("got announce {}: {app_data}",
                        announce.destination.lock().await.desc.address_hash);
                    if counter == 0 {
                        assert!(fruits.contains(&app_data));
                    } else {
                        debug_assert_eq!(counter, 1);
                        assert!(noble_gases.contains(&app_data));
                    }
                    counter += 1;
                }
                Ok(Err(err)) => {
                    log::error!("error waiting for announce: {err}");
                    panic!("error waiting for announce: {err}");
                }
                Err(_) => {
                    log::error!("error waiting for announce: timeout");
                    panic!("error waiting for announce: timeout");
                }
            }
        }
    });

    while !handle.is_finished() {
        if let Some(status) = child.try_wait().unwrap() {
            handle.abort();
            panic!("Python exited early: {status}");
        }
        let stdin = child.stdin.as_mut().expect("child stdin not present");
        stdin.write_all(b"\n").await.unwrap(); // simulates pressing Return
        stdin.flush().await.unwrap();
        time::sleep(time::Duration::from_secs(1)).await;
    }
    handle.await.expect("receive announce task failure");
    let _ = child.start_kill();
    match tokio::time::timeout(time::Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => log::debug!("Python exited with: {status}"),
        _ => panic!("Python did not exit cleanly after kill")
    }
}

#[tokio::test]
/// Spawn Python Reticulum Example/Link.py as server and exchange messages as client
async fn python_link_client() {
    use tokio::io::AsyncBufReadExt;
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let script_path = format!("{}/Examples/Link.py", *RETICULUM_PYTHON_DIR);

    let mut child = Command::new("python3")
        .arg("-u")  // make sure output is not buffered
        .arg(script_path)
        .arg("--server")
        .arg("--config")
        .arg("tests/rns-py-configs/udp")
        .stdin(Stdio::piped())  // we do not send to stdin in this example but to prevent EOF error
        .stdout(Stdio::piped())  // to be able to process stdout lines
        .spawn()
        .expect("failed to start {script_path}");
    let (tx, mut rx) = mpsc::unbounded_channel();
    let stdout = child.stdout.take().expect("child process has no stdout");
    // forward stdout and return server destination hash
    let stdout_handle = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        // when the child process is killed next_line() will return None
        while let Some(line) = lines.next_line().await.map_err(|err|{
            let err = format!("error iterating over child stdout lines: {err}");
            log::error!("{err}");
            err
        })? {
            println!("{line}");
            // parse the hash from:
            // [2026-06-03 12:03:33] [Notice]   Link example <5d3a09e13b866e49624d1bb576c23976> running, waiting for a connection.
            if let Some ((index, _)) = line.match_indices(']').nth(1) {
                let msg = line.split_at(index+1).1.trim();
                if let Some(hash_start) = msg.strip_prefix("Link example <") {
                    if let Some(hash_end) = hash_start.find('>') {
                        let hash = AddressHash::new_from_hex_string(&hash_start[..hash_end])
                            .expect("failed to parse server destination hash");
                        if tx.send(hash).is_err() {
                            log::debug!("child process hash channel closed");
                            break
                        }
                    } else {
                        let err = "could not parse server destination hash".to_string();
                        log::error!("{err}");
                        return Err(err)
                    }
                }
            }
        }
        Ok(())
    });
    let server_hash = rx.recv().await.expect("child process sender hung up");
    log::info!("got server destination hash: {server_hash}");
    let transport = TransportConfig::default().build();
    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4242", Some("127.0.0.1:4243"), false),
        UdpInterface::spawn);
    let mut recv_announces = transport.recv_announces().await;
    // request announce
    transport.request_path(&server_hash, None, None).await;
    // wait for 10 seconds to receive announce, otherwise exit with error
    let result = time::timeout(time::Duration::from_secs(10), recv_announces.recv()).await;
    let server_dest = match result {
        Ok(Ok(announce)) => announce.destination.clone(),
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("error waiting for announce: timeout")
    };
    log::debug!("got server destination: {}", server_dest.lock().await.desc.address_hash);
    // create link
    let mut out_link_events = transport.out_link_events();
    let link = transport.link(server_dest.lock().await.desc).await;
    loop {
        match tokio::time::timeout(time::Duration::from_secs(5), out_link_events.recv()).await {
            Ok(Ok(event)) => match event.event {
                LinkEvent::Activated => {
                    // send data
                    log::debug!("link activated: sending data");
                    let packet = match link.lock().await.data_packet(b"test") {
                        Ok(packet) => packet,
                        Err(err) => panic!("error creating data packet: {err:?}")
                    };
                    transport.send_packet(packet).await;
                }
                LinkEvent::Data(payload) => {
                    log::debug!("got payload: {:?}", str::from_utf8(payload.as_slice()));
                    assert_eq!(payload.as_slice(),
                      b"I received \"test\" over the link");
                    // succeeded: shut down
                    break
                }
                LinkEvent::Proof(_) => {}
                LinkEvent::Closed => panic!("error: link closed unexpectedly")
            }
            Ok(Err(err)) => panic!("error receiving out link events: {err}"),
            Err(err) => panic!("timed out recieving out link events: {err}")
        }
    }
    // shutdown
    let _ = child.start_kill();
    match tokio::time::timeout(time::Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => log::debug!("Python exited with: {status}"),
        _ => panic!("Python did not exit cleanly after kill")
    }
    match stdout_handle.await {
        Ok(Ok(())) => log::debug!("child stdout task finished normally"),
        Ok(Err(err)) => panic!("error in child stdout task: {err}"),
        Err(err) => panic!("child stdout task failed to join: {err:?}")
    }
}

#[tokio::test]
/// Create server and run Python Reticulum Example/Link.py as client and send messages
async fn python_link_server() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let server_identity = PrivateIdentity::new_from_rand(rand_core::OsRng);
    //let server_identity = PrivateIdentity::new_from_name("test-python-link-server");
    let mut transport = TransportConfig::default().build();
    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4242", Some("127.0.0.1:4243"), false),
        UdpInterface::spawn);
    let destination = transport
        .add_destination(server_identity, DestinationName::new("example_utilities", "linkexample"))
        .await;
    let destination_hash = destination.lock().await.desc.address_hash;
    log::info!("created server destination: {destination_hash}");
    log::info!("created server destination: {:?}", destination_hash.as_slice());
    let mut in_link_events = transport.in_link_events();

    let script_path = format!("{}/Examples/Link.py", *RETICULUM_PYTHON_DIR);

    let mut child = Command::new("python3")
        .arg("-u")  // make sure output is not buffered
        .arg(script_path)
        .arg("--config")
        .arg("tests/rns-py-configs/udp")
        .arg(destination_hash.to_string().trim_matches('/'))
        .stdin(Stdio::piped())   // to be able to send to stdin
        .stdout(Stdio::piped())  // to be able to process stdout lines
        .spawn()
        .expect("failed to start {script_path}");
    let stdout = child.stdout.take().expect("child process has no stdout");
    static RUNNING: atomic::AtomicBool = atomic::AtomicBool::new(true);
    static READY_TO_SEND: atomic::AtomicBool = atomic::AtomicBool::new(false);
    // forward stdout and exit when reply is received
    let stdout_handle: JoinHandle<Result<(), String>> = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        // when the child process is killed next_line() will return None
        while let Some(line) = lines.next_line().await.map_err(|err|{
            let err = format!("error iterating over child stdout lines: {err}");
            log::error!("{err}");
            err
        })? {
            println!("{line}");
            // test complete when client outputs:
            // [2026-06-05 23:03:30] [Notice]   Received data on the link: I received "test" over the link
            if let Some ((index, _)) = line.match_indices(']').nth(1) {
                let msg = line.split_at(index+1).1.trim();
                if msg == "Link established with server, enter some text to send, or \"quit\" to quit" {
                    // ready to send message
                    READY_TO_SEND.store(true, atomic::Ordering::SeqCst);
                } else if msg == "Received data on the link: I received \"test\" over the link" {
                    // test complete
                    log::info!("client got reply, breaking stdout loop");
                    RUNNING.store(false, atomic::Ordering::SeqCst);
                    break
                }
            }
        }
        Ok(())
    });
    let link_task = tokio::spawn(async move {
        while RUNNING.load(atomic::Ordering::SeqCst) {
            match in_link_events.try_recv() {
                Ok(event) => match event.event {
                    LinkEvent::Activated => log::debug!("link activated {}", event.id),
                    LinkEvent::Data(payload) => {
                        let payload = str::from_utf8(payload.as_slice()).unwrap();
                        log::info!("got payload: {payload:?}");
                        // send reply
                        let msg = format!("I received \"{payload}\" over the link");
                        let link = transport.find_in_link(&event.id).await
                            .expect("couldn't find in link");
                        let packet = match link.lock().await.data_packet(msg.as_bytes()) {
                            Ok(packet) => packet,
                            Err(err) => panic!("error creating data packet: {err:?}")
                        };
                        transport.send_packet(packet).await;
                    }
                    LinkEvent::Proof(_) => {}
                    LinkEvent::Closed => panic!("error: link closed unexpectedly")
                }
                Err(broadcast::error::TryRecvError::Empty) => {}
                Err(err) => panic!("error receiving in link events: {err}")
            }
            time::sleep(time::Duration::from_millis(100)).await;
        }
    });
    let t_start = time::Instant::now();
    while !READY_TO_SEND.load(atomic::Ordering::SeqCst) {
        if t_start.elapsed() > time::Duration::from_secs(10) {
            let _ = child.start_kill();
            panic!("child stdout did not signal ready to send after 10 seconds");
        }
        time::sleep(time::Duration::from_millis(100)).await;
    }
    // send message
    {
        let stdin = child.stdin.as_mut().expect("child stdin not present");
        stdin.write_all(b"test\n").await.unwrap();
        stdin.flush().await.unwrap();
    }
    // wait for finish
    let t_start = time::Instant::now();
    while !stdout_handle.is_finished() {
        if t_start.elapsed() > time::Duration::from_secs(10) {
            let _ = child.start_kill();
            panic!("child stdout loop did not exit after 10 seconds");
        }
        time::sleep(time::Duration::from_millis(100)).await;
    }
    match stdout_handle.await {
        Ok(Ok(())) => log::debug!("child stdout task finished normally"),
        Ok(Err(err)) => panic!("error in child stdout task: {err}"),
        Err(err) => panic!("child stdout task failed to join: {err:?}")
    }
    match tokio::time::timeout(time::Duration::from_secs(5), link_task).await {
        Ok(Ok(())) => log::debug!("link task finished normally"),
        Ok(Err(err)) => panic!("link task failed to join: {err:?}"),
        Err(err) => panic!("timed out waiting for link task: {err:?}")
    }
    // shutdown
    let _ = child.start_kill();
    match tokio::time::timeout(time::Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => log::debug!("Python exited with: {status}"),
        _ => panic!("Python did not exit cleanly after kill")
    }
}
