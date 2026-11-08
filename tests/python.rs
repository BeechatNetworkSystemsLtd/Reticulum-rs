#![cfg(feature = "python-tests")]

use std::process::Stdio;
use std::sync::{atomic, Arc, LazyLock, Once};

use tokio::process::Command;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time;

use reticulum::hash::AddressHash;
use reticulum::identity::{Identity, PrivateIdentity};
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
                    assert_eq!(payload.as_slice(), b"I received \"test\" over the link");
                    // succeeded: shut down
                    break
                }
                LinkEvent::Proof(_) => {}
                LinkEvent::RemoteIdentified(_) => panic!("error: unexpected remote identified"),
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
                    LinkEvent::RemoteIdentified(_) => panic!("error: unexpected remote identified"),
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

#[tokio::test]
/// Spawn Python Reticulum Example/Identify.py as server and exchange messages as client
async fn python_identify_client() {
    use tokio::io::AsyncBufReadExt;
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let script_path = format!("{}/Examples/Identify.py", *RETICULUM_PYTHON_DIR);

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
    let client_identity = PrivateIdentity::new_from_rand(rand_core::OsRng);
    log::info!("created client identity: <{}>", client_identity.address_hash().to_hex_string());
    let (tx, mut rx) = mpsc::unbounded_channel();
    // forward stdout and return server destination hash
    let stdout = child.stdout.take().expect("child process has no stdout");
    let remote_identified_msg =
        format!("Remote identified as: <{}>", client_identity.address_hash().to_hex_string());
    static READY_TO_SEND: atomic::AtomicBool = atomic::AtomicBool::new(false);
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
            // [2026-06-03 12:03:33] [Notice]   Link identification example <5d3a09e13b866e49624d1bb576c23976> running, waiting for a connection.
            if let Some ((index, _)) = line.match_indices(']').nth(1) {
                let msg = line.split_at(index+1).1.trim();
                if let Some(hash_start) = msg.strip_prefix("Link identification example <") {
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
                } else if msg == remote_identified_msg {
                    // ready to send message
                    READY_TO_SEND.store(true, atomic::Ordering::SeqCst);
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
                    log::debug!("link activated: identifying to remote peer");
                    let packet = match link.lock().await.identify(&client_identity) {
                        Ok(packet) => packet,
                        Err(err) => panic!("error creating identity packet: {err:?}")
                    };
                    transport.send_packet(packet).await;
                    // wait until identified
                    let t_start = time::Instant::now();
                    while !READY_TO_SEND.load(atomic::Ordering::SeqCst) {
                        if t_start.elapsed() > time::Duration::from_secs(5) {
                            let _ = child.start_kill();
                            panic!("child stdout did not signal ready to send after 10 seconds");
                        }
                        time::sleep(time::Duration::from_millis(100)).await;
                    }
                    // link identified: sending packet
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
                        &format!("I received \"test\" over the link from <{}>",
                            client_identity.address_hash().to_hex_string()
                        ).into_bytes());
                    // succeeded: shut down
                    break
                }
                LinkEvent::Proof(_) => {}
                LinkEvent::RemoteIdentified(_) => panic!("error: unexpected remote identified"),
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
/// Create server and run Python Reticulum Example/Identify.py as client and send messages
async fn python_identify_server() {
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
        .add_destination(
            server_identity,
            DestinationName::new("example_utilities", "identifyexample"))
        .await;
    let destination_hash = destination.lock().await.desc.address_hash;
    log::info!("created server destination: {destination_hash}");
    log::info!("created server destination: {:?}", destination_hash.as_slice());
    let mut in_link_events = transport.in_link_events();

    let script_path = format!("{}/Examples/Identify.py", *RETICULUM_PYTHON_DIR);

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
    let remote_identity: Arc<Mutex<Option<Identity>>> = Arc::new(Mutex::new(None));
    // forward stdout and exit when reply is received
    let remote_id = remote_identity.clone();
    let stdout_handle: JoinHandle<Result<(), String>> = tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        // when the child process is killed next_line() will return None
        while let Some(line) = lines.next_line().await.map_err(|err|{
            let err = format!("error iterating over child stdout lines: {err}");
            log::error!("{err}");
            err
        })? {
            println!("{line}");
            if let Some(remote_id) = remote_id.lock().await.as_ref() {
                // test complete when client outputs:
                // [2026-07-29 05:13:45] [Notice]   Received data on the link: I received "test" over the link from <client-id>
                if let Some ((index, _)) = line.match_indices(']').nth(1) {
                    let msg = line.split_at(index+1).1.trim();
                    let received_data_msg =
                        format!("Received data on the link: I received \"test\" over the link from <{}>",
                            remote_id.address_hash.to_hex_string());
                    if msg == received_data_msg {
                        // test complete
                        log::info!("client got reply, breaking stdout loop");
                        RUNNING.store(false, atomic::Ordering::SeqCst);
                        break
                    }
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
                        let link = transport.find_in_link(&event.id).await
                            .expect("couldn't find in link");
                        let remote_id = link.lock().await.remote_identity();
                        if let Some(remote_id) = remote_id {
                            let msg = format!("I received \"{payload}\" over the link from <{}>",
                                remote_id.address_hash.to_hex_string());
                            let packet = match link.lock().await.data_packet(msg.as_bytes()) {
                                Ok(packet) => packet,
                                Err(err) => panic!("error creating data packet: {err:?}")
                            };
                            transport.send_packet(packet).await;
                        } else {
                            panic!("error: received data but link not yet identified")
                        }
                    }
                    LinkEvent::Proof(_) => {}
                    LinkEvent::RemoteIdentified(identity) => {
                        *remote_identity.lock().await = Some(*identity);
                        // ready to send message
                        READY_TO_SEND.store(true, atomic::Ordering::SeqCst);
                    }
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

/// Waits for `link_id` to be activated, failing after 10 seconds
async fn wait_link_activated(
    events: &mut broadcast::Receiver<reticulum::destination::link::LinkEventData>,
    link_id: AddressHash,
) {
    time::timeout(time::Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.expect("link event");
            if event.id == link_id && matches!(event.event, LinkEvent::Activated) {
                break;
            }
        }
    })
    .await
    .expect("link not activated");
}

/// Waits for data over any link, failing after 10 seconds
async fn wait_link_data(
    events: &mut broadcast::Receiver<reticulum::destination::link::LinkEventData>,
) -> Vec<u8> {
    time::timeout(time::Duration::from_secs(10), async {
        loop {
            if let LinkEvent::Data(payload) = events.recv().await.expect("link event").event {
                return payload.as_slice().to_vec();
            }
        }
    })
    .await
    .expect("link data not received")
}

#[tokio::test]
/// Rust node a links to Rust node b over a Python transport node, two hops away
async fn python_relay() {
    use reticulum::transport::Transport;

    let _guard = TEST_MUTEX.lock().await;
    setup();

    // UDP a <-> Python on 4244/4245, b <-> Python on 4246/4247
    let config = std::env::current_dir().unwrap().join("tests/rns-py-configs/relay");
    let _relay = Command::new("python3")
        .current_dir(&*RETICULUM_PYTHON_DIR)
        .arg("-u")
        .arg("-m")
        .arg("RNS.Utilities.rnsd")
        .arg("--config")
        .arg(&config)
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start rnsd");

    let build = |name: &str, bind: &str, forward: &str| {
        let transport: Transport =
            TransportConfig::new(name, &PrivateIdentity::new_from_rand(rand_core::OsRng)).build();
        (transport, bind.to_string(), forward.to_string())
    };
    let (node_a, bind, forward) = build("a", "127.0.0.1:4244", "127.0.0.1:4245");
    node_a.iface_manager().lock().await
        .spawn(UdpInterface::new(bind, Some(forward), false), UdpInterface::spawn);
    let (mut node_b, bind, forward) = build("b", "127.0.0.1:4246", "127.0.0.1:4247");
    node_b.iface_manager().lock().await
        .spawn(UdpInterface::new(bind, Some(forward), false), UdpInterface::spawn);

    let mut announces = node_a.recv_announces().await;
    let mut out_link_events = node_a.out_link_events();
    let mut in_link_events = node_b.in_link_events();

    let destination = node_b
        .add_destination(PrivateIdentity::new_from_rand(rand_core::OsRng), DestinationName::new("test", "relay"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    // announce until rnsd is up and relays it
    let desc = time::timeout(time::Duration::from_secs(30), async {
        loop {
            node_b.send_announce(&destination, None).await;
            if let Ok(Ok(event)) = time::timeout(time::Duration::from_secs(2), announces.recv()).await {
                let desc = event.destination.lock().await.desc;
                if desc.address_hash == address {
                    return desc;
                }
            }
        }
    })
    .await
    .expect("announce of b not relayed by Python");

    let link = node_a.link(desc).await;
    let link_id = *link.lock().await.id();
    wait_link_activated(&mut out_link_events, link_id).await;

    node_a.send_to_out_links(&address, b"hello b").await;
    assert_eq!(wait_link_data(&mut in_link_events).await, b"hello b");

    node_b.send_to_in_links(&address, b"hello a").await;
    assert_eq!(wait_link_data(&mut out_link_events).await, b"hello a");
}

#[tokio::test]
/// Rust node a links to a Python Link.py server over a Rust relay, two hops away
async fn relay_to_python_destination() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use reticulum::iface::{tcp_client::TcpClient, tcp_server::TcpServer};

    let _guard = TEST_MUTEX.lock().await;
    setup();

    // UDP relay <-> Python on 4244/4245
    let script_path = format!("{}/Examples/Link.py", *RETICULUM_PYTHON_DIR);
    let mut server = Command::new("python3")
        .arg("-u")
        .arg(&script_path)
        .arg("--server")
        .arg("--config")
        .arg("tests/rns-py-configs/destination")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start Link.py");

    // parse the hash from:
    // [2026-06-03 12:03:33] [Notice]   Link example <5d3a09e13b866e49624d1bb576c23976> running, waiting for a connection.
    let mut lines = tokio::io::BufReader::new(server.stdout.take().unwrap()).lines();
    let server_hash = time::timeout(time::Duration::from_secs(20), async {
        while let Some(line) = lines.next_line().await.expect("Link.py stdout") {
            println!("{line}");
            if let Some((_, rest)) = line.split_once("Link example <") {
                let hash = rest.split('>').next().unwrap();
                return AddressHash::new_from_hex_string(hash).expect("server destination hash");
            }
        }
        panic!("Link.py exited before printing its destination hash");
    })
    .await
    .expect("Link.py did not print its destination hash");
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            println!("{line}");
        }
    });
    let mut stdin = server.stdin.take().unwrap();

    let relay = TransportConfig::new("relay", &PrivateIdentity::new_from_rand(rand_core::OsRng))
        .set_retransmit(true)
        .build();
    relay.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:4244", Some("127.0.0.1:4245"), false),
        UdpInterface::spawn,
    );
    relay.iface_manager().lock().await.spawn(
        TcpServer::new("127.0.0.1:4250", relay.iface_manager()),
        TcpServer::spawn,
    );

    let node_a = TransportConfig::new("a", &PrivateIdentity::new_from_rand(rand_core::OsRng)).build();
    node_a.iface_manager().lock().await
        .spawn(TcpClient::new("127.0.0.1:4250"), TcpClient::spawn);

    let mut announces = node_a.recv_announces().await;
    let mut out_link_events = node_a.out_link_events();

    // Link.py announces when enter is hit, repeat until relayed to a
    let desc = time::timeout(time::Duration::from_secs(30), async {
        loop {
            stdin.write_all(b"\n").await.expect("write to Link.py");
            if let Ok(Ok(event)) = time::timeout(time::Duration::from_secs(2), announces.recv()).await {
                let desc = event.destination.lock().await.desc;
                if desc.address_hash == server_hash {
                    return desc;
                }
            }
        }
    })
    .await
    .expect("announce of Link.py not relayed to a");

    let link = node_a.link(desc).await;
    let link_id = *link.lock().await.id();
    wait_link_activated(&mut out_link_events, link_id).await;

    node_a.send_to_out_links(&server_hash, b"test").await;
    assert_eq!(wait_link_data(&mut out_link_events).await, b"I received \"test\" over the link");
}

#[tokio::test]
/// Python Link.py client links to Rust node b over a Rust relay, two hops away
async fn python_initiator_through_rust_relay() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use reticulum::iface::{tcp_client::TcpClient, tcp_server::TcpServer};

    let _guard = TEST_MUTEX.lock().await;
    setup();

    // UDP relay <-> Python on 4244/4245, TCP relay <-> b on 4251
    let relay = TransportConfig::new("relay", &PrivateIdentity::new_from_rand(rand_core::OsRng))
        .set_retransmit(true)
        .build();
    relay.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:4244", Some("127.0.0.1:4245"), false),
        UdpInterface::spawn,
    );
    relay.iface_manager().lock().await.spawn(
        TcpServer::new("127.0.0.1:4251", relay.iface_manager()),
        TcpServer::spawn,
    );

    let mut node_b = TransportConfig::new("b", &PrivateIdentity::new_from_rand(rand_core::OsRng)).build();
    node_b.iface_manager().lock().await
        .spawn(TcpClient::new("127.0.0.1:4251"), TcpClient::spawn);

    let destination = node_b
        .add_destination(
            PrivateIdentity::new_from_rand(rand_core::OsRng),
            DestinationName::new("example_utilities", "linkexample"),
        )
        .await;
    let address = destination.lock().await.desc.address_hash;

    // announce once the TCP connection is up, so that the relay can answer the path
    // request of Python
    time::sleep(time::Duration::from_secs(1)).await;
    node_b.send_announce(&destination, None).await;
    time::sleep(time::Duration::from_secs(1)).await;

    // reply to data received over the link
    let mut in_link_events = node_b.in_link_events();
    tokio::spawn(async move {
        while let Ok(event) = in_link_events.recv().await {
            if let LinkEvent::Data(payload) = event.event {
                let payload = str::from_utf8(payload.as_slice()).unwrap().to_string();
                let reply = format!("I received \"{payload}\" over the link");
                node_b.send_to_in_links(&address, reply.as_bytes()).await;
            }
        }
    });

    let script_path = format!("{}/Examples/Link.py", *RETICULUM_PYTHON_DIR);
    let mut client = Command::new("python3")
        .arg("-u")
        .arg(&script_path)
        .arg("--config")
        .arg("tests/rns-py-configs/client")
        .arg(address.to_string().trim_matches('/'))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start Link.py");
    let mut lines = tokio::io::BufReader::new(client.stdout.take().unwrap()).lines();
    let mut stdin = client.stdin.take().unwrap();

    // waits for a line of Link.py output containing `text`
    async fn wait_line(
        lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
        text: &str,
    ) {
        while let Some(line) = lines.next_line().await.expect("Link.py stdout") {
            println!("{line}");
            if line.contains(text) {
                return;
            }
        }
        panic!("Link.py exited before printing {text:?}");
    }

    time::timeout(time::Duration::from_secs(10), wait_line(&mut lines, "Link established with server"))
        .await
        .expect("link from Python not established");

    stdin.write_all(b"test\n").await.expect("write to Link.py");
    stdin.flush().await.expect("flush Link.py stdin");

    time::timeout(
        time::Duration::from_secs(10),
        wait_line(&mut lines, "Received data on the link: I received \"test\" over the link"),
    )
    .await
    .expect("reply not received by Python");
}
