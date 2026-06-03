#![cfg(feature = "python-tests")]

use std::process::{Command, Stdio};
use std::sync::{mpsc, LazyLock, Once};

use tokio::sync::Mutex;
use tokio::time;

use reticulum::hash::AddressHash;
use reticulum::iface::udp::UdpInterface;
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
    use std::io::Write;
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
        .expect("failed to start Announce.py");

    let transport = TransportConfig::default().build();
    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4242", Some("127.0.0.1:4243")),
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
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(b"\n").unwrap(); // simulates pressing Return
            stdin.flush().unwrap();
        }
        time::sleep(time::Duration::from_secs(1)).await;
    }
    handle.await.expect("receive announce task failure");
    let _ = child.kill();
    match tokio::time::timeout(
        time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || child.wait())
    ).await {
        Ok(Ok(Ok(status))) => log::debug!("Python exited with: {status}"),
        _ => log::warn!("Python did not exit cleanly after kill")
    }
}

#[tokio::test]
/// Spawn Python Reticulum Example/Link.py and exchange messages
async fn python_link() {
    use std::io::BufRead;
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let script_path = format!("{}/Examples/Link.py", *RETICULUM_PYTHON_DIR);
    // the Python example will send application data with the announce from one of these lists:
    // fruits = ["Peach", "Quince", "Date", "Tangerine", "Pomelo", "Carambola", "Grape"]
    // noble_gases = ["Helium", "Neon", "Argon", "Krypton", "Xenon", "Radon", "Oganesson"]

    let mut child = Command::new("python3")
        .arg("-u")  // make sure output is not buffered
        .arg(script_path)
        .arg("--server")
        .arg("--config")
        .arg("tests/rns-py-configs/udp")
        .stdin(Stdio::piped())   // to be able to send to stdin
        .stdout(Stdio::piped())  // to be able to process stdout lines
        .spawn()
        .expect("failed to start Announce.py");
    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().expect("child process has no stdout");
    // forward stdout and return server destination hash
    let stdout_handle = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let line = line.unwrap();
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
    let server_hash = rx.recv().expect("child process sender hung up");
    log::info!("got server destination hash: {server_hash}");
    let transport = TransportConfig::default().build();
    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4242", Some("127.0.0.1:4243")),
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
        match out_link_events.recv().await {
            Ok(event) => match event.event {
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
            Err(err) => panic!("error receiving out link events: {err}")
        }
    }
    // shutdown
    let _ = child.kill();
    match tokio::time::timeout(
        time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || child.wait())
    ).await {
        Ok(Ok(Ok(status))) => log::debug!("Python exited with: {status}"),
        _ => log::warn!("Python did not exit cleanly after kill")
    }
    match stdout_handle.join() {
        Ok(Ok(())) => log::debug!("child stdout thread finished normally"),
        Ok(Err(err)) => panic!("error in child stdout thread: {err}"),
        Err(err) => panic!("child stdout thread failed to join: {err:?}")
    }
}
