#![cfg(feature = "python-tests")]

use std::process::{Command, Stdio};
use std::sync::{LazyLock, Once};

use tokio::time;

use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;

static RETICULUM_PYTHON_DIR: LazyLock<String> =
    LazyLock::new(|| std::env::var("RETICULUM_TEST_PYTHON_DIR").unwrap());

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("trace")
        ).init()
    });
}

#[tokio::test]
/// Spawn Python Reticulum Example/Announce.py and listen for announce
async fn python_announce() {
    use std::io::Write;
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
