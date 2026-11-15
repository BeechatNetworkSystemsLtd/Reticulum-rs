#![cfg(feature = "python-tests")]

//! PLAIN (broadcast) destination interop with the Python implementation,
//! exercising `Examples/Broadcast.py` behaviour.

use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::broadcast;

use reticulum::destination::DestinationName;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;

struct Partner {
    child: tokio::process::Child,
    lines: broadcast::Receiver<String>,
}

impl Drop for Partner {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn spawn_plain(send: Option<&str>, listen_secs: f64) -> Partner {
    spawn_plain_on("tests/rns-py-configs/udp-plain", send, listen_secs).await
}

async fn spawn_plain_on(config: &str, send: Option<&str>, listen_secs: f64) -> Partner {
    let mut child = Command::new("python3")
        .arg("-u")
        .arg("tests/py-interop/plain.py")
        .arg("--config")
        .arg(config)
        .args(
            send.map(|s| vec!["--send".to_string(), s.to_string()])
                .unwrap_or_default(),
        )
        .args(vec!["--listen-secs".to_string(), listen_secs.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = broadcast::channel(16);
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            println!("{line}");
            let _ = tx.send(line);
        }
    });
    Partner { child, lines: rx }
}

async fn wait_line(
    rx: &mut broadcast::Receiver<String>,
    needle: &str,
    secs: u64,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(line)) if line.contains(needle) => return Some(line),
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
}

#[tokio::test]
async fn rust_broadcast_received_by_python() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let partner = spawn_plain(None, 15.0).await;
    let mut lines = partner.lines.resubscribe();

    // Wait for the Python broadcast destination to be up, plus a grace
    // period for its shared-instance interfaces to bind.
    wait_line(&mut lines, "[PYI] destination", 15)
        .await
        .expect("destination");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let transport = TransportConfig::default().build();
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:4242", Some("127.0.0.1:4243"), false),
        UdpInterface::spawn,
    );

    let name = DestinationName::new("example_utilities", "broadcast.public_information");
    for _ in 0..3 {
        transport
            .send_to_plain_destination(name, b"hello from rust broadcast")
            .await
            .expect("broadcast");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let received = wait_line(&mut lines, "[PYI] received hello from rust broadcast", 10)
        .await
        .expect("python did not receive the broadcast");
    println!("{received}");
}

#[tokio::test]
async fn python_broadcast_received_by_rust() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let mut transport = TransportConfig::default().build();
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:4272", Some("127.0.0.1:4273"), false),
        UdpInterface::spawn,
    );

    let destination = transport
        .add_plain_destination(DestinationName::new(
            "example_utilities",
            "broadcast.public_information",
        ))
        .await;
    let hash = destination.lock().await.desc.address_hash;

    let mut data_events = transport.received_data_events();
    let partner = spawn_plain_on(
        "tests/rns-py-configs/udp-plain2",
        Some("hello from python broadcast"),
        5.0,
    )
    .await;
    let mut lines = partner.lines.resubscribe();
    wait_line(&mut lines, "[PYI] sent", 15)
        .await
        .expect("python sent");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, data_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.destination == hash {
            received = Some(event.data);
            break;
        }
    }
    let data = received.expect("rust did not receive broadcast");
    assert_eq!(data.as_slice(), b"hello from python broadcast");
}
