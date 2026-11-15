#![cfg(feature = "python-tests")]

//! Buffer-stream interop with the Python implementation
//! (`RNS.Buffer` / `Examples/Buffer.py` behaviour).

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::broadcast;

use rand_core::OsRng;
use reticulum::buffer_stream::{create_reader, create_writer, StreamDataMessage};
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

struct Partner {
    child: tokio::process::Child,
    lines: broadcast::Receiver<String>,
}

impl Drop for Partner {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn spawn_buffer(mode: &str, destination: Option<&str>, size: usize, timeout: f64) -> Partner {
    spawn_buffer_on(
        "tests/rns-py-configs/udp-buffer",
        mode,
        destination,
        size,
        timeout,
    )
    .await
}

async fn spawn_buffer_on(
    config: &str,
    mode: &str,
    destination: Option<&str>,
    size: usize,
    timeout: f64,
) -> Partner {
    let mut child = Command::new("python3")
        .arg("-u")
        .arg("tests/py-interop/buffer.py")
        .arg("--config")
        .arg(config)
        .arg("--mode")
        .arg(mode)
        .arg("--size")
        .arg(size.to_string())
        .arg("--timeout")
        .arg(timeout.to_string())
        .args(
            destination
                .map(|d| vec!["--destination".to_string(), d.to_string()])
                .unwrap_or_default(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = broadcast::channel(32);
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

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

async fn rust_transport(bind: u16, forward: u16) -> Transport {
    let transport = TransportConfig::default().build();
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{bind}"),
            Some(format!("127.0.0.1:{forward}")),
            false,
        ),
        UdpInterface::spawn,
    );
    transport
}

/// Python writes a stream; Rust reads it.
#[tokio::test]
async fn python_writer_rust_reader() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = rust_transport(4252, 4253).await;
    let destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "buffer.stream"),
        )
        .await;
    let hash = destination.lock().await.desc.address_hash;
    transport.send_announce(&destination, None).await;

    // Python connects to us: wait for the inbound link, then upgrade to channel.
    let mut in_link_events = transport.in_link_events();
    let partner = spawn_buffer("writer", Some(&hash.to_hex_string()), 20_000, 30.0).await;
    let mut lines = partner.lines.resubscribe();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    let (mut reader, _channel) = loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no inbound link from python"
        );
        let event = tokio::time::timeout_at(deadline, in_link_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if let LinkEvent::Activated = event.event {
            let link = transport.find_in_link(&event.id).await.expect("in link");
            let (channel, rx) = transport
                .mk_channel::<StreamDataMessage>(link.clone())
                .await
                .expect("channel");
            // Rust is the responder: Python writes to stream 1 (its writer's
            // remote id); Rust reads on stream id 1.
            let reader = create_reader(1, rx);
            break (reader, channel);
        }
    };

    // read until EOF
    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "stream did not finish"
        );
        let mut tmp = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(2), reader.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read error");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&tmp[..n]);
        if received.len() >= 20_000 {
            // the python writer closes after writing; one more read returns 0
        }
    }

    // Python prints "<n> bytes sha <hex>" after writing
    let sha_line = wait_line(&mut lines, "wrote", 20)
        .await
        .expect("python wrote log");
    let parts: Vec<&str> = sha_line.split_whitespace().collect();
    // "[PYI] wrote <len> bytes sha <hex>"
    let expected_len: usize = parts[2].parse().expect("len");
    let expected: String = parts.last().copied().expect("sha").to_string();
    assert_eq!(received.len(), expected_len);
    assert_eq!(sha256_hex(&received), expected);
}

/// Rust writes a stream; Python reads it.
#[tokio::test]
async fn rust_writer_python_reader() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let partner =
        spawn_buffer_on("tests/rns-py-configs/udp-buffer2", "reader", None, 0, 40.0).await;
    let mut lines = partner.lines.resubscribe();

    let dest_line = wait_line(&mut lines, "[PYI] destination", 20)
        .await
        .expect("destination");
    let hex = dest_line
        .split_whitespace()
        .nth(2)
        .expect("hash")
        .to_string();
    let dest_hash = reticulum::hash::AddressHash::new_from_hex_string(&hex).expect("hash");

    let transport = rust_transport(4262, 4263).await;
    transport.request_path(&dest_hash, None, None).await;

    let mut announces = transport.recv_announces().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let desc = loop {
        assert!(tokio::time::Instant::now() < deadline, "no announce");
        let event = tokio::time::timeout_at(deadline, announces.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.destination.lock().await.desc.address_hash == dest_hash {
            break event.destination.lock().await.desc;
        }
    };

    let mut out_events = transport.out_link_events();
    let link = transport.link(desc).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "link inactive");
        let event = tokio::time::timeout_at(deadline, out_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if let LinkEvent::Activated = event.event {
            break;
        }
    }

    // wait for python's "link established"
    wait_line(&mut lines, "link established", 15)
        .await
        .expect("py link");

    let (channel, _rx) = transport
        .mk_channel::<StreamDataMessage>(link.clone())
        .await
        .expect("channel");

    // Python reads on stream id 2 (its reader id): address frames to 2.
    let mut writer = create_writer(2, channel);
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    writer.write_all(&payload).await.expect("write");
    writer.shutdown().await.expect("eof");

    let sha_line = wait_line(&mut lines, "read", 40)
        .await
        .expect("python read log");
    let expected_sha: String = sha_line.split_whitespace().last().expect("sha").to_string();
    assert_eq!(sha256_hex(&payload), expected_sha);
}
