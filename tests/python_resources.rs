#![cfg(feature = "python-tests")]

//! Resource and request interop tests against the Python Reticulum
//! reference implementation (`RETICULUM_TEST_PYTHON_DIR`).

use std::process::Stdio;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

use rand_core::OsRng;
use reticulum::destination::link::{Link, LinkEvent};
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::resource::{ResourceOptions, ResourceStatus, ResourceStrategy};
use reticulum::transport::{Transport, TransportConfig};

#[allow(dead_code)]
static RETICULUM_PYTHON_DIR: LazyLock<String> =
    LazyLock::new(|| std::env::var("RETICULUM_TEST_PYTHON_DIR").unwrap());
static TEST_MUTEX: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));
static INIT: std::sync::Once = std::sync::Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init()
    });
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

struct PyPartner {
    child: tokio::process::Child,
    lines: broadcast::Sender<String>,
}

impl Drop for PyPartner {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn spawn_partner(mode: &str, destination: Option<&str>, size: usize) -> PyPartner {
    let mut child = Command::new("python3")
        .arg("-u")
        .arg("tests/py-interop/partner.py")
        .arg("--config")
        .arg("tests/rns-py-configs/udp")
        .arg("--mode")
        .arg(mode)
        .arg("--size")
        .arg(size.to_string())
        .args(
            destination
                .map(|d| vec!["--destination".to_string(), d.to_string()])
                .unwrap_or_default(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn python partner");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, _) = broadcast::channel(64);
    let forward = tx.clone();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            println!("{line}");
            let _ = forward.send(line);
        }
    });

    PyPartner { child, lines: tx }
}

async fn next_line_containing(
    rx: &mut broadcast::Receiver<String>,
    needle: &str,
    timeout: Duration,
) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
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

async fn rust_transport(port: u16, forward: u16) -> Transport {
    let transport = TransportConfig::default().build();
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{port}"),
            Some(format!("127.0.0.1:{forward}")),
            false,
        ),
        UdpInterface::spawn,
    );
    transport
}

async fn wait_destination(
    transport: &Transport,
    hash: &AddressHash,
) -> reticulum::destination::DestinationDesc {
    transport.request_path(hash, None, None).await;
    let mut announces = transport.recv_announces().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no announce from python"
        );
        let event = tokio::time::timeout_at(deadline, announces.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if &event.destination.lock().await.desc.address_hash == hash {
            return event.destination.lock().await.desc;
        }
    }
}

async fn link_to(
    transport: &Transport,
    desc: reticulum::destination::DestinationDesc,
) -> Arc<AsyncMutex<Link>> {
    let mut events = transport.out_link_events();
    let link = transport.link(desc).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "link not established"
        );
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if let LinkEvent::Activated = event.event {
            return link;
        }
    }
}

fn parse_hash_from_line(line: &str, needle: &str) -> Option<AddressHash> {
    let idx = line.find(needle)?;
    let rest = &line[idx + needle.len()..];
    let hex: String = rest.chars().take(32).collect();
    AddressHash::new_from_hex_string(&hex).ok()
}

#[tokio::test]
async fn python_sends_resource_to_rust() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    // Rust server announces an interop resource destination
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = rust_transport(4242, 4243).await;
    let destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "interop.resource"),
        )
        .await;
    let hash = destination.lock().await.desc.address_hash;

    // Accept all resources on inbound links as they appear
    let strategy_transport = unsafe { &*(&transport as *const Transport) };
    tokio::spawn(async move {
        let mut in_link_events = strategy_transport.in_link_events();
        while let Ok(event) = in_link_events.recv().await {
            if let LinkEvent::Activated = event.event {
                strategy_transport
                    .set_resource_strategy(event.id, ResourceStrategy::All)
                    .await;
            }
        }
    });

    let partner = spawn_partner("resource-client", Some(&hash.to_hex_string()), 60_000).await;
    let mut lines = partner.lines.subscribe();

    // The Python side prints the sha of the payload it sends.
    let sha_line = next_line_containing(&mut lines, "sending sha", Duration::from_secs(20))
        .await
        .expect("python did not send");

    let mut resource_events = transport.resource_events().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut received = None;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, resource_events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.status == ResourceStatus::Complete {
            if let Some(data) = event.data {
                received = Some(data);
                break;
            }
        }
    }
    let received = received.expect("resource not received");
    let expected_sha: String = sha_line
        .split_whitespace()
        .last()
        .expect("sha in line")
        .to_string();
    assert_eq!(sha256_hex(&received), expected_sha);
    log::info!("received {} bytes from python, sha ok", received.len());

    drop(partner);
}

#[tokio::test]
async fn rust_sends_resource_to_python() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let partner = spawn_partner("resource-server", None, 0).await;
    let mut lines = partner.lines.subscribe();

    let dest_line = next_line_containing(&mut lines, "[PYI] destination", Duration::from_secs(20))
        .await
        .expect("python did not announce");
    let dest_hash = parse_hash_from_line(&dest_line, "destination ").expect("hash parse");

    let transport = rust_transport(4242, 4243).await;
    let desc = wait_destination(&transport, &dest_hash).await;
    let link = link_to(&transport, desc).await;

    let payload: Vec<u8> = (0..80_000u32).map(|i| (i % 251) as u8).collect();
    let payload_sha = sha256_hex(&payload);
    log::info!("sending {} bytes to python", payload.len());
    transport
        .send_resource_with_options(
            &link,
            payload,
            ResourceOptions {
                auto_compress: false,
                ..Default::default()
            },
        )
        .await
        .expect("send resource");

    // Python prints "received sha <hex>" once the resource concluded.
    let sha_line = next_line_containing(&mut lines, "received sha", Duration::from_secs(90))
        .await
        .expect("python did not receive the resource");
    let expected_sha: String = sha_line.split_whitespace().last().expect("sha").to_string();
    assert_eq!(payload_sha, expected_sha);
    log::info!("python confirmed sha ok");

    drop(partner);
}

#[tokio::test]
async fn python_request_to_rust() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = rust_transport(4242, 4243).await;
    let destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "interop.request"),
        )
        .await;
    let hash = destination.lock().await.desc.address_hash;

    transport
        .register_request_handler(&hash, "echo", |ctx| {
            Some(reticulum::resource::msgpack_bin(&ctx.data))
        })
        .await;

    let partner = spawn_partner("request-client", Some(&hash.to_hex_string()), 5000).await;
    let mut lines = partner.lines.subscribe();

    let sha_line = next_line_containing(&mut lines, "requesting sha", Duration::from_secs(20))
        .await
        .expect("python did not request");
    let expected_sha: String = sha_line.split_whitespace().last().expect("sha").to_string();

    let response_line = next_line_containing(&mut lines, "response sha", Duration::from_secs(30))
        .await
        .expect("python did not get response");
    let response_sha: String = response_line
        .split_whitespace()
        .last()
        .expect("sha")
        .to_string();
    assert_eq!(expected_sha, response_sha);
    log::info!("python received matching response");

    drop(partner);
}

#[tokio::test]
async fn rust_request_to_python() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let partner = spawn_partner("request-server", None, 0).await;
    let mut lines = partner.lines.subscribe();

    let dest_line = next_line_containing(&mut lines, "[PYI] destination", Duration::from_secs(20))
        .await
        .expect("python did not announce");
    let dest_hash = parse_hash_from_line(&dest_line, "destination ").expect("hash parse");

    let transport = rust_transport(4242, 4243).await;
    let desc = wait_destination(&transport, &dest_hash).await;
    let link = link_to(&transport, desc).await;

    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 247) as u8).collect();
    let rid = transport
        .request(&link, "echo", &payload)
        .await
        .expect("request");

    let response = transport
        .await_request_response(rid, Duration::from_secs(30))
        .await
        .expect("no response");
    assert_eq!(response, payload);
    log::info!("rust received matching response from python");

    drop(partner);
}
