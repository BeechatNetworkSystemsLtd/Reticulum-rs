#![cfg(feature = "python-tests")]

//! Identity/persistence interop tests against the Python Reticulum
//! reference implementation (`RETICULUM_TEST_PYTHON_DIR`), mirroring
//! `Examples/Echo.py` and `Examples/Ratchets.py` behaviour.

use std::process::Stdio;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::broadcast;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::storage::MemoryStorage;
use reticulum::transport::{ReceivedData, Transport, TransportConfig};

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

/// Copy the fixture config into a fresh temp directory so each test owns
/// its storage (identities, ratchets) and concurrent suites never share
/// state (same isolation as the rncp python tests).
fn isolated_config(name: &str) -> String {
    let fixture = format!("{}/tests/rns-py-configs/udp", env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("rn-pyid-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(format!("{fixture}/config"), dir.join("config")).unwrap();
    dir.to_str().unwrap().to_string()
}

async fn spawn_partner(mode: &str, destination: Option<&str>, size: usize) -> PyPartner {
    let mut child = Command::new("python3")
        .arg("-u")
        .arg("tests/py-interop/identity.py")
        .arg("--config")
        .arg(isolated_config(mode))
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
        .stderr(if std::env::var("PYI_STDERR").is_ok() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
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

    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[PYI-ERR] {line}");
            }
        });
    }

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
    let transport = TransportConfig::default()
        .set_storage(Arc::new(MemoryStorage::new()))
        .build();
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

async fn wait_announce(
    announces: &mut broadcast::Receiver<reticulum::transport::AnnounceEvent>,
    hash: &AddressHash,
    timeout: Duration,
) -> Option<Option<[u8; 32]>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no announce from python"
        );
        let event = tokio::time::timeout_at(deadline, announces.recv())
            .await
            .expect("timeout")
            .expect("channel");
        let announced = event.destination.lock().await.desc.address_hash;
        if announced == *hash {
            return Some(event.ratchet);
        }
    }
}

async fn next_received(
    rx: &mut broadcast::Receiver<ReceivedData>,
    destination: &AddressHash,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) if &event.destination == destination => {
                return Some(event.data.as_slice().to_vec())
            }
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
}

fn parse_hash_from_line(line: &str, needle: &str) -> Option<AddressHash> {
    let idx = line.find(needle)?;
    let rest = &line[idx + needle.len()..];
    let hex: String = rest.chars().take(32).collect();
    AddressHash::new_from_hex_string(&hex).ok()
}

/// Rust announces a ratcheted SINGLE destination; Python sends an encrypted
/// packet to it (Echo client behaviour) and receives the delivery proof
/// generated by the Rust destination.
#[tokio::test]
async fn python_sends_encrypted_packet_to_rust() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = rust_transport(4242, 4243).await;
    let destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "identity.echo"),
        )
        .await;
    // Python default is PROVE_NONE (Destination.__init__); a destination
    // that wants delivery receipts opts in explicitly, like the reference
    // echo server does.
    destination
        .lock()
        .await
        .set_proof_strategy(reticulum::destination::ProofStrategy::All);
    let hash = destination.lock().await.desc.address_hash;

    transport
        .enable_destination_ratchets(&hash, "python-interop.ratchets")
        .await
        .expect("enable ratchets");

    transport.send_announce(&destination, None).await;

    let mut received = transport.received_data_events();

    let partner = spawn_partner("echo-client", Some(&hash.to_hex_string()), 96).await;
    let mut lines = partner.lines.subscribe();

    // Python prints the ratchet it will use before sending.
    let ratchet_line =
        next_line_containing(&mut lines, "ratchet-known", Duration::from_secs(30)).await;
    let ratchet_line = ratchet_line.expect("python ratchet status");
    assert!(
        !ratchet_line.contains("none"),
        "python must use the announced ratchet: {ratchet_line}"
    );

    let sending_line =
        next_line_containing(&mut lines, "sending sha", Duration::from_secs(30)).await;
    let sending_line = sending_line.expect("python did not send");
    let expected_sha: String = sending_line
        .split_whitespace()
        .last()
        .expect("sha")
        .to_string();

    let data = next_received(&mut received, &hash, Duration::from_secs(30))
        .await
        .expect("rust did not receive the encrypted packet");
    assert_eq!(sha256_hex(&data), expected_sha);

    // The proof generated by the Rust destination delivers the receipt.
    let delivered_line =
        next_line_containing(&mut lines, "delivered sha", Duration::from_secs(30)).await;
    let delivered_line = delivered_line.expect("python did not get a delivery proof");
    let delivered_sha: String = delivered_line
        .split_whitespace()
        .last()
        .expect("sha")
        .to_string();
    assert_eq!(delivered_sha, expected_sha);

    drop(partner);
}

/// Python announces a ratcheted SINGLE destination (Ratchets.py server);
/// Rust sends an encrypted packet that Python decrypts with its ratchets,
/// and the Python proof delivers the Rust receipt.
#[tokio::test]
async fn rust_sends_encrypted_packet_to_python() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    // Create the transport (and subscribe to announces) before the partner
    // so no announce event is missed.
    let transport = rust_transport(4242, 4243).await;
    let mut announces = transport.recv_announces().await;

    let partner = spawn_partner("echo-server", None, 0).await;
    let mut lines = partner.lines.subscribe();

    let dest_line = next_line_containing(&mut lines, "[PYI] destination", Duration::from_secs(30))
        .await
        .expect("python did not announce");
    let dest_hash = parse_hash_from_line(&dest_line, "destination ").expect("hash parse");

    let ratchet = wait_announce(&mut announces, &dest_hash, Duration::from_secs(20))
        .await
        .expect("announce seen")
        .expect("python announce must carry a ratchet");
    assert_eq!(ratchet.len(), 32);

    let payload: Vec<u8> = (0..200u32).map(|i| (i % 249) as u8).collect();
    let payload_sha = sha256_hex(&payload);

    // Subscribe before sending: python proves immediately, and a broadcast
    // receiver created after the proof arrives would miss it.
    let mut receipts = transport.receipt_events();
    let packet_hash = transport
        .send_to_destination(&dest_hash, &payload)
        .await
        .expect("send");

    let received_line =
        next_line_containing(&mut lines, "received sha", Duration::from_secs(30)).await;
    let received_line = received_line.expect("python did not receive the packet");
    let received_sha: String = received_line
        .split_whitespace()
        .last()
        .expect("sha")
        .to_string();
    assert_eq!(received_sha, payload_sha);

    // Python proves the packet (PROVE_ALL) and the Rust receipt concludes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut delivered = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, receipts.recv()).await {
            Ok(Ok(event)) if event.packet_hash == packet_hash => {
                delivered = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    assert!(delivered, "rust receipt must be proved by python");

    drop(partner);
}

/// Python rotates its ratchet on every announce (Ratchets.py); Rust tracks
/// the rotations from the announces and keeps encrypting to the current
/// ratchet key.
#[tokio::test]
async fn ratchet_rotation_interop() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let transport = rust_transport(4242, 4243).await;
    let mut announces = transport.recv_announces().await;
    let mut received = transport.received_data_events();

    let partner = spawn_partner("ratchet-server", None, 0).await;
    let mut lines = partner.lines.subscribe();

    let dest_line = next_line_containing(&mut lines, "[PYI] destination", Duration::from_secs(30))
        .await
        .expect("python did not announce");
    let dest_hash = parse_hash_from_line(&dest_line, "destination ").expect("hash parse");

    let mut seen_ratchets: Vec<[u8; 32]> = Vec::new();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while seen_ratchets.len() < 2 && tokio::time::Instant::now() < deadline {
        tokio::select! {
            event = announces.recv() => {
                let Ok(event) = event else { continue };
                let announced_hash = event.destination.lock().await.desc.address_hash;
                if announced_hash != dest_hash {
                    continue;
                }
                let Some(ratchet) = event.ratchet else {
                    continue;
                };

                if seen_ratchets.last() != Some(&ratchet) {
                    seen_ratchets.push(ratchet);
                    log::info!("observed python ratchet #{}", seen_ratchets.len());
                }

                // Rust must have remembered a ratchet for the destination
                // (a newer announce may already have rotated it again).
                assert!(transport.get_ratchet(&dest_hash).await.is_some());

                let payload: Vec<u8> = (0..80u32).map(|i| (i + seen_ratchets.len() as u32) as u8).collect();
                let payload_sha = sha256_hex(&payload);

                transport
                    .send_to_destination(&dest_hash, &payload)
                    .await
                    .expect("send");

                let data = next_received(&mut received, &dest_hash, Duration::from_secs(20))
                    .await;
                // The python partner reports the sha of every packet it
                // decrypts; our own echo of the data is not required, but
                // the partner line must match what we sent.
                let line = next_line_containing(&mut lines, "received sha", Duration::from_secs(20))
                    .await
                    .expect("python did not report the packet");
                let reported: String = line.split_whitespace().last().expect("sha").to_string();
                assert_eq!(reported, payload_sha);

                // Python reports whether the packet used a ratchet.
                let ratchet_line = next_line_containing(&mut lines, "received ratchet", Duration::from_secs(5))
                    .await
                    .expect("python ratchet report");
                assert!(ratchet_line.contains("set"), "packets must use the ratchet: {ratchet_line}");

                let _ = data;
            },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
        }
    }

    assert!(
        seen_ratchets.len() >= 2,
        "python must rotate its ratchet across announces"
    );
    assert_ne!(seen_ratchets[0], seen_ratchets[1]);
}

/// Announce-with-ratchet round trip: Rust announces a ratcheted
/// destination, Python validates it, remembers the ratchet and reports the
/// ratchet id it would use (Ratchets.py client-side logic).
#[tokio::test]
async fn announce_ratchet_round_trip() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = rust_transport(4242, 4243).await;
    let destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "identity.echo"),
        )
        .await;
    let hash = destination.lock().await.desc.address_hash;

    transport
        .enable_destination_ratchets(&hash, "round-trip.ratchets")
        .await
        .expect("enable ratchets");
    transport.send_announce(&destination, None).await;

    // Python learns destination + ratchet from the announce and reports
    // them back through the echo client handshake.
    let partner = spawn_partner("echo-client", Some(&hash.to_hex_string()), 32).await;
    let mut lines = partner.lines.subscribe();

    let ratchet_line =
        next_line_containing(&mut lines, "ratchet-known", Duration::from_secs(30)).await;
    let ratchet_line = ratchet_line.expect("python ratchet status");

    let reported_id = ratchet_line
        .split_whitespace()
        .last()
        .expect("ratchet id")
        .to_string();
    assert_eq!(
        reported_id.len(),
        20,
        "ratchet id is 10 bytes hex: {ratchet_line}"
    );

    // The id Python reports must be the id of the ratchet our destination
    // currently announces.
    let expected_id = {
        let destination = destination.lock().await;
        let ratchets = destination.ratchets().expect("destination ratchets");
        let public = reticulum::identity::ratchet_public_from_private(&ratchets[0]);
        reticulum::identity::ratchet_id(&public)
    };
    assert_eq!(reported_id, hex(&expected_id.as_slice()[..10]));

    drop(partner);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
