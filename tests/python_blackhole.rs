#![cfg(feature = "python-tests")]

//! Blackhole interop with PYTHON nodes (Python `publish_blackhole` +
//! `Discovery.BlackholeUpdater` equivalents):
//!
//! 1. `python_fetches_rust_blackhole_list`: a Rust publisher serves
//!    `/list` in the exact Python dict format; a real Python client
//!    links, requests and merges it.
//! 2. `rust_updater_persists_python_list`: a Python publisher's list is
//!    fetched by the Rust `BlackholeUpdater`, persisted under
//!    `blackhole/<hex identity>` and restored by a fresh Rust transport
//!    with the same storage.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::storage::{FsStorage, Storage};
use reticulum::transport::{Transport, TransportConfig};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

fn python_dir() -> String {
    std::env::var("RETICULUM_TEST_PYTHON_DIR").expect("RETICULUM_TEST_PYTHON_DIR")
}

struct Lines(tokio::sync::mpsc::Receiver<String>);

async fn spawn_partner(args: &[String]) -> (Child, Lines) {
    let script = format!(
        "{}/tests/py-interop/blackhole_partner.py",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut argv = vec!["-u".to_string(), script];
    argv.extend(args.iter().cloned());

    let mut child = Command::new("python3")
        .args(&argv)
        .env("PYTHONPATH", python_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn partner");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            eprintln!("partner: {line}");
            let _ = tx.send(line).await;
        }
    });
    (child, Lines(rx))
}

async fn wait_for(lines: &mut Lines, needle: &str, secs: u64) -> Option<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(line)) = timeout(Duration::from_millis(500), lines.0.recv()).await {
            if line.contains(needle) {
                return Some(line);
            }
        }
    }
    None
}

async fn rust_transport(
    name: &str,
    listen: u16,
    forward: u16,
    storage: Option<Arc<FsStorage>>,
    sources: Vec<AddressHash>,
) -> Transport {
    let identity = PrivateIdentity::new_from_name(name);
    let mut config = TransportConfig::new(name, &identity)
        .set_retransmit(true)
        .set_blackhole_publish(true)
        .set_blackhole_sources(sources);
    if let Some(storage) = storage {
        config = config.set_storage(storage);
    }
    let transport = config.build();

    {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{listen}"),
                Some(format!("127.0.0.1:{forward}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    transport
}

#[tokio::test]
async fn python_fetches_rust_blackhole_list() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();
    let victim = AddressHash::new([0xA1; 16]);
    let until = reticulum::time::unix_time_as_secs() as f64 + 3600.0;
    let reason = "interop test entry".to_string();

    let transport = rust_transport("bh-rust-a", 4291, 4292, None, Vec::new()).await;
    transport.enable_blackhole_publishing().await;
    transport
        .blackhole_identity(victim, Some(until), Some(reason.clone()))
        .await;
    assert!(transport.is_blackholed(&victim).await);

    let publisher = transport.identity_hash().await;
    let (mut child, mut lines) = spawn_partner(&[
        "fetch".into(),
        "4292".into(),
        "4291".into(),
        publisher.to_hex_string(),
        victim.to_hex_string(),
        until.to_string(),
        reason,
    ])
    .await;

    let ok = wait_for(&mut lines, "FETCH-OK", 60).await;
    let _ = child.kill().await;
    assert!(
        ok.is_some(),
        "python client did not confirm the fetched list"
    );

    drop(transport);
}

#[tokio::test]
async fn rust_updater_persists_python_list() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();
    let victim = AddressHash::new([0xB7; 16]);
    let until = reticulum::time::unix_time_as_secs() as f64 + 7200.0;
    let reason = "from python".to_string();

    // Python publisher with a fresh random transport identity.
    let (mut child, mut lines) = spawn_partner(&[
        "publish".into(),
        "4294".into(),
        "4293".into(),
        victim.to_hex_string(),
        until.to_string(),
        reason,
    ])
    .await;

    let publisher_line = wait_for(&mut lines, "PUBLISHER-ID", 30)
        .await
        .expect("publisher identity line");
    let publisher_hex = publisher_line
        .split_whitespace()
        .find(|token| token.len() == 32 && token.bytes().all(|b| b.is_ascii_hexdigit()))
        .expect("publisher hex")
        .to_string();
    let ready = wait_for(&mut lines, "PUBLISH-READY", 30).await;
    assert!(ready.is_some(), "python publisher never became ready");
    let publisher = AddressHash::new_from_hex_string(&publisher_hex).expect("publisher hash");

    // Rust transport with file storage; the updater runs every 2 s.
    let storage = Arc::new(FsStorage::new(
        std::env::temp_dir()
            .join(format!("rnsh-test-{}", std::process::id()))
            .to_string_lossy()
            .into_owned(),
    ));
    let transport = Arc::new(
        rust_transport(
            "bh-rust-b",
            4293,
            4294,
            Some(storage.clone()),
            vec![publisher],
        )
        .await,
    );

    reticulum_discovery::BlackholeUpdater::start(
        &transport,
        vec![publisher],
        Duration::from_secs(2),
    )
    .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        if transport.is_blackholed(&victim).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        transport.is_blackholed(&victim).await,
        "rust updater never merged the python list"
    );

    // The fetched list is persisted under the publisher identity.
    let path = format!("blackhole/{publisher_hex}");
    let persisted = storage.read(&path).expect("persisted source list");
    assert!(
        reticulum::transport::Blackholes::parse_table(&persisted).is_some(),
        "persisted list is not the Python dict format"
    );

    // A fresh transport with the same storage restores the list.
    let transport2 = rust_transport("bh-rust-c", 4295, 4296, Some(storage), vec![publisher]).await;
    transport2.load_known_destinations().await.ok();
    let loaded = transport2.reload_blackholes().await;
    assert!(loaded >= 1, "fresh transport restored no blackholes");
    assert!(
        transport2.is_blackholed(&victim).await,
        "victim not blackholed after reload"
    );

    let _ = child.kill().await;
    drop(transport);
    drop(transport2);
}
