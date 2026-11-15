//! Python interop tests for the local shared-instance interfaces
//! (`src/iface/local.rs`, Phase 5.3) against Python Reticulum 1.4.2:
//!
//! 1. a Python `rnsd` shared instance (TCP) with a Python local client
//!    attached, and the Rust node connecting with `LocalClient`,
//! 2. a Rust `LocalServer` shared instance with the Python script attaching
//!    as a local client (Python's bind fails and it falls back to client
//!    mode, exactly like `Reticulum.__start_local_interface`).
//!
//! Both directions exchange announces over the shared instance.

#![cfg(feature = "python-tests")]

use std::process::Stdio;
use std::sync::{LazyLock, Once};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::local::LocalClient,
    iface::local::LocalServer,
    iface::local::SharedInstanceAddress,
    transport::{Transport, TransportConfig},
};
use tokio::io::AsyncBufReadExt;
use tokio::process::Child;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};
use tokio::time;

static RETICULUM_PYTHON_DIR: LazyLock<String> =
    LazyLock::new(|| std::env::var("RETICULUM_TEST_PYTHON_DIR").unwrap());

static INIT: Once = Once::new();
/// Only one test can be running at a time
static TEST_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// TCP port of the shared instance in tests/rns-py-configs/shared-tcp
const SHARED_INSTANCE_PORT: u16 = 42840;

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init()
    });
}

fn python_command() -> Command {
    let mut command = Command::new("python3");
    command
        .arg("-u")
        .env("PYTHONPATH", RETICULUM_PYTHON_DIR.as_str());
    command
}

async fn spawn_rnsd() -> Child {
    let mut child = python_command()
        .arg("-m")
        .arg("RNS.Utilities.rnsd")
        .arg("--config")
        .arg("tests/rns-py-configs/shared-tcp")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to start python rnsd");

    // wait until the shared instance port is listening
    let deadline = time::Instant::now() + Duration::from_secs(20);
    while time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", SHARED_INSTANCE_PORT)).is_ok() {
            log::info!("python rnsd shared instance is listening");
            return child;
        }

        if let Some(status) = child.try_wait().expect("rnsd status") {
            panic!("python rnsd exited early: {status}")
        }

        time::sleep(Duration::from_millis(250)).await;
    }

    panic!("python rnsd did not start listening in time");
}

async fn spawn_partner() -> (Child, mpsc::Receiver<String>) {
    let mut child = python_command()
        .arg("tests/py-interop/shared_instance.py")
        .arg("tests/rns-py-configs/shared-tcp")
        .arg("25")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to start python shared instance partner");

    let stdout = child.stdout.take().expect("partner stdout not piped");
    let (tx, rx) = mpsc::channel::<String>(64);

    // forward stdout lines into a bounded channel with backpressure
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            println!("{line}");
            if tx.send(line).await.is_err() {
                break;
            }
        }
    });

    (child, rx)
}

async fn kill_child(child: &mut Child) {
    let _ = child.start_kill();
    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(status)) => log::debug!("python process exited with {status}"),
        _ => panic!("python process did not exit cleanly after kill"),
    }
}

/// Kills the wrapped child on drop so a panicking test cannot leak a
/// process holding the shared-instance port.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

impl std::ops::Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Rust transport with a local client attached to the shared instance.
async fn rust_local_client() -> Transport {
    let transport =
        TransportConfig::new("rust-local-client", &PrivateIdentity::new_from_rand(OsRng)).build();

    transport.iface_manager().lock().await.spawn(
        LocalClient::new(
            "interop-client",
            SharedInstanceAddress::tcp(SHARED_INSTANCE_PORT),
        ),
        LocalClient::spawn,
    );

    transport
}

/// Rust transport acting as the shared instance.
async fn rust_shared_instance() -> Transport {
    let transport = TransportConfig::new(
        "rust-shared-instance",
        &PrivateIdentity::new_from_rand(OsRng),
    )
    .set_retransmit(true)
    .build();

    transport.iface_manager().lock().await.spawn(
        LocalServer::new(
            SharedInstanceAddress::tcp(SHARED_INSTANCE_PORT),
            transport.iface_manager(),
        ),
        LocalServer::spawn,
    );

    transport
}

/// Wait for an announce from the Python partner (app data marker).
async fn await_python_announce(transport: &Transport, timeout: Duration) {
    let mut announces = transport.recv_announces().await;

    let result = time::timeout(timeout, announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            let app_data = announce.app_data.as_slice();
            log::info!(
                "got python announce for {}",
                announce.destination.lock().await.desc.address_hash
            );
            assert_eq!(
                std::str::from_utf8(app_data).unwrap_or(""),
                "python-shared-instance",
                "unexpected announce app data: {app_data:?}"
            );
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for python announce over shared instance"),
    }
}

/// Announce a Rust destination and wait for the partner to report it.
async fn announce_and_confirm_partner(
    transport: &mut Transport,
    partner_lines: &mut mpsc::Receiver<String>,
    timeout: Duration,
) {
    let id = PrivateIdentity::new_from_name("rust-shared-announce");
    let destination = transport
        .add_destination(id, DestinationName::new("test", "shared"))
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    let expected = dest_hash.to_hex_string();

    let deadline = time::Instant::now() + timeout;
    while time::Instant::now() < deadline {
        transport
            .send_announce(&destination, Some(b"rust-shared-instance".as_slice()))
            .await;

        let remaining = deadline.saturating_duration_since(time::Instant::now());
        match time::timeout(remaining, wait_for_announce_line(partner_lines, &expected)).await {
            Ok(()) => return,
            Err(_) => continue,
        }
    }

    panic!("timeout waiting for partner to receive the Rust announce {expected}");
}

/// Wait for a `GOT_ANNOUNCE <hash>` line from the partner.
async fn wait_for_announce_line(partner_lines: &mut mpsc::Receiver<String>, hash: &str) {
    while let Some(line) = partner_lines.recv().await {
        if let Some(rest) = line.strip_prefix("GOT_ANNOUNCE ") {
            let announced = rest.split_whitespace().next().unwrap_or_default();
            if announced == hash {
                log::info!("partner confirmed announce for {hash}");
                return;
            }
        }
    }

    panic!("partner stdout closed before announce confirmation");
}

#[tokio::test]
/// Python rnsd shared instance + Python local client + Rust LocalClient
async fn python_shared_instance_relay() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let mut rnsd = ChildGuard(spawn_rnsd().await);
    let (partner, mut partner_lines) = spawn_partner().await;
    let mut partner = ChildGuard(partner);

    // python partner announces once connected to the shared instance
    let mut transport = rust_local_client().await;

    await_python_announce(&transport, Duration::from_secs(20)).await;
    announce_and_confirm_partner(&mut transport, &mut partner_lines, Duration::from_secs(25)).await;

    let stats = transport.interface_stats().await;
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "LocalClient" && stat.received >= 1 && stat.online));

    kill_child(&mut partner).await;
    kill_child(&mut rnsd).await;
}

#[tokio::test]
/// Rust LocalServer shared instance with the Python script attaching as a
/// local client (Python bind fails, falls back to client mode).
async fn rust_shared_instance_with_python_client() {
    let _guard = TEST_MUTEX.lock().await;
    setup();

    let mut transport = rust_shared_instance().await;

    // make sure the Rust listener is up before the Python side tries to
    // become the shared instance itself
    time::sleep(Duration::from_secs(1)).await;

    let (partner, mut partner_lines) = spawn_partner().await;
    let mut partner = ChildGuard(partner);

    await_python_announce(&transport, Duration::from_secs(20)).await;
    announce_and_confirm_partner(&mut transport, &mut partner_lines, Duration::from_secs(25)).await;

    let stats = transport.interface_stats().await;
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "LocalClient" && stat.received >= 1 && stat.online));

    kill_child(&mut partner).await;
}
