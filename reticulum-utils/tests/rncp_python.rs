#![cfg(feature = "python-tests")]

//! rncp interop against the Python `RNS/Utilities/rncp.py`:
//! * Rust sender → Python listener
//! * Python sender → Rust listener
//!
//! Each test gets its own isolated Python config directory
//! (`tests/rns-py-configs/udp-rncp{,2}`: `share_instance = No`, unique
//! instance names and dedicated UDP port pairs) so the partners never
//! attach to leftover shared instances or collide with the other
//! interop suites running concurrently in a workspace test run.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::Duration;

use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use tokio::sync::{broadcast, Mutex as AsyncMutex};

use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum_utils::common::load_or_create_private_identity;
use reticulum_utils::rncp::{self, SendOptions, ServeOptions};
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
static RETICULUM_PYTHON_DIR: LazyLock<String> =
    LazyLock::new(|| std::env::var("RETICULUM_TEST_PYTHON_DIR").unwrap());
static TEST_MUTEX: LazyLock<AsyncMutex<()>> = LazyLock::new(|| AsyncMutex::new(()));
static INIT: std::sync::Once = std::sync::Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init()
    });
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rn-rncp-py-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A config dir whose transport talks to the Python UDP test interface.
/// Each caller gets its own port pair so workspace-wide parallel test
/// binaries never collide.
fn rust_config_dir(name: &str, listen: u16, forward: u16) -> PathBuf {
    let dir = temp_dir(name);
    std::fs::write(
        dir.join("config.toml"),
        format!(
            "[[interfaces]]\nname = \"To Python\"\ntype = \"UDPInterface\"\nenabled = true\n\
             listen_ip = \"127.0.0.1\"\nlisten_port = {listen}\n\
             forward_ip = \"127.0.0.1\"\nforward_port = {forward}\n"
        ),
    )
    .unwrap();
    dir
}

/// Copy the fixture config `tests/rns-py-configs/<name>/config` into a
/// fresh temp directory and return its path.
///
/// The copy keeps the run hermetic: the Python partner generates its own
/// storage (identities, caches) inside the temp dir instead of mutating the
/// repository fixture or recalling stale destinations from a previous run.
/// Resolved from the crate manifest because the test binary's cwd is the
/// crate dir while the Python partner runs with the Python repo as its cwd.
fn py_config(name: &str) -> String {
    let fixture = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/rns-py-configs"
    ))
    .join(name);
    let dir = temp_dir(&format!("pycfg-{name}"));
    std::fs::copy(fixture.join("config"), dir.join("config")).expect("copy fixture config");
    dir.to_str().unwrap().to_string()
}

fn rncp_destination_hash(config_dir: &Path) -> reticulum::hash::AddressHash {
    let (identity, _) =
        load_or_create_private_identity(&config_dir.join("storage/identities/rncp")).unwrap();
    SingleInputDestination::new(identity, DestinationName::new(rncp::APP_NAME, "receive"))
        .desc
        .address_hash
}

struct PyChild {
    child: tokio::process::Child,
}

impl PyChild {
    async fn spawn(args: &[&str]) -> (Self, broadcast::Receiver<String>) {
        // The tool lives at RNS/Utilities/rncp.py inside the Python repo
        // (there is no top-level Utilities/ dir); run from the repo root
        // with PYTHONPATH set so `import RNS` resolves.
        let python_dir = RETICULUM_PYTHON_DIR.to_string();
        let mut child = Command::new("python3")
            .arg("-u")
            .arg("RNS/Utilities/rncp.py")
            .args(args)
            .current_dir(&python_dir)
            .env("PYTHONPATH", &python_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn python rncp");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = broadcast::channel(128);
        let tx_forward = tx.clone();
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                println!("py: {line}");
                let _ = tx_forward.send(line);
            }
        });
        (Self { child }, rx)
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
}

impl Drop for PyChild {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn test_file(dir: &Path, size: usize) -> PathBuf {
    let path = dir.join("interop.bin");
    let data: Vec<u8> = (0..size)
        .map(|i| ((i * 37 + i / 253) % 256) as u8)
        .collect();
    std::fs::write(&path, data).unwrap();
    path
}

#[tokio::test]
async fn rust_sender_to_python_listener() {
    setup();
    let _guard = TEST_MUTEX.lock().await;

    let save_dir = temp_dir("py-save");
    let config_dir = rust_config_dir("py-send-client", 4292, 4293);
    let payload = test_file(&config_dir, 120_000);

    // -v raises the python loglevel to INFO so "rncp listening on"
    // (LOG_INFO) is visible; "Saved received file to" is LOG_NOTICE.
    let (listener, mut lines) = PyChild::spawn(&[
        "--config",
        &py_config("udp-rncp"),
        "-l",
        "-n",
        "-v",
        "-b",
        "5",
        "-w",
        "30",
        "-s",
        save_dir.to_str().unwrap(),
    ])
    .await;

    let line =
        PyChild::next_line_containing(&mut lines, "rncp listening on", Duration::from_secs(30))
            .await
            .expect("python listener did not report its destination");
    let hash: String = line
        .split('<')
        .nth(1)
        .unwrap()
        .split('>')
        .next()
        .unwrap()
        .to_string();
    let destination = reticulum_utils::common::parse_hash(&hash).expect("hash from python");

    let message = rncp::send(SendOptions {
        config_dir: Some(config_dir.clone()),
        file: payload.clone(),
        destination,
        timeout: Duration::from_secs(30),
        no_compress: false,
        silent: true,
        identity_path: None,
        udp_loopback: None,
        quiet: false,
        phy_rates: false,
    })
    .await
    .expect("rust → python transfer");

    assert!(message.contains("copied to"), "{message}");
    let saved = PyChild::next_line_containing(
        &mut lines,
        "Saved received file to",
        Duration::from_secs(30),
    )
    .await
    .expect("python listener must save the file");
    let saved_path = saved
        .split("Saved received file to ")
        .nth(1)
        .unwrap()
        .trim();
    assert_eq!(
        std::fs::read(saved_path).unwrap(),
        std::fs::read(&payload).unwrap(),
        "bytes received by python must match"
    );
    drop(listener);
}

#[tokio::test]
async fn python_sender_to_rust_listener() {
    setup();
    let _guard = TEST_MUTEX.lock().await;

    let config_dir = rust_config_dir("py-recv-server", 4302, 4303);
    let save_dir = temp_dir("rust-save");

    let payload = test_file(&config_dir, 60_000);

    let destination = rncp_destination_hash(&config_dir);
    let shutdown = CancellationToken::new();
    let serve_task = {
        let options = ServeOptions {
            config_dir: Some(config_dir.clone()),
            save_dir: save_dir.clone(),
            no_auth: true,
            announce_interval: 5,
            ..Default::default()
        };
        let shutdown = shutdown.clone();
        tokio::spawn(async move { rncp::serve_with_shutdown(options, shutdown).await })
    };
    // Give the listener time to bind its interface and announce before the
    // python sender starts requesting the path (serve announces every 5s).
    tokio::time::sleep(Duration::from_secs(2)).await;

    let (sender, mut lines) = PyChild::spawn(&[
        "--config",
        &py_config("udp-rncp2"),
        "-v",
        "-w",
        "30",
        payload.to_str().unwrap(),
        &destination.to_hex_string(),
    ])
    .await;

    let done = PyChild::next_line_containing(&mut lines, "copied to", Duration::from_secs(120))
        .await
        .expect("python sender must complete the transfer");

    // The Rust listener must have written the file with the announced name.
    let received = save_dir.join("interop.bin");
    assert!(
        received.exists(),
        "rust listener must save the file ({done})"
    );
    assert_eq!(
        std::fs::read(&received).unwrap(),
        std::fs::read(&payload).unwrap()
    );

    drop(sender);
    shutdown.cancel();
    serve_task.await.expect("serve task").expect("serve ok");
}
