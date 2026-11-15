//! Daemon lifecycle test (Phase 7.4): the daemon identity persists across
//! restarts, `--version` works and SIGTERM shuts down cleanly.

use std::io::BufRead;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rs-rnsd-restart-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &std::path::Path) {
    std::fs::write(
        dir.join("config.toml"),
        "[reticulum]\nenable_transport = false\n\n[logging]\nloglevel = \"Info\"\n",
    )
    .unwrap();
}

/// Run the daemon until it logs its identity, then SIGTERM it.
fn identity_hash_from_run(config_dir: &std::path::Path) -> (String, std::process::ExitStatus) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rs-rnsd"))
        .arg("--config-dir")
        .arg(config_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    let stderr = child.stderr.take().expect("stderr");
    let mut hash = None;
    for line in std::io::BufReader::new(stderr).lines() {
        let line = line.expect("read line");
        eprintln!("daemon: {line}");
        if let Some(hex) = line
            .split_once("daemon identity <")
            .and_then(|(_, rest)| rest.split('>').next())
        {
            hash = Some(hex.to_string());
            break;
        }
    }

    // Clean shutdown via SIGTERM (not SIGKILL).
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let status = child.wait().expect("wait for daemon");
    (hash.expect("daemon must log its identity"), status)
}

#[test]
fn identity_is_stable_across_restarts() {
    let dir = temp_dir("identity");
    write_config(&dir);

    let (first, status) = identity_hash_from_run(&dir);
    assert_eq!(first.len(), 32, "identity hash must be 16 bytes hex");
    assert!(status.success(), "daemon must shut down cleanly on SIGTERM");

    let identity_file = dir.join("identity");
    assert!(identity_file.exists(), "identity must be persisted");
    let content = std::fs::read_to_string(&identity_file).unwrap();
    assert_eq!(content.len(), 128, "identity file must hold the hex keys");

    // Restart: the same identity must be loaded and reported.
    for run in 0..2 {
        let (again, status) = identity_hash_from_run(&dir);
        assert_eq!(again, first, "identity must be stable across restart {run}");
        assert!(status.success(), "daemon must shut down cleanly on SIGTERM");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn version_flag_works() {
    let output = Command::new(env!("CARGO_BIN_EXE_rs-rnsd"))
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "got: {text}");
}
