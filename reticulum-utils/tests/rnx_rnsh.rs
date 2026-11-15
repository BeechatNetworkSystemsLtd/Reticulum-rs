//! rnx + rnsh end-to-end over UDP loopback transports (Phase 8).

use std::time::Duration;

#[tokio::test]
async fn rnx_remote_execution_roundtrip() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init();

    // Listener on its own transport + config dir.
    let server_dir = std::env::temp_dir().join(format!("rn-rnx-server-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&server_dir);
    std::fs::create_dir_all(&server_dir).unwrap();

    let server_options = reticulum_utils::rnx::ServeOptions {
        config_dir: server_dir.clone(),
        allow_all: true,
        allowed: vec![],
        udp_loopback: Some((5003, 5004)),
        idle_timeout: None,
    };

    let listener = tokio::spawn(async move {
        let _ = reticulum_utils::rnx::serve(&server_options).await;
    });

    // The listener announces the rnx destination; capture it by watching
    // the shared identity file + announcing over the loopback pair. The
    // client discovers it via the identity storage path.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Read the listener identity from the storage file to derive the
    // destination hash deterministically.
    let identity_hex = std::fs::read_to_string(server_dir.join("storage/identities/rnx"))
        .expect("listener identity file");

    // The destination hash derives from the app name + identity; use the
    // client-side announce discovery over the same UDP pair instead:
    // the listener announces, the client subscribes.
    let client_dir = std::env::temp_dir().join(format!("rn-rnx-client-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&client_dir);
    std::fs::create_dir_all(&client_dir).unwrap();

    // Wait for the listener to be up (its announce went out on 5003),
    // then run the client with the mirrored ports.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let exec_options = reticulum_utils::rnx::ExecOptions {
        config_dir: client_dir.clone(),
        timeout: Duration::from_secs(20),
        udp_loopback: Some((5004, 5003)),
        ..Default::default()
    };

    // Derive the destination hash from the identity file.
    let identity = reticulum::identity::PrivateIdentity::new_from_hex_string(identity_hex.trim())
        .expect("listener identity");
    let destination = reticulum::destination::DestinationName::new("rnx", "execute")
        .address_hash_for(identity.as_identity());

    let result =
        reticulum_utils::rnx::execute(&destination, "printf hello-from-rnx", &exec_options)
            .await
            .expect("remote execution");

    assert!(result.executed, "command must have been executed");
    assert_eq!(result.retval, 0);
    assert_eq!(result.stdout, b"hello-from-rnx");

    listener.abort();
}

#[tokio::test]
async fn rnsh_session_command_roundtrip() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init();

    let server_dir = std::env::temp_dir().join(format!("rn-rnsh-server-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&server_dir);
    std::fs::create_dir_all(&server_dir).unwrap();

    let server_options = reticulum_utils::rnsh::ServeOptions {
        config_dir: server_dir.clone(),
        allow_all: true,
        allowed: Vec::new(),
        default_command: None,
        allow_remote_command: true,
        udp_loopback: Some((5005, 5006)),
    };

    let listener = tokio::spawn(async move {
        let _ = reticulum_utils::rnsh::serve(&server_options).await;
    });

    tokio::time::sleep(Duration::from_secs(2)).await;

    let identity_hex = std::fs::read_to_string(server_dir.join("storage/identities/rnsh"))
        .expect("listener identity file");
    let identity = reticulum::identity::PrivateIdentity::new_from_hex_string(identity_hex.trim())
        .expect("listener identity");
    let destination = reticulum::destination::DestinationName::new("rnsh", "shell")
        .address_hash_for(identity.as_identity());

    let client_dir = std::env::temp_dir().join(format!("rn-rnsh-client-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&client_dir);
    std::fs::create_dir_all(&client_dir).unwrap();

    let options = reticulum_utils::rnsh::ServeOptions {
        config_dir: client_dir,
        allow_all: false,
        allowed: Vec::new(),
        default_command: None,
        allow_remote_command: true,
        udp_loopback: Some((5006, 5005)),
    };

    let outcome = reticulum_utils::rnsh::run_command(&destination, "printf shell-output", &options)
        .await
        .expect("session command");

    assert_eq!(outcome.stdout, b"shell-output");

    listener.abort();
}


/// Local PTY only: the child sees a tty, and the test applies `TIOCSWINSZ` on the local PTY.
#[tokio::test]
async fn rnsh_pty_resize_without_network() {
    let script = r#"
import os, sys, fcntl, struct, termios, time
fd = sys.stdout.fileno()
print("tty" if os.isatty(fd) else "notty", flush=True)
print(os.ttyname(fd), flush=True)
def winsz():
    return struct.unpack("HHHH", fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0"*8))
print("%d %d %d %d" % winsz(), flush=True)
initial = winsz()
for _ in range(100):
    time.sleep(0.05)
    now = winsz()
    if now != initial:
        print("%d %d %d %d" % now, flush=True)
        sys.exit(0)
print("unchanged", flush=True)
sys.exit(1)
"#;
    let argv = vec!["python3".to_string(), "-c".to_string(), script.to_string()];
    let mut proc = reticulum_utils::rnsh::spawn_session_process(
        &argv,
        false,
        false,
        false,
        Some("xterm"),
        None,
        None,
    )
    .expect("spawn pty");
    let mut stdout = proc.take_stdout().expect("pty stdout");

    let first = read_pty_text(&mut stdout, 3).await;
    let lines: Vec<&str> = first
        .split(['\n', '\r'])
        .filter(|line| !line.is_empty())
        .collect();
    assert!(
        lines.first().is_some_and(|line| *line == "tty"),
        "child stdout should be a tty, got {first:?}"
    );
    assert!(
        lines.get(1).is_some_and(|line| line.starts_with("/dev/")),
        "expected a pty path, got {first:?}"
    );
    let initial = lines
        .get(2)
        .and_then(|line| parse_winsz(line))
        .unwrap_or_else(|| panic!("initial winsize missing in {first:?}"));

    let (rows, cols, hpix, vpix) = if initial.0 == 48 {
        (50, 130, 11, 22)
    } else {
        (48, 123, 640, 480)
    };
    proc.set_window_size(Some(rows), Some(cols), Some(hpix), Some(vpix))
        .expect("TIOCSWINSZ");

    let rest = read_pty_text(&mut stdout, 1).await;
    let updated = rest
        .split(['\n', '\r'])
        .filter(|line| !line.is_empty())
        .find_map(parse_winsz)
        .unwrap_or_else(|| panic!("resize did not change winsize, output {rest:?}"));
    assert_eq!(updated, (rows, cols, hpix, vpix));

    drop(stdout);
    drop(proc);
}

fn parse_winsz(line: &str) -> Option<(u32, u32, u32, u32)> {
    let mut parts = line.split_whitespace();
    let rows = parts.next()?.parse().ok()?;
    let cols = parts.next()?.parse().ok()?;
    let hpix = parts.next()?.parse().ok()?;
    let vpix = parts.next()?.parse().ok()?;
    Some((rows, cols, hpix, vpix))
}

async fn read_pty_text(
    reader: &mut reticulum_utils::rnsh::SessionReader,
    min_lines: usize,
) -> String {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let lines = out.iter().filter(|b| **b == b'\n').count();
        if lines >= min_lines {
            break;
        }
        match tokio::time::timeout(std::time::Duration::from_millis(200), reader.read(&mut buf))
            .await
        {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Err(_) if lines >= min_lines => break,
            Err(_) => {}
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn rnx_propagates_nonzero_remote_status_from_exit_message() {
    let request = reticulum_utils::rnx::encode_request("exit 7", 5.0, Some(64), Some(64), None);
    let response = reticulum_utils::rnx::execute_request(&request).await;
    let decoded = reticulum_utils::rnx::decode_exec_response(&response).expect("exit message");
    assert!(decoded.executed, "command must have run");
    assert_eq!(reticulum_utils::rnx::remote_exit_code(&decoded), 7);

    let capped = reticulum_utils::rnx::encode_request(
        "printf stdout-data; printf stderr-data >&2",
        5.0,
        Some(6),
        Some(3),
        None,
    );
    let capped = reticulum_utils::rnx::decode_exec_response(
        &reticulum_utils::rnx::execute_request(&capped).await,
    )
    .expect("capped output");
    assert_eq!(capped.stdout, b"stdout");
    assert_eq!(capped.stderr, b"std");
    assert!(capped.stdout_len > capped.stdout.len() as u64);
    assert!(capped.stderr_len > capped.stderr.len() as u64);

    let dir = std::env::temp_dir().join(format!("rn-rnx-stdin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let stdin_file = dir.join("stdin.txt");
    std::fs::write(&stdin_file, b"hello-stdin").unwrap();
    let stdin = reticulum_utils::rnx::stdin_payload(None, Some(&stdin_file))
        .expect("stdin file")
        .expect("bytes");
    let echoed = reticulum_utils::rnx::encode_request("cat", 5.0, Some(4), Some(0), Some(&stdin));
    let echoed = reticulum_utils::rnx::decode_exec_response(
        &reticulum_utils::rnx::execute_request(&echoed).await,
    )
    .expect("stdin echo");
    assert_eq!(echoed.stdout, b"hell");
    assert_eq!(echoed.stdout_len, b"hello-stdin".len() as u64);
    assert!(echoed.stderr.is_empty());
}
