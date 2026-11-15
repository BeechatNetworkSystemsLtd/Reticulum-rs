//! `rnx` — remote command execution over Reticulum links
//! (Python `RNS/Utilities/rnx.py`).
//!
//! The listener announces a SINGLE destination `rnx.execute` and serves
//! `command` requests; the request payload is a msgpack list
//! `[command, timeout, o_limit, e_limit, stdin]` and the response is
//! `[executed, retval, stdout, stderr, stdout_len, stderr_len, started,
//! concluded]`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reticulum::destination::link::LinkEvent;
use reticulum::destination::{DestinationName, ProofStrategy};
use reticulum::hash::AddressHash;

use crate::common::{
    build_tool_transport, load_or_create_private_identity, resolve_config_dir, ToolTransportOptions,
};

pub const APP_NAME: &str = "rnx";

/// Options for the listener (`rnx --serve`).
pub struct ServeOptions {
    pub config_dir: PathBuf,
    /// Accept commands from anyone (Python `--allow-all`).
    pub allow_all: bool,
    /// Allowed remote identity hashes (Python `--allow`).
    pub allowed: Vec<AddressHash>,
    pub udp_loopback: Option<(u16, u16)>,
    /// Idle timeout for the listener before exiting (None = forever).
    pub idle_timeout: Option<Duration>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            allow_all: false,
            allowed: Vec::new(),
            udp_loopback: Some((4998, 4999)),
            idle_timeout: None,
        }
    }
}

/// Run an `rnx` listener until `idle_timeout` elapses (or forever).
/// Returns the announced destination hash.
pub async fn serve(options: &ServeOptions) -> Result<AddressHash, String> {
    let transport = Arc::new(
        build_tool_transport(ToolTransportOptions {
            config_dir: &options.config_dir,
            instance_name: "rnx",
            enable_transport: false,
            udp_loopback: options.udp_loopback,
        })
        .await,
    );

    // Identity persisted per-app like Python (`<storage>/identities/rnx`).
    let identity_path = options.config_dir.join("storage/identities/rnx");
    let (identity, _) =
        load_or_create_private_identity(&identity_path).map_err(|err| err.to_string())?;

    let destination = transport
        .add_destination(identity, DestinationName::new(APP_NAME, "execute"))
        .await;

    {
        let mut destination = destination.lock().await;
        destination.set_proof_strategy(ProofStrategy::None);
    }

    let address = destination.lock().await.desc.address_hash;

    // The command handler executes the command and builds the response.
    let allow_all = options.allow_all;
    let allowed = std::sync::Arc::new(options.allowed.clone());
    transport
        .register_async_request_handler(&address, "command", {
            let allowed = allowed.clone();
            move |ctx| {
                let allowed = allowed.clone();
                async move {
                    if !allow_all {
                        let Some(remote) = &ctx.remote_identity else {
                            return None;
                        };
                        if !allowed.contains(&remote.address_hash) {
                            return None;
                        }
                    }

                    Some(execute_request(&ctx.data).await)
                }
            }
        })
        .await;

    transport.send_announce(&destination, None).await;

    log::info!("rnx listening for commands on {address}");

    // Park until the idle timeout (if any).
    if let Some(timeout) = options.idle_timeout {
        tokio::time::sleep(timeout).await;
    } else {
        std::future::pending::<()>().await;
    }

    Ok(address)
}

/// Read stdin bytes from an inline string or a file. A file wins when
/// both are set.
pub fn stdin_payload(
    inline: Option<&str>,
    file: Option<&std::path::Path>,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(path) = file {
        return std::fs::read(path)
            .map(Some)
            .map_err(|err| format!("could not read stdin file {}: {err}", path.display()));
    }
    Ok(inline.map(|text| text.as_bytes().to_vec()))
}

/// Encode a `command` request:
/// `[command, timeout, stdout_limit, stderr_limit, stdin]`.
/// The command is msgpack bin (UTF-8 bytes) and the timeout is f64
/// seconds. `None` limits and stdin are msgpack nil (no cap / no stdin).
pub fn encode_request(
    command: &str,
    timeout_secs: f64,
    stdout_limit: Option<u64>,
    stderr_limit: Option<u64>,
    stdin: Option<&[u8]>,
) -> Vec<u8> {
    use rmp::encode as mp;
    let mut request = Vec::new();
    mp::write_array_len(&mut request, 5).ok();
    mp::write_bin(&mut request, command.as_bytes()).ok();
    mp::write_f64(&mut request, timeout_secs).ok();
    match stdout_limit {
        Some(limit) => {
            mp::write_u64(&mut request, limit).ok();
        }
        None => {
            mp::write_nil(&mut request).ok();
        }
    }
    match stderr_limit {
        Some(limit) => {
            mp::write_u64(&mut request, limit).ok();
        }
        None => {
            mp::write_nil(&mut request).ok();
        }
    }
    match stdin {
        Some(data) => {
            mp::write_bin(&mut request, data).ok();
        }
        None => {
            mp::write_nil(&mut request).ok();
        }
    }
    request
}

/// Decode the request payload and execute the command
/// (Python `execute_received_command`).
pub async fn execute_request(data: &[u8]) -> Vec<u8> {
    use rmpv::Value;

    let mut cursor = std::io::Cursor::new(data);
    let Ok(Value::Array(items)) = rmpv::decode::read_value(&mut cursor) else {
        return pack_failure(now_secs());
    };

    let command = match items.first() {
        Some(value) => value
            .as_str()
            .map(|text| text.to_string())
            .or_else(|| {
                value
                    .as_slice()
                    .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
            })
            .unwrap_or_default(),
        None => String::new(),
    };

    // [command, timeout, o_limit, e_limit, stdin]
    // Absent or non-numeric timeouts fall back to 30s. A positive finite
    // timeout is used as given, including fractions and values outside
    // 1..=3600. Non-positive finite values, including +0 and -0, expire
    // immediately. Only a non-finite positive such as +inf uses the long deadline.
    let timeout = match items.get(1).and_then(|value| value.as_f64()) {
        Some(secs) if secs.is_finite() && secs > 0.0 => {
            Duration::try_from_secs_f64(secs).unwrap_or(Duration::MAX)
        }
        Some(secs) if secs.is_finite() => Duration::ZERO,
        Some(secs) if secs.is_sign_positive() => Duration::MAX,
        Some(_) => Duration::ZERO,
        None => Duration::from_secs(30),
    };
    let stdout_limit = optional_limit(items.get(2));
    let stderr_limit = optional_limit(items.get(3));
    let stdin = optional_bytes(items.get(4));

    let started = now_secs();

    // The request handler runs while the transport handler is locked, so
    // the child runs under a kill timer. The stdin write shares that
    // deadline: a payload larger than the pipe buffer must not stall the
    // timer when the child does not read.
    Box::pin(async move {
        let mut command_line = tokio::process::Command::new("sh");
        command_line
            .arg("-c")
            .arg(&command)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            });
        let mut child = match command_line.spawn() {
            Ok(child) => child,
            Err(_) => return pack_failure(started),
        };

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdin_pipe = child.stdin.take();
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(86400 * 365));

        let stdout_task = tokio::spawn(read_capped(stdout_pipe, stdout_limit, deadline));
        let stderr_task = tokio::spawn(read_capped(stderr_pipe, stderr_limit, deadline));

        // Drop the stdin future (and the pipe) before killing so a write
        // blocked on a full buffer cannot outlive the deadline.
        let waited = {
            let write_stdin = async {
                if let Some(mut pipe) = stdin_pipe {
                    use tokio::io::AsyncWriteExt;
                    if let Some(data) = stdin.as_deref() {
                        let _ = pipe.write_all(data).await;
                    }
                    drop(pipe);
                }
            };
            let mut write_stdin = std::pin::pin!(write_stdin);
            let mut writing = true;
            loop {
                tokio::select! {
                    status = child.wait() => break Ok(status),
                    _ = &mut write_stdin, if writing => writing = false,
                    _ = tokio::time::sleep_until(deadline) => break Err(()),
                }
            }
        };
        let status = match waited {
            Ok(status) => status.ok(),
            Err(()) => {
                let _ = child.start_kill();
                match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
                    Ok(Ok(status)) => Some(status),
                    _ => None,
                }
            }
        };

        let (stdout, stdout_len) = stdout_task.await.unwrap_or_default();
        let (stderr, stderr_len) = stderr_task.await.unwrap_or_default();

        let Some(status) = status else {
            return pack_failure(started);
        };

        let retval = {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status
                    .code()
                    .map(i64::from)
                    .or_else(|| status.signal().map(|signal| 128 + i64::from(signal)))
                    .unwrap_or(-1)
            }
            #[cfg(not(unix))]
            {
                status.code().map(i64::from).unwrap_or(-1)
            }
        };
        pack_success(
            retval,
            &stdout,
            &stderr,
            stdout_len,
            stderr_len,
            started,
            now_secs(),
        )
    })
    .await
}

/// Read until EOF or `deadline`. `limit` caps bytes retained; `None`
/// retains everything read. The second value counts bytes observed,
/// including those past the cap.
async fn read_capped<R>(
    mut pipe: Option<R>,
    limit: Option<u64>,
    deadline: tokio::time::Instant,
) -> (Vec<u8>, u64)
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    use tokio::io::AsyncReadExt;
    let Some(pipe) = pipe.as_mut() else {
        return (Vec::new(), 0);
    };
    let mut stored = Vec::new();
    let mut total = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        let read = tokio::time::timeout_at(deadline, pipe.read(&mut buf)).await;
        let Ok(Ok(n)) = read else {
            break;
        };
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        let room = match limit {
            None => usize::MAX,
            Some(limit) => (limit as usize).saturating_sub(stored.len()),
        };
        if room > 0 {
            let take = room.min(n);
            stored.extend_from_slice(&buf[..take]);
        }
    }
    (stored, total)
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn optional_limit(value: Option<&rmpv::Value>) -> Option<u64> {
    let value = value?;
    if value.is_nil() {
        return None;
    }
    value.as_u64().or_else(|| {
        value
            .as_i64()
            .filter(|number| *number >= 0)
            .map(|number| number as u64)
    })
}

fn optional_bytes(value: Option<&rmpv::Value>) -> Option<Vec<u8>> {
    match value? {
        rmpv::Value::Nil => None,
        rmpv::Value::Binary(bytes) => Some(bytes.clone()),
        rmpv::Value::String(text) => text.as_str().map(|text| text.as_bytes().to_vec()),
        _ => None,
    }
}

fn pack_failure(started: f64) -> Vec<u8> {
    use rmp::encode as mp;
    let mut out = Vec::new();
    mp::write_array_len(&mut out, 8).ok();
    mp::write_bool(&mut out, false).ok();
    for _ in 0..5 {
        mp::write_nil(&mut out).ok();
    }
    mp::write_f64(&mut out, started).ok();
    mp::write_nil(&mut out).ok();
    out
}

fn pack_success(
    retval: i64,
    stdout: &[u8],
    stderr: &[u8],
    stdout_len: u64,
    stderr_len: u64,
    started: f64,
    concluded: f64,
) -> Vec<u8> {
    use rmp::encode as mp;
    let mut out = Vec::new();
    mp::write_array_len(&mut out, 8).ok();
    mp::write_bool(&mut out, true).ok();
    mp::write_i64(&mut out, retval).ok();
    mp::write_bin(&mut out, stdout).ok();
    mp::write_bin(&mut out, stderr).ok();
    mp::write_u64(&mut out, stdout_len).ok();
    mp::write_u64(&mut out, stderr_len).ok();
    mp::write_f64(&mut out, started).ok();
    mp::write_f64(&mut out, concluded).ok();
    out
}

/// Decode a command response into the remote status and captured output.
pub fn decode_exec_response(data: &[u8]) -> Result<ExecResult, String> {
    let mut cursor = std::io::Cursor::new(data);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|err| format!("invalid response: {err}"))?;
    let rmpv::Value::Array(items) = value else {
        return Err("invalid response shape".to_string());
    };
    let executed = items
        .first()
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let retval = items.get(1).and_then(|value| {
        if value.is_nil() {
            return None;
        }
        value
            .as_i64()
            .or_else(|| value.as_u64().map(|number| number as i64))
            .or_else(|| {
                value
                    .as_f64()
                    .filter(|number| number.is_finite())
                    .map(|number| number as i64)
            })
    });
    let has_retval = retval.is_some();
    let retval = retval.unwrap_or(0);
    let stdout = bytes_field(items.get(2));
    let stderr = bytes_field(items.get(3));
    let stdout_len = items
        .get(4)
        .and_then(|value| value.as_u64())
        .unwrap_or(stdout.len() as u64);
    let stderr_len = items
        .get(5)
        .and_then(|value| value.as_u64())
        .unwrap_or(stderr.len() as u64);
    Ok(ExecResult {
        executed,
        retval,
        has_retval,
        stdout,
        stderr,
        stdout_len,
        stderr_len,
    })
}

fn bytes_field(value: Option<&rmpv::Value>) -> Vec<u8> {
    match value {
        Some(rmpv::Value::Binary(bytes)) => bytes.clone(),
        Some(rmpv::Value::String(text)) => text
            .as_str()
            .map(|text| text.as_bytes().to_vec())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Process status for a decoded result. A command that did not run
/// yields 248. Otherwise the remote code is wrapped into a byte
/// (`-15` becomes 241).
pub fn remote_exit_code(result: &ExecResult) -> i32 {
    if !result.executed {
        return 248;
    }
    result.retval as u8 as i32
}

/// Options for executing a command remotely (`rnx <command>`).
#[derive(Clone)]
pub struct ExecOptions {
    pub config_dir: PathBuf,
    pub timeout: Duration,
    pub udp_loopback: Option<(u16, u16)>,
    /// Bytes written to the remote command's stdin.
    pub stdin: Option<Vec<u8>>,
    /// Maximum stdout bytes returned. `None` means no cap.
    pub stdout_limit: Option<u64>,
    /// Maximum stderr bytes returned. `None` means no cap.
    pub stderr_limit: Option<u64>,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            timeout: Duration::from_secs(30),
            udp_loopback: Some((4996, 4997)),
            stdin: None,
            stdout_limit: None,
            stderr_limit: None,
        }
    }
}

pub struct ExecResult {
    pub executed: bool,
    pub retval: i64,
    /// `false` when the response omitted the return value (msgpack nil).
    pub has_retval: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Untruncated stdout length reported by the remote.
    pub stdout_len: u64,
    /// Untruncated stderr length reported by the remote.
    pub stderr_len: u64,
}

/// Execute `command` on the remote listener identified by the announce
/// of an `rnx` destination.
pub async fn execute(
    destination: &AddressHash,
    command: &str,
    options: &ExecOptions,
) -> Result<ExecResult, String> {
    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: "rnx-client",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

    if !transport
        .await_path(destination, Some(options.timeout), None)
        .await
    {
        return Err(format!("no path to {destination}"));
    }

    let identity = transport
        .recall(destination)
        .await
        .ok_or("could not recall identity")?;

    let desc = reticulum::destination::DestinationDesc {
        identity,
        address_hash: *destination,
        name: DestinationName::new(APP_NAME, "execute"),
    };

    let mut events = transport.out_link_events();
    let link = transport.link(desc).await;
    let link_id = *link.lock().await.id();
    let link_deadline = tokio::time::Instant::now() + options.timeout.max(Duration::from_secs(10));
    loop {
        if tokio::time::Instant::now() >= link_deadline {
            return Err(format!("could not establish link with {destination}"));
        }
        let event = match tokio::time::timeout_at(link_deadline, events.recv()).await {
            Ok(Ok(event)) => event,
            _ => return Err(format!("could not establish link with {destination}")),
        };
        if event.id != link_id {
            continue;
        }
        match event.event {
            LinkEvent::Activated => break,
            LinkEvent::Closed => {
                return Err(format!("could not establish link with {destination}"));
            }
            _ => {}
        }
    }

    // Identify so the listener's allow list can match us.
    let (client_identity, _) =
        load_or_create_private_identity(&options.config_dir.join("storage/identities/rnx"))
            .map_err(|err| err.to_string())?;
    let identify = link.lock().await.identify(&client_identity);
    if let Ok(packet) = identify {
        transport.send_packet(packet).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let request = encode_request(
        command,
        options.timeout.as_secs_f64(),
        options.stdout_limit,
        options.stderr_limit,
        options.stdin.as_deref(),
    );

    let rid = transport
        .request(&link, "command", &request)
        .await
        .map_err(|e| format!("request error: {e:?}"))?;

    let response = transport
        .await_request_response(rid, options.timeout)
        .await
        .ok_or("no response from remote")?;

    decode_exec_response(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn negative_remote_status_wraps_to_a_byte() {
        let response = pack_success(-15, b"", b"", 0, 0, 0.0, 0.0);
        let decoded = decode_exec_response(&response).unwrap();
        assert!(decoded.has_retval);
        assert_eq!(decoded.retval, -15);
        assert_eq!(remote_exit_code(&decoded), 241);

        let missing = pack_failure(0.0);
        let decoded = decode_exec_response(&missing).unwrap();
        assert!(!decoded.executed);
        assert!(!decoded.has_retval);
        assert_eq!(remote_exit_code(&decoded), 248);
    }

    #[test]
    fn command_is_msgpack_bin_and_timeout_is_f64() {
        let request = encode_request("exit 7", 1.5, None, None, None);
        assert_eq!(request[0], 0x95);
        assert_eq!(request[1], 0xc4);
        assert_eq!(request[2], 6);
        assert_eq!(&request[3..9], b"exit 7");
        assert_eq!(request[9], 0xcb);
    }

    #[tokio::test]
    async fn str_command_and_integer_timeout_still_run() {
        use rmp::encode as mp;
        let mut request = Vec::new();
        mp::write_array_len(&mut request, 5).unwrap();
        mp::write_str(&mut request, "exit 9").unwrap();
        mp::write_u64(&mut request, 5).unwrap();
        mp::write_nil(&mut request).unwrap();
        mp::write_nil(&mut request).unwrap();
        mp::write_nil(&mut request).unwrap();
        let decoded = decode_exec_response(&execute_request(&request).await).unwrap();
        assert!(decoded.executed);
        assert_eq!(remote_exit_code(&decoded), 9);
    }

    #[tokio::test]
    async fn fractional_timeout_is_not_replaced_or_truncated() {
        let started = Instant::now();
        let decoded = decode_exec_response(
            &execute_request(&encode_request("sleep 30", 0.4, Some(0), Some(0), None)).await,
        )
        .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(1200),
            "fractional timeout was not applied: {elapsed:?}"
        );
        assert!(decoded.executed);
        assert_ne!(remote_exit_code(&decoded), 0);

        let started = Instant::now();
        let decoded = decode_exec_response(
            &execute_request(&encode_request("sleep 1.2", 2.5, Some(0), Some(0), None)).await,
        )
        .unwrap();
        let elapsed = started.elapsed();
        assert!(decoded.executed);
        assert_eq!(remote_exit_code(&decoded), 0);
        assert!(
            elapsed < Duration::from_secs(4),
            "timeout was clamped below the command: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn stdin_write_obeys_the_same_deadline_as_the_child() {
        let payload = vec![b'x'; 1024 * 1024];
        let started = Instant::now();
        let decoded = decode_exec_response(
            &execute_request(&encode_request(
                "sleep 30",
                0.4,
                Some(0),
                Some(0),
                Some(&payload),
            ))
            .await,
        )
        .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "stdin write ran past the deadline: {elapsed:?}"
        );
        assert!(decoded.executed);
    }

    #[tokio::test]
    async fn zero_timeout_expires_immediately() {
        for timeout in [0.0, -0.0] {
            let started = Instant::now();
            let decoded = decode_exec_response(
                &execute_request(&encode_request("sleep 30", timeout, Some(0), Some(0), None))
                    .await,
            )
            .unwrap();
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_secs(3),
                "timeout {timeout} waited {elapsed:?} instead of expiring immediately"
            );
            assert!(decoded.executed);
        }

        use rmp::encode as mp;
        let mut request = Vec::new();
        mp::write_array_len(&mut request, 5).unwrap();
        mp::write_bin(&mut request, b"sleep 30").unwrap();
        mp::write_u64(&mut request, 0).unwrap();
        mp::write_nil(&mut request).unwrap();
        mp::write_nil(&mut request).unwrap();
        mp::write_nil(&mut request).unwrap();
        let started = Instant::now();
        let decoded = decode_exec_response(&execute_request(&request).await).unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "integer timeout 0 waited {elapsed:?} instead of expiring immediately"
        );
        assert!(decoded.executed);
    }

    #[tokio::test]
    async fn signal_death_maps_to_128_plus_signal() {
        let decoded = decode_exec_response(
            &execute_request(&encode_request(
                "kill -TERM $$",
                2.0,
                Some(0),
                Some(0),
                None,
            ))
            .await,
        )
        .unwrap();
        assert!(decoded.executed);
        assert_eq!(remote_exit_code(&decoded), 128 + 15);
    }
}
