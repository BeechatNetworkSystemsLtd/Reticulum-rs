//! `rnsh` — remote shell sessions over Reticulum channels
//! (Python `RNS/Utilities/rnsh`, channel-session protocol).
//!
//! Wire-compatible with the Python rnsh protocol: messages are
//! msgpack-packed channel messages with types `0xac00`-`0xac07`
//! (`MSG_MAGIC = 0xac`), the handshake is
//! identify → `VersionInfoMessage` exchange → `ExecuteCommandMessage`,
//! stream data flows as `StreamDataMessage` (2-byte big-endian header:
//! stream id with EOF/compressed flags) and the session ends with
//! `CommandExitedMessage`.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use reticulum::channel::Message;
use reticulum::destination::{DestinationName, ProofStrategy};
use reticulum::error::RnsError;
use reticulum::hash::AddressHash;
use reticulum::identity::Identity;
use reticulum::transport::Transport;

use crate::common::{
    build_tool_transport, load_or_create_private_identity, resolve_config_dir, rmpv_to_bytes,
    ToolTransportOptions,
};

pub const APP_NAME: &str = "rnsh";

/// Python `rnsh` protocol constants.
const MSG_MAGIC: u16 = 0xac;
const PROTOCOL_VERSION: u32 = 1;

/// Rust rnsh software version reported in the handshake.
const SW_VERSION: &str = concat!("reticulum-rs ", env!("CARGO_PKG_VERSION"));

const MSG_NOOP: u16 = MSG_MAGIC << 8;
const MSG_WINDOW_SIZE: u16 = (MSG_MAGIC << 8) | 2;
const MSG_EXECUTE_COMMAND: u16 = (MSG_MAGIC << 8) | 3;
const MSG_STREAM_DATA: u16 = (MSG_MAGIC << 8) | 4;
const MSG_VERSION_INFO: u16 = (MSG_MAGIC << 8) | 5;
const MSG_ERROR: u16 = (MSG_MAGIC << 8) | 6;
const MSG_COMMAND_EXITED: u16 = (MSG_MAGIC << 8) | 7;

pub const STREAM_ID_STDIN: u16 = 0;
pub const STREAM_ID_STDOUT: u16 = 1;
pub const STREAM_ID_STDERR: u16 = 2;

/// One rnsh protocol channel message (Python `RNS/Utilities/rnsh/protocol.py`).
#[derive(Debug, Clone)]
pub enum RnshMessage {
    Noop,
    WindowSize {
        rows: Option<u32>,
        cols: Option<u32>,
        hpix: Option<u32>,
        vpix: Option<u32>,
    },
    ExecuteCommand {
        cmdline: Option<Vec<String>>,
        pipe_stdin: bool,
        pipe_stdout: bool,
        pipe_stderr: bool,
        term: Option<String>,
        rows: Option<u32>,
        cols: Option<u32>,
        hpix: Option<u32>,
        vpix: Option<u32>,
    },
    StreamData {
        stream_id: u16,
        eof: bool,
        data: Vec<u8>,
    },
    VersionInfo {
        sw_version: String,
        protocol_version: u32,
    },
    Error {
        msg: Option<String>,
        fatal: bool,
    },
    CommandExited {
        return_code: Option<i32>,
    },
}

/// Serialize an `rmpv::Value` tree to msgpack bytes.
pub fn test_pack_value(value: &rmpv::Value) -> Vec<u8> {
    rmpv_to_bytes(value)
}

fn pack_opt_u32(value: Option<u32>) -> rmpv::Value {
    match value {
        Some(v) => v.into(),
        None => rmpv::Value::Nil,
    }
}

fn unpack_opt_u32(value: &rmpv::Value) -> Option<u32> {
    value.as_u64().map(|v| v as u32)
}

fn unpack_opt_string(value: &rmpv::Value) -> Option<String> {
    match value {
        rmpv::Value::String(s) => s.as_str().map(str::to_string),
        _ => None,
    }
}

fn unpack_opt_bool(value: &rmpv::Value) -> bool {
    matches!(value, rmpv::Value::Boolean(true))
}

impl Message for RnshMessage {
    fn message_type(&self) -> u16 {
        match self {
            Self::Noop => MSG_NOOP,
            Self::WindowSize { .. } => MSG_WINDOW_SIZE,
            Self::ExecuteCommand { .. } => MSG_EXECUTE_COMMAND,
            Self::StreamData { .. } => MSG_STREAM_DATA,
            Self::VersionInfo { .. } => MSG_VERSION_INFO,
            Self::Error { .. } => MSG_ERROR,
            Self::CommandExited { .. } => MSG_COMMAND_EXITED,
        }
    }

    fn pack(&self) -> Vec<u8> {
        match self {
            Self::Noop => Vec::new(),
            Self::WindowSize {
                rows,
                cols,
                hpix,
                vpix,
            } => {
                let tuple = rmpv::Value::Array(vec![
                    pack_opt_u32(*rows),
                    pack_opt_u32(*cols),
                    pack_opt_u32(*hpix),
                    pack_opt_u32(*vpix),
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::ExecuteCommand {
                cmdline,
                pipe_stdin,
                pipe_stdout,
                pipe_stderr,
                term,
                rows,
                cols,
                hpix,
                vpix,
            } => {
                let cmdline = match cmdline {
                    Some(args) => rmpv::Value::Array(
                        args.iter()
                            .map(|a| rmpv::Value::String(a.as_str().into()))
                            .collect(),
                    ),
                    None => rmpv::Value::Nil,
                };
                let tuple = rmpv::Value::Array(vec![
                    cmdline,
                    (*pipe_stdin).into(),
                    (*pipe_stdout).into(),
                    (*pipe_stderr).into(),
                    rmpv::Value::Nil, // tcflags
                    match term {
                        Some(t) => rmpv::Value::String(t.as_str().into()),
                        None => rmpv::Value::Nil,
                    },
                    pack_opt_u32(*rows),
                    pack_opt_u32(*cols),
                    pack_opt_u32(*hpix),
                    pack_opt_u32(*vpix),
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::StreamData {
                stream_id,
                eof,
                data,
            } => {
                // 2-byte big-endian header: id | eof<<15 (compression
                // unsupported on this side).
                let header = (stream_id & 0x3fff) | if *eof { 0x8000 } else { 0 };
                let mut packed = Vec::with_capacity(2 + data.len());
                packed.extend_from_slice(&header.to_be_bytes());
                packed.extend_from_slice(data);
                packed
            }
            Self::VersionInfo {
                sw_version,
                protocol_version,
            } => {
                let tuple = rmpv::Value::Array(vec![
                    rmpv::Value::String(sw_version.as_str().into()),
                    (*protocol_version).into(),
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::Error { msg, fatal } => {
                let tuple = rmpv::Value::Array(vec![
                    match msg {
                        Some(m) => rmpv::Value::String(m.as_str().into()),
                        None => rmpv::Value::Nil,
                    },
                    (*fatal).into(),
                    rmpv::Value::Nil, // data dict
                ]);
                rmpv_to_bytes(&tuple)
            }
            Self::CommandExited { return_code } => match return_code {
                Some(code) => rmpv_to_bytes(&rmpv::Value::from(*code)),
                None => rmpv_to_bytes(&rmpv::Value::Nil),
            },
        }
    }

    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError> {
        match message_type {
            MSG_NOOP => Ok(Self::Noop),
            MSG_WINDOW_SIZE => {
                let value: rmpv::Value = rmpv::decode::value::read_value(&mut &packed[..])
                    .map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                Ok(Self::WindowSize {
                    rows: items.first().and_then(unpack_opt_u32),
                    cols: items.get(1).and_then(unpack_opt_u32),
                    hpix: items.get(2).and_then(unpack_opt_u32),
                    vpix: items.get(3).and_then(unpack_opt_u32),
                })
            }
            MSG_EXECUTE_COMMAND => {
                let value: rmpv::Value = rmpv::decode::value::read_value(&mut &packed[..])
                    .map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                let cmdline = match items.first() {
                    Some(rmpv::Value::Array(args)) => Some(
                        args.iter()
                            .filter_map(unpack_opt_string)
                            .collect::<Vec<String>>(),
                    ),
                    _ => None,
                };
                Ok(Self::ExecuteCommand {
                    cmdline,
                    pipe_stdin: items.get(1).map(unpack_opt_bool).unwrap_or(false),
                    pipe_stdout: items.get(2).map(unpack_opt_bool).unwrap_or(false),
                    pipe_stderr: items.get(3).map(unpack_opt_bool).unwrap_or(false),
                    term: items.get(5).and_then(unpack_opt_string),
                    rows: items.get(6).and_then(unpack_opt_u32),
                    cols: items.get(7).and_then(unpack_opt_u32),
                    hpix: items.get(8).and_then(unpack_opt_u32),
                    vpix: items.get(9).and_then(unpack_opt_u32),
                })
            }
            MSG_STREAM_DATA => {
                if packed.len() < 2 {
                    return Err(RnsError::ChannelMessageTooBig);
                }
                let header = u16::from_be_bytes([packed[0], packed[1]]);
                let compressed = header & 0x4000 > 0;
                let data = if compressed {
                    // Python `RNS.Buffer.StreamDataMessage` opportunistically
                    // bzip2-compresses repetitive stream chunks.
                    let mut decoder = bzip2::read::BzDecoder::new(&packed[2..]);
                    let mut data = Vec::new();
                    std::io::Read::read_to_end(&mut decoder, &mut data)
                        .map_err(|_| RnsError::ChannelMessageTooBig)?;
                    data
                } else {
                    packed[2..].to_vec()
                };
                Ok(Self::StreamData {
                    stream_id: header & 0x3fff,
                    eof: header & 0x8000 > 0,
                    data,
                })
            }
            MSG_VERSION_INFO => {
                let value: rmpv::Value = rmpv::decode::value::read_value(&mut &packed[..])
                    .map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                Ok(Self::VersionInfo {
                    sw_version: items
                        .first()
                        .and_then(unpack_opt_string)
                        .unwrap_or_default(),
                    protocol_version: items.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                })
            }
            MSG_ERROR => {
                let value: rmpv::Value = rmpv::decode::value::read_value(&mut &packed[..])
                    .map_err(|_| RnsError::ChannelMessageTooBig)?;
                let rmpv::Value::Array(items) = value else {
                    return Err(RnsError::ChannelMessageTooBig);
                };
                Ok(Self::Error {
                    msg: items.first().and_then(unpack_opt_string),
                    fatal: items.get(1).map(unpack_opt_bool).unwrap_or(false),
                })
            }
            MSG_COMMAND_EXITED => {
                let value: rmpv::Value = rmpv::decode::value::read_value(&mut &packed[..])
                    .map_err(|_| RnsError::ChannelMessageTooBig)?;
                Ok(Self::CommandExited {
                    return_code: value.as_i64().map(|v| v as i32),
                })
            }
            _ => Err(RnsError::ChannelMessageTooBig),
        }
    }
}

/// Options for the shell listener (`rn sh --serve`).
pub struct ServeOptions {
    pub config_dir: PathBuf,
    /// Accept sessions from any identified or unidentified peer.
    pub allow_all: bool,
    /// Remote identities allowed to start shell sessions.
    pub allowed: Vec<AddressHash>,
    /// Default command for sessions (Python `-l -- <cmd>`); remote
    /// command lines replace it when remote commands are allowed.
    pub default_command: Option<Vec<String>>,
    /// Execute remote command lines (Python default; `-C` disables).
    pub allow_remote_command: bool,
    pub udp_loopback: Option<(u16, u16)>,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            allow_all: false,
            allowed: Vec::new(),
            default_command: None,
            allow_remote_command: true,
            udp_loopback: Some((5001, 5002)),
        }
    }
}

fn remote_authorized(
    allow_all: bool,
    allowed: &HashSet<AddressHash>,
    remote: Option<&Identity>,
) -> bool {
    allow_all || remote.is_some_and(|identity| allowed.contains(&identity.address_hash))
}

/// Run an `rnsh` listener. Returns the announced destination hash; the
/// listener runs until cancelled by dropping the transport.
pub async fn serve(options: &ServeOptions) -> Result<AddressHash, String> {
    let transport = Arc::new(
        build_tool_transport(ToolTransportOptions {
            config_dir: &options.config_dir,
            instance_name: "rnsh",
            enable_transport: false,
            udp_loopback: options.udp_loopback,
        })
        .await,
    );

    let identity_path = options.config_dir.join("storage/identities/rnsh");
    let (identity, _) =
        load_or_create_private_identity(&identity_path).map_err(|err| err.to_string())?;

    let destination = transport
        .add_destination(identity, DestinationName::new(APP_NAME, "shell"))
        .await;
    destination
        .lock()
        .await
        .set_proof_strategy(ProofStrategy::All);
    let address = destination.lock().await.desc.address_hash;

    // Establish a channel per incoming link and serve exec sessions.
    let event_transport = transport.clone();
    let allow_all = options.allow_all;
    let allowed: HashSet<AddressHash> = options.allowed.iter().copied().collect();
    let default_command = options.default_command.clone();
    let allow_remote_command = options.allow_remote_command;
    let config_dir = options.config_dir.clone();
    if !allow_all && allowed.is_empty() && load_allowed_identity_files(&config_dir).is_empty() {
        log::warn!("No allowed identities configured, rnsh will not accept any connections");
    }
    tokio::spawn(async move {
        let mut link_events = event_transport.in_link_events();
        loop {
            let Ok(event) = link_events.recv().await else {
                return;
            };
            match event.event {
                reticulum::destination::link::LinkEvent::Activated if allow_all => {
                    start_session(
                        event_transport.clone(),
                        event.id,
                        default_command.clone(),
                        allow_remote_command,
                        None,
                    )
                    .await;
                }
                reticulum::destination::link::LinkEvent::RemoteIdentified(identity)
                    if !allow_all =>
                {
                    // Reload on each link, same as the Python listener.
                    let mut effective = allowed.clone();
                    effective.extend(load_allowed_identity_files(&config_dir));
                    if remote_authorized(false, &effective, Some(&identity)) {
                        let remote = crate::common::prettyhexrep(identity.address_hash.as_slice());
                        start_session(
                            event_transport.clone(),
                            event.id,
                            default_command.clone(),
                            allow_remote_command,
                            Some(remote),
                        )
                        .await;
                    } else {
                        log::warn!("rnsh: unauthorized identity attempted a session");
                        let _ = event_transport.link_close(event.id).await;
                    }
                }
                _ => {}
            }
        }
    });

    transport.send_announce(&destination, None).await;
    log::info!("rnsh listening for sessions on {address}");

    Ok(address)
}

/// Locate an established inbound link by id.
async fn find_link(
    transport: &Arc<Transport>,
    link_id: reticulum::destination::link::LinkId,
) -> Option<Arc<tokio::sync::Mutex<reticulum::destination::link::Link>>> {
    transport.find_in_link(&link_id).await
}

async fn start_session(
    transport: Arc<Transport>,
    link_id: reticulum::destination::link::LinkId,
    default_command: Option<Vec<String>>,
    allow_remote_command: bool,
    remote_identity: Option<String>,
) {
    let Some(link) = find_link(&transport, link_id).await else {
        return;
    };
    let (channel, mut receiver) = match transport.mk_channel::<RnshMessage>(link).await {
        Ok(pair) => pair,
        Err(_) => return,
    };

    tokio::spawn(async move {
        let mut session: Option<SessionProcess> = None;
        let mut version_exchanged = false;
        let mut stdin_is_pipe = false;

        while let Ok(message) = receiver.recv().await {
            match message {
                RnshMessage::VersionInfo {
                    protocol_version, ..
                } => {
                    if protocol_version != PROTOCOL_VERSION {
                        let _ = send_when_ready(
                            &channel,
                            RnshMessage::Error {
                                msg: Some("Incompatible protocol".into()),
                                fatal: true,
                            },
                        )
                        .await;
                        break;
                    }
                    // Reply with our version info (Python listener
                    // handshake).
                    if !send_when_ready(
                        &channel,
                        RnshMessage::VersionInfo {
                            sw_version: SW_VERSION.to_string(),
                            protocol_version: PROTOCOL_VERSION,
                        },
                    )
                    .await
                    {
                        break;
                    }
                    version_exchanged = true;
                }
                RnshMessage::ExecuteCommand {
                    cmdline,
                    pipe_stdin,
                    pipe_stdout,
                    pipe_stderr,
                    term,
                    rows,
                    cols,
                    hpix,
                    vpix,
                } if version_exchanged => {
                    stdin_is_pipe = pipe_stdin;
                    let mut command = default_command.clone().unwrap_or_default();
                    match cmdline {
                        Some(remote) if !remote.is_empty() => {
                            if !allow_remote_command {
                                let _ = send_when_ready(
                                    &channel,
                                    RnshMessage::Error {
                                        msg: Some(
                                            "Remote command line not allowed by listener".into(),
                                        ),
                                        fatal: true,
                                    },
                                )
                                .await;
                                break;
                            }
                            command = remote;
                        }
                        _ => {}
                    }

                    if command.is_empty() {
                        // Python `listener.listen` uses `pwd.getpwuid(os.getuid()).pw_shell`.
                        let mut shell = String::new();
                        let mut buf_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
                        if buf_len < 1024 {
                            buf_len = 16 * 1024;
                        }
                        let mut buf = vec![0u8; buf_len as usize];
                        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
                        let mut result: *mut libc::passwd = std::ptr::null_mut();
                        let rc = unsafe {
                            libc::getpwuid_r(
                                libc::getuid(),
                                &mut pwd,
                                buf.as_mut_ptr().cast(),
                                buf.len(),
                                &mut result,
                            )
                        };
                        if rc == 0 && !result.is_null() && !pwd.pw_shell.is_null() {
                            if let Ok(text) =
                                unsafe { std::ffi::CStr::from_ptr(pwd.pw_shell) }.to_str()
                            {
                                shell = text.to_string();
                            }
                        } else if rc != 0 {
                            log::error!(
                                "Error looking up shell: {}",
                                std::io::Error::from_raw_os_error(rc)
                            );
                        }
                        if shell.is_empty() {
                            shell = "/bin/sh".to_string();
                        }
                        command = vec![shell];
                    }

                    match spawn_session_process(
                        &command,
                        pipe_stdin,
                        pipe_stdout,
                        pipe_stderr,
                        term.as_deref(),
                        remote_identity.as_deref(),
                        winsize_tuple(rows, cols, hpix, vpix),
                    ) {
                        Ok(spawned) => session = Some(spawned),
                        Err(err) => {
                            let _ = send_when_ready(
                                &channel,
                                RnshMessage::Error {
                                    msg: Some(format!("Could not start command: {err}")),
                                    fatal: true,
                                },
                            )
                            .await;
                            break;
                        }
                    }
                    break;
                }
                _ => {}
            }
        }

        let Some(mut session) = session else { return };

        let stdout = session.take_stdout();
        let stderr = session.take_stderr();
        let stdin = session.take_stdin();
        let winsize = session.winsize_fd.clone();
        let child_pid = session.child.id();
        // Set only when `prepare_child_tty` ran `setsid`, so this pid is the process group.
        let session_leader = session.winsize_fd.is_some();

        let channel_out = channel.clone();
        let mut stdout_task = tokio::spawn(async move {
            let mut stdout = stdout;
            if let Some(stdout) = stdout.as_mut() {
                let mut buffer = vec![0u8; stream_chunk_size(&channel_out.link).await];
                loop {
                    match stdout.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if !send_stream_data(
                                &channel_out,
                                STREAM_ID_STDOUT,
                                buffer[..n].to_vec(),
                            )
                            .await
                            {
                                return false;
                            }
                        }
                    }
                }
            }
            let _ = send_when_ready(
                &channel_out,
                RnshMessage::StreamData {
                    stream_id: STREAM_ID_STDOUT,
                    eof: true,
                    data: Vec::new(),
                },
            )
            .await;
            true
        });

        let channel_err = channel.clone();
        let mut stderr_task = tokio::spawn(async move {
            let mut stderr = stderr;
            if let Some(stderr) = stderr.as_mut() {
                let mut buffer = vec![0u8; stream_chunk_size(&channel_err.link).await];
                loop {
                    match stderr.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if !send_stream_data(
                                &channel_err,
                                STREAM_ID_STDERR,
                                buffer[..n].to_vec(),
                            )
                            .await
                            {
                                return false;
                            }
                        }
                    }
                }
            }
            true
        });

        let stdout_abort = stdout_task.abort_handle();
        let stderr_abort = stderr_task.abort_handle();
        let (halt_tx, mut halt_rx) = tokio::sync::mpsc::channel::<()>(4);

        // The channel broadcast stays open across link close. This task is the
        // one that sees `LinkEvent::Closed` and is not blocked on a PTY write.
        let halt_link = halt_tx.clone();
        let watch_transport = transport.clone();
        let link_watch = tokio::spawn(async move {
            let mut events = watch_transport.in_link_events();
            loop {
                match events.recv().await {
                    Ok(event)
                        if event.id == link_id
                            && matches!(
                                event.event,
                                reticulum::destination::link::LinkEvent::Closed
                            ) =>
                    {
                        let _ = halt_link.send(()).await;
                        break;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("rnsh link events lagged; dropped {skipped} messages");
                        let closed = match watch_transport.find_in_link(&link_id).await {
                            Some(link) => {
                                link.lock().await.status()
                                    == reticulum::destination::link::LinkStatus::Closed
                            }
                            None => true,
                        };
                        if closed {
                            let _ = halt_link.send(()).await;
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        let _ = halt_link.send(()).await;
                        break;
                    }
                }
            }
        });

        // Same receiver that accepted ExecuteCommand, so a WindowSize or
        // stdin frame that follows it is not dropped.
        let halt_input = halt_tx;
        let input_task = tokio::spawn(async move {
            let mut stdin = stdin;
            loop {
                match receiver.recv().await {
                    Ok(RnshMessage::WindowSize {
                        rows,
                        cols,
                        hpix,
                        vpix,
                    }) => {
                        if let Some(fd) = &winsize {
                            let _ = apply_winsize(fd, rows, cols, hpix, vpix);
                        }
                    }
                    Ok(RnshMessage::StreamData {
                        stream_id: STREAM_ID_STDIN,
                        data,
                        eof,
                    }) => {
                        if let Some(writer) = stdin.as_mut() {
                            if !data.is_empty() && writer.write_all(&data).await.is_err() {
                                let _ = halt_input.send(()).await;
                                break;
                            }
                        }
                        if eof {
                            stdin.take();
                            // A pipe must drain. Tear down only when stdin is the PTY.
                            if !stdin_is_pipe && session_leader {
                                let _ = halt_input.send(()).await;
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("rnsh session input lagged; dropped {skipped} messages");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        let _ = halt_input.send(()).await;
                        break;
                    }
                }
            }
        });

        let mut stdout_done = false;
        let mut stderr_done = false;
        let mut teardown = false;
        loop {
            if stdout_done && stderr_done {
                break;
            }
            tokio::select! {
                _ = halt_rx.recv() => {
                    teardown = true;
                    break;
                }
                joined = &mut stdout_task, if !stdout_done => {
                    stdout_done = true;
                    match joined {
                        Ok(true) if stderr_done => break,
                        Ok(true) => {}
                        _ => {
                            teardown = true;
                            break;
                        }
                    }
                }
                joined = &mut stderr_task, if !stderr_done => {
                    stderr_done = true;
                    match joined {
                        Ok(true) if stdout_done => break,
                        Ok(true) => {}
                        _ => {
                            teardown = true;
                            break;
                        }
                    }
                }
            }
        }

        if teardown {
            if let Some(pid) = child_pid {
                let pid = pid as libc::pid_t;
                if pid > 0 {
                    // Negative pid is the process group from `prepare_child_tty`.
                    // A pipe child never called `setsid`, so only its pid is signalled.
                    let target = if session_leader { -pid } else { pid };
                    unsafe {
                        libc::kill(target, libc::SIGTERM);
                        libc::kill(target, libc::SIGHUP);
                        libc::kill(target, libc::SIGKILL);
                    }
                }
            }
            if !stdout_done {
                stdout_abort.abort();
            }
            if !stderr_done {
                stderr_abort.abort();
            }
        }
        input_task.abort();
        link_watch.abort();
        if !stdout_done {
            let _ = stdout_task.await;
        }
        if !stderr_done {
            let _ = stderr_task.await;
        }
        let _ = input_task.await;
        let _ = link_watch.await;

        let status = session.wait().await;
        let return_code = status.ok().and_then(|s| s.code());
        let _ = send_when_ready(&channel, RnshMessage::CommandExited { return_code }).await;
    });
}

/// Child process for one listener session.
///
/// A PTY is opened when stdout or stderr is not a pipe. When both are
/// pipes, a non-pipe stdin is `/dev/null`.
pub struct SessionProcess {
    child: tokio::process::Child,
    stdin: Option<SessionWriter>,
    stdout: Option<SessionReader>,
    stderr: Option<SessionReader>,
    winsize_fd: Option<Arc<std::fs::File>>,
}

/// Read end of a session pipe or PTY master.
pub struct SessionReader {
    inner: Box<dyn AsyncRead + Send + Unpin>,
}

/// Write end of a session pipe or PTY master.
pub struct SessionWriter {
    inner: Box<dyn AsyncWrite + Send + Unpin>,
}

impl SessionReader {
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf).await
    }
}

impl SessionWriter {
    pub async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(data).await
    }
}

impl SessionProcess {
    pub fn take_stdin(&mut self) -> Option<SessionWriter> {
        self.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<SessionReader> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<SessionReader> {
        self.stderr.take()
    }

    /// Apply a window-size update (`TIOCSWINSZ` on the PTY master).
    pub fn set_window_size(
        &self,
        rows: Option<u32>,
        cols: Option<u32>,
        hpix: Option<u32>,
        vpix: Option<u32>,
    ) -> std::io::Result<()> {
        match &self.winsize_fd {
            Some(fd) => apply_winsize(fd, rows, cols, hpix, vpix),
            None => Ok(()),
        }
    }

    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }
}

/// Spawn `argv`. `initial` is applied to the PTY before exec when one is opened.
pub fn spawn_session_process(
    argv: &[String],
    pipe_stdin: bool,
    pipe_stdout: bool,
    pipe_stderr: bool,
    term: Option<&str>,
    remote_identity: Option<&str>,
    initial: Option<(u16, u16, u16, u16)>,
) -> std::io::Result<SessionProcess> {
    if argv.is_empty() || argv[0].is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty command",
        ));
    }

    let use_pty = !pipe_stdout || !pipe_stderr;
    let mut master = None;
    let mut slave = None;
    if use_pty {
        let (master_fd, slave_fd) = open_pty_pair()?;
        if let Some((rows, cols, hpix, vpix)) = initial {
            let _ = apply_winsize_raw(master_fd.as_raw_fd(), rows, cols, hpix, vpix);
        }
        master = Some(master_fd);
        slave = Some(slave_fd);
    }

    let mut builder = tokio::process::Command::new(&argv[0]);
    builder.args(&argv[1..]);
    builder.kill_on_drop(true);
    builder.env(
        "TERM",
        term.map(str::to_string)
            .or_else(|| std::env::var("TERM").ok())
            .unwrap_or_else(|| "xterm".to_string()),
    );
    builder.env("RNS_REMOTE_IDENTITY", remote_identity.unwrap_or(""));

    if pipe_stdin {
        builder.stdin(std::process::Stdio::piped());
    } else if let Some(slave) = slave.as_ref() {
        builder.stdin(std::process::Stdio::from(slave.try_clone()?));
    } else {
        builder.stdin(std::process::Stdio::null());
    }
    if pipe_stdout {
        builder.stdout(std::process::Stdio::piped());
    } else if let Some(slave) = slave.as_ref() {
        builder.stdout(std::process::Stdio::from(slave.try_clone()?));
    } else {
        builder.stdout(std::process::Stdio::null());
    }
    if pipe_stderr {
        builder.stderr(std::process::Stdio::piped());
    } else if let Some(slave) = slave.as_ref() {
        builder.stderr(std::process::Stdio::from(slave.try_clone()?));
    } else {
        builder.stderr(std::process::Stdio::null());
    }

    if use_pty {
        let tty_fd = if !pipe_stdin {
            0
        } else if !pipe_stdout {
            1
        } else {
            2
        };
        unsafe {
            builder.pre_exec(move || {
                prepare_child_tty(tty_fd);
                Ok(())
            });
        }
    }

    let mut child = builder.spawn()?;
    drop(slave);

    let mut winsize_fd = None;
    let mut stdin = None;
    let mut stdout = None;
    let mut stderr = None;
    if let Some(master) = master {
        let shared = Arc::new(master);
        winsize_fd = Some(Arc::clone(&shared));
        if !pipe_stdin {
            if let Ok(dup) = shared.try_clone() {
                stdin = Some(file_writer(dup));
            }
        }
        if !pipe_stdout {
            if let Ok(dup) = shared.try_clone() {
                stdout = Some(file_reader(dup));
            }
        } else if !pipe_stderr {
            if let Ok(dup) = shared.try_clone() {
                stderr = Some(file_reader(dup));
            }
        }
    }
    if pipe_stdin {
        if let Some(pipe) = child.stdin.take() {
            stdin = Some(SessionWriter {
                inner: Box::new(pipe),
            });
        }
    }
    if pipe_stdout {
        if let Some(pipe) = child.stdout.take() {
            stdout = Some(SessionReader {
                inner: Box::new(pipe),
            });
        }
    }
    if pipe_stderr {
        if let Some(pipe) = child.stderr.take() {
            stderr = Some(SessionReader {
                inner: Box::new(pipe),
            });
        }
    }

    Ok(SessionProcess {
        child,
        stdin,
        stdout,
        stderr,
        winsize_fd,
    })
}

fn file_reader(file: std::fs::File) -> SessionReader {
    SessionReader {
        inner: Box::new(tokio::fs::File::from_std(file)),
    }
}

fn file_writer(file: std::fs::File) -> SessionWriter {
    SessionWriter {
        inner: Box::new(tokio::fs::File::from_std(file)),
    }
}

fn open_pty_pair() -> std::io::Result<(std::fs::File, std::fs::File)> {
    let mut master = -1;
    let mut slave = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let master = unsafe { std::fs::File::from(OwnedFd::from_raw_fd(master)) };
    let slave = unsafe { std::fs::File::from(OwnedFd::from_raw_fd(slave)) };
    set_cloexec(master.as_raw_fd());
    set_cloexec(slave.as_raw_fd());
    Ok((master, slave))
}

fn set_cloexec(fd: i32) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            let _ = libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// `setsid`, controlling tty, and canonical input. Runs after fork.
fn prepare_child_tty(tty_fd: i32) {
    unsafe {
        let _ = libc::setsid();
        let _ = libc::ioctl(tty_fd, libc::TIOCSCTTY, 0);
        let _ = libc::setpgid(0, 0);
        let pgid = libc::getpgrp();
        let _ = libc::ioctl(tty_fd, libc::TIOCSPGRP, &pgid);
        let mut attr: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(tty_fd, &mut attr) == 0 {
            attr.c_lflag |= libc::ICANON | libc::ISIG | libc::ECHO;
            let _ = libc::tcsetattr(tty_fd, libc::TCSANOW, &attr);
        }
    }
}

fn winsize_tuple(
    rows: Option<u32>,
    cols: Option<u32>,
    hpix: Option<u32>,
    vpix: Option<u32>,
) -> Option<(u16, u16, u16, u16)> {
    let rows = u16::try_from(rows?).ok()?;
    let cols = u16::try_from(cols?).ok()?;
    let hpix = hpix.and_then(|v| u16::try_from(v).ok()).unwrap_or(0);
    let vpix = vpix.and_then(|v| u16::try_from(v).ok()).unwrap_or(0);
    Some((rows, cols, hpix, vpix))
}

fn apply_winsize(
    fd: &std::fs::File,
    rows: Option<u32>,
    cols: Option<u32>,
    hpix: Option<u32>,
    vpix: Option<u32>,
) -> std::io::Result<()> {
    let Some((rows, cols, hpix, vpix)) = winsize_tuple(rows, cols, hpix, vpix) else {
        return Ok(());
    };
    apply_winsize_raw(fd.as_raw_fd(), rows, cols, hpix, vpix)
}

fn apply_winsize_raw(fd: i32, rows: u16, cols: u16, hpix: u16, vpix: u16) -> std::io::Result<()> {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: hpix,
        ws_ypixel: vpix,
    };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Identity hashes from `allowed_identities`, one 32-character hex line each.
///
/// Looks at `{config_dir}/allowed_identities` and, when present, the Python
/// default files `~/.config/rnsh/allowed_identities` and `~/.rnsh/allowed_identities`.
fn load_allowed_identity_files(config_dir: &Path) -> HashSet<AddressHash> {
    let mut allowed = HashSet::new();
    let mut paths = Vec::new();
    let configured = config_dir.join("allowed_identities");
    if configured.is_file() {
        paths.push(configured);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        for rel in [
            ".config/rnsh/allowed_identities",
            ".rnsh/allowed_identities",
        ] {
            let path = home.join(rel);
            if path.is_file() && !paths.iter().any(|existing| existing == &path) {
                paths.push(path);
            }
        }
    }
    for path in paths {
        allowed.extend(load_allowed_identities(&path));
    }
    allowed
}

fn load_allowed_identities(path: &Path) -> HashSet<AddressHash> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    let mut allowed = HashSet::new();
    for (index, line) in text.replace('\r', "").split('\n').enumerate() {
        if line.len() != 32 {
            continue;
        }
        match parse_allowed_identity_line(line) {
            Some(hash) => {
                allowed.insert(hash);
            }
            None => {
                log::debug!(
                    "discarded invalid identity hash in {} at line {}",
                    path.display(),
                    index + 1
                );
            }
        }
    }
    allowed
}

fn parse_allowed_identity_line(line: &str) -> Option<AddressHash> {
    if line.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&line[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(AddressHash::new(bytes))
}

/// Maximum payload of one StreamDataMessage: the link MDU minus the
/// channel envelope (6 bytes) and the stream header (2 bytes)
/// (Python `StreamDataMessage.OVERHEAD`).
async fn stream_chunk_size(
    link: &Arc<tokio::sync::Mutex<reticulum::destination::link::Link>>,
) -> usize {
    link.lock().await.mdu().saturating_sub(8).max(32)
}

/// Stream arbitrary data as MDU-sized StreamDataMessages on one stream id.
async fn send_stream_data(
    channel: &reticulum::channel::Channel<RnshMessage>,
    stream_id: u16,
    data: Vec<u8>,
) -> bool {
    let chunk_size = stream_chunk_size(&channel.link).await;
    let mut start = 0;
    while start < data.len() {
        let end = (start + chunk_size).min(data.len());
        let last = end == data.len();
        if !send_when_ready(
            channel,
            RnshMessage::StreamData {
                stream_id,
                eof: false,
                data: data[start..end].to_vec(),
            },
        )
        .await
        {
            return false;
        }
        start = end;
        if !last {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    if data.is_empty() {
        return send_when_ready(
            channel,
            RnshMessage::StreamData {
                stream_id,
                eof: false,
                data: Vec::new(),
            },
        )
        .await;
    }
    true
}

async fn send_when_ready(
    channel: &reticulum::channel::Channel<RnshMessage>,
    message: RnshMessage,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if channel.is_ready().await && channel.send(&message).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Outcome of a remote command session.
pub struct CommandOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
}

struct ClientLink {
    transport: Transport,
    channel: reticulum::channel::Channel<RnshMessage>,
    receiver: tokio::sync::broadcast::Receiver<RnshMessage>,
}

/// Link, identify, and exchange version info. The transport is returned so
/// the caller can keep the instance alive for the rest of the session.
async fn connect_client(
    destination: &AddressHash,
    options: &ServeOptions,
) -> Result<ClientLink, String> {
    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: "rnsh-client",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;
    let identity_path = options.config_dir.join("storage/identities/rnsh");
    let (client_identity, _) =
        load_or_create_private_identity(&identity_path).map_err(|err| err.to_string())?;

    if !transport
        .await_path(destination, Some(Duration::from_secs(15)), None)
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
        name: DestinationName::new(APP_NAME, "shell"),
    };

    let link = transport.link(desc).await;

    let mut events = transport.out_link_events();
    let _ = tokio::time::timeout(Duration::from_secs(10), events.recv()).await;
    let identify = link
        .lock()
        .await
        .identify(&client_identity)
        .map_err(|err| format!("identify failed: {err:?}"))?;
    transport.send_packet(identify).await;

    let (channel, mut receiver) = transport
        .mk_channel::<RnshMessage>(link)
        .await
        .map_err(|e| format!("channel error: {e:?}"))?;

    // Handshake: exchange version info (Python initiator sends first and
    // waits for the listener's reply).
    if !send_when_ready(
        &channel,
        RnshMessage::VersionInfo {
            sw_version: SW_VERSION.to_string(),
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await
    {
        return Err("could not send version info".into());
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut peer_version = false;
    while !peer_version {
        match tokio::time::timeout_at(deadline, receiver.recv()).await {
            Ok(Ok(RnshMessage::VersionInfo {
                sw_version,
                protocol_version,
            })) => {
                log::info!(
                    "connected server version info: sw {sw_version}, proto {protocol_version}"
                );
                if protocol_version != PROTOCOL_VERSION {
                    return Err("incompatible protocol".into());
                }
                peer_version = true;
            }
            Ok(Ok(RnshMessage::Error { msg, .. })) => {
                return Err(msg.unwrap_or_else(|| "remote error".into()));
            }
            _ => return Err("protocol error (no version info)".into()),
        }
    }

    Ok(ClientLink {
        transport,
        channel,
        receiver,
    })
}

/// Run one command in a session on the remote listener
/// (`rnsh --command <cmd> <destination>`), streaming stdin when piped.
pub async fn run_command(
    destination: &AddressHash,
    command: &str,
    options: &ServeOptions,
) -> Result<CommandOutcome, String> {
    let connected = connect_client(destination, options).await?;
    let _transport = connected.transport;
    let channel = connected.channel;
    let mut receiver = connected.receiver;

    // Whether stdin is a pipe determines pipe_stdin on the wire. An
    // already-closed or empty stdin (e.g. `/dev/null`) is not advertised
    // at all: the Python listener closes the child's stdin on EOF and
    // then encourages a prompt process shutdown 50 ms later, which can
    // kill a fast command before its output has been streamed back.
    let (stdin_is_pipe, stdin_data) = read_initial_stdin();
    // `-c` takes a shell command line: run it through the shell on the
    // remote side (the Python tool passes an argument list after `--`).
    let cmdline: Vec<String> = if command.is_empty() {
        Vec::new()
    } else {
        vec!["sh".to_string(), "-c".to_string(), command.to_string()]
    };

    if !send_when_ready(
        &channel,
        RnshMessage::ExecuteCommand {
            cmdline: Some(cmdline),
            pipe_stdin: stdin_is_pipe,
            pipe_stdout: true,
            pipe_stderr: true,
            term: std::env::var("TERM").ok(),
            rows: None,
            cols: None,
            hpix: None,
            vpix: None,
        },
    )
    .await
    {
        return Err("could not send execute command".into());
    }

    // Stream piped stdin to the remote until EOF. Python's initiator
    // buffers all of stdin at startup and streams it after the execute
    // command, which also gives the listener time to start pumping the
    // command output before any EOF arrives.
    if stdin_is_pipe {
        if !stdin_data.is_empty() && !send_stream_data(&channel, STREAM_ID_STDIN, stdin_data).await
        {
            return Err("could not stream stdin".into());
        }

        // All stdin data was buffered at startup and has been sent;
        // signal EOF after a short grace so the listener's output pump
        // gets a turn before its prompt-shutdown heuristic fires.
        tokio::time::sleep(Duration::from_millis(750)).await;
        let _ = send_when_ready(
            &channel,
            RnshMessage::StreamData {
                stream_id: STREAM_ID_STDIN,
                eof: true,
                data: Vec::new(),
            },
        )
        .await;
    }

    let mut outcome = CommandOutcome {
        stdout: Vec::new(),
        stderr: Vec::new(),
        exit_code: None,
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    while let Ok(Ok(message)) = tokio::time::timeout_at(deadline, receiver.recv()).await {
        match message {
            RnshMessage::StreamData {
                stream_id: STREAM_ID_STDOUT,
                data,
                ..
            } => {
                outcome.stdout.extend_from_slice(&data);
            }
            RnshMessage::StreamData {
                stream_id: STREAM_ID_STDERR,
                data,
                ..
            } => {
                outcome.stderr.extend_from_slice(&data);
            }
            RnshMessage::CommandExited { return_code } => {
                outcome.exit_code = return_code;
                break;
            }
            RnshMessage::Error {
                msg, fatal: true, ..
            } => {
                return Err(msg.unwrap_or_else(|| "remote error".into()));
            }
            RnshMessage::Error { .. } => {}
            _ => {}
        }
    }

    Ok(outcome)
}

fn is_tty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Interactive client session.
///
/// `command` `None` or `""` sends no command line, and the listener runs
/// the shell it already chose. This does not ask the listener for `pw_shell`.
/// [`run_command`] remains the non-interactive `--command` path.
pub async fn run_interactive(
    destination: &AddressHash,
    command: Option<&str>,
    options: &ServeOptions,
) -> Result<i32, String> {
    let connected = connect_client(destination, options).await?;
    let transport = connected.transport;
    let channel = connected.channel;
    let mut receiver = connected.receiver;

    let pipe_stdin = !is_tty(0);
    let pipe_stdout = !is_tty(1);
    let pipe_stderr = !is_tty(2);
    let (rows, cols, hpix, vpix) = local_winsize();
    let cmdline = match command {
        Some(text) if !text.is_empty() => {
            Some(vec!["sh".to_string(), "-c".to_string(), text.to_string()])
        }
        _ => None,
    };

    if !send_when_ready(
        &channel,
        RnshMessage::ExecuteCommand {
            cmdline,
            pipe_stdin,
            pipe_stdout,
            pipe_stderr,
            term: std::env::var("TERM").ok(),
            rows,
            cols,
            hpix,
            vpix,
        },
    )
    .await
    {
        return Err("could not send execute command".into());
    }

    let _raw = if is_tty(0) { enter_raw(0).ok() } else { None };

    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                if stdin_tx.blocking_send(buf[..n as usize].to_vec()).is_err() {
                    break;
                }
            } else if n == 0 {
                let _ = stdin_tx.blocking_send(Vec::new());
                break;
            } else {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                let _ = stdin_tx.blocking_send(Vec::new());
                break;
            }
        }
    });

    let mut winch =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok();
    let mut keys = InteractiveKeys::new();
    let filter_keys = is_tty(0);
    let mut sent_eof = false;

    let code = loop {
        tokio::select! {
            message = receiver.recv() => {
                match message {
                    Ok(RnshMessage::StreamData { stream_id, data, .. }) => {
                        let fd = if stream_id == STREAM_ID_STDOUT {
                            1
                        } else if stream_id == STREAM_ID_STDERR {
                            2
                        } else {
                            continue;
                        };
                        if !data.is_empty() {
                            let _ = write_fd(fd, &data);
                        }
                    }
                    Ok(RnshMessage::CommandExited { return_code }) => {
                        break return_code.unwrap_or(255);
                    }
                    Ok(RnshMessage::Error { msg, fatal: true }) => {
                        return Err(msg.unwrap_or_else(|| "remote error".into()));
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(format!(
                            "rnsh session lagged; dropped {skipped} messages"
                        ));
                    }
                    Err(_) => break 255,
                }
            }
            chunk = stdin_rx.recv() => {
                match chunk {
                    Some(chunk) if chunk.is_empty() && !sent_eof => {
                        if filter_keys {
                            let _ = send_stream_data(&channel, STREAM_ID_STDIN, vec![0x04]).await;
                        }
                        let _ = send_when_ready(
                            &channel,
                            RnshMessage::StreamData {
                                stream_id: STREAM_ID_STDIN,
                                eof: true,
                                data: Vec::new(),
                            },
                        )
                        .await;
                        sent_eof = true;
                    }
                    Some(chunk) if !chunk.is_empty() => {
                        let data = if filter_keys {
                            let (data, quit) = keys.push(&chunk);
                            if quit {
                                let link_id = *channel.link.lock().await.id();
                                let _ = transport.link_close(link_id).await;
                                break 0;
                            }
                            data
                        } else {
                            chunk
                        };
                        if !data.is_empty()
                            && !send_stream_data(&channel, STREAM_ID_STDIN, data).await
                        {
                            return Err("could not stream stdin".into());
                        }
                    }
                    _ => {}
                }
            }
            _ = wait_winch(&mut winch) => {
                let (rows, cols, hpix, vpix) = local_winsize();
                if rows.is_some() && cols.is_some() {
                    let _ = send_when_ready(
                        &channel,
                        RnshMessage::WindowSize { rows, cols, hpix, vpix },
                    )
                    .await;
                }
            }
        }
    };
    Ok(code)
}

async fn wait_winch(winch: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(winch) = winch {
        let _ = winch.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

fn local_winsize() -> (Option<u32>, Option<u32>, Option<u32>, Option<u32>) {
    for fd in [0, 1, 2] {
        if let Some((rows, cols, hpix, vpix)) = tty_winsize(fd) {
            return (
                Some(u32::from(rows)),
                Some(u32::from(cols)),
                Some(u32::from(hpix)),
                Some(u32::from(vpix)),
            );
        }
    }
    (None, None, None, None)
}

fn tty_winsize(fd: i32) -> Option<(u16, u16, u16, u16)> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if rc == -1 {
        None
    } else {
        Some((ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel))
    }
}

struct RawTermios {
    fd: i32,
    saved: libc::termios,
}

impl Drop for RawTermios {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSADRAIN, &self.saved);
        }
    }
}

fn enter_raw(fd: i32) -> std::io::Result<RawTermios> {
    unsafe {
        let mut saved: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut saved) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut raw = saved;
        libc::cfmakeraw(&mut raw);
        if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(RawTermios { fd, saved })
    }
}

fn write_fd(fd: i32, data: &[u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let n = unsafe { libc::write(fd, data[offset..].as_ptr().cast(), data.len() - offset) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            break;
        }
        offset += n as usize;
    }
    Ok(())
}

/// Escape handling for a local tty (`~~`, `~.`, `~L`, `~?`).
struct InteractiveKeys {
    line_mode: bool,
    pre_esc: bool,
    esc: bool,
    line_buffer: Vec<u8>,
    blind: usize,
}

impl InteractiveKeys {
    fn new() -> Self {
        Self {
            line_mode: false,
            pre_esc: true,
            esc: false,
            line_buffer: Vec::new(),
            blind: 0,
        }
    }

    fn push(&mut self, input: &[u8]) -> (Vec<u8>, bool) {
        const FLUSH: &[u8] = &[
            0x01, 0x03, 0x04, 0x05, 0x0c, 0x11, 0x13, 0x15, 0x19, b'\t', 0x1a, 0x1b,
        ];
        let mut out = Vec::new();
        let mut quit = false;
        for &byte in input {
            if byte == b'\r' || (self.line_mode && FLUSH.contains(&byte)) {
                self.pre_esc = byte == b'\r';
                if self.line_mode {
                    self.line_buffer.push(byte);
                    out.extend(std::mem::take(&mut self.line_buffer));
                    if self.blind > 0 {
                        let erase = b"\x08 \x08".repeat(self.blind);
                        let _ = write_fd(1, &erase);
                        self.blind = 0;
                    }
                } else {
                    out.push(byte);
                }
            } else if self.line_mode && (byte == 0x08 || byte == 0x7f) {
                self.pre_esc = false;
                if !self.line_buffer.is_empty() {
                    self.line_buffer.pop();
                    self.blind = self.blind.saturating_sub(1);
                    let _ = write_fd(1, b"\x08 \x08");
                }
            } else if self.pre_esc && byte == b'~' {
                self.pre_esc = false;
                self.esc = true;
            } else if self.esc {
                self.esc = false;
                match byte {
                    b'?' => {
                        let _ = write_fd(
                            1,
                            b"\n\r\n\rSupported rnsh escape sequences:\n\r  ~~  Send the escape character by typing it twice\n\r  ~.  Terminate session and exit immediately\n\r  ~L  Toggle line-interactive mode\n\r  ~?  Display this quick reference\n\r\n\r(Escape sequences are only recognized immediately after newline)\n\r",
                        );
                    }
                    b'.' => quit = true,
                    b'L' => {
                        self.line_mode = !self.line_mode;
                        if self.line_mode {
                            let _ = write_fd(1, b"\n\rLine-interactive mode enabled\n\r");
                        } else {
                            let _ = write_fd(1, b"\n\rLine-interactive mode disabled\n\r");
                        }
                    }
                    other => {
                        let mut produced = [0u8; 2];
                        let count = if other == b'~' {
                            produced[0] = other;
                            1
                        } else {
                            produced[0] = b'~';
                            produced[1] = other;
                            2
                        };
                        for produced_byte in produced.into_iter().take(count) {
                            if self.line_mode {
                                self.line_buffer.push(produced_byte);
                                let _ = write_fd(1, &[produced_byte]);
                                self.blind += 1;
                            } else {
                                out.push(produced_byte);
                            }
                        }
                    }
                }
            } else {
                self.pre_esc = false;
                if self.line_mode {
                    self.line_buffer.push(byte);
                    let _ = write_fd(1, &[byte]);
                    self.blind += 1;
                } else {
                    out.push(byte);
                }
            }
        }

        if quit {
            (Vec::new(), true)
        } else {
            (out, false)
        }
    }
}

/// Read the initial stdin contents (Python's initiator buffers all of
/// stdin at startup). Returns whether a stdin pipe should be advertised
/// and the buffered data. A TTY advertises no pipe. A non-empty read
/// advertises a pipe. An immediately empty closed stdin does not.
fn read_initial_stdin() -> (bool, Vec<u8>) {
    // Python's initiator sets `pipe_stdin = not os.isatty(0)` and sends
    // a stdin EOF once its buffer drains. An immediately-closed, empty
    // stdin (e.g. `rn sh -c ... < /dev/null`) here advertises no pipe
    // instead: the Python listener closes the child's stdin on EOF and
    // runs a "prompt shutdown" check 50 ms later that kills fast
    // commands before their output has been streamed back, losing the
    // response entirely. Real piped input keeps the pipe and a delayed
    // EOF so EOF-dependent commands still terminate.
    if is_tty(0) {
        return (false, Vec::new());
    }
    use std::io::Read;
    let mut buffer = Vec::new();
    let _ = std::io::stdin().lock().read_to_end(&mut buffer);
    if buffer.is_empty() {
        (false, buffer)
    } else {
        (true, buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use reticulum::identity::PrivateIdentity;

    #[test]
    fn authentication_is_deny_by_default_and_allow_all_is_explicit() {
        let authorized = PrivateIdentity::new_from_rand(OsRng);
        let unauthorized = PrivateIdentity::new_from_rand(OsRng);
        let allowed = HashSet::from([*authorized.address_hash()]);

        assert!(remote_authorized(
            false,
            &allowed,
            Some(authorized.as_identity())
        ));
        assert!(!remote_authorized(
            false,
            &allowed,
            Some(unauthorized.as_identity())
        ));
        assert!(!remote_authorized(false, &allowed, None));
        assert!(!remote_authorized(false, &HashSet::new(), None));
        assert!(remote_authorized(true, &HashSet::new(), None));
    }

    #[test]
    fn stream_data_packing_matches_python_format() {
        let message = RnshMessage::StreamData {
            stream_id: STREAM_ID_STDOUT,
            eof: false,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let packed = message.pack();
        assert_eq!(packed, vec![0x00, 0x01, 0xde, 0xad, 0xbe, 0xef]);

        let unpacked = RnshMessage::unpack(&packed, MSG_STREAM_DATA).expect("unpack stream data");
        match unpacked {
            RnshMessage::StreamData {
                stream_id,
                eof,
                data,
            } => {
                assert_eq!(stream_id, STREAM_ID_STDOUT);
                assert!(!eof);
                assert_eq!(data, vec![0xde, 0xad, 0xbe, 0xef]);
            }
            other => panic!("unexpected {other:?}"),
        }

        let eof = RnshMessage::StreamData {
            stream_id: STREAM_ID_STDIN,
            eof: true,
            data: Vec::new(),
        }
        .pack();
        assert_eq!(eof, vec![0x80, 0x00]);
    }

    #[test]
    fn version_info_round_trips() {
        let message = RnshMessage::VersionInfo {
            sw_version: "test".into(),
            protocol_version: 1,
        };
        let packed = message.pack();
        // msgpack fixarray of 2 elements
        assert_eq!(packed[0], 0x92);
        let unpacked = RnshMessage::unpack(&packed, MSG_VERSION_INFO).expect("unpack version info");
        match unpacked {
            RnshMessage::VersionInfo {
                sw_version,
                protocol_version,
            } => {
                assert_eq!(sw_version, "test");
                assert_eq!(protocol_version, 1);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn execute_command_round_trips() {
        let message = RnshMessage::ExecuteCommand {
            cmdline: Some(vec!["echo".into(), "hi".into()]),
            pipe_stdin: true,
            pipe_stdout: true,
            pipe_stderr: false,
            term: Some("xterm".into()),
            rows: Some(24),
            cols: Some(80),
            hpix: None,
            vpix: Some(0),
        };
        let packed = message.pack();
        let unpacked = RnshMessage::unpack(&packed, MSG_EXECUTE_COMMAND).expect("unpack exec");
        match unpacked {
            RnshMessage::ExecuteCommand {
                cmdline,
                pipe_stdin,
                pipe_stdout,
                pipe_stderr,
                term,
                rows,
                cols,
                hpix,
                vpix,
            } => {
                assert_eq!(cmdline, Some(vec!["echo".into(), "hi".into()]));
                assert!(pipe_stdin);
                assert!(pipe_stdout);
                assert!(!pipe_stderr);
                assert_eq!(term, Some("xterm".into()));
                assert_eq!(rows, Some(24));
                assert_eq!(cols, Some(80));
                assert_eq!(hpix, None);
                assert_eq!(vpix, Some(0));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn allowed_identities_file_matches_python_line_rules() {
        let dir = std::env::temp_dir().join(format!("rnsh-allow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "ab".repeat(16);
        let text = format!(
            "\n# short\n{hash}\r\n{hash_upper}\nzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n",
            hash_upper = hash.to_uppercase()
        );
        // 32 z's is the right length but not hex.
        let path = dir.join("allowed_identities");
        std::fs::write(&path, text).unwrap();
        let loaded = load_allowed_identities(&path);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(&parse_allowed_identity_line(&hash).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn line_mode_applies_erase_inside_the_chunk() {
        let mut keys = InteractiveKeys::new();
        keys.line_mode = true;
        let (data, quit) = keys.push(b"a\x7f");
        assert!(!quit);
        assert!(data.is_empty());
        assert!(keys.line_buffer.is_empty());

        let (data, quit) = keys.push(b"ab\x08c\x7f\r");
        assert!(!quit);
        assert_eq!(data, b"a\r");
        assert!(keys.line_buffer.is_empty());
    }

    #[tokio::test]
    async fn piped_stdout_and_stderr_leave_stdin_at_eof() {
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "if [ -t 0 ]; then printf tty; else printf notty; fi; cat".to_string(),
        ];
        let mut proc =
            spawn_session_process(&argv, false, true, true, None, None, None).expect("spawn");
        let mut stdout = proc.take_stdout().expect("stdout");
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while got != b"notty" && tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(200), stdout.read(&mut buf))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
                Ok(Err(err)) => panic!("{err}"),
                Err(_) => {}
            }
        }
        assert_eq!(got, b"notty");
        let status = tokio::time::timeout(std::time::Duration::from_secs(2), proc.wait())
            .await
            .expect("child still running")
            .expect("wait");
        assert!(status.success());
    }

    #[tokio::test]
    async fn piped_stdin_pty_stdout_eof_lets_child_finish() {
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "trap 'printf signaled; exit 42' TERM HUP; sleep 0.4; printf 'ok:%s' \"$(cat)\""
                .to_string(),
        ];
        let mut proc = spawn_session_process(&argv, true, false, true, Some("xterm"), None, None)
            .expect("spawn");
        let mut stdin = proc.take_stdin().expect("stdin pipe");
        let mut stdout = proc.take_stdout().expect("pty stdout");
        stdin.write_all(b"hello\n").await.expect("write");
        drop(stdin);

        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            if String::from_utf8_lossy(&got).contains("ok:hello") {
                break;
            }
            match tokio::time::timeout(std::time::Duration::from_millis(200), stdout.read(&mut buf))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
                Err(_) => {}
            }
        }
        let text = String::from_utf8_lossy(&got);
        assert!(
            text.contains("ok:hello"),
            "child did not finish after stdin EOF: {text:?}"
        );
        let status = tokio::time::timeout(std::time::Duration::from_secs(2), proc.wait())
            .await
            .expect("child still running")
            .expect("wait");
        assert!(status.success(), "{status:?}");
    }
}
