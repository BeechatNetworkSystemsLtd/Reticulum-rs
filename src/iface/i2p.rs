//! I2P interface — Python `RNS.Interfaces.I2PInterface` parity (Phase 5.6)
//! via the SAMv3 bridge protocol spoken directly
//! (`RNS.vendor.i2plib`).
//!
//! The SAM bridge exposes stream transports over I2P:
//!
//! * each stream operation (`SESSION CREATE`, `STREAM CONNECT`,
//!   `STREAM ACCEPT`) opens a fresh TCP connection to the SAM bridge,
//!   performs the `HELLO` handshake and the command; the socket then
//!   carries the raw stream data
//! * sessions persist on the bridge side by name. A connectable server
//!   reuses one destination private key, stored the way Python
//!   `I2PController.server_tunnel` stores it (`storage/i2p/<hash>.i2p`).
//!   Without that key the session stays `DESTINATION=TRANSIENT`. Client
//!   peers connect their own session's streams to the published destination
//!
//! Packets over an established stream are HDLC framed exactly like the
//! TCP interfaces (Python `I2PInterfacePeer.process_outgoing`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::hash::Hash;
use crate::iface::hdlc::Hdlc;
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

/// Default SAM bridge address (Python `i2plib.DEFAULT_ADDRESS`).
pub const DEFAULT_SAM_ADDRESS: (&str, u16) = ("127.0.0.1", 7656);

/// Protocol MTU of I2P streams (Python `I2PInterfacePeer.HW_MTU`).
pub const HW_MTU: usize = 1064;

/// Nominal bitrate guess for I2P tunnels
/// (Python `I2PInterface.BITRATE_GUESS`).
pub const BITRATE_GUESS: u64 = 256_000;

/// Reconnect wait between tunnel re-establishments
/// (Python `I2PInterfacePeer.RECONNECT_WAIT`).
pub const RECONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// The fixed SAM protocol versions (Python `i2plib.DEFAULT_MIN_VER`).
const SAM_MIN_VERSION: &str = "3.1";
const SAM_MAX_VERSION: &str = "3.1";

/// Python `Destination.default_sig_type` (`EdDSA_SHA512_Ed25519`).
const SAM_SIGNATURE_EDDSA_SHA512_ED25519: &str = "7";

/// Shortest SAM private key: the destination, the encryption private key,
/// and a DSA-SHA1 signing private key. Python rejects anything shorter
/// before `create_session`.
const MIN_SAM_PRIVATE_KEY: usize = 663;

/// A parsed SAM reply line.
#[derive(Debug, Clone)]
pub struct SamReply {
    pub cmd: String,
    pub action: String,
    pub opts: std::collections::HashMap<String, String>,
}

impl SamReply {
    fn parse(line: &str) -> Option<Self> {
        let mut parts = line.splitn(3, ' ');
        let cmd = parts.next()?.to_string();
        let action = parts.next()?.to_string();
        let rest = parts.next().unwrap_or("");

        let mut opts = std::collections::HashMap::new();
        for token in rest.split(' ') {
            if token.is_empty() {
                continue;
            }
            match token.split_once('=') {
                Some((key, value)) => opts.insert(key.to_string(), value.to_string()),
                None => opts.insert(token.to_string(), "true".to_string()),
            };
        }

        Some(Self { cmd, action, opts })
    }

    pub fn ok(&self) -> bool {
        self.opts.get("RESULT").map(String::as_str) == Some("OK")
    }
}

/// Read one `\n`-terminated SAM reply line.
async fn read_reply<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<SamReply, RnsError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];

    loop {
        match reader.read(&mut byte).await {
            Ok(0) => return Err(RnsError::ConnectionError),
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > 8192 {
                    return Err(RnsError::OutOfMemory);
                }
            }
            Err(_) => return Err(RnsError::ConnectionError),
        }
    }

    let text = String::from_utf8_lossy(&line).trim().to_string();
    SamReply::parse(&text).ok_or(RnsError::PacketError)
}

/// Open a TCP connection to the SAM bridge. The caller performs HELLO.
async fn tcp_sam(sam_addr: &str) -> Result<TcpStream, RnsError> {
    let socket = TcpStream::connect(sam_addr)
        .await
        .map_err(|_| RnsError::ConnectionError)?;
    socket.set_nodelay(true).ok();
    Ok(socket)
}

/// Open a connection to the SAM bridge and perform the HELLO handshake.
async fn sam_connect(sam_addr: &str) -> Result<TcpStream, RnsError> {
    let mut socket = tcp_sam(sam_addr).await?;
    hello(&mut socket).await?;
    Ok(socket)
}

async fn sam_command<S>(io: &mut S, command: &str) -> Result<SamReply, RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    io.write_all(command.as_bytes())
        .await
        .map_err(|_| RnsError::ConnectionError)?;
    read_reply(io).await
}

async fn hello<S>(io: &mut S) -> Result<(), RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let reply = sam_command(
        io,
        &format!("HELLO VERSION MIN={SAM_MIN_VERSION} MAX={SAM_MAX_VERSION}\n"),
    )
    .await?;
    if !reply.ok() {
        return Err(RnsError::ConnectionError);
    }
    Ok(())
}

/// `DEST GENERATE` on a fresh SAM socket (Python `i2plib.new_destination`).
/// The reply has no `RESULT`; the private key is `PRIV`.
async fn generate_private_key<S>(io: &mut S) -> Result<String, RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    hello(io).await?;
    let reply = sam_command(
        io,
        &format!("DEST GENERATE SIGNATURE_TYPE={SAM_SIGNATURE_EDDSA_SHA512_ED25519}\n"),
    )
    .await?;
    reply
        .opts
        .get("PRIV")
        .cloned()
        .filter(|key| !key.is_empty())
        .ok_or(RnsError::PacketError)
}

/// `SESSION CREATE`. `destination` is `TRANSIENT` or the full private-key
/// string (Python `destination.private_key.base64`).
///
/// `SESSION STATUS DESTINATION` is that private key again, not the address.
/// The returned string is only the public prefix.
async fn session_create<S>(
    io: &mut S,
    session_id: &str,
    destination: &str,
) -> Result<String, RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let reply = sam_command(
        io,
        &format!("SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={destination}\n"),
    )
    .await?;
    if !reply.ok() {
        return Err(RnsError::ConnectionError);
    }
    let status_dest = reply
        .opts
        .get("DESTINATION")
        .ok_or(RnsError::IncorrectHash)?;
    public_destination_b64(status_dest)
}

/// A key file is usable only when it decodes to a full SAM private key.
fn validate_private_key(key: &str) -> Result<(), RnsError> {
    let bytes = i2p_b64_decode(key).ok_or(RnsError::Storage)?;
    if bytes.len() < MIN_SAM_PRIVATE_KEY {
        return Err(RnsError::Storage);
    }
    Ok(())
}

/// Read a persisted I2P private key. `Ok(None)` when the file is absent.
///
/// One trailing newline is ignored. Any other extra byte is rejected and
/// the file is left untouched: a short or corrupt key must not be sent to
/// SAM and must not be replaced with a newly generated one.
fn read_destination_key(path: &Path) -> Result<Option<String>, RnsError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RnsError::Storage),
    };
    let key = text.strip_suffix('\n').unwrap_or(text.as_str());
    validate_private_key(key)?;
    Ok(Some(key.to_string()))
}

fn write_destination_key(path: &Path, key: &str) -> Result<(), RnsError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|_| RnsError::Storage)?;
        }
    }
    // Python writes `private_key.base64` with no extra newline.
    std::fs::write(path, key).map_err(|_| RnsError::Storage)
}

/// Load or mint the private key, then HELLO and `SESSION CREATE`.
///
/// `connect` is one SAM socket per call. Generation uses its own socket
/// (Python `new_destination` closes that connection before
/// `create_session`). An invalid key file returns [`RnsError::Storage`]
/// before any socket is opened.
async fn open_dialogue<S, F, Fut>(
    session_id: &str,
    key_path: Option<&Path>,
    mut connect: F,
) -> Result<(String, S), RnsError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<S, RnsError>>,
{
    let destination_param = if let Some(path) = key_path {
        match read_destination_key(path)? {
            Some(key) => key,
            None => {
                let mut io = connect().await?;
                let key = generate_private_key(&mut io).await?;
                drop(io);
                // Do not persist a blob the next start would reject.
                validate_private_key(&key).map_err(|_| RnsError::PacketError)?;
                write_destination_key(path, &key)?;
                key
            }
        }
    } else {
        "TRANSIENT".to_string()
    };

    let mut socket = connect().await?;
    hello(&mut socket).await?;
    let destination = session_create(&mut socket, session_id, &destination_param).await?;
    Ok((destination, socket))
}

/// Key file for a connectable I2P interface
/// (Python `I2PController.server_tunnel`).
///
/// `storage_path` is `Reticulum.storagepath`. `identity_hash` is
/// `Transport.identity.hash` (the truncated 16-byte hash), not a full
/// SHA-256. An existing old-format file wins over the name+identity file.
pub fn i2p_destination_key_path(
    storage_path: impl AsRef<Path>,
    interface_name: &str,
    identity_hash: &[u8],
) -> PathBuf {
    let i2p_dir = storage_path.as_ref().join("i2p");
    let name_hash = Hash::new_from_slice(interface_name.as_bytes());
    let hash = Hash::new_from_slice(name_hash.as_slice());
    let old_path = i2p_dir.join(format!("{hash}.i2p"));
    if old_path.is_file() {
        return old_path;
    }
    let ident_hash = Hash::new_from_slice(identity_hash);
    let mut material = Vec::with_capacity(name_hash.as_slice().len() + ident_hash.as_slice().len());
    material.extend_from_slice(name_hash.as_slice());
    material.extend_from_slice(ident_hash.as_slice());
    let hash = Hash::new_from_slice(&material);
    i2p_dir.join(format!("{hash}.i2p"))
}

/// A SAM session handle: one stream session, plus connect/accept
/// (Python `i2plib.create_session` + `stream_connect`/`stream_accept`).
pub struct SamSession {
    sam_addr: String,
    session_id: String,
    /// The SAM control connection that created this session. SAM bridges
    /// invalidate a session when this socket closes, so it must live for the
    /// entire lifetime of the session handle.
    _control_socket: TcpStream,
    /// Base64 public destination. The private key never leaves the key file
    /// and the `SESSION CREATE` line.
    pub destination: String,
}

impl SamSession {
    async fn open(
        sam_addr: &str,
        session_id: &str,
        key_path: Option<&Path>,
    ) -> Result<Self, RnsError> {
        let (destination, socket) =
            open_dialogue(session_id, key_path, || tcp_sam(sam_addr)).await?;
        Ok(Self {
            sam_addr: sam_addr.to_string(),
            session_id: session_id.to_string(),
            destination,
            _control_socket: socket,
        })
    }

    /// Create a transient STREAM session on the bridge
    /// (Python `i2plib.create_session(..., destination=TRANSIENT)`).
    pub async fn create(sam_addr: &str, session_id: &str) -> Result<Self, RnsError> {
        Self::open(sam_addr, session_id, None).await
    }

    /// Create a STREAM session that reuses the private key at `key_path`
    /// (Python `I2PController.server_tunnel`). The same file makes a later
    /// create request the same `DESTINATION=`.
    pub async fn create_with_key(
        sam_addr: &str,
        session_id: &str,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, RnsError> {
        Self::open(sam_addr, session_id, Some(key_path.as_ref())).await
    }

    /// Open an outbound stream to a base64 destination; the returned
    /// socket carries the raw stream data afterwards
    /// (Python `i2plib.stream_connect`).
    pub async fn stream_connect(&self, destination: &str) -> Result<TcpStream, RnsError> {
        let mut socket = sam_connect(&self.sam_addr).await?;

        let command = format!(
            "STREAM CONNECT ID={} DESTINATION={destination} SILENT=false\n",
            self.session_id
        );

        {
            let (mut reader, mut writer) = socket.split();
            writer
                .write_all(command.as_bytes())
                .await
                .map_err(|_| RnsError::ConnectionError)?;

            let mut buf = BufReader::new(&mut reader);
            let reply = read_reply(&mut buf).await?;
            if !reply.ok() {
                return Err(RnsError::ConnectionError);
            }
        }

        Ok(socket)
    }

    /// Accept an inbound stream on the session; the returned socket
    /// carries the raw stream data afterwards
    /// (Python `i2plib.stream_accept`).
    pub async fn stream_accept(&self) -> Result<(TcpStream, String), RnsError> {
        let mut socket = sam_connect(&self.sam_addr).await?;

        let command = format!("STREAM ACCEPT ID={} SILENT=false\n", self.session_id);
        let remote;

        {
            let (mut reader, mut writer) = socket.split();
            writer
                .write_all(command.as_bytes())
                .await
                .map_err(|_| RnsError::ConnectionError)?;

            let mut buf = BufReader::new(&mut reader);
            let reply = read_reply(&mut buf).await?;
            if !reply.ok() {
                return Err(RnsError::ConnectionError);
            }

            remote = reply.opts.get("DESTINATION").cloned().unwrap_or_default();
        }

        Ok((socket, remote))
    }

    /// The `.b32.i2p` address of the local destination
    /// (Python `Destination.base32`). Fails closed: a bad decode is not
    /// hashed as an empty buffer.
    pub fn b32(&self) -> Result<String, RnsError> {
        destination_b32(&self.destination)
    }
}

fn i2p_b64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'~' => Some(63),
        _ => None,
    }
}

/// Decode I2P base64 (`A-Za-z0-9-~`, not URL-safe `_`). Padding must match
/// Python `b64decode(..., validate=True)`.
fn i2p_b64_decode(data: &str) -> Option<Vec<u8>> {
    let bytes = data.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut index = 0;
    while index < bytes.len() {
        let mut chunk = [0u8; 4];
        let mut pads = 0;
        for slot in 0..4 {
            let byte = bytes[index + slot];
            if byte == b'=' {
                if slot < 2 {
                    return None;
                }
                pads += 1;
                chunk[slot] = 0;
            } else if pads > 0 {
                return None;
            } else {
                chunk[slot] = i2p_b64_value(byte)?;
            }
        }
        if pads > 2 {
            return None;
        }
        let packed = ((chunk[0] as u32) << 18)
            | ((chunk[1] as u32) << 12)
            | ((chunk[2] as u32) << 6)
            | (chunk[3] as u32);
        out.push((packed >> 16) as u8);
        if pads < 2 {
            out.push((packed >> 8) as u8);
        }
        if pads < 1 {
            out.push(packed as u8);
        }
        index += 4;
    }
    Some(out)
}

fn i2p_b64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut index = 0;
    while index + 3 <= data.len() {
        let packed = ((data[index] as u32) << 16)
            | ((data[index + 1] as u32) << 8)
            | (data[index + 2] as u32);
        out.push(ALPHABET[((packed >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((packed >> 12) & 63) as usize] as char);
        out.push(ALPHABET[((packed >> 6) & 63) as usize] as char);
        out.push(ALPHABET[(packed & 63) as usize] as char);
        index += 3;
    }
    match data.len() - index {
        1 => {
            let packed = (data[index] as u32) << 16;
            out.push(ALPHABET[((packed >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((packed >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let packed = ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8);
            out.push(ALPHABET[((packed >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((packed >> 12) & 63) as usize] as char);
            out.push(ALPHABET[((packed >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/// Public destination bytes inside a SAM key.
///
/// Python `Destination` reads the certificate length at bytes 385..387 and
/// keeps `data[:387+cert_len]`. A real private key is at least 663 bytes and
/// that prefix fits. A shorter blob whose certificate does not fit is already
/// a public destination: the mock SAM bridge answers with a 387-byte
/// placeholder, and treating that as a private key would refuse `create`.
fn public_key_bytes(data: &[u8]) -> Result<&[u8], RnsError> {
    if data.len() < 387 {
        return Err(RnsError::PacketError);
    }
    let cert_len = u16::from_be_bytes([data[385], data[386]]) as usize;
    let public_len = 387 + cert_len;
    if public_len <= data.len() {
        return Ok(&data[..public_len]);
    }
    if data.len() < MIN_SAM_PRIVATE_KEY {
        return Ok(data);
    }
    Err(RnsError::PacketError)
}

fn public_destination_b64(encoded: &str) -> Result<String, RnsError> {
    let bytes = i2p_b64_decode(encoded).ok_or(RnsError::PacketError)?;
    Ok(i2p_b64_encode(public_key_bytes(&bytes)?))
}

/// RFC 4648 base32, lowercase. SHA-256 is 256 bits, so the last character is
/// the leftover 1-bit quantum (Python `b32encode(digest)[:52].lower()`).
fn base32_52(hash: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(52);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in hash {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out.truncate(52);
    out
}

/// `.b32.i2p` hash of a destination (Python `Destination.base32`).
///
/// The hash covers only the public prefix, never a private-key suffix.
/// Decode failure is an error: empty input is not hashed.
pub fn destination_b32(destination_b64: &str) -> Result<String, RnsError> {
    let bytes = i2p_b64_decode(destination_b64).ok_or(RnsError::PacketError)?;
    let public = public_key_bytes(&bytes)?;
    Ok(base32_52(Hash::new_from_slice(public).as_slice()))
}

/// One HDLC-framed stream peer over an established I2P stream
/// (Python `I2PInterfacePeer`): either an initiator connecting out to a
/// published destination, or spawned by [`I2pServer`] for an accepted
/// stream.
pub struct I2pPeer {
    /// Base64 destination to connect to (initiator mode).
    pub target_destination: Option<String>,
    /// SAM bridge address.
    pub sam_addr: String,
    /// Session id for initiator connections.
    pub session_id: String,
    /// Already-established stream (spawned mode).
    pub connected_stream: Option<TcpStream>,
    /// Interface manager of the owning transport, used to flag tunnel
    /// synthesis once the stream is up (Python `wants_tunnel`).
    pub iface_manager: Option<Arc<tokio::sync::Mutex<InterfaceManager>>>,
}

impl I2pPeer {
    /// Create a spawned peer for an accepted stream
    /// (Python `incoming_connection` handler).
    pub fn new_from_stream(name: impl Into<String>, stream: TcpStream) -> Self {
        let _ = name;
        Self {
            target_destination: None,
            sam_addr: String::new(),
            session_id: String::new(),
            connected_stream: Some(stream),
            iface_manager: None,
        }
    }

    /// Create an initiator peer connecting to a published destination
    /// (Python `I2PInterfacePeer(target_i2p_dest=...)`).
    pub fn new_initiator(sam_addr: &str, session_id: &str, destination: &str) -> Self {
        Self {
            target_destination: Some(destination.to_string()),
            sam_addr: sam_addr.to_string(),
            session_id: session_id.to_string(),
            connected_stream: None,
            iface_manager: None,
        }
    }

    /// Attach the interface manager of the owning transport
    /// (used for tunnel-synthesis signalling).
    pub fn with_manager(mut self, manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        self.iface_manager = Some(manager);
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();
        let inner = context.inner.clone();

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            // Establish the stream: spawned peers use their handed-over
            // stream once; initiators (re)connect through SAM. (The guard
            // is scoped so it is never held across an await.)
            let connected = inner.lock().unwrap().connected_stream.take();
            let stream = match connected {
                Some(stream) => stream,
                None => {
                    let (target, sam_addr, session_id) = {
                        let inner = inner.lock().unwrap();
                        (
                            inner.target_destination.clone(),
                            inner.sam_addr.clone(),
                            inner.session_id.clone(),
                        )
                    };

                    let Some(target) = target else { break };

                    let session = match SamSession::create(&sam_addr, &session_id).await {
                        Ok(session) => session,
                        Err(_) => {
                            log::warn!(
                                "i2p_peer: could not create SAM session, retrying in {}s",
                                RECONNECT_WAIT.as_secs()
                            );
                            tokio::time::sleep(RECONNECT_WAIT).await;
                            continue;
                        }
                    };

                    match session.stream_connect(&target).await {
                        Ok(stream) => {
                            log::info!("i2p_peer: tunnel established to {target}");
                            stream
                        }
                        Err(_) => {
                            log::warn!(
                                "i2p_peer: tunnel not ready, retrying in {}s",
                                RECONNECT_WAIT.as_secs()
                            );
                            tokio::time::sleep(RECONNECT_WAIT).await;
                            continue;
                        }
                    }
                }
            };

            stats.set_online(true);

            // The tunnel is up: request tunnel synthesis from the
            // transport (Python sets `wants_tunnel = True` and
            // `Transport.synthesize_tunnel` runs).
            let manager_of = inner.lock().unwrap().iface_manager.clone();
            if let Some(manager) = manager_of {
                let manager = manager.lock().await;
                manager.set_iface_wants_tunnel(&iface_address, true);
            }

            let (read_half, write_half) = stream.into_split();

            let rx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let channel_ifac_rx = channel_ifac.clone();
                let mut stream = read_half;

                tokio::spawn(async move {
                    use crate::iface::hdlc::HdlcDecoder;

                    let mut decoder = HdlcDecoder::new(HW_MTU);
                    let mut buffer = [0u8; 4096];
                    let mut frames: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = stop.cancelled() => true,
                            result = stream.read(&mut buffer) => match result {
                                Ok(0) | Err(_) => true,
                                Ok(n) => {
                                    decoder.feed(&buffer[..n], |frame| {
                                        if frame.len() > 2 {
                                            frames.push(frame.to_vec());
                                        }
                                    });

                                    for frame in frames.drain(..) {
                                        let plain = {
                                            let ifac = channel_ifac_rx.read().expect("ifac lock").clone();
                                            match crate::iface::ifac::decode_inbound(
                                                &frame,
                                                ifac.as_deref(),
                                                Some(&stats),
                                            ) {
                                                Some(plain) => plain,
                                                None => {
                                                    log::debug!("i2p_peer: dropping packet with invalid access code");
                                                    continue;
                                                }
                                            }
                                        };
                                        if let Ok(packet) =
                                            Packet::deserialize(&mut InputBuffer::new(&plain))
                                        {
                                            stats.count_rx(plain.len());
                                            let _ = rx_channel
                                                .send(RxMessage { address: iface_address, packet: Box::new(packet) })
                                                .await;
                                        }
                                    }

                                    false
                                }
                            },
                        };

                        if closed {
                            break;
                        }
                    }
                })
            };

            let tx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let stats = stats.clone();
                let tx_channel = tx_channel.clone();
                let channel_ifac = channel_ifac.clone();
                let mut stream = write_half;

                tokio::spawn(async move {
                    loop {
                        let mut buffer = [0u8; 2048];
                        let mut hdlc_buffer = [0u8; 2048 + 256];

                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            message = tx_channel.recv() => match message {
                                Some(message) => message,
                                None => break,
                            },
                        };

                        let packet = message.packet;
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let ifac = channel_ifac.read().expect("ifac lock").clone();
                            let wire =
                                crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());

                            let mut framed = OutputBuffer::new(&mut hdlc_buffer[..]);
                            if Hdlc::encode(&wire, &mut framed).is_ok()
                                && stream.write_all(framed.as_slice()).await.is_ok()
                            {
                                let _ = stream.flush().await;
                                stats.count_tx(wire.len());
                            } else {
                                break;
                            }
                        }
                    }
                })
            };

            let _ = tokio::join!(tx_task, rx_task);
            stats.set_online(false);

            if inner.lock().unwrap().target_destination.is_none() {
                // spawned peer: done when its stream ends
                break;
            }

            log::info!(
                "i2p_peer: tunnel lost, reconnecting in {}s",
                RECONNECT_WAIT.as_secs()
            );
            tokio::time::sleep(RECONNECT_WAIT).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for I2pPeer {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// The I2P server interface: owns a connectable SAM session and spawns
/// an [`I2pPeer`] for every accepted stream
/// (Python `I2PInterface` with `connectable = yes`).
pub struct I2pServer {
    /// SAM bridge address.
    pub sam_addr: String,
    /// Session id (must be unique among local sessions).
    pub session_id: String,
    /// Established session once created; the destination is needed by
    /// embedders to publish (discovery data / manual peers).
    pub session: Arc<tokio::sync::RwLock<Option<Arc<SamSession>>>>,
    /// Live base32 destination hash (no `.b32.i2p` suffix). `None` until
    /// the SAM session exists, and cleared when the session drops.
    pub b32_slot: Arc<std::sync::RwLock<Option<String>>>,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    /// Persisted destination private key. `None` keeps
    /// `DESTINATION=TRANSIENT` so [`I2pServer::new`] stays source-compatible.
    destination_key: Option<PathBuf>,
}

impl I2pServer {
    pub fn new<T: Into<String>>(
        sam_addr: T,
        session_id: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            sam_addr: sam_addr.into(),
            session_id: session_id.into(),
            session: Arc::new(tokio::sync::RwLock::new(None)),
            b32_slot: Arc::new(std::sync::RwLock::new(None)),
            iface_manager,
            destination_key: None,
        }
    }

    /// Reuse the private key at `key_path` for the published destination.
    pub fn with_destination_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.destination_key = Some(key_path.into());
        self
    }

    /// Persist the destination under Python's `storage/i2p/<hash>.i2p` name.
    ///
    /// `identity_hash` is `Transport.identity.hash` (truncated).
    pub fn with_stable_destination(
        self,
        storage_path: impl AsRef<Path>,
        interface_name: &str,
        identity_hash: &[u8],
    ) -> Self {
        self.with_destination_key(i2p_destination_key_path(
            storage_path,
            interface_name,
            identity_hash,
        ))
    }

    /// The published public base64 destination, once established
    /// (empty string before). This is not the SAM private key.
    pub async fn destination(&self) -> String {
        self.session
            .read()
            .await
            .as_ref()
            .map(|session| session.destination.clone())
            .unwrap_or_default()
    }

    /// The published `.b32.i2p` address, once established.
    pub async fn b32(&self) -> String {
        self.session
            .read()
            .await
            .as_ref()
            .and_then(|session| session.b32().ok())
            .unwrap_or_default()
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let sam_addr = { context.inner.lock().unwrap().sam_addr.clone() };
        let session_id = { context.inner.lock().unwrap().session_id.clone() };
        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let session_slot = { context.inner.lock().unwrap().session.clone() };
        let destination_key = { context.inner.lock().unwrap().destination_key.clone() };
        let b32_slot = { context.inner.lock().unwrap().b32_slot.clone() };
        let parent = context.channel.address;

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            // Establish the connectable session. A configured key file is
            // reused so the published address survives a restart.
            let session = match &destination_key {
                Some(path) => SamSession::create_with_key(&sam_addr, &session_id, path).await,
                None => SamSession::create(&sam_addr, &session_id).await,
            };
            let session = match session {
                Ok(session) => Arc::new(session),
                Err(_) => {
                    log::warn!(
                        "i2p_server: SAM session not ready (is the I2P router running with SAM enabled?), retrying"
                    );
                    tokio::time::sleep(RECONNECT_WAIT).await;
                    continue;
                }
            };

            log::info!(
                "i2p_server: session {} connectable as {}.b32.i2p",
                session_id,
                session.b32().unwrap_or_default()
            );

            *session_slot.write().await = Some(session.clone());
            *b32_slot.write().expect("b32 slot") = session.b32().ok();
            stats.set_online(true);

            // Accept loop: each accepted stream becomes a spawned peer.
            loop {
                if context.cancel.is_cancelled() {
                    break;
                }

                match session.stream_accept().await {
                    Ok((stream, remote)) => {
                        log::debug!("i2p_server: accepted stream from {remote}");

                        // Capture the server's access code for inheritance
                        // before locking the manager (no guard across await).
                        let inherited = context.channel.ifac.read().expect("ifac lock").clone();

                        let mut manager = iface_manager.lock().await;
                        let peer_context = manager.open(I2pPeer::new_from_stream(
                            format!("{session_id}-peer"),
                            stream,
                        ));
                        // Spawned peers inherit the server's access code
                        // (Python I2PInterfacePeer ifac inheritance).
                        if let Some(key) = inherited {
                            *peer_context.channel.ifac.write().expect("ifac lock") = Some(key);
                        }
                        let address = peer_context.channel.address;
                        manager.copy_spawned_control(&parent, &address);
                        manager.launch(peer_context, I2pPeer::spawn);
                    }
                    Err(_) => {
                        log::warn!("i2p_server: stream accept failed, recreating session");
                        break;
                    }
                }
            }

            stats.set_online(false);
            *session_slot.write().await = None;
            *b32_slot.write().expect("b32 slot") = None;
            tokio::time::sleep(RECONNECT_WAIT).await;
        }
    }
}

impl Interface for I2pServer {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// Run an initiator I2P interface until cancelled: connects to a
/// published destination and keeps the peer alive
/// (Python `I2PInterface(peers=[...])`).
pub async fn i2p_peer_interface(
    transport: &crate::transport::Transport,
    sam_addr: &str,
    session_id: &str,
    destination: &str,
    name: &str,
) -> Result<crate::hash::AddressHash, RnsError> {
    let manager = transport.iface_manager();
    let mut manager = manager.lock().await;

    Ok(manager.spawn_named(
        name,
        I2pPeer::new_initiator(sam_addr, session_id, destination),
        I2pPeer::spawn,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "reticulum-i2p-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// One scripted SAM socket. Replies are served in order; every written
    /// line is appended to `log`.
    struct ScriptedSam {
        incoming: VecDeque<u8>,
        write_buf: Vec<u8>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl AsyncRead for ScriptedSam {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.incoming.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let n = buf.remaining().min(this.incoming.len());
            let bytes: Vec<u8> = this.incoming.drain(..n).collect();
            buf.put_slice(&bytes);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedSam {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.write_buf.extend_from_slice(data);
            while let Some(pos) = this.write_buf.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = this.write_buf.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line).trim().to_string();
                this.log.lock().unwrap().push(text);
            }
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Successive SAM connections, each with its own reply lines.
    struct Transcript {
        stages: Mutex<VecDeque<Vec<String>>>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Transcript {
        fn new(stages: Vec<Vec<&str>>) -> Self {
            let stages = stages
                .into_iter()
                .map(|lines| lines.into_iter().map(str::to_string).collect())
                .collect();
            Self {
                stages: Mutex::new(stages),
                log: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn connect(&self) -> Result<ScriptedSam, RnsError> {
            let lines = self
                .stages
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(RnsError::ConnectionError)?;
            let mut incoming = VecDeque::new();
            for line in lines {
                incoming.extend(line.into_bytes());
                incoming.push_back(b'\n');
            }
            Ok(ScriptedSam {
                incoming,
                write_buf: Vec::new(),
                log: self.log.clone(),
            })
        }

        fn requests(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    fn requested_destination(requests: &[String]) -> String {
        requests
            .iter()
            .find(|line| line.starts_with("SESSION CREATE"))
            .and_then(|line| {
                line.split_whitespace()
                    .find_map(|token| token.strip_prefix("DESTINATION="))
            })
            .unwrap()
            .to_string()
    }

    #[test]
    fn destination_key_path_matches_python_server_tunnel() {
        // Vectors from Python `hashlib.sha256`, which is `Identity.full_hash`,
        // and `hexrep(..., delimit=False)`. Name "testiface", identity hash
        // sixteen 0x11 bytes (truncated `Transport.identity.hash`).
        let tmp = TempDir::new();
        let storage = tmp.0.join("storage");
        let identity = [0x11u8; 16];
        let path = i2p_destination_key_path(&storage, "testiface", &identity);
        assert_eq!(
            path,
            storage
                .join("i2p")
                .join("8d290c37f9bf4deb5548fad60d53c789a3e521c1b6019c94cebbe8b7c50b81a4.i2p")
        );

        let old = storage
            .join("i2p")
            .join("83a4a268a09ee04976ae488dcfa91c2a248b364166858523d3dded9efcbde406.i2p");
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, "legacy-key").unwrap();
        assert_eq!(
            i2p_destination_key_path(&storage, "testiface", &identity),
            old
        );

        let manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(4)));
        let server = I2pServer::new("127.0.0.1:7656", "sid", manager).with_stable_destination(
            &storage,
            "testiface",
            &identity,
        );
        assert_eq!(server.destination_key.as_deref(), Some(old.as_path()));
    }

    /// 663-byte SAM private key and its public prefix, from Python
    /// `b64encode(..., altchars=b"-~")` / `Destination.base32`.
    const PRIVATE_KEY: &str = "AxQlNkdYaXqLnK2-z-DxAhMkNUZXaHmKm6y9zt~wARIjNEVWZ3iJmqu8zd7vABEiM0RVZneImaq7zN3u~xAhMkNUZXaHmKm6y9zt~g8gMUJTZHWGl6i5ytvs~Q4fMEFSY3SFlqe4ydrr~A0eL0BRYnOElaa3yNnq-wwdLj9QYXKDlKW2x9jp-gscLT5PYHGCk6S1xtfo-QobLD1OX3CBkqO0xdbn-AkaKzxNXm-AkaKzxNXm9wgZKjtMXW5~kKGyw9Tl9gcYKTpLXG1-j6CxwtPk9QYXKDlKW2x9jp-wwdLj9AUWJzhJWmt8jZ6vwNHi8wQVJjdIWWp7jJ2uv9Dh8gMUJTZHWGl6i5ytvs~g8QITJDVGV2h5ipusvc7f8AESIzRFVmd4iZqrvM3e7wARIjNEVWZ3iJmqu8zd7v8QITJDVGV2h5ipusvc7f4PIDFCU2R1hpeoucrb7P0OHzBBUmN0hZanuMna6~wNHi9AUWJzhJWmt8jZ6vsMHS4~UGFygwAEAQIDBPoLHC0-T2BxgpOktcbX6PkKGyw9Tl9wgZKjtMXW5~gJGis8TV5vgJGis8TV5vcIGSo7TF1uf5ChssPU5fYHGCk6S1xtfo-gscLT5PUGFyg5SltsfY6fsMHS4~QFFic4SVprfI2er8DR4vMEFSY3SFlqe4ydrr~Q4fIDFCU2R1hpeoucrb7P4PECEyQ1RldoeYqbrL3O3~ABEiM0RVZneImaq7zN3u8AESIzRFVmd4iZqrvM3e7~ECEyQ1RldoeYqbrL3O3-DyAxQlNkdYaXqLnK2-z9Dh8wQVJjdIWWp7jJ2uv8DR4vQFFic4SVprfI2er7DB0uP1BhcoOUpbbH2On6CxwtPk9gcYKTpLXG1-j5";
    const PUBLIC_DEST: &str = "AxQlNkdYaXqLnK2-z-DxAhMkNUZXaHmKm6y9zt~wARIjNEVWZ3iJmqu8zd7vABEiM0RVZneImaq7zN3u~xAhMkNUZXaHmKm6y9zt~g8gMUJTZHWGl6i5ytvs~Q4fMEFSY3SFlqe4ydrr~A0eL0BRYnOElaa3yNnq-wwdLj9QYXKDlKW2x9jp-gscLT5PYHGCk6S1xtfo-QobLD1OX3CBkqO0xdbn-AkaKzxNXm-AkaKzxNXm9wgZKjtMXW5~kKGyw9Tl9gcYKTpLXG1-j6CxwtPk9QYXKDlKW2x9jp-wwdLj9AUWJzhJWmt8jZ6vwNHi8wQVJjdIWWp7jJ2uv9Dh8gMUJTZHWGl6i5ytvs~g8QITJDVGV2h5ipusvc7f8AESIzRFVmd4iZqrvM3e7wARIjNEVWZ3iJmqu8zd7v8QITJDVGV2h5ipusvc7f4PIDFCU2R1hpeoucrb7P0OHzBBUmN0hZanuMna6~wNHi9AUWJzhJWmt8jZ6vsMHS4~UGFygwAEAQIDBA==";
    const PUBLIC_B32: &str = "t4lwmrkihjofp2vtlmdihepocam4pcywi6uolcxh3uwiehenmwaa";

    fn status_line() -> String {
        format!("SESSION STATUS RESULT=OK DESTINATION={PRIVATE_KEY}")
    }

    async fn dialogue(
        key_path: Option<&Path>,
        stages: Vec<Vec<&str>>,
    ) -> (Result<String, RnsError>, Vec<String>) {
        let transcript = Transcript::new(stages);
        let result = open_dialogue("sess", key_path, || {
            let conn = transcript.connect();
            async move { conn }
        })
        .await
        .map(|(destination, _socket)| destination);
        (result, transcript.requests())
    }

    #[test]
    fn public_prefix_and_base32_match_python() {
        assert_eq!(public_destination_b64(PRIVATE_KEY).unwrap(), PUBLIC_DEST);
        assert_eq!(destination_b32(PRIVATE_KEY).unwrap(), PUBLIC_B32);
        assert_eq!(destination_b32(PUBLIC_DEST).unwrap(), PUBLIC_B32);
        assert_eq!(PUBLIC_B32.len(), 52);
        assert_ne!(PUBLIC_DEST, PRIVATE_KEY);
        // URL-safe `_` is not I2P base64, and a failed decode is not sha256("").
        assert!(destination_b32("____").is_err());
        assert!(destination_b32("").is_err());
        assert!(destination_b32("~").is_err());
    }

    #[tokio::test]
    async fn second_create_requests_the_same_destination() {
        let tmp = TempDir::new();
        let key_path = tmp.0.join("i2p").join("node.i2p");
        let generate = format!("DEST REPLY PUB={PUBLIC_DEST} PRIV={PRIVATE_KEY}");
        let status = status_line();

        let (public_dest, first_requests) = dialogue(
            Some(key_path.as_path()),
            vec![
                vec!["HELLO REPLY RESULT=OK VERSION=3.1", generate.as_str()],
                vec!["HELLO REPLY RESULT=OK VERSION=3.1", status.as_str()],
            ],
        )
        .await;
        let public_dest = public_dest.expect("first create");
        assert_eq!(public_dest, PUBLIC_DEST);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), PRIVATE_KEY);
        assert!(
            first_requests
                .iter()
                .any(|line| line == "DEST GENERATE SIGNATURE_TYPE=7"),
            "missing key must be minted with DEST GENERATE: {first_requests:?}"
        );
        assert_eq!(requested_destination(&first_requests), PRIVATE_KEY);

        let (again, second_requests) = dialogue(
            Some(key_path.as_path()),
            vec![vec!["HELLO REPLY RESULT=OK VERSION=3.1", status.as_str()]],
        )
        .await;
        assert_eq!(again.expect("second create"), PUBLIC_DEST);
        assert!(
            second_requests
                .iter()
                .all(|line| !line.starts_with("DEST GENERATE")),
            "existing key must not be regenerated: {second_requests:?}"
        );
        assert_eq!(
            requested_destination(&second_requests),
            requested_destination(&first_requests)
        );
    }

    #[tokio::test]
    async fn newline_terminated_key_file_is_the_same_destination() {
        let tmp = TempDir::new();
        let key_path = tmp.0.join("node.i2p");
        std::fs::write(&key_path, format!("{PRIVATE_KEY}\n")).unwrap();
        let status = status_line();
        let (public_dest, requests) = dialogue(
            Some(key_path.as_path()),
            vec![vec!["HELLO REPLY RESULT=OK VERSION=3.1", status.as_str()]],
        )
        .await;
        assert_eq!(public_dest.expect("stored key"), PUBLIC_DEST);
        assert_eq!(requested_destination(&requests), PRIVATE_KEY);
        assert!(requests
            .iter()
            .all(|line| !line.starts_with("DEST GENERATE")));
        assert_eq!(
            std::fs::read_to_string(&key_path).unwrap(),
            format!("{PRIVATE_KEY}\n")
        );
    }

    #[tokio::test]
    async fn invalid_key_file_does_not_open_a_session() {
        let tmp = TempDir::new();
        for (index, contents) in ["same-key", "same-key\n", "not a key", "AAAA", "AAAA_AAA="]
            .into_iter()
            .enumerate()
        {
            let key_path = tmp.0.join(format!("bad-{index}"));
            std::fs::write(&key_path, contents).unwrap();
            let (result, requests) = dialogue(Some(key_path.as_path()), Vec::new()).await;
            assert_eq!(result.unwrap_err(), RnsError::Storage, "{contents:?}");
            assert!(
                requests.is_empty(),
                "invalid key must not send SAM commands: {requests:?}"
            );
            assert_eq!(std::fs::read_to_string(&key_path).unwrap(), contents);
        }

        // A second newline is still inside the token, so the file is not a key
        // and must not be replaced by DEST GENERATE.
        let doubled = format!("{PRIVATE_KEY}\n\n");
        let key_path = tmp.0.join("doubled.i2p");
        std::fs::write(&key_path, &doubled).unwrap();
        let (result, requests) = dialogue(Some(key_path.as_path()), Vec::new()).await;
        assert_eq!(result.unwrap_err(), RnsError::Storage);
        assert!(requests.is_empty());
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), doubled);
    }

    #[tokio::test]
    async fn create_without_key_file_stays_transient() {
        let status = status_line();
        let (public_dest, requests) = dialogue(
            None,
            vec![vec!["HELLO REPLY RESULT=OK VERSION=3.1", status.as_str()]],
        )
        .await;
        assert_eq!(public_dest.expect("transient create"), PUBLIC_DEST);
        assert_eq!(requested_destination(&requests), "TRANSIENT");
        assert!(requests
            .iter()
            .all(|line| !line.starts_with("DEST GENERATE")));
    }
}
