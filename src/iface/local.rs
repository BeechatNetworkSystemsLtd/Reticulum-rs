//! Local shared-instance interfaces, a port of `RNS/Interfaces/LocalInterface.py`
//! (v1.4.2) including its `BackboneInterface` model.
//!
//! * [`LocalServer`] is the shared instance: a listener on `127.0.0.1`
//!   (default port 37428, `Reticulum.SHARED_INSTANCE_PORT`) or on the
//!   abstract unix domain socket `\0rns/<instance_name>`. Every accepted
//!   connection is spawned as a full peer interface in the same
//!   [`InterfaceManager`], so the daemon transport relays frames between
//!   all connected local clients and its own interfaces - exactly like
//!   `LocalServerInterface.incoming_connection` spawning a
//!   `LocalClientInterface` per client.
//! * [`LocalClient`] connects this transport to an existing shared instance
//!   with the same HDLC framing.
//!
//! Wire format on both sides is HDLC framing (`0x7E` flags, `0x7D` escapes)
//! around serialized Reticulum packets, identical to `TCPInterface`. Empty
//! frames (`0x7E 0x7E`) are keepalives and are ignored, matching
//! `if len(frame) > RNS.Reticulum.HEADER_MINSIZE` in `LocalInterface.py`.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use crate::buffer::InputBuffer;
use crate::buffer::OutputBuffer;
use crate::iface::hdlc::Hdlc;
use crate::iface::hdlc::HdlcDecoder;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::Interface;
use super::InterfaceContext;
use super::InterfaceManager;

/// `Reticulum.SHARED_INSTANCE_PORT`
pub const SHARED_INSTANCE_PORT: u16 = 37428;

/// `LocalClientInterface.RECONNECT_WAIT` in seconds
pub const RECONNECT_WAIT: Duration = Duration::from_secs(8);

/// Hardware MTU from `AUTOCONFIGURE_MTU` at 1e9 bps (`Interface.optimise_mtu`).
pub const HW_MTU: usize = 524_288;

/// `Interface.optimise_mtu` tiers. Test-only: the local interface always
/// uses [`HW_MTU`], and a non-test copy would be dead.
#[cfg(test)]
const fn optimise_mtu(bitrate_bps: u64) -> Option<usize> {
    if bitrate_bps >= 1_000_000_000 {
        Some(524_288)
    } else if bitrate_bps >= 750_000_000 {
        Some(262_144)
    } else if bitrate_bps >= 400_000_000 {
        Some(131_072)
    } else if bitrate_bps >= 200_000_000 {
        Some(65_536)
    } else if bitrate_bps >= 100_000_000 {
        Some(32_768)
    } else if bitrate_bps >= 10_000_000 {
        Some(16_384)
    } else if bitrate_bps >= 5_000_000 {
        Some(8_192)
    } else if bitrate_bps >= 2_000_000 {
        Some(4_096)
    } else if bitrate_bps >= 1_000_000 {
        Some(2_048)
    } else if bitrate_bps >= 62_500 {
        Some(1_024)
    } else {
        None
    }
}

/// Python ignores frames of at most `Reticulum.HEADER_MINSIZE` bytes
/// (2 + 1 + TRUNCATED_HASHLENGTH/8 = 19).
const HEADER_MINSIZE: usize = 19;

const PACKET_TRACE: bool = false;

/// Address of a shared Reticulum instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedInstanceAddress {
    /// TCP shared instance (`shared_instance_type = tcp`), always on loopback
    Tcp { port: u16 },
    /// Abstract unix domain socket (`shared_instance_type = domain`),
    /// bound to `\0rns/<instance_name>` (`LocalInterface.py` address format).
    #[cfg(unix)]
    UnixAbstract { instance_name: String },
}

impl SharedInstanceAddress {
    pub fn tcp(port: u16) -> Self {
        Self::Tcp { port }
    }

    /// Abstract socket address `\0rns/<instance_name>` (the leading NUL byte
    /// marks the Linux abstract namespace).
    #[cfg(unix)]
    pub fn unix_abstract(instance_name: impl Into<String>) -> Self {
        Self::UnixAbstract {
            instance_name: instance_name.into(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Tcp { port } => format!("127.0.0.1:{port}"),
            #[cfg(unix)]
            Self::UnixAbstract { instance_name } => format!("\0rns/{instance_name}"),
        }
    }
}

/// Owned halves of an accepted or connected local stream.
enum LocalStreamRead {
    Tcp(tokio::net::tcp::OwnedReadHalf),
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedReadHalf),
}

enum LocalStreamWrite {
    Tcp(tokio::net::tcp::OwnedWriteHalf),
    #[cfg(unix)]
    Unix(tokio::net::unix::OwnedWriteHalf),
}

async fn stream_read(stream: &mut LocalStreamRead, buffer: &mut [u8]) -> io::Result<usize> {
    match stream {
        LocalStreamRead::Tcp(stream) => stream.read(buffer).await,
        #[cfg(unix)]
        LocalStreamRead::Unix(stream) => stream.read(buffer).await,
    }
}

async fn stream_write_all(stream: &mut LocalStreamWrite, data: &[u8]) -> io::Result<()> {
    match stream {
        LocalStreamWrite::Tcp(stream) => {
            stream.write_all(data).await?;
            stream.flush().await
        }
        #[cfg(unix)]
        LocalStreamWrite::Unix(stream) => {
            stream.write_all(data).await?;
            stream.flush().await
        }
    }
}

enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

/// Access control for a shared-instance server.
///
/// By default any local process may connect (the Python shared instance
/// relies on filesystem/TCP loopback isolation only). An access config adds
/// an explicit handshake before any Reticulum frames are exchanged:
/// a name allow list, a shared token, and a concurrent-client cap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedInstanceAccessConfig {
    /// Client names allowed to connect. An empty list allows any name.
    pub allow: Vec<String>,
    /// Require clients to authenticate with this token (constant-time
    /// comparison). `None` accepts unauthenticated clients.
    pub required_token: Option<Vec<u8>>,
    /// Maximum number of simultaneously connected clients
    /// (`None` = unlimited).
    pub max_clients: Option<u32>,
}

impl SharedInstanceAccessConfig {
    /// Whether this configuration requires the authentication handshake.
    pub fn requires_handshake(&self) -> bool {
        !self.allow.is_empty() || self.required_token.is_some()
    }

    /// Validate an announced client name and token against this config.
    fn accepts(&self, name: &str, token: &[u8]) -> bool {
        if !self.allow.is_empty() && !self.allow.iter().any(|allowed| allowed == name) {
            return false;
        }
        if let Some(required) = &self.required_token {
            // Constant-time comparison for equal-length tokens.
            if required.len() != token.len() {
                return false;
            }
            let mut diff = 0u8;
            for (a, b) in required.iter().zip(token.iter()) {
                diff |= a ^ b;
            }
            if diff != 0 {
                return false;
            }
        }
        true
    }
}

/// Magic prefix of the shared-instance authentication frame
/// (`"RNSLIA1" || name_len u8 || name || token_len u16be || token`).
const AUTH_MAGIC: &[u8] = b"RNSLIA1";
/// Server-side wait for the authentication frame before dropping a client.
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

fn encode_auth_frame(name: &str, token: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(AUTH_MAGIC.len() + 3 + name.len() + token.len());
    payload.extend_from_slice(AUTH_MAGIC);
    payload.push(name.len() as u8);
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(&(token.len() as u16).to_be_bytes());
    payload.extend_from_slice(token);
    Hdlc::encode_frame_vec(&payload)
}

fn parse_auth_frame(frame: &[u8]) -> Option<(String, Vec<u8>)> {
    let payload = frame.strip_prefix(AUTH_MAGIC)?;
    let (&name_len, rest) = payload.split_first()?;
    let name = std::str::from_utf8(rest.get(..name_len as usize)?)
        .ok()?
        .to_string();
    let rest = &rest[name_len as usize..];
    let token_len = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]) as usize;
    let token = rest.get(2..2 + token_len)?.to_vec();
    Some((name, token))
}

/// Shared instance listener (`LocalServerInterface`).
///
/// Every accepted client connection is spawned as a [`LocalClient`] peer
/// interface in the same interface manager, making local clients full peers
/// of the daemon transport.
pub struct LocalServer {
    address: SharedInstanceAddress,
    endpoint: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    access: SharedInstanceAccessConfig,
}

impl LocalServer {
    pub fn new(
        address: SharedInstanceAddress,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self::new_with_access(
            address,
            iface_manager,
            SharedInstanceAccessConfig::default(),
        )
    }

    /// Create a shared-instance server enforcing `access`.
    pub fn new_with_access(
        address: SharedInstanceAddress,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        access: SharedInstanceAccessConfig,
    ) -> Self {
        let endpoint = address.describe();
        Self {
            address,
            endpoint,
            iface_manager,
            access,
        }
    }

    pub fn address(&self) -> &SharedInstanceAddress {
        &self.address
    }

    pub fn access_config(&self) -> &SharedInstanceAccessConfig {
        &self.access
    }

    async fn bind(address: &SharedInstanceAddress) -> Option<Listener> {
        match address {
            SharedInstanceAddress::Tcp { port } => {
                let listener = TcpListener::bind(("127.0.0.1", *port)).await.ok()?;
                Some(Listener::Tcp(listener))
            }
            #[cfg(target_os = "linux")]
            SharedInstanceAddress::UnixAbstract { instance_name } => {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::net::SocketAddr as UnixSocketAddr;

                let socket_address =
                    UnixSocketAddr::from_abstract_name(format!("rns/{instance_name}").as_bytes())
                        .ok()?;
                let listener = std::os::unix::net::UnixListener::bind_addr(&socket_address).ok()?;
                listener.set_nonblocking(true).ok()?;
                let listener = tokio::net::UnixListener::from_std(listener).ok()?;
                Some(Listener::Unix(listener))
            }
        }
    }

    async fn accept(
        listener: &mut Listener,
        access: &SharedInstanceAccessConfig,
    ) -> Option<LocalClient> {
        let (name, stream) = match listener {
            Listener::Tcp(listener) => {
                let (stream, peer) = listener.accept().await.ok()?;
                let _ = stream.set_nodelay(true);
                (format!("{peer}"), StreamType::Tcp(stream))
            }
            #[cfg(unix)]
            Listener::Unix(listener) => {
                let (stream, _) = listener.accept().await.ok()?;
                ("local".to_string(), StreamType::Unix(stream))
            }
        };
        if !access.requires_handshake() {
            return Some(LocalClient::new_from_stream(name, stream));
        }
        match Self::authenticate(stream, access).await {
            Some((client_name, stream)) => {
                log::debug!("local_server: authenticated shared-instance client <{client_name}>");
                Some(LocalClient::new_from_stream(client_name, stream))
            }
            None => {
                log::warn!("local_server: rejected unauthenticated shared-instance client");
                None
            }
        }
    }

    /// Run the access handshake on a freshly accepted `stream`: wait for
    /// the authentication frame and validate it against `access`.
    /// Returns the client-declared name and the stream on success.
    async fn authenticate(
        stream: StreamType,
        access: &SharedInstanceAccessConfig,
    ) -> Option<(String, StreamType)> {
        let deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
        let mut decoder = HdlcDecoder::new(HW_MTU);
        let mut buffer = [0u8; 4096];
        let (mut read_half, write_half) = stream.split();
        loop {
            let mut frames: Vec<Vec<u8>> = Vec::new();
            let n = tokio::select! {
                _ = tokio::time::sleep_until(deadline) => return None,
                result = stream_read(&mut read_half, &mut buffer[..]) => match result {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => n,
                },
            };
            decoder.feed(&buffer[..n], |frame| {
                // Auth frames are not packets; consider every frame
                // (keepalives fail the magic check and are ignored).
                frames.push(frame.to_vec());
            });
            for frame in frames.drain(..) {
                if let Some((name, token)) = parse_auth_frame(&frame) {
                    let accepted = access.accepts(&name, &token);
                    if !accepted {
                        return None;
                    }
                    let stream = StreamType::reunite(read_half, write_half)?;
                    return Some((name, stream));
                }
            }
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let address = context.inner.lock().unwrap().address.clone();
        let iface_manager = context.inner.lock().unwrap().iface_manager.clone();
        let access = context.inner.lock().unwrap().access.clone();
        let stats = context.channel.stats.clone();
        let parent = context.channel.address;

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = Self::bind(&address).await;

            let mut listener = match listener {
                Some(listener) => listener,
                None => {
                    log::warn!("local_server: couldn't bind to <{}>", address.describe());
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
            };

            log::info!(
                "local_server: shared instance listening on <{}>",
                address.describe()
            );
            stats.set_online(true);

            // Drain tx messages: actual clients are spawned as their own
            // interfaces in the manager (see TcpServer::spawn).
            let tx_task = {
                let cancel = context.cancel.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            // Skip all tx messages
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            loop {
                if context.cancel.is_cancelled() {
                    break;
                }

                // Enforce the concurrent-client cap before accepting more.
                if let Some(max_clients) = access.max_clients {
                    let connected = {
                        let iface_manager = iface_manager.lock().await;
                        iface_manager
                            .stats()
                            .into_iter()
                            .filter(|stats| stats.kind == "LocalClient")
                            .count() as u32
                    };
                    if connected >= max_clients {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                }

                tokio::select! {
                    _ = context.cancel.cancelled() => break,
                    client = Self::accept(&mut listener, &access) => {
                        if let Some(client) = client {
                            let mut iface_manager = iface_manager.lock().await;
                            let name = client.name().to_string();
                            let peer_context = iface_manager.open(client);
                            let address = peer_context.channel.address;
                            // Parent control, including a forced shared-instance
                            // bitrate, is copied before the client worker runs.
                            iface_manager.copy_spawned_control(&parent, &address);
                            iface_manager.note_spawned(&parent, &address);
                            // Surface the client's declared (or peer) name
                            // in interface statistics.
                            iface_manager.set_iface_name(&address, &name);
                            // Interfaces spawned by the shared instance are
                            // local client interfaces
                            // (Python `is_local_shared_instance`).
                            iface_manager.set_iface_local_client(&address);
                            iface_manager.launch(peer_context, LocalClient::spawn);
                        }
                    }
                }
            }

            stats.set_online(false);
            let _ = tx_task.await;
        }
    }
}

impl Interface for LocalServer {
    fn mtu() -> usize {
        HW_MTU
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// An already connected stream handed to a [`LocalClient`].
pub enum StreamType {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl StreamType {
    /// Split into owned read/write halves (for handshakes before the
    /// interface worker loop takes over).
    fn split(self) -> (LocalStreamRead, LocalStreamWrite) {
        match self {
            StreamType::Tcp(stream) => {
                let (read, write) = stream.into_split();
                (LocalStreamRead::Tcp(read), LocalStreamWrite::Tcp(write))
            }
            #[cfg(unix)]
            StreamType::Unix(stream) => {
                let (read, write) = stream.into_split();
                (LocalStreamRead::Unix(read), LocalStreamWrite::Unix(write))
            }
        }
    }

    /// Reunite owned halves into a whole stream.
    fn reunite(read: LocalStreamRead, write: LocalStreamWrite) -> Option<Self> {
        match (read, write) {
            (LocalStreamRead::Tcp(read), LocalStreamWrite::Tcp(write)) => {
                read.reunite(write).ok().map(StreamType::Tcp)
            }
            #[cfg(unix)]
            (LocalStreamRead::Unix(read), LocalStreamWrite::Unix(write)) => {
                read.reunite(write).ok().map(StreamType::Unix)
            }
            #[cfg(unix)]
            _ => None,
        }
    }
}

/// Local client interface (`LocalClientInterface`).
///
/// Used in two modes, matching the Python class:
///
/// * spawned by [`LocalServer`] for an accepted connection
///   (`connected_socket` mode, no reconnect),
/// * created directly to attach this transport to an existing shared
///   instance (reconnects with [`RECONNECT_WAIT`] while cancelled).
pub struct LocalClient {
    name: String,
    address: Option<SharedInstanceAddress>,
    endpoint: String,
    stream: Option<StreamType>,
    /// Access token presented to servers that require authentication.
    auth_token: Option<Vec<u8>>,
}

impl LocalClient {
    /// Create a client that connects to a shared instance at `address`.
    pub fn new(name: impl Into<String>, address: SharedInstanceAddress) -> Self {
        let endpoint = address.describe();
        Self {
            name: name.into(),
            address: Some(address),
            endpoint,
            stream: None,
            auth_token: None,
        }
    }

    /// Create a client that authenticates against access-controlled shared
    /// instances with `token` (see [`SharedInstanceAccessConfig`]). The
    /// authentication frame is sent immediately after connecting, before
    /// any Reticulum packets.
    pub fn new_authenticated(
        name: impl Into<String>,
        address: SharedInstanceAddress,
        token: Vec<u8>,
    ) -> Self {
        let endpoint = address.describe();
        Self {
            name: name.into(),
            address: Some(address),
            endpoint,
            stream: None,
            auth_token: Some(token),
        }
    }

    /// Set or clear the authentication token of this client.
    pub fn set_auth_token(&mut self, token: Option<Vec<u8>>) {
        self.auth_token = token;
    }

    /// The declared client name (used by shared-instance servers for
    /// interface naming and allow lists).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create a client for an already connected stream (server side).
    pub fn new_from_stream(name: impl Into<String>, stream: StreamType) -> Self {
        Self {
            name: name.into(),
            address: None,
            endpoint: String::new(),
            stream: Some(stream),
            auth_token: None,
        }
    }

    async fn connect(address: &SharedInstanceAddress) -> Option<StreamType> {
        match address {
            SharedInstanceAddress::Tcp { port } => {
                let stream = TcpStream::connect(("127.0.0.1", *port)).await.ok()?;
                let _ = stream.set_nodelay(true);
                Some(StreamType::Tcp(stream))
            }
            #[cfg(unix)]
            SharedInstanceAddress::UnixAbstract { instance_name } => {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::net::SocketAddr as UnixSocketAddr;

                let socket_address =
                    UnixSocketAddr::from_abstract_name(format!("rns/{instance_name}").as_bytes())
                        .ok()?;
                let stream = std::os::unix::net::UnixStream::connect_addr(&socket_address).ok()?;
                stream.set_nonblocking(true).ok()?;
                Some(StreamType::Unix(
                    tokio::net::UnixStream::from_std(stream).ok()?,
                ))
            }
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let exited = context.channel.exited.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();
        let name = context.inner.lock().unwrap().name.clone();
        let address = context.inner.lock().unwrap().address.clone();
        let auth_token = context.inner.lock().unwrap().auth_token.clone();
        let mut stream = context.inner.lock().unwrap().stream.take();

        if let Some(address) = &address {
            log::debug!(
                "local_client[{}]: connecting to shared instance <{}>",
                name,
                address.describe()
            );
        }

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        // A pre-set stream is a server-accepted connection that never
        // reconnects (Python `connected_socket` mode).
        let server_side = stream.is_some();

        'outer: loop {
            if context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                break;
            }

            let connected = match stream.take() {
                Some(stream) => Some(stream),
                None => {
                    let Some(target) = address.as_ref() else {
                        break;
                    };

                    // drain tx queue while disconnected, retry periodically
                    let mut tx_channel = tx_channel.lock().await;
                    tokio::select! {
                        biased;
                        _ = context.cancel.cancelled() => break,
                        _ = iface_stop.cancelled() => break,
                        Some(_) = tx_channel.recv() => continue,
                        connected = Self::connect(target) => connected,
                    }
                }
            };

            let stream = match connected {
                Some(stream) => stream,
                None => {
                    stats.set_online(false);

                    log::info!(
                        "local_client[{}]: couldn't connect to <{}>, retrying",
                        name,
                        address.as_ref().map(|a| a.describe()).unwrap_or_default()
                    );

                    let retry_at = tokio::time::Instant::now() + RECONNECT_WAIT;
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            biased;
                            _ = context.cancel.cancelled() => break 'outer,
                            _ = iface_stop.cancelled() => break 'outer,
                            Some(_) = tx_channel.recv() => {}
                            _ = tokio::time::sleep_until(retry_at) => break,
                        }
                    }
                    continue;
                }
            };

            let cancel = context.cancel.clone();

            let (read_half, mut write_half) = match stream {
                StreamType::Tcp(stream) => {
                    let (read, write) = stream.into_split();
                    (LocalStreamRead::Tcp(read), LocalStreamWrite::Tcp(write))
                }
                #[cfg(unix)]
                StreamType::Unix(stream) => {
                    let (read, write) = stream.into_split();
                    (LocalStreamRead::Unix(read), LocalStreamWrite::Unix(write))
                }
            };

            // Access-controlled servers expect the authentication frame
            // before any Reticulum packets, so send it before the rx/tx
            // tasks start whenever a token is configured.
            if let Some(token) = &auth_token {
                let frame = encode_auth_frame(&name, token);
                if stream_write_all(&mut write_half, &frame).await.is_err() {
                    log::debug!("local_client[{}]: authentication write failed", name);
                    if server_side || cancel.is_cancelled() || iface_stop.is_cancelled() {
                        break;
                    }
                    continue;
                }
            }

            stats.set_online(true);
            log::debug!(
                "local_client[{}]: connected to <{}>",
                name,
                address
                    .as_ref()
                    .map(|a| a.describe())
                    .unwrap_or_else(|| "client".into())
            );

            // Start receive task
            let mut rx_task = {
                let cancel = cancel.clone();
                let iface_stop = iface_stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let mut stream = read_half;
                let channel_ifac_rx = channel_ifac.clone();

                tokio::spawn(async move {
                    let mut decoder = HdlcDecoder::new(HW_MTU);
                    let mut buffer = [0u8; 4096];
                    let mut frames = Vec::new();

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = iface_stop.cancelled() => break,
                            result = stream_read(&mut stream, &mut buffer[..]) => match result {
                                Ok(0) => {
                                    log::debug!("local_client: connection closed");
                                    break;
                                }
                                Ok(n) => {
                                    frames.clear();
                                    decoder.feed(&buffer[..n], |frame| {
                                        // ignore keepalive and noise frames like
                                        // LocalInterface.handle_hdlc
                                        if frame.len() > HEADER_MINSIZE {
                                            frames.push(frame.to_vec());
                                        }
                                    });

                                    for frame in frames.drain(..) {
                                        let plain = {
                                            let ifac = channel_ifac_rx
                                                .read()
                                                .expect("ifac lock")
                                                .clone();
                                            match crate::iface::ifac::decode_inbound(
                                                &frame,
                                                ifac.as_deref(),
                                                Some(&stats),
                                            ) {
                                                Some(plain) => plain,
                                                None => {
                                                    log::debug!("local_client: dropping packet with invalid access code");
                                                    continue;
                                                }
                                            }
                                        };
                                        match Packet::deserialize(&mut InputBuffer::new(&plain[..])) {
                                            Ok(packet) => {
                                                if PACKET_TRACE {
                                                    log::trace!(
                                                        "local_client: rx << ({}) {}",
                                                        iface_address,
                                                        packet
                                                    );
                                                }
                                                stats.count_rx(frame.len());
                                                let _ = rx_channel
                                                    .send(RxMessage {
                                                        address: iface_address,
                                                        packet,
                                                    })
                                                    .await;
                                            }
                                            Err(_) => {
                                                log::debug!(
                                                    "local_client: couldn't decode packet"
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::debug!("local_client: connection error {}", e);
                                    break;
                                }
                            }
                        }
                    }
                })
            };

            // Start transmit task
            let mut tx_task = {
                let cancel = cancel.clone();
                let iface_stop = iface_stop.clone();
                let tx_channel = tx_channel.clone();
                let stats = stats.clone();
                let mut stream = write_half;
                let channel_ifac = channel_ifac.clone();

                tokio::spawn(async move {
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = iface_stop.cancelled() => break,
                            Some(message) = tx_channel.recv() => message,
                        };

                        if PACKET_TRACE {
                            log::trace!(
                                "local_client: tx >> ({}) {}",
                                iface_address,
                                message.packet
                            );
                        }

                        let packet = message.packet;
                        let mut buffer = [0u8; 8192 + 16];
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let ifac = channel_ifac.read().expect("ifac lock").clone();
                            let wire =
                                crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());
                            let frame = Hdlc::encode_frame_vec(&wire);
                            if stream_write_all(&mut stream, &frame).await.is_ok() {
                                stats.count_tx(wire.len());
                            }
                        }
                    }
                })
            };

            // Only the losing task is awaited: select already polled the
            // winner to completion, and re-polling its JoinHandle panics.
            tokio::select! {
                _ = &mut rx_task => {
                    tx_task.abort();
                    let _ = tx_task.await;
                }
                _ = &mut tx_task => {
                    rx_task.abort();
                    let _ = rx_task.await;
                }
            }

            stats.set_online(false);
            log::debug!("local_client[{}]: disconnected", name);

            // A channel stop ends the client. Do not open the socket again.
            if server_side || cancel.is_cancelled() || iface_stop.is_cancelled() {
                break;
            }
        }

        let _ = exited.send(true);
        iface_stop.cancel();
    }
}

impl Interface for LocalClient {
    fn mtu() -> usize {
        HW_MTU
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autoconfigure_mtu_at_1e9_is_524288() {
        assert_eq!(HW_MTU, 524_288);
        assert_eq!(optimise_mtu(1_000_000_000), Some(HW_MTU));
        assert_eq!(<LocalClient as Interface>::mtu(), 524_288);
        assert_eq!(<LocalServer as Interface>::mtu(), 524_288);

        assert_eq!(optimise_mtu(750_000_000), Some(262_144));
        assert_eq!(optimise_mtu(400_000_000), Some(131_072));
        assert_eq!(optimise_mtu(200_000_000), Some(65_536));
        assert_eq!(optimise_mtu(100_000_000), Some(32_768));
        assert_eq!(optimise_mtu(10_000_000), Some(16_384));
        assert_eq!(optimise_mtu(5_000_000), Some(8_192));
        assert_eq!(optimise_mtu(2_000_000), Some(4_096));
        assert_eq!(optimise_mtu(1_000_000), Some(2_048));
        assert_eq!(optimise_mtu(62_500), Some(1_024));
        assert_eq!(optimise_mtu(62_499), None);
    }
}
