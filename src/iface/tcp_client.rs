use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use tokio::io::AsyncReadExt;

use alloc::string::String;

use super::hdlc::Hdlc;
use super::{Interface, InterfaceContext};

// TODO: Configure via features
const PACKET_TRACE: bool = false;

/// `TCPInterface.HW_MTU` before `fixed_mtu` / `optimise_mtu`.
pub const HW_MTU: usize = 262_144;

/// `TCPClientInterface.RECONNECT_WAIT` in seconds.
pub const RECONNECT_WAIT_SECS: u64 = 5;

/// `TCPClientInterface.INITIAL_CONNECT_TIMEOUT` in seconds.
pub const INITIAL_CONNECT_TIMEOUT: u64 = 5;

/// `TCPClientInterface.RECONNECT_MAX_TRIES` (`None` retries forever).
pub const RECONNECT_MAX_TRIES: Option<u32> = None;

/// KISS markers from `TCPInterface.KISS` (not the serial KISS interface).
const KISS_FEND: u8 = 0xC0;
const KISS_FESC: u8 = 0xDB;
const KISS_TFEND: u8 = 0xDC;
const KISS_TFESC: u8 = 0xDD;
const KISS_CMD_DATA: u8 = 0x00;
const KISS_CMD_UNKNOWN: u8 = 0xFE;

/// Python TCP client/server knobs. Defaults keep [`TcpClient::new`] and
/// [`TcpServer::new`](super::tcp_server::TcpServer::new) on today's path:
/// HDLC framing, no device bind, no IPv6 preference, autoconfigured
/// hardware MTU, unlimited reconnects, and no extra connect timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOptions {
    /// `kiss_framing`. Default false (HDLC).
    pub kiss_framing: bool,
    /// `prefer_ipv6`. Default false.
    pub prefer_ipv6: bool,
    /// Kernel device to bind (`device`). Default none.
    pub device: Option<String>,
    /// `fixed_mtu`. `None` keeps [`HW_MTU`] and `AUTOCONFIGURE_MTU`.
    /// Values below `Reticulum.MTU` (500) are rejected.
    pub fixed_mtu: Option<usize>,
    /// `max_reconnect_tries`. `None` retries forever.
    pub max_reconnect_tries: Option<u32>,
    /// `connect_timeout` in seconds. `None` leaves the plain
    /// `TcpStream::connect` untimed (today's behavior). Python applies
    /// [`INITIAL_CONNECT_TIMEOUT`] when the key is absent; pass
    /// `Some(INITIAL_CONNECT_TIMEOUT)` to cap the connect the same way.
    pub connect_timeout: Option<u64>,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            kiss_framing: false,
            prefer_ipv6: false,
            device: None,
            fixed_mtu: None,
            max_reconnect_tries: RECONNECT_MAX_TRIES,
            connect_timeout: None,
        }
    }
}

impl TcpOptions {
    pub fn validate(&self) -> Result<(), RnsError> {
        if let Some(mtu) = self.fixed_mtu {
            if mtu < crate::packet::PROTOCOL_MTU {
                log::error!("Configured MTU of {mtu} bytes is too small");
                return Err(RnsError::InvalidArgument);
            }
        }
        Ok(())
    }

    /// Hardware MTU for a fixed limit, otherwise [`HW_MTU`] (262144).
    pub fn hardware_mtu(&self) -> usize {
        self.fixed_mtu.unwrap_or(HW_MTU)
    }

    /// Options copied onto a client accepted by a TCP server. Accepted
    /// sockets are not initiators, so reconnect and bind knobs stay default.
    /// Framing and `fixed_mtu` follow the listener.
    pub fn for_accepted_client(&self) -> Self {
        Self {
            kiss_framing: self.kiss_framing,
            fixed_mtu: self.fixed_mtu,
            ..Self::default()
        }
    }
}

/// Bind target for a TCP server. `Literal` is the address string unchanged
/// (omitted `device` / `prefer_ipv6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindTarget {
    Literal(String),
    Resolved(SocketAddr),
}

pub struct TcpClient {
    addr: String,
    stream: Option<TcpStream>,
    options: TcpOptions,
}

impl TcpClient {
    pub fn new<T: Into<String>>(addr: T) -> Self {
        Self::from_parts(addr.into(), None, TcpOptions::default())
    }

    /// `new` plus Python TCP knobs. Invalid `fixed_mtu` is rejected.
    pub fn with_options<T: Into<String>>(addr: T, options: TcpOptions) -> Result<Self, RnsError> {
        options.validate()?;
        Ok(Self::from_parts(addr.into(), None, options))
    }

    pub fn new_from_stream<T: Into<String>>(addr: T, stream: TcpStream) -> Self {
        Self::from_parts(addr.into(), Some(stream), TcpOptions::default())
    }

    pub fn new_from_stream_with_options<T: Into<String>>(
        addr: T,
        stream: TcpStream,
        options: TcpOptions,
    ) -> Result<Self, RnsError> {
        options.validate()?;
        Ok(Self::from_parts(addr.into(), Some(stream), options))
    }

    pub(crate) fn from_parts(addr: String, stream: Option<TcpStream>, options: TcpOptions) -> Self {
        Self {
            addr,
            stream,
            options,
        }
    }

    pub fn options(&self) -> &TcpOptions {
        &self.options
    }

    pub async fn spawn(context: InterfaceContext<TcpClient>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let options = { context.inner.lock().unwrap().options.clone() };
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();
        let mut stream = { context.inner.lock().unwrap().stream.take() };

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        let mut running = true;
        // Per outage, matching `TCPClientInterface.reconnect` (`attempts = 0`
        // each time that runs). The first dial stays immediate.
        let mut reconnect_attempts: u32 = 0;
        'outer: loop {
            if !running || context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                break;
            }

            let stream = match stream.take() {
                Some(stream) => {
                    running = false;
                    Ok(stream)
                }
                None => {
                    let mut tx_channel = tx_channel.lock().await;

                    tokio::select! {
                        biased;
                        _ = context.cancel.cancelled() => {
                            break;
                        }
                        _ = iface_stop.cancelled() => {
                            break;
                        }
                        Some(_) = tx_channel.recv() => {
                            continue;
                        }
                        result = connect_once(&addr, &options) => {
                            result.map_err(|_| RnsError::ConnectionError)
                        }
                    }
                }
            };

            stats.set_online(false);
            if stream.is_err() {
                log::info!("tcp_client: couldn't connect to <{}>", addr);
                if !pause_before_reconnect(&context.cancel, &iface_stop, &tx_channel).await {
                    break 'outer;
                }
                // `initial_connect` failed, so this is `reconnect`: the
                // wait already elapsed, and `attempts > max` skips the dial.
                if !reconnect_after_wait(&mut reconnect_attempts, options.max_reconnect_tries) {
                    log::error!("tcp_client: max reconnection attempts reached for <{addr}>");
                    break 'outer;
                }
                continue;
            }

            let cancel = context.cancel.clone();

            let stream = stream.unwrap();
            let (read_stream, write_stream) = stream.into_split();

            stats.set_online(true);
            // Next outage starts at zero.
            reconnect_attempts = 0;
            log::info!("tcp_client connected to <{}>", addr);

            const BUFFER_SIZE: usize = core::mem::size_of::<Packet>() * 2;
            let kiss_framing = options.kiss_framing;
            let fixed_limit = options.fixed_mtu;
            let hw_mtu = options.hardware_mtu();

            // Start receive task
            let mut rx_task = {
                let cancel = cancel.clone();
                let iface_stop = iface_stop.clone();
                let mut stream = read_stream;
                let rx_channel = rx_channel.clone();
                let stats = stats.clone();
                let channel_ifac_rx = channel_ifac.clone();

                tokio::spawn(async move {
                    let mut hdlc_rx_buffer = [0u8; BUFFER_SIZE];
                    let mut rx_buffer = [0u8; BUFFER_SIZE + (BUFFER_SIZE / 2)];
                    let mut tcp_buffer = [0u8; (BUFFER_SIZE * 16)];
                    let mut kiss_decoder = TcpKissDecoder::new(hw_mtu);

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = iface_stop.cancelled() => {
                                    break;
                            }
                            result = stream.read(&mut tcp_buffer[..]) => {
                                    match result {
                                        Ok(0) => {
                                            log::warn!("tcp_client: connection closed");
                                            break;
                                        }
                                        Ok(n) => {
                                            if kiss_framing {
                                                for frame in kiss_decoder.feed(&tcp_buffer[..n]) {
                                                    deliver_frame(
                                                        &frame,
                                                        &channel_ifac_rx,
                                                        &rx_channel,
                                                        &stats,
                                                        iface_address,
                                                    )
                                                    .await;
                                                }
                                                continue;
                                            }
                                            // TCP stream may contain several or partial HDLC frames
                                            for byte in &tcp_buffer[..n] {
                                                // Push new byte from the end of buffer
                                                rx_buffer[BUFFER_SIZE-1] = *byte;

                                                // Check if it is contains a HDLC frame
                                                let frame = Hdlc::find(&rx_buffer[..]);
                                                if let Some(frame) = frame {
                                                    // Decode HDLC frame and deserialize packet
                                                    let frame_buffer = &mut rx_buffer[frame.0..frame.1+1];
                                                    let mut output = OutputBuffer::new(&mut hdlc_rx_buffer[..]);
                                                    if Hdlc::decode(frame_buffer, &mut output).is_ok() {
                                                        if let Some(limit) = fixed_limit {
                                                            let ifac_size = {
                                                                let ifac = channel_ifac_rx
                                                                    .read()
                                                                    .expect("ifac lock");
                                                                ifac.as_ref()
                                                                    .map(|key| key.size)
                                                                    .unwrap_or(0)
                                                            };
                                                            if output.offset()
                                                                > limit.saturating_add(ifac_size)
                                                            {
                                                                log::debug!("tcp_client: dropping frame larger than fixed mtu");
                                                                frame_buffer.fill(0);
                                                                continue;
                                                            }
                                                        }
                                                        let plain = {
                                                            let ifac = channel_ifac_rx
                                                                .read()
                                                                .expect("ifac lock")
                                                                .clone();
                                                            match crate::iface::ifac::decode_inbound(
                                                                output.as_slice(),
                                                                ifac.as_deref(),
                                                                Some(&stats),
                                                            ) {
                                                                Some(plain) => plain,
                                                                None => {
                                                                    log::debug!("tcp_client_interface: dropping packet with invalid access code");
                                                                    continue;
                                                                }
                                                            }
                                                        };
                                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&plain[..])) {
                                                            if PACKET_TRACE {
                                                                log::trace!("tcp_client: rx << ({}) {}", iface_address, packet);
                                                            }
                                                            stats.count_rx(output.offset());
                                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                        } else {
                                                            log::warn!("tcp_client: couldn't decode packet");
                                                        }
                                                    } else {
                                                        log::warn!("tcp_client: couldn't decode hdlc frame");
                                                    }

                                                    // Remove current HDLC frame data
                                                    frame_buffer.fill(0);
                                                } else {
                                                    // Move data left
                                                    rx_buffer.copy_within(1.., 0);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!("tcp_client: connection error {}", e);
                                            break;
                                        }
                                    }
                                },
                        };
                    }
                })
            };

            // Start transmit task
            let mut tx_task = {
                let cancel = cancel.clone();
                let iface_stop = iface_stop.clone();
                let tx_channel = tx_channel.clone();
                let stats = stats.clone();
                let mut stream = write_stream;
                let channel_ifac = channel_ifac.clone();
                let kiss_framing = options.kiss_framing;

                tokio::spawn(async move {
                    loop {
                        if cancel.is_cancelled() || iface_stop.is_cancelled() {
                            break;
                        }

                        let mut hdlc_tx_buffer = [0u8; BUFFER_SIZE];
                        let mut tx_buffer = [0u8; BUFFER_SIZE];

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = iface_stop.cancelled() => {
                                    break;
                            }
                            Some(message) = tx_channel.recv() => {
                                let packet = message.packet;
                                if PACKET_TRACE {
                                    log::trace!("tcp_client: tx >> ({}) {}", iface_address, packet);
                                }
                                let mut output = OutputBuffer::new(&mut tx_buffer);
                                if packet.serialize(&mut output).is_ok() {
                                    let wire = {
                                        let ifac = channel_ifac
                                            .read()
                                            .expect("ifac lock")
                                            .clone();
                                        crate::iface::ifac::encode(output.as_slice(), ifac.as_deref())
                                    };

                                    let mut framed = OutputBuffer::new(&mut hdlc_tx_buffer[..]);
                                    let wrote = if kiss_framing {
                                        let encoded = kiss_encode(&wire);
                                        stream.write_all(&encoded).await.is_ok()
                                    } else {
                                        Hdlc::encode(&wire, &mut framed).is_ok()
                                            && stream.write_all(framed.as_slice()).await.is_ok()
                                    };
                                    if wrote {
                                        let _ = stream.flush().await;
                                        stats.count_tx(wire.len());
                                    }
                                }
                            }
                        };
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
            log::info!("tcp_client: disconnected from <{}>", addr);

            // Accepted sockets set `running` false and must not dial.
            // A channel stop ends the peer; it must not dial again.
            // An initiator waits, then applies `attempts > max`, before
            // the next `connect_once`. The startup dial above is not gated.
            if !running || context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                break;
            }
            if !pause_before_reconnect(&context.cancel, &iface_stop, &tx_channel).await {
                break;
            }
            if !reconnect_after_wait(&mut reconnect_attempts, options.max_reconnect_tries) {
                log::error!("tcp_client: max reconnection attempts reached for <{addr}>");
                break 'outer;
            }
        }

        iface_stop.cancel();
    }
}

impl Interface for TcpClient {
    fn mtu() -> usize {
        2048
    }

    fn endpoint(&self) -> &str {
        &self.addr
    }
}

/// `None` keeps today's untimed `TcpStream::connect`. A device bind, IPv6
/// preference, or explicit `connect_timeout` applies the cap (Python's
/// omitted key is [`INITIAL_CONNECT_TIMEOUT`] once the plain path is left).
fn connect_budget(options: &TcpOptions) -> Option<Duration> {
    if options.device.is_none() && !options.prefer_ipv6 && options.connect_timeout.is_none() {
        return None;
    }
    Some(Duration::from_secs(
        options.connect_timeout.unwrap_or(INITIAL_CONNECT_TIMEOUT),
    ))
}

async fn connect_once(addr: &str, options: &TcpOptions) -> std::io::Result<TcpStream> {
    let connect = async {
        if options.device.is_none() && !options.prefer_ipv6 {
            TcpStream::connect(addr).await
        } else {
            connect_configured(addr, options).await
        }
    };
    match connect_budget(options) {
        None => connect.await,
        Some(limit) => match tokio::time::timeout(limit, connect).await {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tcp connect timeout",
            )),
        },
    }
}

async fn connect_configured(addr: &str, options: &TcpOptions) -> std::io::Result<TcpStream> {
    let remote = resolve_preferred(addr, options.prefer_ipv6)
        .await
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no tcp address")
        })?;
    if let Some(device) = &options.device {
        let local = device_socket_addr(device, 0, options.prefer_ipv6).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "device has no address",
            )
        })?;
        let socket = match local {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
        };
        socket.bind(local)?;
        socket.connect(remote).await
    } else {
        TcpStream::connect(remote).await
    }
}

/// Python stops when `attempts > max_reconnect_tries`. `None` never stops.
fn reconnect_permitted(attempts: u32, max_reconnect_tries: Option<u32>) -> bool {
    match max_reconnect_tries {
        Some(max) => attempts <= max,
        None => true,
    }
}

/// After `RECONNECT_WAIT`, increment and report whether the next dial may run.
fn reconnect_after_wait(attempts: &mut u32, max_reconnect_tries: Option<u32>) -> bool {
    *attempts = attempts.saturating_add(1);
    reconnect_permitted(*attempts, max_reconnect_tries)
}

/// Drain outbound packets until `RECONNECT_WAIT` elapses. `false` means stop.
async fn pause_before_reconnect(
    cancel: &CancellationToken,
    iface_stop: &CancellationToken,
    tx_channel: &Arc<tokio::sync::Mutex<super::InterfaceTxReceiver>>,
) -> bool {
    let retry_at = tokio::time::Instant::now() + Duration::from_secs(RECONNECT_WAIT_SECS);
    loop {
        let mut tx_channel = tx_channel.lock().await;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                return false;
            }
            _ = iface_stop.cancelled() => {
                return false;
            }
            Some(_) = tx_channel.recv() => {}
            _ = tokio::time::sleep_until(retry_at) => {
                return true;
            }
        }
    }
}

pub(crate) async fn resolve_bind_target(addr: &str, options: &TcpOptions) -> Option<BindTarget> {
    if options.device.is_none() && !options.prefer_ipv6 {
        return Some(BindTarget::Literal(addr.to_string()));
    }
    if let Some(device) = &options.device {
        let port = split_port(addr)?;
        return device_socket_addr(device, port, options.prefer_ipv6).map(BindTarget::Resolved);
    }
    resolve_preferred(addr, true)
        .await
        .map(BindTarget::Resolved)
}

fn split_port(addr: &str) -> Option<u16> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (_, port) = rest.rsplit_once("]:")?;
        return port.parse().ok();
    }
    let (_, port) = addr.rsplit_once(':')?;
    port.parse().ok()
}

fn select_resolved(addrs: &[SocketAddr], prefer_ipv6: bool) -> Option<SocketAddr> {
    if addrs.is_empty() {
        return None;
    }
    if prefer_ipv6 {
        if let Some(addr) = addrs.iter().copied().find(SocketAddr::is_ipv6) {
            return Some(addr);
        }
    } else if let Some(addr) = addrs.iter().copied().find(SocketAddr::is_ipv4) {
        return Some(addr);
    }
    Some(addrs[0])
}

async fn resolve_preferred(addr: &str, prefer_ipv6: bool) -> Option<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(addr).await.ok()?.collect();
    select_resolved(&addrs, prefer_ipv6)
}

fn device_socket_addr(name: &str, port: u16, prefer_ipv6: bool) -> Option<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        linux_device_addr(name, port, prefer_ipv6)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, port, prefer_ipv6);
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_device_addr(name: &str, port: u16, prefer_ipv6: bool) -> Option<SocketAddr> {
    let v4 = ipv4_for_device(name);
    let v6 = ipv6_for_device(name);
    if prefer_ipv6 || v4.is_none() {
        if let Some((ip, ifindex, link_local)) = v6 {
            let scope = if link_local { ifindex } else { 0 };
            return Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip, port, 0, scope,
            )));
        }
    }
    v4.map(|ip| SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)))
}

#[cfg(target_os = "linux")]
fn ipv4_for_device(name: &str) -> Option<std::net::Ipv4Addr> {
    use std::os::fd::AsRawFd;

    if name.is_empty() || name.len() >= 16 {
        return None;
    }
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    let mut buf = [0u8; 40];
    buf[..name.len()].copy_from_slice(name.as_bytes());
    // SIOCGIFADDR. Address bytes sit at offset 20 of `struct ifreq`.
    // The request argument is `unsigned long` (`libc::c_ulong`); a `u64`
    // is the wrong C ABI on ILP32. libc stays behind `iface-serial`, so
    // this uses the same type from std.
    let rc = unsafe { ioctl(socket.as_raw_fd(), 0x8915, buf.as_mut_ptr()) };
    if rc < 0 {
        return None;
    }
    if u16::from_ne_bytes([buf[16], buf[17]]) != 2 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]))
}

#[cfg(target_os = "linux")]
fn ipv6_for_device(name: &str) -> Option<(std::net::Ipv6Addr, u32, bool)> {
    let text = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(addr), Some(index), Some(_prefix), Some(_scope), Some(_flags), Some(ifname)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if ifname != name || addr.len() != 32 {
            continue;
        }
        let mut bytes = [0u8; 16];
        for (i, chunk) in addr.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).ok()?;
            bytes[i] = u8::from_str_radix(hex, 16).ok()?;
        }
        let ip = std::net::Ipv6Addr::from(bytes);
        let ifindex = u32::from_str_radix(index, 16).ok()?;
        return Some((ip, ifindex, addr.starts_with("fe80")));
    }
    None
}

#[cfg(target_os = "linux")]
extern "C" {
    fn ioctl(fd: i32, request: std::os::raw::c_ulong, argp: *mut u8) -> i32;
}

async fn deliver_frame(
    frame: &[u8],
    channel_ifac: &super::IfacSlot,
    rx_channel: &super::InterfaceRxSender,
    stats: &super::InterfaceCounters,
    iface_address: crate::hash::AddressHash,
) {
    let plain = {
        let ifac = channel_ifac.read().expect("ifac lock").clone();
        match crate::iface::ifac::decode(frame, ifac.as_deref()) {
            Some(plain) => plain,
            None => {
                log::debug!("tcp_client_interface: dropping packet with invalid access code");
                return;
            }
        }
    };
    if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&plain[..])) {
        if PACKET_TRACE {
            log::trace!("tcp_client: rx << ({}) {}", iface_address, packet);
        }
        stats.count_rx(frame.len());
        let _ = rx_channel
            .send(super::RxMessage {
                address: iface_address,
                packet,
            })
            .await;
    } else {
        log::warn!("tcp_client: couldn't decode packet");
    }
}

/// `FEND + CMD_DATA + escape(data) + FEND`, byte-for-byte `TCPInterface.KISS`.
fn kiss_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.push(KISS_FEND);
    out.push(KISS_CMD_DATA);
    for &byte in data {
        match byte {
            KISS_FESC => out.extend_from_slice(&[KISS_FESC, KISS_TFESC]),
            KISS_FEND => out.extend_from_slice(&[KISS_FESC, KISS_TFEND]),
            other => out.push(other),
        }
    }
    out.push(KISS_FEND);
    out
}

/// TCP KISS read loop from `TCPClientInterface.read_loop` (`kiss_framing`).
struct TcpKissDecoder {
    frame: Vec<u8>,
    in_frame: bool,
    escape: bool,
    command: u8,
    mtu: usize,
}

impl TcpKissDecoder {
    fn new(mtu: usize) -> Self {
        Self {
            frame: Vec::new(),
            in_frame: false,
            escape: false,
            command: KISS_CMD_UNKNOWN,
            mtu,
        }
    }

    fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for &byte in data {
            if self.in_frame && byte == KISS_FEND && self.command == KISS_CMD_DATA {
                self.in_frame = false;
                self.escape = false;
                self.command = KISS_CMD_UNKNOWN;
                frames.push(std::mem::take(&mut self.frame));
            } else if byte == KISS_FEND {
                self.in_frame = true;
                self.escape = false;
                self.command = KISS_CMD_UNKNOWN;
                self.frame.clear();
            } else if self.in_frame && self.frame.len() < self.mtu {
                if self.frame.is_empty() && self.command == KISS_CMD_UNKNOWN {
                    self.command = byte & 0x0F;
                } else if self.command == KISS_CMD_DATA {
                    if byte == KISS_FESC {
                        self.escape = true;
                    } else {
                        let mut byte = byte;
                        if self.escape {
                            if byte == KISS_TFEND {
                                byte = KISS_FEND;
                            }
                            if byte == KISS_TFESC {
                                byte = KISS_FESC;
                            }
                            self.escape = false;
                        }
                        self.frame.push(byte);
                    }
                }
            }
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_tcp_options_keep_current_behavior() {
        let client = TcpClient::new("127.0.0.1:4242");
        assert_eq!(client.options(), &TcpOptions::default());
        assert!(!client.options().kiss_framing);
        assert!(!client.options().prefer_ipv6);
        assert!(client.options().device.is_none());
        assert!(client.options().fixed_mtu.is_none());
        assert_eq!(client.options().max_reconnect_tries, RECONNECT_MAX_TRIES);
        assert!(client.options().connect_timeout.is_none());
        assert_eq!(client.options().hardware_mtu(), 262_144);
        assert_eq!(<TcpClient as Interface>::mtu(), 2048);
        // Plain connect: no timeout cap, so a slow handshake still behaves
        // the way `TcpClient::new` did before these knobs existed.
        assert!(connect_budget(client.options()).is_none());
        assert!(reconnect_permitted(
            10_000,
            client.options().max_reconnect_tries
        ));
    }

    #[test]
    fn fixed_mtu_below_protocol_mtu_is_rejected() {
        let options = TcpOptions {
            fixed_mtu: Some(crate::packet::PROTOCOL_MTU - 1),
            ..TcpOptions::default()
        };
        assert!(TcpClient::with_options("127.0.0.1:1", options).is_err());

        let options = TcpOptions {
            fixed_mtu: Some(crate::packet::PROTOCOL_MTU),
            ..TcpOptions::default()
        };
        let client = TcpClient::with_options("127.0.0.1:1", options).unwrap();
        assert_eq!(
            client.options().fixed_mtu,
            Some(crate::packet::PROTOCOL_MTU)
        );
        assert_eq!(client.options().hardware_mtu(), crate::packet::PROTOCOL_MTU);
    }

    #[test]
    fn reconnect_limit_matches_python() {
        // One fresh outage: the immediate dial is not counted. After the
        // wait, `attempts > max` stops. `None` never stops.
        assert!(reconnect_permitted(1, None));
        assert!(reconnect_permitted(1, Some(1)));
        assert!(!reconnect_permitted(1, Some(0)));
        assert!(!reconnect_permitted(2, Some(1)));

        let mut attempts = 0;
        assert!(!reconnect_after_wait(&mut attempts, Some(0)));

        let mut attempts = 0;
        assert!(reconnect_after_wait(&mut attempts, Some(1)));
        assert!(!reconnect_after_wait(&mut attempts, Some(1)));

        // A later live session clears a spent cap. The next outage counts
        // from zero after its own wait, before the next dial.
        let mut attempts = 2;
        assert!(!reconnect_after_wait(&mut attempts, Some(1)));
        attempts = 0;
        assert!(reconnect_after_wait(&mut attempts, Some(1)));
        attempts = 0;
        assert!(reconnect_after_wait(&mut attempts, Some(1)));

        let mut attempts = 0;
        assert!(!reconnect_after_wait(&mut attempts, Some(0)));

        let mut attempts = 0;
        assert!(reconnect_after_wait(&mut attempts, None));
        assert!(reconnect_after_wait(&mut attempts, None));
    }

    #[test]
    fn explicit_connect_timeout_is_applied() {
        let options = TcpOptions {
            connect_timeout: Some(INITIAL_CONNECT_TIMEOUT),
            ..TcpOptions::default()
        };
        assert_eq!(
            connect_budget(&options),
            Some(Duration::from_secs(INITIAL_CONNECT_TIMEOUT))
        );
    }

    #[test]
    fn prefer_ipv6_selects_matching_family() {
        let v4: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let v6: SocketAddr = "[::1]:9".parse().unwrap();
        assert_eq!(select_resolved(&[v4, v6], false), Some(v4));
        assert_eq!(select_resolved(&[v6, v4], false), Some(v4));
        assert_eq!(select_resolved(&[v4, v6], true), Some(v6));
        // No address in the preferred family: keep the first, like Python.
        assert_eq!(select_resolved(&[v4], true), Some(v4));
        assert_eq!(select_resolved(&[], false), None);
    }

    #[test]
    fn kiss_framing_roundtrip_matches_python() {
        let payload = [0xC0, 0xDB, 0x01];
        let encoded = kiss_encode(&payload);
        assert_eq!(
            encoded,
            [
                KISS_FEND,
                KISS_CMD_DATA,
                KISS_FESC,
                KISS_TFEND,
                KISS_FESC,
                KISS_TFESC,
                0x01,
                KISS_FEND
            ]
        );
        let mut decoder = TcpKissDecoder::new(HW_MTU);
        let frames = decoder.feed(&encoded);
        assert_eq!(frames, [payload.to_vec()]);
    }

    #[test]
    fn accepted_client_inherits_framing_and_mtu_only() {
        let options = TcpOptions {
            kiss_framing: true,
            prefer_ipv6: true,
            device: Some("lo".to_string()),
            fixed_mtu: Some(1500),
            max_reconnect_tries: Some(3),
            connect_timeout: Some(2),
        };
        let spawned = options.for_accepted_client();
        assert!(spawned.kiss_framing);
        assert_eq!(spawned.fixed_mtu, Some(1500));
        assert!(spawned.max_reconnect_tries.is_none());
        assert!(!spawned.prefer_ipv6);
        assert!(spawned.device.is_none());
        assert!(spawned.connect_timeout.is_none());
    }

    #[tokio::test]
    async fn omitted_options_keep_bind_address_and_connect() {
        let target = resolve_bind_target("0.0.0.0:4242", &TcpOptions::default())
            .await
            .unwrap();
        assert_eq!(target, BindTarget::Literal("0.0.0.0:4242".into()));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let stream = connect_once(&addr, &TcpOptions::default()).await.unwrap();
        assert!(stream.peer_addr().is_ok());
        accept.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn device_bind_uses_loopback_addresses() {
        let v4 = device_socket_addr("lo", 4242, false).unwrap();
        assert_eq!(v4, "127.0.0.1:4242".parse().unwrap());
        let v6 = device_socket_addr("lo", 4242, true).unwrap();
        assert_eq!(v6, "[::1]:4242".parse().unwrap());
    }
}
