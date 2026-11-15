//! Backbone interface — Python `RNS.Interfaces.BackboneInterface` parity
//! (Phase 5.8).
//!
//! High-throughput TCP backbone links: the server spawns one
//! [`BackboneClient`] peer per accepted connection (announces and access
//! codes are inherited), and clients reconnect with
//! tunnel synthesis once connected (`wants_tunnel`).
//!
//! Fast-flapping connection suppression
//! (Python `BackboneInterface.fast_flapping`): peers whose connections
//! repeatedly drop within `fast_flap_threshold` seconds are counted per
//! remote address; once the count exceeds `fast_flap_grace`, further
//! connections from that address are ignored until the block expires
//! after `fast_flap_expiry` seconds without a flap.

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::iface::hdlc::{Hdlc, HdlcDecoder};
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

/// Nominal bitrate guess (Python `BackboneInterface.BITRATE_GUESS`).
pub const BITRATE_GUESS: u64 = 100_000_000;

/// `Interface.bitrate` default (Python `Interface.__init__`).
#[cfg(test)]
const GENERIC_INTERFACE_BITRATE: u64 = 62_500;

/// Hardware MTU selected by Python `Interface.optimise_mtu`.
///
/// Below 62_500 Python clears `HW_MTU`. The decoder keeps the last finite
/// tier (1024) rather than the 1048576 class ceiling.
pub const fn hw_mtu_for_bitrate(bitrate: u64) -> usize {
    if bitrate >= 1_000_000_000 {
        524_288
    } else if bitrate >= 750_000_000 {
        262_144
    } else if bitrate >= 400_000_000 {
        131_072
    } else if bitrate >= 200_000_000 {
        65_536
    } else if bitrate >= 100_000_000 {
        32_768
    } else if bitrate >= 10_000_000 {
        16_384
    } else if bitrate >= 5_000_000 {
        8_192
    } else if bitrate >= 2_000_000 {
        4_096
    } else if bitrate >= 1_000_000 {
        2_048
    } else {
        1_024
    }
}

/// Effective backbone hardware MTU at [`BITRATE_GUESS`] (after `optimise_mtu`).
pub const HW_MTU: usize = hw_mtu_for_bitrate(BITRATE_GUESS);

/// Python `TransmitBuffer.COALESCE_TARGET`.
pub const COALESCE_TARGET: usize = 65_536;

/// Python `Interface.tx_hwm` / `BackboneInterface.DP_EC_HIGH_WM` (4 MiB).
pub const TX_HWM: usize = 4 * 1024 * 1024;
pub const DP_EC_HIGH_WM: usize = TX_HWM;
pub const DP_EC_MID_WM: usize = 128 * 1024;
pub const DP_EC_STALL_TICKS: u32 = 3;
pub const DP_EC_MAX_ETA: f64 = 10.0;
pub const DP_EC_RELEASE_ETA: f64 = 5.0;
pub const DP_EC_DEAD_TIME: Duration = Duration::from_secs(12);
pub const DP_EC_INTERVAL: Duration = Duration::from_secs(1);

/// Coalesced egress buffer (Python `TransmitBuffer`).
#[derive(Debug, Default)]
pub struct TransmitBuffer {
    cur: Vec<u8>,
    chunks: VecDeque<Vec<u8>>,
    head_offset: usize,
    tx_total: u64,
    tx_visible: u64,
    tx_sent: u64,
    /// HDLC lengths in send order. A frame is one packet once `tx_sent`
    /// covers it, including when several frames share one `try_write`.
    frame_lens: VecDeque<u64>,
    /// Prefix of `tx_sent` already reported to `count_tx`.
    frames_accounted: u64,
}

impl TransmitBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn buffered(&self) -> usize {
        (self.tx_total - self.tx_sent) as usize
    }

    pub fn sendable(&self) -> usize {
        (self.tx_visible - self.tx_sent) as usize
    }

    pub fn tx_sent(&self) -> u64 {
        self.tx_sent
    }

    /// Queue one HDLC frame. `false` when [`TX_HWM`] would be exceeded.
    pub fn append(&mut self, frame: &[u8]) -> bool {
        if self.buffered() + frame.len() > TX_HWM {
            return false;
        }

        if frame.len() >= COALESCE_TARGET {
            self.flush_tail();
            self.tx_visible += frame.len() as u64;
            self.chunks.push_back(frame.to_vec());
        } else {
            if !self.cur.is_empty() && self.cur.len() + frame.len() > COALESCE_TARGET {
                self.flush_tail();
            }
            self.cur.extend_from_slice(frame);
            // Python flushes immediately only while the chunk queue is idle.
            if self.chunks.is_empty() {
                self.flush_tail();
            }
        }
        self.tx_total += frame.len() as u64;
        self.frame_lens.push_back(frame.len() as u64);
        true
    }

    pub fn flush(&mut self) {
        self.flush_tail();
    }

    fn flush_tail(&mut self) {
        if !self.cur.is_empty() {
            self.tx_visible += self.cur.len() as u64;
            self.chunks.push_back(std::mem::take(&mut self.cur));
        }
    }

    fn pop_head(&mut self) {
        self.chunks.pop_front();
        self.head_offset = 0;
    }

    /// Write queued chunks. Each chunk is one `write` call. `Ok(0)` and
    /// [`DrainError::Blocked`] stop the drain; [`DrainError::Failed`]
    /// aborts the peer. Returns `false` only on a hard write failure.
    pub fn drain_to<F>(&mut self, mut write: F) -> bool
    where
        F: FnMut(&[u8]) -> Result<usize, DrainError>,
    {
        loop {
            if self.chunks.is_empty() {
                self.flush_tail();
                if self.chunks.is_empty() {
                    return true;
                }
            }

            let start = self.head_offset;
            let len = self.chunks[0].len();
            if start >= len {
                self.pop_head();
                continue;
            }

            match write(&self.chunks[0][start..]) {
                Ok(0) => return true,
                Ok(n) => {
                    let n = n.min(len - start);
                    self.head_offset += n;
                    self.tx_sent += n as u64;
                    if self.head_offset >= self.chunks[0].len() {
                        self.pop_head();
                    } else {
                        return true;
                    }
                }
                Err(DrainError::Blocked) => return true,
                Err(DrainError::Failed) => return false,
            }
        }
    }

    /// Lengths of frames whose bytes have fully left the socket.
    fn completed_frame_lengths(&mut self) -> Vec<usize> {
        let mut lengths = Vec::new();
        let mut covered = self.tx_sent.saturating_sub(self.frames_accounted);
        while let Some(&len) = self.frame_lens.front() {
            if covered < len {
                break;
            }
            self.frame_lens.pop_front();
            covered -= len;
            self.frames_accounted += len;
            lengths.push(len as usize);
        }
        lengths
    }
}

/// Socket write outcome for [`TransmitBuffer::drain_to`].
#[derive(Debug)]
pub enum DrainError {
    Blocked,
    Failed,
}

/// Dataplane egress control (Python `BackboneInterface._dp_ec_evaluate`).
#[derive(Debug)]
pub struct EgressControl {
    prev_sent: u64,
    zero_ticks: u32,
    last_drain: Instant,
    pub tx_stalled: bool,
}

impl EgressControl {
    pub fn new(now: Instant) -> Self {
        Self {
            prev_sent: 0,
            zero_ticks: 0,
            last_drain: now,
            tx_stalled: false,
        }
    }

    /// `true` when the peer must be torn down (no drain progress for
    /// [`DP_EC_DEAD_TIME`] while bytes are still sendable).
    pub fn evaluate(&mut self, buffer: &TransmitBuffer, now: Instant) -> bool {
        let drained = buffer.tx_sent().saturating_sub(self.prev_sent);
        self.prev_sent = buffer.tx_sent();
        let sendable = buffer.sendable();
        let buffered = buffer.buffered();

        if buffered == 0 || sendable == 0 {
            self.zero_ticks = 0;
            self.last_drain = now;
            self.tx_stalled = false;
            return false;
        }

        if now.saturating_duration_since(self.last_drain) >= DP_EC_DEAD_TIME {
            return true;
        }

        if drained > 0 {
            self.last_drain = now;
            self.zero_ticks = 0;
            let drain_rate = drained as f64 / DP_EC_INTERVAL.as_secs_f64();
            let clear_eta = if drain_rate > 0.0 {
                buffered as f64 / drain_rate
            } else {
                f64::INFINITY
            };
            if buffered > DP_EC_MID_WM && clear_eta > DP_EC_MAX_ETA {
                self.tx_stalled = true;
            } else if clear_eta < DP_EC_RELEASE_ETA || buffered <= DP_EC_MID_WM {
                self.tx_stalled = false;
            }
        } else if buffered > DP_EC_MID_WM {
            self.zero_ticks = self.zero_ticks.saturating_add(1);
            if self.zero_ticks >= DP_EC_STALL_TICKS {
                self.tx_stalled = true;
            }
        } else {
            self.zero_ticks = 0;
            self.tx_stalled = false;
        }
        false
    }
}

fn accept_outbound(stalled: bool, buffer: &mut TransmitBuffer, frame: &[u8]) -> bool {
    !stalled && buffer.append(frame)
}

fn encode_hdlc_frame(
    packet: &Packet,
    ifac: Option<&crate::iface::ifac::IfacKey>,
) -> Option<Vec<u8>> {
    let mut raw = [0u8; 4096];
    let mut output = OutputBuffer::new(&mut raw);
    if packet.serialize(&mut output).is_err() {
        return None;
    }
    let wire = crate::iface::ifac::encode(output.as_slice(), ifac);
    Some(Hdlc::encode_frame_vec(&wire))
}

/// `true` when the frame was dropped (stalled or over [`TX_HWM`]).
fn enqueue_frame(
    packet: &Packet,
    ifac: &crate::iface::IfacSlot,
    stalled: bool,
    buffer: &mut TransmitBuffer,
) -> bool {
    let ifac = ifac.read().expect("ifac lock").clone();
    let Some(frame) = encode_hdlc_frame(packet, ifac.as_deref()) else {
        return false;
    };
    if accept_outbound(stalled, buffer, &frame) {
        return false;
    }
    log::debug!(
        "backbone: egress control dropping outbound frame of {} bytes",
        frame.len()
    );
    true
}

fn drain_write(
    stream: &tokio::net::tcp::OwnedWriteHalf,
    buffer: &mut TransmitBuffer,
    stats: &crate::iface::InterfaceCounters,
) -> bool {
    let ok = buffer.drain_to(|chunk| match stream.try_write(chunk) {
        Ok(n) => Ok(n),
        Err(err) if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::Interrupted => {
            Err(DrainError::Blocked)
        }
        Err(_) => Err(DrainError::Failed),
    });
    for len in buffer.completed_frame_lengths() {
        stats.count_tx(len);
    }
    ok
}

/// `0` is the unset constructor rate and means [`BITRATE_GUESS`].
fn bitrate_or_guess(rate: u64) -> u64 {
    if rate == 0 {
        BITRATE_GUESS
    } else {
        rate
    }
}

/// Enable fast-flapping suppression by default
/// (Python `BLOCK_FAST_FLAPPING`).
pub const BLOCK_FAST_FLAPPING: bool = true;

/// A connection counts as a fast flap if it lasted less than this
/// (Python `FAST_FLAP_THRESHOLD`).
pub const FAST_FLAP_THRESHOLD: Duration = Duration::from_secs(20);

/// Allowed fast flaps before the remote is blocked
/// (Python `FAST_FLAP_GRACE`).
pub const FAST_FLAP_GRACE: u32 = 5;

/// Blocked remotes are released after this flap-free period
/// (Python `FAST_FLAP_EXPIRY`).
pub const FAST_FLAP_EXPIRY: Duration = Duration::from_secs(12 * 60 * 60);

/// Reconnect wait for initiator clients
/// (Python `BackboneClientInterface.RECONNECT_WAIT`).
pub const RECONNECT_WAIT: Duration = Duration::from_secs(15);

/// Fast-flapping suppression state
/// (Python `BackboneInterface.fast_flapping`: `[started, last_flap,
/// flaps]` per remote address).
#[derive(Debug, Default)]
pub struct FastFlapTable {
    enabled: bool,
    threshold: Duration,
    grace: u32,
    expiry: Duration,
    entries: HashMap<String, (tokio::time::Instant, tokio::time::Instant, u32)>,
}

impl FastFlapTable {
    pub fn new(enabled: bool, threshold: Duration, grace: u32, expiry: Duration) -> Self {
        Self {
            enabled,
            threshold,
            grace,
            expiry,
            entries: HashMap::new(),
        }
    }

    /// Whether an incoming connection from `remote` is currently
    /// blocked (Python `incoming_connection` check).
    pub fn is_blocked(&mut self, remote: &str, now: tokio::time::Instant) -> bool {
        if !self.enabled {
            return false;
        }
        match self.entries.get(remote) {
            Some((_, _, flaps)) => {
                *flaps > self.grace && now.duration_since(self.entries[remote].1) < self.expiry
            }
            None => false,
        }
    }

    /// Account a disconnect of `remote` after `connected_for`
    /// (Python `BackboneClientInterface.teardown` fast-flap accounting).
    /// Returns the updated flap count.
    pub fn account_disconnect(
        &mut self,
        remote: &str,
        connected_for: Duration,
        now: tokio::time::Instant,
    ) -> u32 {
        if !self.enabled || connected_for >= self.threshold {
            return self.entries.get(remote).map(|e| e.2).unwrap_or(0);
        }

        let entry = self
            .entries
            .entry(remote.to_string())
            .or_insert((now, now, 0));
        entry.1 = now;
        entry.2 += 1;
        entry.2
    }

    /// Release blocks whose last flap is older than the expiry
    /// (Python `blocked_ip_list` maintenance in the server job).
    pub fn clean(&mut self, now: tokio::time::Instant) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, last_flap, _)| now.duration_since(*last_flap) < self.expiry);
        before - self.entries.len()
    }

    /// Number of currently blocked remotes
    /// (Python `blocked_ip_count`).
    pub fn blocked_count(&self) -> usize {
        self.entries.values().filter(|e| e.2 > self.grace).count()
    }
}

/// One backbone peer: a TCP stream with HDLC framing, either an
/// initiator client (reconnecting, requests tunnel synthesis) or
/// spawned by [`BackboneServer`] for an accepted connection
/// (Python `BackboneClientInterface`).
pub struct BackboneClient {
    /// `host:port` to connect to (initiator mode).
    pub addr: Option<String>,
    /// Already-accepted stream (spawned mode).
    pub connected_stream: Option<TcpStream>,
    /// Remote IP for fast-flap accounting (spawned mode). The port is
    /// not part of this key.
    pub remote: Option<String>,
    /// Full peer socket address (`ip:port`) for the stable interface id.
    /// Empty for an initiator that has not recorded one.
    peer_endpoint: String,
    /// Interface manager of the owning transport (tunnel synthesis
    /// signalling; the server also uses it to spawn peers).
    pub iface_manager: Option<Arc<tokio::sync::Mutex<InterfaceManager>>>,
    /// Shared fast-flap table of the parent server, if spawned.
    pub fast_flap: Option<Arc<tokio::sync::Mutex<FastFlapTable>>>,
    /// Constructor bitrate (Python `BITRATE_GUESS`, or [`Self::with_bitrate`]).
    bitrate: u64,
}

impl BackboneClient {
    /// Create an initiator client (Python `BackboneClientInterface`
    /// with `target_host`/`target_port`).
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: Some(addr.into()),
            connected_stream: None,
            remote: None,
            peer_endpoint: String::new(),
            iface_manager: None,
            fast_flap: None,
            bitrate: BITRATE_GUESS,
        }
    }

    /// Create a spawned peer for an accepted stream
    /// (Python `incoming_connection`).
    ///
    /// `remote` is the peer socket address. Fast-flap accounting keeps
    /// only the IP. `endpoint()` returns the full `ip:port` so concurrent
    /// peers do not share a stable id.
    pub fn new_from_stream(stream: TcpStream, remote: String) -> Self {
        let flap_ip = remote
            .parse::<std::net::SocketAddr>()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|_| remote.clone());
        Self {
            addr: None,
            connected_stream: Some(stream),
            remote: Some(flap_ip),
            peer_endpoint: remote,
            iface_manager: None,
            fast_flap: None,
            bitrate: BITRATE_GUESS,
        }
    }

    /// Override the bitrate `optimise_mtu` uses for this peer.
    pub fn with_bitrate(mut self, bitrate: u64) -> Self {
        self.bitrate = bitrate;
        self
    }

    /// Attach the interface manager of the owning transport.
    pub fn with_manager(mut self, manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        self.iface_manager = Some(manager);
        self
    }

    /// Attach the parent server's fast-flap table (spawned peers).
    pub fn with_fast_flap(mut self, table: Arc<tokio::sync::Mutex<FastFlapTable>>) -> Self {
        self.fast_flap = Some(table);
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

        let constructor_rate = inner.lock().unwrap().bitrate;

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let connected = inner.lock().unwrap().connected_stream.take();
            let initiator_addr = inner.lock().unwrap().addr.clone();

            let spawned_at = tokio::time::Instant::now();
            let mut spawned_remote = inner.lock().unwrap().remote.clone();

            let stream = match connected {
                Some(stream) => stream,
                None => {
                    let Some(addr) = initiator_addr else { break };

                    match TcpStream::connect(&addr).await {
                        Ok(stream) => {
                            log::info!("backbone: connected to <{addr}>");
                            spawned_remote = Some(addr);
                            stream
                        }
                        Err(_) => {
                            log::debug!("backbone: could not connect to <{addr}>, retrying");
                            tokio::time::sleep(RECONNECT_WAIT).await;
                            continue;
                        }
                    }
                }
            };

            stream.set_nodelay(true).ok();
            stats.set_online(true);

            // Tunnel synthesis once the link is up
            // (Python `initial_connect`: `self.wants_tunnel = True`).
            // One sample of the control bitrate, under this same lock.
            let manager_of = inner.lock().unwrap().iface_manager.clone();
            let hw_mtu = if let Some(manager) = manager_of {
                let manager = manager.lock().await;
                manager.set_iface_wants_tunnel(&iface_address, true);
                let rate = manager
                    .with_control(&iface_address, |control| control.bitrate)
                    .unwrap_or_else(|| bitrate_or_guess(constructor_rate));
                hw_mtu_for_bitrate(rate)
            } else {
                hw_mtu_for_bitrate(bitrate_or_guess(constructor_rate))
            };

            let (read_half, write_half) = stream.into_split();
            let link_cancel = tokio_util::sync::CancellationToken::new();

            let rx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let channel_ifac_rx = channel_ifac.clone();
                let mut stream = read_half;

                tokio::spawn(async move {
                    let mut decoder = HdlcDecoder::new(hw_mtu);
                    let mut buffer = vec![0u8; hw_mtu];
                    let mut frames: Vec<Vec<u8>> = Vec::new();

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = stop.cancelled() => true,
                            _ = link_cancel.cancelled() => true,
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
                                                    log::debug!("backbone: dropping packet with invalid access code");
                                                    continue;
                                                }
                                            }
                                        };
                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&plain)) {
                                            stats.count_rx(plain.len());
                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet: Box::new(packet) }).await;
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
                    link_cancel.cancel();
                })
            };

            let tx_task = {
                let cancel = context.cancel.clone();
                let stop = iface_stop.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let tx_channel = tx_channel.clone();
                let channel_ifac = channel_ifac.clone();
                let stream = write_half;

                tokio::spawn(async move {
                    let mut coalesce = TransmitBuffer::new();
                    let armed = Instant::now();
                    let mut egress = EgressControl::new(armed);
                    // Python sleeps `DP_EC_INTERVAL` before the first evaluation.
                    let mut ec_tick =
                        tokio::time::interval_at(armed + DP_EC_INTERVAL, DP_EC_INTERVAL);
                    ec_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    let mut tx_channel = tx_channel.lock().await;

                    loop {
                        let sendable = coalesce.sendable() > 0;
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            _ = link_cancel.cancelled() => break,
                            _ = ec_tick.tick() => {
                                if egress.evaluate(&coalesce, Instant::now()) {
                                    log::warn!("backbone: egress stalled, tearing down peer");
                                    break;
                                }
                            }
                            ready = stream.writable(), if sendable => {
                                if ready.is_err() || !drain_write(&stream, &mut coalesce, &stats) {
                                    break;
                                }
                            }
                            message = tx_channel.recv() => {
                                let Some(message) = message else { break };
                                let _dropped = enqueue_frame(
                                    &message.packet,
                                    &channel_ifac,
                                    egress.tx_stalled,
                                    &mut coalesce,
                                );
                            }
                        }
                    }
                    link_cancel.cancel();
                })
            };

            let _ = tokio::join!(tx_task, rx_task);
            stats.set_online(false);

            // Fast-flap accounting for spawned peers
            // (Python `teardown` fast-flapping update).
            let fast_flap = inner.lock().unwrap().fast_flap.clone();
            let remote = inner.lock().unwrap().remote.clone().or(spawned_remote);
            if let (Some(table), Some(remote)) = (fast_flap, remote) {
                let mut table = table.lock().await;
                let flaps = table.account_disconnect(
                    &remote,
                    spawned_at.elapsed(),
                    tokio::time::Instant::now(),
                );
                if flaps > 0 {
                    log::debug!("backbone: {remote} fast-flap count {flaps}");
                }
            }

            if inner.lock().unwrap().connected_stream.is_none()
                && inner.lock().unwrap().addr.is_none()
            {
                break;
            }

            tokio::time::sleep(RECONNECT_WAIT).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for BackboneClient {
    fn mtu() -> usize {
        HW_MTU
    }

    fn constructor_bitrate(&self) -> Option<u64> {
        Some(bitrate_or_guess(self.bitrate))
    }

    fn endpoint(&self) -> &str {
        &self.peer_endpoint
    }
}

/// The backbone server: accepts connections and spawns peers with
/// inherited access codes and the shared fast-flap table
/// (Python `BackboneInterface`).
pub struct BackboneServer {
    /// Listen address.
    pub addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    /// Fast-flapping suppression table shared with spawned peers.
    pub fast_flap: Arc<tokio::sync::Mutex<FastFlapTable>>,
}

impl BackboneServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        fast_flap: Arc<tokio::sync::Mutex<FastFlapTable>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            fast_flap,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let iface_stop = context.channel.stop.clone();
        let exited = context.channel.exited.clone();
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let fast_flap = { context.inner.lock().unwrap().fast_flap.clone() };
        let parent = context.channel.address;

        loop {
            if context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let listener = match TcpListener::bind(&addr).await {
                Ok(listener) => listener,
                Err(_) => {
                    log::warn!("backbone_server: couldn't bind to <{addr}>");
                    tokio::select! {
                        _ = iface_stop.cancelled() => break,
                        _ = context.cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(5)) => continue,
                    }
                }
            };

            log::info!("backbone_server: listen on <{addr}>");
            stats.set_online(true);

            // Periodic fast-flap block expiry
            // (Python server job `blocked_ip_list` maintenance).
            let flap_task = {
                let fast_flap = fast_flap.clone();
                let cancel = context.cancel.clone();
                let iface_stop = iface_stop.clone();
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(Duration::from_secs(60));
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = iface_stop.cancelled() => break,
                            _ = tick.tick() => {
                                let removed = fast_flap
                                    .lock()
                                    .await
                                    .clean(tokio::time::Instant::now());
                                if removed > 0 {
                                    log::debug!("backbone_server: {removed} fast-flap blocks expired");
                                }
                            }
                        }
                    }
                })
            };

            loop {
                if context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                    break;
                }

                let accepted = tokio::select! {
                    _ = context.cancel.cancelled() => break,
                    _ = iface_stop.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };

                let Ok((socket, peer)) = accepted else {
                    log::warn!("backbone_server: accept error on <{addr}>");
                    break;
                };

                let remote_ip = peer.ip().to_string();

                // Fast-flapping suppression gate
                // (Python `incoming_connection`).
                let blocked = {
                    let mut table = fast_flap.lock().await;
                    table.is_blocked(&remote_ip, tokio::time::Instant::now())
                };
                if blocked {
                    log::warn!(
                        "backbone_server: ignoring connection from fast-flapping {remote_ip}"
                    );
                    continue;
                }

                let peer_endpoint = peer.to_string();
                log::debug!("backbone_server: accepting connection from {peer_endpoint}");

                let inherited = context.channel.ifac.read().expect("ifac lock").clone();

                // Register under ip:port, with the parent's control state
                // and access code, before the worker can learn a path.
                // Fast-flap above stays keyed by IP only.
                let mut manager = iface_manager.lock().await;
                // Python `spawned_interface.bitrate = self.bitrate`.
                // `with_bitrate` makes `launch` publish that rate before the
                // worker starts; `copy_spawned_control` carries the rest.
                let parent_bitrate = manager
                    .with_control(&parent, |c| c.bitrate)
                    .unwrap_or(BITRATE_GUESS);
                let peer_context = manager.open_named(
                    &peer_endpoint,
                    BackboneClient::new_from_stream(socket, peer_endpoint.clone())
                        .with_fast_flap(fast_flap.clone())
                        .with_bitrate(parent_bitrate),
                );
                if let Some(key) = inherited {
                    *peer_context.channel.ifac.write().expect("ifac lock") = Some(key);
                }
                let address = peer_context.channel.address;
                manager.copy_spawned_control(&parent, &address);
                manager.note_spawned(&parent, &address);
                manager.launch(peer_context, BackboneClient::spawn);
            }

            drop(listener);
            flap_task.abort();
            let _ = flap_task.await;
            stats.set_online(false);
            if context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                break;
            }
        }
        let _ = exited.send(true);
    }
}

impl Interface for BackboneServer {
    fn mtu() -> usize {
        HW_MTU
    }

    fn constructor_bitrate(&self) -> Option<u64> {
        Some(BITRATE_GUESS)
    }

    fn endpoint(&self) -> &str {
        &self.addr
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::Instant;

    use super::*;
    use crate::iface::{InterfaceCounters, InterfaceManager, TxMessage, TxMessageType};
    use crate::packet::Packet;

    #[tokio::test]
    async fn two_small_frames_coalesce_while_the_consumer_is_behind() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let mut buffer = TransmitBuffer::new();

        assert!(buffer.append(&[0xAB; 32]));
        let queued = buffer.sendable();
        assert!(queued > 0);

        tx.send(b"aaaa".to_vec()).await.unwrap();
        let second = tokio::spawn({
            let tx = tx.clone();
            async move {
                tx.send(b"bbbb".to_vec()).await.unwrap();
            }
        });

        let first = rx.recv().await.unwrap();
        assert!(buffer.append(&first));
        assert_eq!(buffer.sendable(), queued);

        let second_frame = rx.recv().await.unwrap();
        second.await.unwrap();
        assert!(buffer.append(&second_frame));
        assert_eq!(buffer.sendable(), queued);

        let mut writes = Vec::new();
        assert!(buffer.drain_to(|chunk| {
            writes.push(chunk.to_vec());
            Ok(chunk.len())
        }));
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[1], b"aaaabbbb");
    }

    #[test]
    fn lone_idle_frame_is_published_immediately() {
        let mut buffer = TransmitBuffer::new();
        assert!(buffer.append(b"only"));
        assert_eq!(buffer.sendable(), 4);
    }

    #[test]
    fn coalesce_window_splits_above_target() {
        let mut buffer = TransmitBuffer::new();
        assert!(buffer.append(&[9u8; 16]));
        assert!(buffer.append(&[1u8; COALESCE_TARGET - 4]));
        assert!(buffer.append(&[2u8; 8]));

        let mut writes = Vec::new();
        assert!(buffer.drain_to(|chunk| {
            writes.push(chunk.len());
            assert!(chunk.len() <= COALESCE_TARGET);
            Ok(chunk.len())
        }));
        assert_eq!(writes, vec![16, COALESCE_TARGET - 4, 8]);
    }

    #[test]
    fn tx_high_water_mark_rejects_another_frame() {
        let mut buffer = TransmitBuffer::new();
        assert!(buffer.append(&[0u8; TX_HWM]));
        assert!(!accept_outbound(false, &mut buffer, &[1]));
        assert_eq!(TX_HWM, DP_EC_HIGH_WM);
    }

    #[test]
    fn stalled_peer_is_torn_down() {
        let t0 = Instant::now();
        let mut buffer = TransmitBuffer::new();
        let mut egress = EgressControl::new(t0);
        assert!(accept_outbound(false, &mut buffer, b"stuck-frame"));
        assert!(buffer.sendable() > 0);

        assert!(
            !egress.evaluate(&buffer, t0),
            "a full sendable buffer is not torn down immediately"
        );
        assert!(
            egress.evaluate(&buffer, t0 + DP_EC_DEAD_TIME),
            "no egress progress for the dead time tears the peer down"
        );
    }

    #[test]
    fn egress_mid_watermark_gates_outbound() {
        let t0 = Instant::now();
        let mut buffer = TransmitBuffer::new();
        let mut egress = EgressControl::new(t0);
        assert!(buffer.append(&[0u8; DP_EC_MID_WM + 1]));

        for tick in 0..DP_EC_STALL_TICKS {
            assert!(!egress.evaluate(&buffer, t0 + DP_EC_INTERVAL * tick));
        }
        assert!(egress.tx_stalled);
        assert!(!accept_outbound(egress.tx_stalled, &mut buffer, b"dropped"));
    }

    #[test]
    fn decoder_mtu_follows_bitrate_tier() {
        assert_eq!(BITRATE_GUESS, 100_000_000);
        assert_eq!(HW_MTU, 32_768);
        assert_eq!(hw_mtu_for_bitrate(BITRATE_GUESS), HW_MTU);
        assert_eq!(BackboneClient::mtu(), HW_MTU);
        assert_eq!(BackboneServer::mtu(), HW_MTU);
        assert_eq!(hw_mtu_for_bitrate(1_000_000_000), 524_288);
        assert_eq!(hw_mtu_for_bitrate(750_000_000), 262_144);
        assert_eq!(hw_mtu_for_bitrate(400_000_000), 131_072);
        assert_eq!(hw_mtu_for_bitrate(200_000_000), 65_536);
        assert_eq!(hw_mtu_for_bitrate(10_000_000), 16_384);
        assert_eq!(hw_mtu_for_bitrate(5_000_000), 8_192);
        assert_eq!(hw_mtu_for_bitrate(2_000_000), 4_096);
        assert_eq!(hw_mtu_for_bitrate(1_000_000), 2_048);
        assert_eq!(hw_mtu_for_bitrate(62_500), 1_024);
        assert_eq!(hw_mtu_for_bitrate(1_000), 1_024);
        assert_ne!(hw_mtu_for_bitrate(62_500), HW_MTU);
    }

    fn control_bitrate(
        manager: &InterfaceManager,
        address: &crate::hash::AddressHash,
    ) -> Option<u64> {
        manager.with_control(address, |control| control.bitrate)
    }

    #[tokio::test]
    async fn constructor_bitrate_is_published_before_spawn_returns() {
        let manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(16)));

        assert_eq!(
            BackboneClient::new("127.0.0.1:1")
                .with_bitrate(0)
                .constructor_bitrate(),
            Some(BITRATE_GUESS)
        );
        assert_eq!(
            BackboneServer::new(
                "127.0.0.1:1",
                manager.clone(),
                Arc::new(tokio::sync::Mutex::new(FastFlapTable::new(
                    false,
                    FAST_FLAP_THRESHOLD,
                    FAST_FLAP_GRACE,
                    FAST_FLAP_EXPIRY,
                ))),
            )
            .constructor_bitrate(),
            Some(BITRATE_GUESS)
        );

        // Untouched: `spawn` stores the constructor rate before it returns.
        let untouched = {
            let mut guard = manager.lock().await;
            guard.spawn(
                BackboneClient::new("127.0.0.1:1").with_manager(manager.clone()),
                BackboneClient::spawn,
            )
        };
        let rate = {
            let guard = manager.lock().await;
            control_bitrate(&guard, &untouched).unwrap()
        };
        assert_eq!(rate, 100_000_000);
        assert_eq!(hw_mtu_for_bitrate(rate), 32_768);
        manager.lock().await.stop_iface(&untouched);

        // Zero is the same guess, published by `spawn_named`.
        let zero = {
            let mut guard = manager.lock().await;
            guard.spawn_named(
                "zero",
                BackboneClient::new("127.0.0.1:1")
                    .with_manager(manager.clone())
                    .with_bitrate(0),
                BackboneClient::spawn,
            )
        };
        assert_eq!(
            control_bitrate(&*manager.lock().await, &zero),
            Some(100_000_000)
        );
        assert_eq!(hw_mtu_for_bitrate(100_000_000), 32_768);
        manager.lock().await.stop_iface(&zero);

        let custom = {
            let mut guard = manager.lock().await;
            guard.spawn(
                BackboneClient::new("127.0.0.1:1")
                    .with_manager(manager.clone())
                    .with_bitrate(7_500_000),
                BackboneClient::spawn,
            )
        };
        assert_eq!(
            control_bitrate(&*manager.lock().await, &custom),
            Some(7_500_000)
        );
        manager.lock().await.stop_iface(&custom);

        // Spawn publishes the guess, then an explicit 62500. The polled
        // worker must not write the guess back.
        let replaced = {
            let mut guard = manager.lock().await;
            guard.spawn(
                BackboneClient::new("127.0.0.1:1").with_manager(manager.clone()),
                BackboneClient::spawn,
            )
        };
        {
            let guard = manager.lock().await;
            assert_eq!(control_bitrate(&guard, &replaced), Some(100_000_000));
            guard.set_iface_bitrate(&replaced, GENERIC_INTERFACE_BITRATE);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let rate = {
            let guard = manager.lock().await;
            control_bitrate(&guard, &replaced).unwrap()
        };
        assert_eq!(rate, 62_500);
        assert_eq!(hw_mtu_for_bitrate(rate), 1_024);
        manager.lock().await.stop_iface(&replaced);
    }

    #[tokio::test]
    async fn accepted_peer_inherits_parent_bitrate() {
        for parent_rate in [BITRATE_GUESS, GENERIC_INTERFACE_BITRATE] {
            let manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(16)));
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = probe.local_addr().unwrap().port();
            drop(probe);

            let server = {
                let mut guard = manager.lock().await;
                let address = guard.spawn_named(
                    "backbone",
                    BackboneServer::new(
                        format!("127.0.0.1:{port}"),
                        manager.clone(),
                        Arc::new(tokio::sync::Mutex::new(FastFlapTable::new(
                            false,
                            FAST_FLAP_THRESHOLD,
                            FAST_FLAP_GRACE,
                            FAST_FLAP_EXPIRY,
                        ))),
                    ),
                    BackboneServer::spawn,
                );
                let published = control_bitrate(&guard, &address).unwrap();
                assert_eq!(published, 100_000_000);
                assert_eq!(hw_mtu_for_bitrate(published), 32_768);
                if parent_rate != BITRATE_GUESS {
                    guard.set_iface_bitrate(&address, parent_rate);
                    let configured = control_bitrate(&guard, &address).unwrap();
                    assert_eq!(configured, 62_500);
                    assert_eq!(hw_mtu_for_bitrate(configured), 1_024);
                }
                address
            };

            let mut connected = None;
            for _ in 0..50 {
                if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
                    connected = Some(stream);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let _connected = connected.expect("backbone server accepts");

            let child_rate = async {
                for _ in 0..50 {
                    let guard = manager.lock().await;
                    if let Some(child) = guard
                        .stats()
                        .into_iter()
                        .find(|stat| stat.kind == "BackboneClient")
                    {
                        return control_bitrate(&guard, &child.address);
                    }
                    drop(guard);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                None
            }
            .await
            .expect("accepted peer is registered");

            assert_eq!(child_rate, parent_rate);
            assert_eq!(
                hw_mtu_for_bitrate(child_rate),
                if parent_rate == BITRATE_GUESS {
                    32_768
                } else {
                    1_024
                }
            );
            let server_rate = {
                let guard = manager.lock().await;
                control_bitrate(&guard, &server).unwrap()
            };
            assert_eq!(server_rate, parent_rate);
            manager.lock().await.stop_iface(&server);
        }
    }

    #[tokio::test]
    async fn tx_bytes_count_bytes_written_not_bytes_queued() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (_server, _) = listener.accept().await.unwrap();
        let client = connector.await.unwrap();
        let (_read, write) = client.into_split();

        let stats = InterfaceCounters::default();
        let mut buffer = TransmitBuffer::new();
        assert!(buffer.append(b"abcdef"));
        assert_eq!(stats.tx_bytes(), 0);
        assert_eq!(stats.sent(), 0);
        assert!(drain_write(&write, &mut buffer, &stats));
        assert_eq!(stats.tx_bytes(), 6);
        assert_eq!(stats.sent(), 1);

        let mut partial = TransmitBuffer::new();
        assert!(partial.append(b"abcdef"));
        assert!(partial.drain_to(|_| Ok(2)));
        assert!(partial.completed_frame_lengths().is_empty());
        assert!(partial.drain_to(|chunk| Ok(chunk.len())));
        assert_eq!(partial.completed_frame_lengths(), vec![6]);

        let mut coalesced = TransmitBuffer::new();
        assert!(coalesced.append(b"XXXX"));
        assert!(coalesced.append(b"aaaa"));
        assert!(coalesced.append(b"bbbb"));
        let stats = InterfaceCounters::default();
        assert!(drain_write(&write, &mut coalesced, &stats));
        assert_eq!(stats.sent(), 3);
        assert_eq!(stats.tx_bytes(), 12);
    }

    #[tokio::test]
    async fn stuck_try_write_drops_the_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connector = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (mut server, _) = listener.accept().await.unwrap();
        let client = connector.await.unwrap();

        loop {
            match client.try_write(&[0x5A; 8192]) {
                Ok(0) => break,
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => panic!("fill send buffer: {err}"),
            }
        }

        let manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(16)));
        let address = {
            let mut guard = manager.lock().await;
            guard.spawn(
                BackboneClient::new_from_stream(client, "stuck".into())
                    .with_manager(manager.clone()),
                BackboneClient::spawn,
            )
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        manager
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Direct(address),
                packet: Box::new(Packet::default()),
            })
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        tokio::time::pause();
        for _ in 0..14 {
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        tokio::time::resume();

        let mut buf = [0u8; 8192];
        let mut saw_eof = false;
        for _ in 0..10_000 {
            match tokio::time::timeout(Duration::from_secs(2), server.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    saw_eof = true;
                    break;
                }
                Ok(Ok(_)) => {}
                Ok(Err(err)) => panic!("peer read: {err}"),
                Err(_) => break,
            }
        }
        assert!(saw_eof, "stuck try_write must drop the stream");
    }

    #[tokio::test]
    async fn accepted_peers_differ_by_port_and_flap_by_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let _client_a = TcpStream::connect(local).await.unwrap();
        let (sock_a, peer_a) = listener.accept().await.unwrap();
        let _client_b = TcpStream::connect(local).await.unwrap();
        let (sock_b, peer_b) = listener.accept().await.unwrap();
        assert_eq!(peer_a.ip(), peer_b.ip());
        assert_ne!(peer_a.port(), peer_b.port());

        let endpoint_a = peer_a.to_string();
        let client_a = BackboneClient::new_from_stream(sock_a, endpoint_a.clone());
        assert_eq!(client_a.endpoint(), endpoint_a);
        assert_eq!(
            client_a.remote.as_deref(),
            Some(peer_a.ip().to_string()).as_deref()
        );

        let endpoint_b = peer_b.to_string();
        let client_b = BackboneClient::new_from_stream(sock_b, endpoint_b.clone());
        assert_eq!(
            client_b.remote.as_deref(),
            Some(peer_b.ip().to_string()).as_deref()
        );

        let mut manager = InterfaceManager::new(4);
        let id_a = manager.spawn_named(&endpoint_a, client_a, BackboneClient::spawn);
        let id_b = manager.spawn_named(&endpoint_b, client_b, BackboneClient::spawn);
        let (map, ambiguous) = manager.classify_stable_ids();
        assert!(
            ambiguous.is_empty(),
            "concurrent peers from one IP must not share a stable id"
        );
        assert!(map.values().any(|address| *address == id_a));
        assert!(map.values().any(|address| *address == id_b));
    }
}
