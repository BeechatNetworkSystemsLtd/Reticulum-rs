//! Weave interface, a port of `RNS/Interfaces/WeaveInterface.py`.
//!
//! WDCL frames are HDLC (`FLAG + escape + FLAG`). The receive loop keeps
//! the closing flag as the next frame start, so one shared boundary flag
//! separates two frames. [`crate::iface::hdlc::HdlcDecoder`] does not.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::hash::{AddressHash, Hash};
use crate::identity::{Identity, PrivateIdentity, Signature, PUBLIC_KEY_LENGTH};
use crate::iface::hdlc::Hdlc;
use crate::iface::ifac::decode_inbound;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::{
    Interface, InterfaceContext, InterfaceCounters, InterfaceManager, InterfaceRxSender,
    InterfaceTxReceiver, RxMessage, TxMessage,
};

/// `WeaveInterface.HW_MTU`
pub const HW_MTU: usize = 1024;

/// `WeaveInterface.BITRATE_GUESS` when bitrate is omitted or below 5.
pub const BITRATE_GUESS: u64 = 250_000;

/// `WeaveInterface.PEERING_TIMEOUT`
pub const PEERING_TIMEOUT: Duration = Duration::from_secs(20);

const PEER_JOB_INTERVAL: Duration = Duration::from_secs(22);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(all(feature = "iface-serial", not(target_os = "android")))]
const RECONNECT_INTERVAL: Duration = Duration::from_secs(5);
const MULTI_IF_DEQUE_LEN: usize = 48;
const MULTI_IF_DEQUE_TTL: Duration = Duration::from_millis(750);
#[cfg(all(feature = "iface-serial", not(target_os = "android")))]
const SERIAL_BAUD: u32 = 3_000_000;

const FLAG: u8 = 0x7e;
const ESC: u8 = 0x7d;
const ESC_MASK: u8 = 0x20;

const SWITCH_ID_LEN: usize = 4;
const ENDPOINT_ID_LEN: usize = 8;
const SIGNATURE_LEN: usize = 64;
/// Frames of this length or shorter are not WDCL (`WDCL.HEADER_MINSIZE`).
const HEADER_MINSIZE: usize = SWITCH_ID_LEN + 1;

const WDCL_T_DISCOVER: u8 = 0x00;
const WDCL_T_CONNECT: u8 = 0x01;
const WDCL_T_CMD: u8 = 0x02;
const WDCL_T_LOG: u8 = 0x03;
const WDCL_T_ENDPOINT_PKT: u8 = 0x05;
const CMD_ENDPOINT_PKT: u16 = 0x0001;
const ET_PROTO_WDCL_CONNECTION: u16 = 0x3002;
const ET_PROTO_WEAVE_EP_ALIVE: u16 = 0x3102;
const BROADCAST: [u8; SWITCH_ID_LEN] = [0xff, 0xff, 0xff, 0xff];

const DISCOVERY_LEN: usize = SWITCH_ID_LEN + 1 + PUBLIC_KEY_LENGTH + SIGNATURE_LEN;

struct PeerEgress {
    endpoint: [u8; ENDPOINT_ID_LEN],
    wire: Vec<u8>,
}

struct PeerSlot {
    address: AddressHash,
    stats: Arc<InterfaceCounters>,
    last_heard: tokio::time::Instant,
}

/// Byte accumulator that treats the closing `FLAG` as the next frame start.
#[derive(Debug, Default)]
struct WdclReassembler {
    buffer: Vec<u8>,
}

impl WdclReassembler {
    fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buffer.extend_from_slice(data);
        let mut frames = Vec::new();
        while let Some(start) = self.buffer.iter().position(|byte| *byte == FLAG) {
            let Some(rel_end) = self.buffer[start + 1..]
                .iter()
                .position(|byte| *byte == FLAG)
            else {
                break;
            };
            let end = start + 1 + rel_end;
            let frame = unescape(&self.buffer[start + 1..end]);
            if frame.len() > HEADER_MINSIZE {
                frames.push(frame);
            }
            self.buffer.drain(..end);
        }
        frames
    }
}

fn unescape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        if index + 1 < data.len() && data[index] == ESC {
            let next = data[index + 1];
            if next == FLAG ^ ESC_MASK {
                out.push(FLAG);
                index += 2;
                continue;
            }
            if next == ESC ^ ESC_MASK {
                out.push(ESC);
                index += 2;
                continue;
            }
        }
        out.push(data[index]);
        index += 1;
    }
    out
}

fn frame_wdcl(payload: &[u8]) -> Vec<u8> {
    Hdlc::encode_frame_vec(payload)
}

fn discover_payload(local_switch_id: &[u8; SWITCH_ID_LEN]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SWITCH_ID_LEN + 1 + SWITCH_ID_LEN);
    frame.extend_from_slice(&BROADCAST);
    frame.push(WDCL_T_DISCOVER);
    frame.extend_from_slice(local_switch_id);
    frame
}

fn handshake_payload(
    remote_switch_id: &[u8; SWITCH_ID_LEN],
    local_pub: &[u8; PUBLIC_KEY_LENGTH],
    signature: &[u8; SIGNATURE_LEN],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(DISCOVERY_LEN);
    frame.extend_from_slice(remote_switch_id);
    frame.push(WDCL_T_CONNECT);
    frame.extend_from_slice(local_pub);
    frame.extend_from_slice(signature);
    frame
}

fn endpoint_command(
    remote_switch_id: &[u8; SWITCH_ID_LEN],
    endpoint: &[u8; ENDPOINT_ID_LEN],
    wire: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SWITCH_ID_LEN + 1 + 2 + ENDPOINT_ID_LEN + wire.len());
    frame.extend_from_slice(remote_switch_id);
    frame.push(WDCL_T_CMD);
    frame.extend_from_slice(&CMD_ENDPOINT_PKT.to_be_bytes());
    frame.extend_from_slice(endpoint);
    frame.extend_from_slice(wire);
    frame
}

fn accepted_discovery(frame: &[u8]) -> Option<[u8; SWITCH_ID_LEN]> {
    if frame.len() != DISCOVERY_LEN || frame[SWITCH_ID_LEN] != WDCL_T_DISCOVER {
        return None;
    }
    let signed_id = &frame[..SWITCH_ID_LEN];
    let remote_pub = &frame[SWITCH_ID_LEN + 1..SWITCH_ID_LEN + 1 + PUBLIC_KEY_LENGTH];
    let mut remote_switch = [0u8; SWITCH_ID_LEN];
    remote_switch.copy_from_slice(&remote_pub[remote_pub.len() - SWITCH_ID_LEN..]);
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(&frame[DISCOVERY_LEN - SIGNATURE_LEN..]);
    let identity = Identity::new_from_slices(remote_pub, remote_pub);
    identity
        .verify(signed_id, &Signature::from_bytes(&signature))
        .ok()?;
    Some(remote_switch)
}

/// Log event id and trailing data. `fd` starts two bytes after the switch id.
fn log_event(frame: &[u8]) -> Option<(u16, &[u8])> {
    if frame.len() < 14 || frame.get(SWITCH_ID_LEN) != Some(&WDCL_T_LOG) {
        return None;
    }
    let fd = frame.get(SWITCH_ID_LEN + 2..)?;
    if fd.len() < 8 {
        return None;
    }
    let event = u16::from_be_bytes([fd[6], fd[7]]);
    Some((event, &fd[8..]))
}

fn endpoint_packet<'a>(
    frame: &'a [u8],
    local_switch_id: &[u8; SWITCH_ID_LEN],
) -> Option<(&'a [u8], [u8; ENDPOINT_ID_LEN])> {
    if frame.len() < SWITCH_ID_LEN + 1 + ENDPOINT_ID_LEN
        || frame.get(SWITCH_ID_LEN) != Some(&WDCL_T_ENDPOINT_PKT)
        || frame.get(..SWITCH_ID_LEN) != Some(local_switch_id.as_slice())
    {
        return None;
    }
    let src_at = frame.len() - ENDPOINT_ID_LEN;
    if src_at < SWITCH_ID_LEN + 1 {
        return None;
    }
    let mut source = [0u8; ENDPOINT_ID_LEN];
    source.copy_from_slice(&frame[src_at..]);
    Some((&frame[SWITCH_ID_LEN + 1..src_at], source))
}

fn endpoint_name(endpoint: &[u8; ENDPOINT_ID_LEN]) -> String {
    let hex = endpoint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("WeaveInterfacePeer[{hex}]")
}

fn admit(deque: &mut VecDeque<(Hash, tokio::time::Instant)>, data: &[u8]) -> bool {
    let hash = Hash::new_from_slice(data);
    let now = tokio::time::Instant::now();
    let hit = deque
        .iter()
        .any(|(entry, at)| *entry == hash && now < *at + MULTI_IF_DEQUE_TTL);
    if hit {
        return false;
    }
    deque.push_back((hash, now));
    while deque.len() > MULTI_IF_DEQUE_LEN {
        deque.pop_front();
    }
    true
}

struct Host {
    port: String,
    identity: PrivateIdentity,
    local_switch_id: [u8; SWITCH_ID_LEN],
    local_pub: [u8; PUBLIC_KEY_LENGTH],
    remote_switch_id: Option<[u8; SWITCH_ID_LEN]>,
    online: bool,
    peers: HashMap<[u8; ENDPOINT_ID_LEN], PeerSlot>,
    deque: VecDeque<(Hash, tokio::time::Instant)>,
    egress_tx: mpsc::Sender<PeerEgress>,
    egress_rx: mpsc::Receiver<PeerEgress>,
    link_up: Arc<AtomicBool>,
    parent: AddressHash,
    parent_stats: Arc<InterfaceCounters>,
    parent_ifac: super::IfacSlot,
    manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    rx: InterfaceRxSender,
    reassembler: WdclReassembler,
    peer_job_at: tokio::time::Instant,
}

impl Host {
    fn new(
        port: String,
        identity: PrivateIdentity,
        parent: AddressHash,
        parent_stats: Arc<InterfaceCounters>,
        parent_ifac: super::IfacSlot,
        manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        rx: InterfaceRxSender,
    ) -> Self {
        let local_pub = *identity.as_identity().verifying_key_bytes();
        let mut local_switch_id = [0u8; SWITCH_ID_LEN];
        local_switch_id.copy_from_slice(&local_pub[PUBLIC_KEY_LENGTH - SWITCH_ID_LEN..]);
        let (egress_tx, egress_rx) = mpsc::channel(64);
        Self {
            port,
            identity,
            local_switch_id,
            local_pub,
            remote_switch_id: None,
            online: false,
            peers: HashMap::new(),
            deque: VecDeque::new(),
            egress_tx,
            egress_rx,
            link_up: Arc::new(AtomicBool::new(false)),
            parent,
            parent_stats,
            parent_ifac,
            manager,
            rx,
            reassembler: WdclReassembler::default(),
            peer_job_at: tokio::time::Instant::now() + PEER_JOB_INTERVAL,
        }
    }

    fn begin_link(&mut self) {
        self.remote_switch_id = None;
        self.set_link_online(false);
        self.deque.clear();
        self.reassembler = WdclReassembler::default();
    }

    fn set_link_online(&mut self, online: bool) {
        self.online = online;
        self.link_up.store(online, Ordering::Relaxed);
        self.parent_stats.set_online(online);
        let now = tokio::time::Instant::now();
        for peer in self.peers.values() {
            if online && now > peer.last_heard + PEERING_TIMEOUT {
                continue;
            }
            peer.stats.set_online(online);
        }
    }
}

async fn timeout_peers(host: &mut Host) {
    host.peer_job_at = tokio::time::Instant::now() + PEER_JOB_INTERVAL;
    let now = tokio::time::Instant::now();
    let expired: Vec<([u8; ENDPOINT_ID_LEN], AddressHash)> = host
        .peers
        .iter()
        .filter(|(_, peer)| now > peer.last_heard + PEERING_TIMEOUT)
        .map(|(endpoint, peer)| (*endpoint, peer.address))
        .collect();
    if expired.is_empty() {
        return;
    }
    for (endpoint, _) in &expired {
        host.peers.remove(endpoint);
        log::debug!(
            "weave: removed peer {} on {}",
            endpoint_name(endpoint),
            host.port
        );
    }
    let mut manager = host.manager.lock().await;
    for (_, address) in expired {
        manager.stop_iface(&address);
    }
}

async fn add_peer(host: &mut Host, endpoint: [u8; ENDPOINT_ID_LEN]) {
    if let Some(peer) = host.peers.get_mut(&endpoint) {
        peer.last_heard = tokio::time::Instant::now();
        if host.online {
            peer.stats.set_online(true);
        }
        return;
    }
    let name = endpoint_name(&endpoint);
    let peer = WeaveInterfacePeer {
        endpoint,
        egress: host.egress_tx.clone(),
        link_up: Arc::clone(&host.link_up),
    };
    let parent_ifac = host.parent_ifac.read().expect("ifac lock").clone();
    let (address, stats) = {
        let mut manager = host.manager.lock().await;
        let context = match parent_ifac {
            Some(key) => manager.open_with_ifac(peer, key),
            None => manager.open_named(&name, peer),
        };
        let address = context.channel.address;
        let stats = Arc::clone(&context.channel.stats);
        manager.set_iface_name(&address, &name);
        manager.copy_spawned_control(&host.parent, &address);
        manager.note_spawned(&host.parent, &address);
        if host.online {
            stats.set_online(true);
        }
        manager.launch(context, WeaveInterfacePeer::spawn);
        (address, stats)
    };
    host.peers.insert(
        endpoint,
        PeerSlot {
            address,
            stats,
            last_heard: tokio::time::Instant::now(),
        },
    );
    log::debug!(
        "weave: {} added peer {}",
        host.port,
        endpoint_name(&endpoint)
    );
}

async fn deliver_packet(host: &mut Host, payload: &[u8], source: [u8; ENDPOINT_ID_LEN]) {
    add_peer(host, source).await;
    if !host.online || !admit(&mut host.deque, payload) {
        return;
    }
    let Some(peer) = host.peers.get(&source) else {
        return;
    };
    let address = peer.address;
    let stats = Arc::clone(&peer.stats);
    let plain = {
        let ifac = host.parent_ifac.read().expect("ifac lock").clone();
        match decode_inbound(payload, ifac.as_deref(), Some(&stats)) {
            Some(plain) => plain,
            None => return,
        }
    };
    match Packet::deserialize(&mut InputBuffer::new(&plain)) {
        Ok(packet) => {
            stats.count_rx(payload.len());
            host.parent_stats.count_rx(payload.len());
            let _ = host.rx.send(RxMessage { address, packet: Box::new(packet) }).await;
        }
        Err(_) => log::debug!("weave: couldn't decode packet"),
    }
}

async fn write_payload<W>(write: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = frame_wdcl(payload);
    write.write_all(&frame).await?;
    write.flush().await
}

async fn handle_frame<W>(host: &mut Host, write: &mut W, frame: &[u8]) -> bool
where
    W: AsyncWrite + Unpin,
{
    if let Some((payload, source)) = endpoint_packet(frame, &host.local_switch_id) {
        deliver_packet(host, payload, source).await;
        return true;
    }
    if frame.len() > HEADER_MINSIZE && frame[SWITCH_ID_LEN] == WDCL_T_DISCOVER {
        if let Some(remote) = accepted_discovery(frame) {
            host.remote_switch_id = Some(remote);
            let signature = host.identity.sign(&remote).to_bytes();
            let payload = handshake_payload(&remote, &host.local_pub, &signature);
            if write_payload(write, &payload).await.is_err() {
                return false;
            }
            log::debug!(
                "weave: remote device {} discovered on {}",
                remote
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                host.port
            );
        }
        return true;
    }
    if let Some((event, data)) = log_event(frame) {
        if event == ET_PROTO_WDCL_CONNECTION {
            host.set_link_online(true);
        } else if event == ET_PROTO_WEAVE_EP_ALIVE && data.len() == ENDPOINT_ID_LEN {
            let mut endpoint = [0u8; ENDPOINT_ID_LEN];
            endpoint.copy_from_slice(data);
            add_peer(host, endpoint).await;
        }
    }
    true
}

async fn write_egress<W>(host: &mut Host, write: &mut W, egress: PeerEgress) -> bool
where
    W: AsyncWrite + Unpin,
{
    if !host.online {
        return true;
    }
    let Some(remote) = host.remote_switch_id else {
        return true;
    };
    let payload = endpoint_command(&remote, &egress.endpoint, &egress.wire);
    if write_payload(write, &payload).await.is_err() {
        return false;
    }
    host.parent_stats.count_tx(egress.wire.len());
    if let Some(peer) = host.peers.get(&egress.endpoint) {
        peer.stats.count_tx(egress.wire.len());
    }
    true
}

enum LinkEvent {
    Stop,
    HandshakeTimeout,
    Read(std::io::Result<usize>),
    ParentTx,
    Egress(Option<PeerEgress>),
    PeerJob,
}

async fn run_link<S>(
    stream: S,
    tx: &mut InterfaceTxReceiver,
    host: &mut Host,
    cancel: &tokio_util::sync::CancellationToken,
    iface_stop: &tokio_util::sync::CancellationToken,
) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut read, mut write) = tokio::io::split(stream);
    host.begin_link();
    let handshake_deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut buf = [0u8; 1500];

    if write_payload(&mut write, &discover_payload(&host.local_switch_id))
        .await
        .is_err()
    {
        host.set_link_online(false);
        return true;
    }
    log::info!(
        "weave: port <{}> is now open, discovering remote device",
        host.port
    );

    loop {
        let online = host.online;
        let event = tokio::select! {
            _ = cancel.cancelled() => LinkEvent::Stop,
            _ = iface_stop.cancelled() => LinkEvent::Stop,
            _ = tokio::time::sleep_until(handshake_deadline), if !online => {
                LinkEvent::HandshakeTimeout
            }
            result = read.read(&mut buf) => LinkEvent::Read(result),
            message = tx.recv() => match message {
                Some(_) => LinkEvent::ParentTx,
                None => LinkEvent::Stop,
            },
            egress = host.egress_rx.recv() => LinkEvent::Egress(egress),
            _ = tokio::time::sleep_until(host.peer_job_at) => LinkEvent::PeerJob,
        };

        match event {
            LinkEvent::Stop => {
                host.set_link_online(false);
                return false;
            }
            LinkEvent::HandshakeTimeout => {
                log::warn!("weave: WDCL handshake timed out for port <{}>", host.port);
                host.set_link_online(false);
                return true;
            }
            LinkEvent::ParentTx => {}
            LinkEvent::PeerJob => timeout_peers(host).await,
            LinkEvent::Egress(None) => {}
            LinkEvent::Egress(Some(egress)) => {
                if !write_egress(host, &mut write, egress).await {
                    log::warn!("weave: serial port <{}> closed", host.port);
                    host.set_link_online(false);
                    return true;
                }
            }
            LinkEvent::Read(Ok(0)) | LinkEvent::Read(Err(_)) => {
                log::warn!("weave: serial port <{}> closed", host.port);
                host.set_link_online(false);
                return true;
            }
            LinkEvent::Read(Ok(n)) => {
                let frames = host.reassembler.push(&buf[..n]);
                for frame in frames {
                    if !handle_frame(host, &mut write, &frame).await {
                        log::warn!("weave: serial port <{}> closed", host.port);
                        host.set_link_online(false);
                        return true;
                    }
                }
            }
        }
    }
}

/// Sleep for `duration` while the link is down, still running the
/// peer-ageing job at its scheduled time so peers keep expiring
/// during reconnect waits and failed opens.
#[cfg(all(feature = "iface-serial", not(target_os = "android")))]
async fn link_down_sleep(
    host: &mut Host,
    duration: Duration,
    cancel: &tokio_util::sync::CancellationToken,
    iface_stop: &tokio_util::sync::CancellationToken,
) {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = iface_stop.cancelled() => break,
            _ = tokio::time::sleep_until(deadline) => break,
            _ = tokio::time::sleep_until(host.peer_job_at) => timeout_peers(host).await,
        }
    }
}

/// Parent Weave port. It discovers the device and spawns one
/// [`WeaveInterfacePeer`] per endpoint. The parent does not carry RNS
/// packets (`WeaveInterface.process_outgoing` is a no-op).
pub struct WeaveInterface {
    port: String,
    identity: PrivateIdentity,
    injected: Option<tokio::io::DuplexStream>,
    manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl WeaveInterface {
    pub fn new(
        port: impl Into<String>,
        manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            port: port.into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            injected: None,
            manager,
        }
    }

    /// Drive the worker from an in-memory stream. The stream is consumed
    /// once and the worker does not reopen a device.
    pub fn from_stream(
        stream: tokio::io::DuplexStream,
        manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            port: "mock".to_string(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            injected: Some(stream),
            manager,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let exited = context.channel.exited.clone();
        let stats = Arc::clone(&context.channel.stats);
        let parent = context.channel.address;
        let parent_ifac = Arc::clone(&context.channel.ifac);
        let rx = context.channel.rx_channel.clone();
        let cancel = context.cancel.clone();
        let (_, mut tx) = context.channel.split();

        let (port, identity, manager, injected) = {
            let mut inner = context.inner.lock().unwrap();
            (
                inner.port.clone(),
                inner.identity.clone(),
                Arc::clone(&inner.manager),
                inner.injected.take(),
            )
        };

        let mut host = Host::new(
            port.clone(),
            identity,
            parent,
            Arc::clone(&stats),
            parent_ifac,
            manager,
            rx,
        );

        if let Some(stream) = injected {
            let _reconnect = run_link(stream, &mut tx, &mut host, &cancel, &iface_stop).await;
        } else {
            #[cfg(target_os = "android")]
            {
                log::error!("Weave USB serial is not supported; not opening port <{port}>");
            }
            #[cfg(all(not(target_os = "android"), feature = "iface-serial"))]
            {
                loop {
                    if cancel.is_cancelled() || iface_stop.is_cancelled() {
                        break;
                    }
                    match crate::iface::kiss::SerialPortConfig::new(&port, SERIAL_BAUD).open() {
                        Ok(stream) => {
                            let reconnect =
                                run_link(stream, &mut tx, &mut host, &cancel, &iface_stop).await;
                            stats.set_online(false);
                            if !reconnect || cancel.is_cancelled() || iface_stop.is_cancelled() {
                                break;
                            }
                            log::warn!("weave: will attempt to reconnect port <{port}>");
                            link_down_sleep(&mut host, RECONNECT_INTERVAL, &cancel, &iface_stop)
                                .await;
                        }
                        Err(_) => {
                            log::warn!("weave: couldn't open serial port <{port}>, retrying");
                            link_down_sleep(&mut host, RECONNECT_INTERVAL, &cancel, &iface_stop)
                                .await;
                        }
                    }
                }
            }
            #[cfg(all(not(target_os = "android"), not(feature = "iface-serial")))]
            {
                log::error!("weave: port <{port}> requires building with --features iface-serial");
            }
        }

        stats.set_online(false);
        let _ = exited.send(true);
        iface_stop.cancel();
    }
}

impl Interface for WeaveInterface {
    fn mtu() -> usize {
        HW_MTU
    }

    fn endpoint(&self) -> &str {
        &self.port
    }
}

/// One remote Weave endpoint. Transmit builds a WDCL command and the
/// parent writes it; receive is delivered by the parent.
pub struct WeaveInterfacePeer {
    endpoint: [u8; ENDPOINT_ID_LEN],
    egress: mpsc::Sender<PeerEgress>,
    link_up: Arc<AtomicBool>,
}

impl WeaveInterfacePeer {
    async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = Arc::clone(&context.channel.stats);
        let channel_ifac = Arc::clone(&context.channel.ifac);
        let cancel = context.cancel.clone();
        let (_, mut tx) = context.channel.split();

        let (endpoint, egress, link_up) = {
            let inner = context.inner.lock().unwrap();
            (
                inner.endpoint,
                inner.egress.clone(),
                Arc::clone(&inner.link_up),
            )
        };

        loop {
            let message = tokio::select! {
                _ = cancel.cancelled() => break,
                _ = iface_stop.cancelled() => break,
                message = tx.recv() => match message {
                    Some(message) => message,
                    None => break,
                },
            };
            if !link_up.load(Ordering::Relaxed) {
                continue;
            }
            let TxMessage { packet, .. } = message;
            let mut buffer = [0u8; 4096];
            let mut output = OutputBuffer::new(&mut buffer);
            if packet.serialize(&mut output).is_err() {
                continue;
            }
            let ifac = channel_ifac.read().expect("ifac lock").clone();
            let wire = crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());
            if egress.send(PeerEgress { endpoint, wire }).await.is_err() {
                break;
            }
        }

        stats.set_online(false);
        iface_stop.cancel();
    }
}

impl Interface for WeaveInterfacePeer {
    fn mtu() -> usize {
        HW_MTU
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use std::sync::Arc;

    use rand_core::OsRng;

    use super::super::InterfaceManager;
    use super::{
        frame_wdcl, WdclReassembler, WeaveInterface, CMD_ENDPOINT_PKT, ET_PROTO_WDCL_CONNECTION,
        ET_PROTO_WEAVE_EP_ALIVE, SWITCH_ID_LEN, WDCL_T_CMD, WDCL_T_CONNECT, WDCL_T_DISCOVER,
        WDCL_T_ENDPOINT_PKT, WDCL_T_LOG,
    };
    use crate::buffer::OutputBuffer;
    use crate::identity::{Identity, PrivateIdentity, Signature};
    use crate::packet::Packet;
    use crate::serde::Serialize;

    fn log_frame(event: u16, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + data.len()];
        frame[SWITCH_ID_LEN] = WDCL_T_LOG;
        frame[12..14].copy_from_slice(&event.to_be_bytes());
        frame[14..].copy_from_slice(data);
        frame
    }

    async fn read_frame<R>(read: &mut R, reassembler: &mut WdclReassembler) -> (Vec<u8>, Vec<u8>)
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut buf = [0u8; 2048];
        let mut raw = Vec::new();
        loop {
            let n = tokio::time::timeout(Duration::from_secs(2), read.read(&mut buf))
                .await
                .expect("read timeout")
                .expect("read");
            assert!(n > 0, "device side closed");
            raw.extend_from_slice(&buf[..n]);
            let mut frames = reassembler.push(&buf[..n]);
            if !frames.is_empty() {
                return (frames.remove(0), raw);
            }
        }
    }

    #[tokio::test]
    async fn wdcl_frames_round_trip_on_a_mock_port() {
        let (client, server) = tokio::io::duplex(8192);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(8)));
        let iface = WeaveInterface::from_stream(client, Arc::clone(&manager));
        let parent = {
            let mut guard = manager.lock().await;
            guard.spawn(iface, WeaveInterface::spawn)
        };

        let mut device_reassembler = WdclReassembler::default();
        let (discover, discover_raw) = read_frame(&mut server_read, &mut device_reassembler).await;
        assert_eq!(discover.len(), 9);
        assert_eq!(&discover[..5], &[0xff, 0xff, 0xff, 0xff, WDCL_T_DISCOVER]);
        let local_switch: [u8; 4] = discover[5..9].try_into().unwrap();
        assert_eq!(discover_raw, frame_wdcl(&discover));

        let remote = PrivateIdentity::new_from_rand(OsRng);
        let remote_pub = *remote.as_identity().verifying_key_bytes();
        let mut remote_switch = [0u8; 4];
        remote_switch.copy_from_slice(&remote_pub[remote_pub.len() - 4..]);
        let signature = remote.sign(&remote_switch).to_bytes();
        let mut response = Vec::new();
        response.extend_from_slice(&remote_switch);
        response.push(WDCL_T_DISCOVER);
        response.extend_from_slice(&remote_pub);
        response.extend_from_slice(&signature);
        assert_eq!(response.len(), 101);
        let framed = frame_wdcl(&response);
        server_write.write_all(&framed).await.unwrap();

        let (handshake, handshake_raw) =
            read_frame(&mut server_read, &mut device_reassembler).await;
        assert_eq!(handshake.len(), 101);
        assert_eq!(&handshake[..4], &remote_switch);
        assert_eq!(handshake[4], WDCL_T_CONNECT);
        assert_eq!(&handshake[33..37], &local_switch);
        let mut host_sig = [0u8; 64];
        host_sig.copy_from_slice(&handshake[37..101]);
        Identity::new_from_slices(&handshake[5..37], &handshake[5..37])
            .verify(&remote_switch, &Signature::from_bytes(&host_sig))
            .expect("handshake signature");
        assert_eq!(handshake_raw, frame_wdcl(&handshake));

        let endpoint_id = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let connection = frame_wdcl(&log_frame(ET_PROTO_WDCL_CONNECTION, &[]));
        let alive = frame_wdcl(&log_frame(ET_PROTO_WEAVE_EP_ALIVE, &endpoint_id));
        let mut stitched = connection;
        // Closing flag of the first frame is the opening flag of the second.
        stitched.extend_from_slice(&alive[1..]);
        server_write.write_all(&stitched).await.unwrap();

        let mut peer_addr = None;
        for _ in 0..50 {
            let stats = manager.lock().await.stats();
            let parent_online = stats
                .iter()
                .any(|stat| stat.address == parent && stat.online && stat.kind == "WeaveInterface");
            let peers: Vec<_> = stats
                .iter()
                .filter(|stat| stat.kind == "WeaveInterfacePeer")
                .collect();
            if parent_online && peers.len() == 1 {
                assert_eq!(peers[0].name, "WeaveInterfacePeer[11:22:33:44:55:66:77:88]");
                peer_addr = Some(peers[0].address);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let peer_addr = peer_addr.expect("weave peer");

        let mut packet = Packet::default();
        packet
            .data
            .write(&[0x7e, 0x11, 0x7d, 0x22])
            .expect("packet data");
        let mut serialized = [0u8; 4096];
        let mut output = OutputBuffer::new(&mut serialized);
        packet.serialize(&mut output).unwrap();
        let serialized = output.as_slice().to_vec();
        let mut inbound = Vec::new();
        inbound.extend_from_slice(&local_switch);
        inbound.push(WDCL_T_ENDPOINT_PKT);
        inbound.extend_from_slice(&serialized);
        inbound.extend_from_slice(&endpoint_id);
        let inbound = frame_wdcl(&inbound);
        server_write.write_all(&inbound).await.unwrap();
        server_write.write_all(&inbound).await.unwrap();

        let rx = manager.lock().await.receiver();
        let message = tokio::time::timeout(Duration::from_secs(2), rx.lock().await.recv())
            .await
            .expect("rx timeout")
            .expect("rx");
        assert_eq!(message.address, peer_addr);
        assert_eq!(message.packet.data.as_slice(), &[0x7e, 0x11, 0x7d, 0x22]);
        let duplicate =
            tokio::time::timeout(Duration::from_millis(200), rx.lock().await.recv()).await;
        assert!(
            duplicate.is_err(),
            "duplicate endpoint packet was delivered"
        );

        manager
            .lock()
            .await
            .send(super::super::TxMessage {
                tx_type: super::super::TxMessageType::Direct(peer_addr),
                packet: Box::new(packet),
            })
            .await;
        let (command, command_raw) = read_frame(&mut server_read, &mut device_reassembler).await;
        let mut expected = Vec::new();
        expected.extend_from_slice(&remote_switch);
        expected.push(WDCL_T_CMD);
        expected.extend_from_slice(&CMD_ENDPOINT_PKT.to_be_bytes());
        expected.extend_from_slice(&endpoint_id);
        expected.extend_from_slice(&serialized);
        assert_eq!(command, expected);
        assert_eq!(command_raw, frame_wdcl(&expected));

        let stats = manager.lock().await.stats();
        let parent_stats = stats.iter().find(|stat| stat.address == parent).unwrap();
        let peer_stats = stats.iter().find(|stat| stat.address == peer_addr).unwrap();
        assert!(parent_stats.rx_bytes >= serialized.len() as u64);
        assert!(peer_stats.rx_bytes >= serialized.len() as u64);
        assert!(parent_stats.tx_bytes >= serialized.len() as u64);
        assert!(peer_stats.tx_bytes >= serialized.len() as u64);

        drop(server_write);
        drop(server_read);
        let mut saw_close = false;
        for _ in 0..50 {
            let stats = manager.lock().await.stats();
            let parent_up = stats
                .iter()
                .any(|stat| stat.address == parent && stat.online);
            if parent_up {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
            saw_close = true;
            assert!(
                stats
                    .iter()
                    .any(|stat| stat.address == peer_addr && stat.kind == "WeaveInterfacePeer"),
                "peer slot removed when the mock link closed"
            );
            break;
        }
        assert!(saw_close, "mock link did not close");

        manager.lock().await.stop_iface(&parent);
    }
}
