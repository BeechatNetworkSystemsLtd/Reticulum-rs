pub mod control;
pub mod hdlc;
pub mod ifac;
pub mod local;

pub mod tcp_client;
pub mod tcp_server;
pub mod udp;

#[cfg(feature = "iface-auto")]
pub mod auto;
#[cfg(feature = "iface-serial")]
pub mod ax25;
pub mod backbone;
#[cfg(feature = "iface-i2p")]
pub mod i2p;
#[cfg(feature = "iface-serial")]
pub mod kiss;
#[cfg(feature = "iface-pipe")]
pub mod pipe;
#[cfg(feature = "iface-rnode")]
pub mod rnode;
#[cfg(feature = "iface-serial")]
pub mod serial;
pub mod weave;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU32;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::AtomicU64;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;

use rand_core::RngCore;
use tokio::sync::mpsc;
use tokio::task;
use tokio_util::sync::CancellationToken;

use crate::hash::AddressHash;
use crate::hash::Hash;
pub use crate::iface::control::{IfaceControlParams, IfaceControlState, InterfaceMode};
use crate::packet::{DestinationType, HeaderType, Packet, PacketType, PropagationType};

pub type InterfaceTxSender = mpsc::Sender<TxMessage>;
pub type InterfaceTxReceiver = mpsc::Receiver<TxMessage>;

pub type InterfaceRxSender = mpsc::Sender<RxMessage>;
pub type InterfaceRxReceiver = mpsc::Receiver<RxMessage>;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum TxMessageType {
    Broadcast(Option<AddressHash>),
    Direct(AddressHash),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TxMessage {
    pub tx_type: TxMessageType,
    pub packet: Box<Packet>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RxMessage {
    pub address: AddressHash, // Address of source interface
    pub packet: Box<Packet>, // Received packet
}

/// Runtime counters for a single interface, shared between the
/// [`InterfaceManager`] and the interface worker tasks.
///
/// Mirrors the `sent/received/txb/rxb/online` bookkeeping of
/// `RNS.Interfaces.Interface` used by `rnstatus`.
#[derive(Debug)]
pub struct InterfaceCounters {
    sent: AtomicU64,
    received: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    online: AtomicBool,
    /// Announce traffic (Python `arxb/atxb/arxc/atxc`).
    announces_received: AtomicU64,
    announces_sent: AtomicU64,
    announce_bytes_received: AtomicU64,
    announce_bytes_sent: AtomicU64,
    /// Path request traffic (Python `prxb/ptxb/prxc/ptxc`).
    path_requests_received: AtomicU64,
    path_requests_sent: AtomicU64,
    /// Protocol violations (Python `protocol_violations`).
    protocol_violations: AtomicU64,
    /// IFAC violations (Python `ifac_violations`).
    ifac_violations: AtomicU64,
    /// Early packet filter hits (Python `packet_filter_hits`).
    packet_filter_hits: AtomicU64,
    /// Last reported radio RSSI in dBm (`i32::MIN` = not reported).
    rssi: AtomicI32,
    /// Last reported radio SNR as f32 bits (`u32::MAX` = not reported).
    snr_bits: AtomicU32,
    /// Last reported derived link-quality percentage as f32 bits
    /// (`u32::MAX` = not reported; Python `r_stat_q`).
    quality_bits: AtomicU32,
    /// Radio channel readings (`u32::MAX` = not reported).
    airtime_short_bits: AtomicU32,
    airtime_long_bits: AtomicU32,
    channel_load_short_bits: AtomicU32,
    channel_load_long_bits: AtomicU32,
}

/// Radio channel readings an interface has actually reported.
#[derive(Debug, Clone, Copy, Default)]
pub struct RadioTelemetry {
    pub airtime_short: Option<f32>,
    pub airtime_long: Option<f32>,
    pub channel_load_short: Option<f32>,
    pub channel_load_long: Option<f32>,
}

impl InterfaceCounters {
    /// Account one transmitted packet of `bytes` payload bytes.
    pub fn count_tx(&self, bytes: usize) {
        self.sent.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Account one received packet of `bytes` payload bytes.
    pub fn count_rx(&self, bytes: usize) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn set_online(&self, online: bool) {
        self.online.store(online, Ordering::Relaxed);
    }

    /// Account a received announce (Python `Interface.received_announce`).
    pub fn count_announce_rx(&self, bytes: usize) {
        self.announces_received.fetch_add(1, Ordering::Relaxed);
        self.announce_bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Account a sent announce (Python `Interface.sent_announce`).
    pub fn count_announce_tx(&self, bytes: usize) {
        self.announces_sent.fetch_add(1, Ordering::Relaxed);
        self.announce_bytes_sent
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Account a received path request
    /// (Python `Interface.received_path_request`).
    pub fn count_path_request_rx(&self, bytes: usize) {
        self.path_requests_received.fetch_add(1, Ordering::Relaxed);
        let _ = bytes;
    }

    /// Account a sent path request (Python `Interface.sent_path_request`).
    pub fn count_path_request_tx(&self, bytes: usize) {
        self.path_requests_sent.fetch_add(1, Ordering::Relaxed);
        let _ = bytes;
    }

    /// Account a protocol violation (Python `Interface.protocol_violation`).
    pub fn count_protocol_violation(&self) {
        self.protocol_violations.fetch_add(1, Ordering::Relaxed);
    }

    /// Account an IFAC violation (Python `Interface.ifac_violation`).
    pub fn count_ifac_violation(&self) {
        self.ifac_violations.fetch_add(1, Ordering::Relaxed);
    }

    /// Account an early packet filter hit
    /// (Python `Interface.packet_filter_hit`).
    pub fn count_packet_filter_hit(&self) {
        self.packet_filter_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Received announce count.
    pub fn announces_received(&self) -> u64 {
        self.announces_received.load(Ordering::Relaxed)
    }

    /// Sent announce count.
    pub fn announces_sent(&self) -> u64 {
        self.announces_sent.load(Ordering::Relaxed)
    }

    /// Received announce bytes.
    pub fn announce_bytes_received(&self) -> u64 {
        self.announce_bytes_received.load(Ordering::Relaxed)
    }

    /// Sent announce bytes.
    pub fn announce_bytes_sent(&self) -> u64 {
        self.announce_bytes_sent.load(Ordering::Relaxed)
    }

    /// Received path request count.
    pub fn path_requests_received(&self) -> u64 {
        self.path_requests_received.load(Ordering::Relaxed)
    }

    /// Sent path request count.
    pub fn path_requests_sent(&self) -> u64 {
        self.path_requests_sent.load(Ordering::Relaxed)
    }

    /// Protocol violation count.
    pub fn protocol_violations(&self) -> u64 {
        self.protocol_violations.load(Ordering::Relaxed)
    }

    /// IFAC violation count.
    pub fn ifac_violations(&self) -> u64 {
        self.ifac_violations.load(Ordering::Relaxed)
    }

    /// Packet filter hit count.
    pub fn packet_filter_hits(&self) -> u64 {
        self.packet_filter_hits.load(Ordering::Relaxed)
    }

    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    /// Publish the latest radio link-quality telemetry for this interface
    /// (Python `r_stat_rssi`/`r_stat_snr`/`r_stat_q`). `None` values keep
    /// the previous reading; quality is usually derived from SNR by the
    /// reporting interface.
    pub fn set_radio_quality(&self, rssi: Option<i16>, snr: Option<f32>, quality: Option<f32>) {
        if let Some(rssi) = rssi {
            self.rssi.store(rssi as i32, Ordering::Relaxed);
        }
        if let Some(snr) = snr {
            self.snr_bits.store(snr.to_bits(), Ordering::Relaxed);
        }
        if let Some(quality) = quality {
            self.quality_bits
                .store(quality.to_bits(), Ordering::Relaxed);
        }
    }

    /// Last reported RSSI in dBm, when this interface reports one.
    pub fn rssi(&self) -> Option<i16> {
        let value = self.rssi.load(Ordering::Relaxed);
        (value != i32::MIN).then_some(value as i16)
    }

    /// Last reported SNR in dB, when this interface reports one.
    pub fn snr(&self) -> Option<f32> {
        let bits = self.snr_bits.load(Ordering::Relaxed);
        (bits != u32::MAX).then(|| f32::from_bits(bits))
    }

    /// Last reported derived link-quality percentage (Python `r_stat_q`).
    pub fn quality(&self) -> Option<f32> {
        optional_f32(&self.quality_bits)
    }

    /// Store radio channel readings. `None` keeps the previous value.
    pub fn set_radio_channel(
        &self,
        airtime_short: Option<f32>,
        airtime_long: Option<f32>,
        channel_load_short: Option<f32>,
        channel_load_long: Option<f32>,
    ) {
        store_opt_f32(&self.airtime_short_bits, airtime_short);
        store_opt_f32(&self.airtime_long_bits, airtime_long);
        store_opt_f32(&self.channel_load_short_bits, channel_load_short);
        store_opt_f32(&self.channel_load_long_bits, channel_load_long);
    }

    pub fn radio_telemetry(&self) -> RadioTelemetry {
        RadioTelemetry {
            airtime_short: optional_f32(&self.airtime_short_bits),
            airtime_long: optional_f32(&self.airtime_long_bits),
            channel_load_short: optional_f32(&self.channel_load_short_bits),
            channel_load_long: optional_f32(&self.channel_load_long_bits),
        }
    }
}

fn optional_f32(bits: &AtomicU32) -> Option<f32> {
    let bits = bits.load(Ordering::Relaxed);
    (bits != u32::MAX).then(|| f32::from_bits(bits))
}

fn store_opt_f32(slot: &AtomicU32, value: Option<f32>) {
    if let Some(value) = value {
        slot.store(value.to_bits(), Ordering::Relaxed);
    }
}

/// Sentinel initializers for the radio-telemetry atomics in
/// [`InterfaceCounters`] (`AtomicI32`/`AtomicU64` default to 0, which is a
/// valid reading, so "unreported" is encoded explicitly).
impl Default for InterfaceCounters {
    fn default() -> Self {
        Self {
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            online: AtomicBool::new(false),
            announces_received: AtomicU64::new(0),
            announces_sent: AtomicU64::new(0),
            announce_bytes_received: AtomicU64::new(0),
            announce_bytes_sent: AtomicU64::new(0),
            path_requests_received: AtomicU64::new(0),
            path_requests_sent: AtomicU64::new(0),
            protocol_violations: AtomicU64::new(0),
            ifac_violations: AtomicU64::new(0),
            packet_filter_hits: AtomicU64::new(0),
            rssi: AtomicI32::new(i32::MIN),
            snr_bits: AtomicU32::new(u32::MAX),
            quality_bits: AtomicU32::new(u32::MAX),
            airtime_short_bits: AtomicU32::new(u32::MAX),
            airtime_long_bits: AtomicU32::new(u32::MAX),
            channel_load_short_bits: AtomicU32::new(u32::MAX),
            channel_load_long_bits: AtomicU32::new(u32::MAX),
        }
    }
}

/// Snapshot of the statistics of one interface
/// (compare `rnstatus` output of the Python reference implementation).
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceStats {
    /// Interface address used for routing
    pub address: AddressHash,
    /// Human-readable interface name (configuration name)
    pub name: String,
    /// Interface type (short Rust type name of the spawned interface)
    pub kind: String,
    /// Packets sent
    pub sent: u64,
    /// Packets received
    pub received: u64,
    /// Payload bytes sent
    pub tx_bytes: u64,
    /// Payload bytes received
    pub rx_bytes: u64,
    /// Whether the interface considers itself online
    pub online: bool,
    /// Announces received/sent (Python 1.5.0 traffic stats).
    pub announces_received: u64,
    pub announces_sent: u64,
    /// Announce payload bytes received/sent.
    pub announce_bytes_received: u64,
    pub announce_bytes_sent: u64,
    /// Path requests received/sent.
    pub path_requests_received: u64,
    pub path_requests_sent: u64,
    /// Protocol violations detected on this interface.
    pub protocol_violations: u64,
    /// IFAC violations detected on this interface.
    pub ifac_violations: u64,
    /// Early packet filter hits.
    pub packet_filter_hits: u64,
    /// Last reported radio RSSI in dBm (Python `r_stat_rssi`), when the
    /// interface reports radio telemetry (RNode and friends).
    pub rssi: Option<i16>,
    /// Last reported radio SNR in dB (Python `r_stat_snr`).
    pub snr: Option<f32>,
    /// Last reported derived link-quality percentage 0–100
    /// (Python `r_stat_q`).
    pub quality: Option<f32>,
}

pub struct InterfaceChannel {
    pub address: AddressHash,
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
    pub stop: CancellationToken,
    /// Set after this worker has dropped its listener sockets.
    pub exited: tokio::sync::watch::Sender<bool>,
    pub stats: Arc<InterfaceCounters>,
    /// Interface access code configuration for this interface
    /// (Python `interface.ifac_identity`); packets are wrapped/unwrapped
    /// by the interface worker when present.
    pub ifac: IfacSlot,
}

/// Shared IFAC configuration slot of an interface.
pub type IfacSlot = Arc<std::sync::RwLock<Option<Arc<ifac::IfacKey>>>>;

impl InterfaceChannel {
    pub fn make_rx_channel(cap: usize) -> (InterfaceRxSender, InterfaceRxReceiver) {
        mpsc::channel(cap)
    }

    pub fn make_tx_channel(cap: usize) -> (InterfaceTxSender, InterfaceTxReceiver) {
        mpsc::channel(cap)
    }

    pub fn new(
        rx_channel: InterfaceRxSender,
        tx_channel: InterfaceTxReceiver,
        address: AddressHash,
        stop: CancellationToken,
    ) -> Self {
        let (exited, _) = tokio::sync::watch::channel(false);
        Self {
            address,
            rx_channel,
            tx_channel,
            stop,
            exited,
            stats: Arc::new(InterfaceCounters::default()),
            ifac: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    pub fn address(&self) -> &AddressHash {
        &self.address
    }

    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

pub trait Interface {
    fn mtu() -> usize;

    /// Bitrate to store on the control word when this interface is spawned.
    ///
    /// `None` leaves the generic default. The worker is not polled until
    /// after [`InterfaceManager::spawn`] returns, so this is the only
    /// chance to publish a constructor rate before that return.
    fn constructor_bitrate(&self) -> Option<u64> {
        None
    }

    /// Whether this type applies announce ingress limiting.
    ///
    /// KISS (including AX.25) and serial return false here, so those
    /// links forward announce bursts instead of holding them.
    fn should_ingress_limit() -> bool {
        true
    }

    /// Bind or peer endpoint included in the stable interface id.
    /// Empty when this interface has neither.
    fn endpoint(&self) -> &str {
        ""
    }
}

struct LocalInterface {
    address: AddressHash,
    name: String,
    kind: String,
    /// Bind or peer string recorded for the stable id. Separate from
    /// `name` so a later config-name change does not drop it. Empty when
    /// the interface recorded neither.
    endpoint: String,
    /// Parent listener that spawned this interface, when there is one.
    parent: Option<AddressHash>,
    tx_send: InterfaceTxSender,
    stop: CancellationToken,
    /// Becomes true after the worker drops its listener.
    exited: tokio::sync::watch::Receiver<bool>,
    stats: Arc<InterfaceCounters>,
    ifac: IfacSlot,
}

pub struct InterfaceContext<T: Interface> {
    pub inner: Arc<Mutex<T>>,
    pub channel: InterfaceChannel,
    pub cancel: CancellationToken,
}

pub struct InterfaceManager {
    counter: usize,
    rx_recv: Arc<tokio::sync::Mutex<InterfaceRxReceiver>>,
    rx_send: InterfaceRxSender,
    cancel: CancellationToken,
    ifaces: Vec<LocalInterface>,
    /// Per-interface transport control state (Python `Interface` ingress /
    /// egress control attributes).
    controls: Mutex<HashMap<AddressHash, IfaceControlState>>,
    /// Sampled hops-0 rewrite onto the wider network
    /// (Python `Transport.local_hops_delta`). Zero disables it.
    pub(crate) local_hops_delta: AtomicU8,
    /// Transport identity inserted when an announce header is upgraded.
    transport_identity: Mutex<Option<AddressHash>>,
}

impl InterfaceManager {
    pub fn new(rx_cap: usize) -> Self {
        let (rx_send, rx_recv) = InterfaceChannel::make_rx_channel(rx_cap);
        let rx_recv = Arc::new(tokio::sync::Mutex::new(rx_recv));

        Self {
            counter: 0,
            rx_recv,
            rx_send,
            cancel: CancellationToken::new(),
            ifaces: Vec::new(),
            controls: Mutex::new(HashMap::new()),
            local_hops_delta: AtomicU8::new(0),
            transport_identity: Mutex::new(None),
        }
    }

    /// Enable the local-client hop rewrite sampled by transport
    /// (Python `Transport.local_hops_delta`, 2 through 7).
    pub fn set_local_hops_delta(&self, delta: u8, transport_id: Option<AddressHash>) {
        self.local_hops_delta.store(delta, Ordering::Relaxed);
        *self.transport_identity.lock().expect("transport id") = transport_id;
    }

    /// Drop queued announces on every interface
    /// (Python `Transport.drop_announce_queues`).
    pub fn drop_announce_queues(&self) {
        let mut controls = self.controls.lock().expect("iface control lock");
        for control in controls.values_mut() {
            control.clear_announce_queue();
        }
    }

    pub fn connected_to_shared_instance(&self) -> bool {
        self.ifaces.iter().any(|iface| {
            iface.kind == "LocalClient"
                && iface.stats.online()
                && !iface.stop.is_cancelled()
                && !self.is_local_client_iface(&iface.address)
        })
    }

    pub fn new_channel(&mut self, tx_cap: usize) -> InterfaceChannel {
        self.new_channel_named(tx_cap, "", "")
    }

    /// Create a new interface channel registered under `name` (configuration
    /// name, used for statistics) and `kind` (interface type).
    pub fn new_channel_named(&mut self, tx_cap: usize, name: &str, kind: &str) -> InterfaceChannel {
        self.counter += 1;

        // u64 cast: usize is 4 bytes on 32-bit targets (Xtensa) and the
        // seed prefix is always 8 bytes wide.
        let counter_bytes = (self.counter as u64).to_le_bytes();
        let mut address_seed = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut address_seed);
        address_seed[..8].copy_from_slice(&counter_bytes[..8]);
        let address = AddressHash::new_from_hash(&Hash::new_from_slice(&address_seed));

        let (tx_send, tx_recv) = InterfaceChannel::make_tx_channel(tx_cap);

        log::debug!("iface: create channel {} <{}:{}>", address, name, kind);

        let stop = CancellationToken::new();
        let stats = Arc::new(InterfaceCounters::default());
        stats.set_online(false);
        let (exited_tx, exited_rx) = tokio::sync::watch::channel(false);

        let ifac: IfacSlot = Arc::new(std::sync::RwLock::new(None));

        self.ifaces.push(LocalInterface {
            address,
            name: name.to_string(),
            kind: kind.to_string(),
            endpoint: String::new(),
            parent: None,
            tx_send,
            stop: stop.clone(),
            exited: exited_rx,
            stats: stats.clone(),
            ifac: ifac.clone(),
        });

        self.controls
            .lock()
            .expect("iface control lock")
            .insert(address, IfaceControlState::new(tokio::time::Instant::now()));

        InterfaceChannel {
            rx_channel: self.rx_send.clone(),
            tx_channel: tx_recv,
            address,
            stop,
            exited: exited_tx,
            stats,
            ifac,
        }
    }

    pub fn new_context<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        let kind = interface_kind_name::<T>();
        let endpoint = inner.endpoint().to_string();
        let channel = self.new_channel_named(1, &kind, &kind);
        let address = channel.address;
        if let Some(iface) = self
            .ifaces
            .iter_mut()
            .find(|iface| iface.address == address)
        {
            iface.endpoint = endpoint;
        }

        let inner = Arc::new(Mutex::new(inner));
        let address = channel.address;
        self.apply_type_ingress_policy::<T>(&address);

        InterfaceContext::<T> {
            inner: inner.clone(),
            channel,
            cancel: self.cancel.clone(),
        }
    }

    /// KISS (including AX.25) and serial return false from
    /// `should_ingress_limit`. Applied when the channel is registered so
    /// transport (which only sees [`IfaceControlState`]) holds no
    /// announces for these types.
    fn apply_type_ingress_policy<T: Interface>(&self, address: &AddressHash) {
        if !T::should_ingress_limit() {
            self.with_control(address, |control| {
                control.set_announce_ingress_limit(false);
            });
        }
    }

    /// Set the statistics name of an already registered interface
    /// (interfaces spawned by a server get the peer address as name).
    pub fn set_iface_name(&mut self, address: &AddressHash, name: &str) {
        if let Some(iface) = self.ifaces.iter_mut().find(|i| &i.address == address) {
            iface.name = name.to_string();
        }
    }

    /// Record that `child` was spawned by `parent` so detach can stop both.
    pub fn note_spawned(&mut self, parent: &AddressHash, child: &AddressHash) {
        if let Some(iface) = self.ifaces.iter_mut().find(|iface| &iface.address == child) {
            iface.parent = Some(*parent);
        }
    }

    /// Config name of the listener that spawned `address`, when that
    /// listener is still registered.
    pub fn spawned_parent_name(&self, address: &AddressHash) -> Option<String> {
        let parent = self
            .ifaces
            .iter()
            .find(|iface| iface.address == *address)?
            .parent?;
        self.ifaces
            .iter()
            .find(|iface| iface.address == parent)
            .map(|iface| iface.name.clone())
    }

    /// Bind or peer string recorded for `address`. Empty when none was stored.
    pub fn iface_endpoint(&self, address: &AddressHash) -> String {
        self.ifaces
            .iter()
            .find(|iface| iface.address == *address)
            .map(|iface| iface.endpoint.clone())
            .unwrap_or_default()
    }

    /// Connected clients of a `LocalServer`, or `None` for every other kind.
    pub fn local_server_clients(&self, address: &AddressHash) -> Option<u64> {
        let kind = self
            .ifaces
            .iter()
            .find(|iface| iface.address == *address)?
            .kind
            .as_str();
        if kind != "LocalServer" {
            return None;
        }
        let count = self
            .ifaces
            .iter()
            .filter(|iface| iface.parent == Some(*address) && !iface.stop.is_cancelled())
            .count();
        Some(count as u64)
    }

    /// Stop a single interface by address, and any peers it spawned.
    ///
    /// The returned watch becomes true after a parent worker drops its
    /// listener. Callers that ignore it still cancel the worker.
    pub fn stop_iface(
        &mut self,
        address: &AddressHash,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        let children: Vec<AddressHash> = self
            .ifaces
            .iter()
            .filter(|iface| iface.parent == Some(*address))
            .map(|iface| iface.address)
            .collect();
        for child in children {
            let _ = self.stop_iface(&child);
        }
        let index = self
            .ifaces
            .iter()
            .position(|iface| &iface.address == address)?;
        let iface = self.ifaces.remove(index);
        iface.stats.set_online(false);
        iface.stop.cancel();
        self.controls
            .lock()
            .expect("iface control lock")
            .remove(address);
        Some(iface.exited)
    }

    /// Run `f` with the control state of one interface
    /// (Python reads/writes attributes directly on the interface object).
    pub fn with_control<R>(
        &self,
        address: &AddressHash,
        f: impl FnOnce(&mut IfaceControlState) -> R,
    ) -> Option<R> {
        let mut controls = self.controls.lock().expect("iface control lock");
        controls.get_mut(address).map(f)
    }

    fn with_stats(&self, address: &AddressHash, f: impl FnOnce(&InterfaceCounters)) {
        if let Some(iface) = self.ifaces.iter().find(|i| i.address == *address) {
            f(&iface.stats);
        }
    }

    /// Configure the interface mode of an interface
    /// (Python interface `mode` configuration option).
    pub fn set_iface_mode(&self, address: &AddressHash, mode: InterfaceMode) -> bool {
        self.with_control(address, |control| control.mode = mode)
            .is_some()
    }

    /// Configure the nominal bitrate of an interface in bits per second
    /// (Python interface `bitrate` configuration option).
    pub fn set_iface_bitrate(&self, address: &AddressHash, bitrate: u64) -> bool {
        self.with_control(address, |control| control.bitrate = bitrate)
            .is_some()
    }

    /// Mark an interface as a local shared-instance client
    /// (Python `is_local_client_interface`).
    pub fn set_iface_local_client(&self, address: &AddressHash) -> bool {
        self.with_control(address, |control| control.is_local_client = true)
            .is_some()
    }

    /// Bind an interface to a tunnel id
    /// (Python `Interface.tunnel_id`).
    pub fn set_iface_tunnel(&self, address: &AddressHash, tunnel_id: Option<AddressHash>) -> bool {
        self.with_control(address, |control| control.tunnel_id = tunnel_id)
            .is_some()
    }

    /// Configure the interface access code of an interface
    /// (Python `ifac_size` / `networkname` / `passphrase` interface
    /// options; Python `Reticulum._add_interface` derivation).
    pub fn set_iface_ifac(
        &self,
        address: &AddressHash,
        netname: Option<&str>,
        netkey: Option<&str>,
        size: usize,
    ) -> Result<bool, crate::error::RnsError> {
        let key = ifac::IfacKey::derive(netname, netkey, size)?;
        Ok(self
            .with_iface_ifac(address, move |slot| {
                *slot.write().expect("ifac lock") = Some(Arc::new(key));
            })
            .is_some())
    }

    /// Register an interface without starting its worker, so the caller
    /// can publish control state before the worker accepts.
    pub fn open<T: Interface>(&mut self, inner: T) -> InterfaceContext<T> {
        self.new_context(inner)
    }

    /// [`Self::open`] registered under `name`.
    pub fn open_named<T: Interface>(
        &mut self,
        name: impl AsRef<str>,
        inner: T,
    ) -> InterfaceContext<T> {
        let context = self.new_context(inner);
        let address = context.channel.address;
        self.set_iface_name(&address, name.as_ref());
        context
    }

    /// [`Self::open`] with the IFAC slot already populated and, when
    /// `endpoint()` is non-empty, that string as the statistics name.
    pub fn open_with_ifac<T: Interface>(
        &mut self,
        inner: T,
        ifac: Arc<ifac::IfacKey>,
    ) -> InterfaceContext<T> {
        let kind = interface_kind_name::<T>();
        let endpoint = inner.endpoint().to_string();
        let channel = self.new_channel_named(1, &kind, &kind);
        *channel.ifac.write().expect("ifac lock") = Some(ifac);

        let address = channel.address;
        self.apply_type_ingress_policy::<T>(&address);
        // Name and endpoint are recorded before the worker starts, so an
        // accepted client cannot learn a path under the shared type name.
        if let Some(iface) = self
            .ifaces
            .iter_mut()
            .find(|iface| iface.address == address)
        {
            if !endpoint.is_empty() {
                iface.name = endpoint.clone();
            }
            iface.endpoint = endpoint;
        }

        InterfaceContext::<T> {
            inner: Arc::new(Mutex::new(inner)),
            channel,
            cancel: self.cancel.clone(),
        }
    }

    /// Start a worker for an interface registered with [`Self::open`].
    pub fn launch<T, F, R>(&self, context: InterfaceContext<T>, worker: F) -> AddressHash
    where
        T: Interface,
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        self.publish_constructor_bitrate(&context);
        let address = context.channel.address;
        task::spawn(worker(context));
        address
    }

    /// Copy the parent control fields Python copies onto a spawned peer:
    /// mode, gravity, bitrate, announce cap and rate, ingress/egress,
    /// `ic_*` / `ec_*`, and the recursive path-request and
    /// internal-announce flags.
    pub fn copy_spawned_control(&self, parent: &AddressHash, child: &AddressHash) {
        let mut controls = self.controls.lock().expect("iface control lock");
        let Some(source) = controls.get(parent) else {
            return;
        };
        let mode = source.mode;
        let gravity = source.gravity;
        let bitrate = source.bitrate;
        let announce_cap = source.announce_cap;
        let announce_rate_target = source.announce_rate_target;
        let announce_rate_grace = source.announce_rate_grace;
        let announce_rate_penalty = source.announce_rate_penalty;
        let ingress_control = source.ingress_control;
        let egress_control = source.egress_control;
        let recursive_prs = source.recursive_prs;
        let announces_from_internal = source.announces_from_internal;
        let announces_to_internal = source.announces_to_internal;
        let params = *source.params();
        let Some(dest) = controls.get_mut(child) else {
            return;
        };
        dest.mode = mode;
        dest.gravity = gravity;
        dest.bitrate = bitrate;
        dest.announce_cap = announce_cap;
        dest.announce_rate_target = announce_rate_target;
        dest.announce_rate_grace = announce_rate_grace;
        dest.announce_rate_penalty = announce_rate_penalty;
        dest.ingress_control = ingress_control;
        dest.egress_control = egress_control;
        dest.recursive_prs = recursive_prs;
        dest.announces_from_internal = announces_from_internal;
        dest.announces_to_internal = announces_to_internal;
        dest.set_params(params);
    }

    /// Spawn an interface worker with its IFAC slot already populated,
    /// so the worker never observes an unauthenticated frame before the
    /// key is installed (needed on multithreaded runtimes where `spawn`
    /// may begin polling immediately).
    ///
    /// When `endpoint()` is non-empty, that string becomes the statistics
    /// name before the worker starts. A later `set_iface_name` can still
    /// replace it with a config name.
    pub fn spawn_with_ifac<T, F, R>(
        &mut self,
        inner: T,
        worker: F,
        ifac: Arc<ifac::IfacKey>,
    ) -> AddressHash
    where
        T: Interface,
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.open_with_ifac(inner, ifac);
        self.launch(context, worker)
    }

    /// Access the IFAC configuration slot of an interface.
    pub fn with_iface_ifac<R>(
        &self,
        address: &AddressHash,
        f: impl FnOnce(&IfacSlot) -> R,
    ) -> Option<R> {
        self.ifaces
            .iter()
            .find(|iface| &iface.address == address)
            .map(|iface| f(&iface.ifac))
    }

    /// Request tunnel synthesis for an interface
    /// (Python `Interface.wants_tunnel`).
    pub fn set_iface_wants_tunnel(&self, address: &AddressHash, wants: bool) -> bool {
        self.with_control(address, |control| control.wants_tunnel = wants)
            .is_some()
    }

    /// Addresses of interfaces currently requesting tunnel synthesis
    /// (Python `Interface.wants_tunnel`).
    pub fn interfaces_wanting_tunnel(&self) -> Vec<AddressHash> {
        let controls = self.controls.lock().expect("iface control lock");
        self.ifaces
            .iter()
            .filter(|iface| {
                !iface.stop.is_cancelled()
                    && controls
                        .get(&iface.address)
                        .map(|control| control.wants_tunnel)
                        .unwrap_or(false)
            })
            .map(|iface| iface.address)
            .collect()
    }

    /// The tunnel id an interface is bound to, if any.
    pub fn iface_tunnel(&self, address: &AddressHash) -> Option<AddressHash> {
        self.with_control(address, |control| control.tunnel_id)
            .flatten()
    }

    /// Whether an interface is a local shared-instance client.
    pub fn is_local_client_iface(&self, address: &AddressHash) -> bool {
        self.with_control(address, |control| control.is_local_client)
            .unwrap_or(false)
    }

    /// Addresses of live local-client interfaces
    /// (Python `Transport.local_client_interfaces`).
    pub fn local_client_iface_addresses(&self) -> Vec<AddressHash> {
        let controls = self.controls.lock().expect("iface control lock");
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .filter(|iface| {
                controls
                    .get(&iface.address)
                    .map(|control| control.is_local_client)
                    .unwrap_or(false)
            })
            .map(|iface| iface.address)
            .collect()
    }

    /// The interface mode of an interface (default `Full`).
    pub fn iface_mode(&self, address: &AddressHash) -> InterfaceMode {
        self.with_control(address, |control| control.mode)
            .unwrap_or(InterfaceMode::Full)
    }

    /// Account a received announce on an interface
    /// (Python `Interface.received_announce`).
    pub fn received_announce(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.received_announce(now));
        self.with_stats(address, |stats| stats.count_announce_rx(bytes));
    }

    /// Account a sent announce on an interface
    /// (Python `Interface.sent_announce`).
    pub fn sent_announce(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.sent_announce(now));
        self.with_stats(address, |stats| stats.count_announce_tx(bytes));
    }

    /// Account a received path request on an interface
    /// (Python `Interface.received_path_request`).
    pub fn received_path_request(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.received_path_request(now));
        self.with_stats(address, |stats| stats.count_path_request_rx(bytes));
    }

    /// Account a sent path request on an interface
    /// (Python `Interface.sent_path_request`).
    pub fn sent_path_request(&self, address: &AddressHash, bytes: usize) {
        let now = tokio::time::Instant::now();
        self.with_control(address, |control| control.sent_path_request(now));
        self.with_stats(address, |stats| stats.count_path_request_tx(bytes));
    }

    /// Account an early packet filter hit on an interface
    /// (Python `Interface.packet_filter_hit`).
    pub fn count_packet_filter_hit(&self, address: &AddressHash) {
        self.with_stats(address, |stats| stats.count_packet_filter_hit());
    }

    /// Account a protocol violation on an interface
    /// (Python `Interface.protocol_violation`).
    pub fn count_protocol_violation(&self, address: &AddressHash) {
        self.with_stats(address, |stats| stats.count_protocol_violation());
    }

    /// Account an IFAC violation on an interface
    /// (Python `Interface.ifac_violation`).
    pub fn count_ifac_violation(&self, address: &AddressHash) {
        self.with_stats(address, |stats| stats.count_ifac_violation());
    }

    /// Release held announces on all interfaces whose burst penalty has
    /// elapsed (Python `Interface.process_held_announces`, driven by
    /// `threading.Timer` there and by the transport ticker here).
    /// Returns the interface each packet was held on, for re-injection.
    pub fn release_held_announces(&self) -> Vec<(AddressHash, Packet)> {
        let now = tokio::time::Instant::now();
        let mut controls = self.controls.lock().expect("iface control lock");
        let mut released = Vec::new();
        for (address, control) in controls.iter_mut() {
            while let Some(packet) = control.release_held_announce(now) {
                released.push((*address, packet));
            }
        }
        released
    }

    /// Transmit one queued announce per interface
    /// (Python `Interface.process_announce_queue`: the selected announce is
    /// transmitted directly — it does not re-enter `Transport.outbound`, so
    /// the announce-cap gate must not be applied a second time, which would
    /// otherwise re-queue it and starve the queue forever).
    pub async fn process_announce_queues(&self) {
        let now = tokio::time::Instant::now();
        let drained = {
            let mut controls = self.controls.lock().expect("iface control lock");
            let mut drained = Vec::new();
            for (address, control) in controls.iter_mut() {
                if let Some(packet) = control.take_queued_announce(now) {
                    control.sent_announce(now);
                    drained.push((*address, packet));
                }
            }
            drained
        };

        for (address, packet) in drained {
            let Some(iface) = self
                .ifaces
                .iter()
                .find(|iface| iface.address == address && !iface.stop.is_cancelled())
            else {
                continue;
            };
            let size = control::packet_wire_len(&packet);
            iface.stats.count_announce_tx(size);
            let _ = iface
                .tx_send
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(address),
                    packet: Box::new(packet),
                })
                .await;
        }
    }

    /// Runtime address to a stable identity (kind, config name, and bind
    /// or peer endpoint), so a restart can resolve persisted paths onto
    /// the new `AddressHash`.
    pub fn stable_iface_map(&self) -> HashMap<AddressHash, AddressHash> {
        let mut map = HashMap::new();
        for iface in &self.ifaces {
            if iface.stop.is_cancelled() {
                continue;
            }
            map.insert(iface.address, iface_stable_id(iface));
        }
        map
    }

    /// Classify live interfaces once.
    ///
    /// The map is stable id to the single runtime address that owns it.
    /// The set is every stable id shared by more than one live interface.
    /// Load skips those ids instead of attaching every saved path to the
    /// last interface.
    pub fn classify_stable_ids(&self) -> (HashMap<AddressHash, AddressHash>, HashSet<AddressHash>) {
        let mut counts: HashMap<AddressHash, usize> = HashMap::new();
        let mut first: HashMap<AddressHash, AddressHash> = HashMap::new();
        for iface in &self.ifaces {
            if iface.stop.is_cancelled() {
                continue;
            }
            let id = iface_stable_id(iface);
            *counts.entry(id).or_insert(0) += 1;
            first.entry(id).or_insert(iface.address);
        }
        let mut unique = HashMap::new();
        let mut ambiguous = HashSet::new();
        for (id, count) in counts {
            if count == 1 {
                if let Some(address) = first.remove(&id) {
                    unique.insert(id, address);
                }
            } else {
                ambiguous.insert(id);
            }
        }
        (unique, ambiguous)
    }

    /// Addresses of all live interfaces with their online status,
    /// for fan-out decisions (path request forwarding).
    pub fn live_iface_addresses(&self) -> Vec<(AddressHash, bool)> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| (iface.address, iface.stats.online()))
            .collect()
    }

    /// Kind string of a live interface (used for Python-parity
    /// per-interface capabilities such as link MTU negotiation).
    pub fn iface_kind(&self, address: &AddressHash) -> Option<String> {
        self.ifaces
            .iter()
            .find(|iface| &iface.address == address && !iface.stop.is_cancelled())
            .map(|iface| iface.kind.clone())
    }

    /// The lowest bitrate of all online interfaces with a configured
    /// bitrate (Python `Transport.lowest_interface_bitrate`, recomputed
    /// on the jobs loop there; `None` when no online interface has one).
    pub fn lowest_interface_bitrate(&self) -> Option<u64> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled() && iface.stats.online())
            .filter_map(|iface| self.with_control(&iface.address, |c| c.bitrate))
            .min()
    }

    /// The hardware MTU of the first live interface (single-interface
    /// instances have an unambiguous next hop).
    /// Address of the first live interface.
    pub fn first_iface_address(&self) -> Option<AddressHash> {
        self.ifaces
            .first()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| iface.address)
    }

    pub fn first_iface_hw_mtu(&self) -> Option<usize> {
        self.ifaces
            .first()
            .filter(|iface| !iface.stop.is_cancelled())
            .and_then(|iface| self.iface_hw_mtu(&iface.address))
    }

    /// Latest radio channel readings for `address`.
    pub fn radio_telemetry(&self, address: &AddressHash) -> RadioTelemetry {
        self.ifaces
            .iter()
            .find(|iface| iface.address == *address)
            .map(|iface| iface.stats.radio_telemetry())
            .unwrap_or_default()
    }

    /// Path-signalling hardware MTU.
    ///
    /// Bitrate tiers match `Interface.optimise_mtu`, including `None`
    /// below 62_500 bps. The `min` with 524288, `TCPInterface.HW_MTU`
    /// (262144), or 1048576 is this function's ceiling, not a step
    /// `optimise_mtu` takes. Auto keeps its fixed hardware MTU of 1196.
    /// Weave keeps its fixed hardware MTU of 1024.
    pub fn iface_hw_mtu(&self, address: &AddressHash) -> Option<usize> {
        let kind = self.iface_kind(address)?;
        // Fixed hardware MTU, not a bitrate tier.
        if kind == "AutoInterface" || kind == "AutoPeer" {
            return Some(1_196);
        }
        if kind == "WeaveInterface" || kind == "WeaveInterfacePeer" {
            return Some(weave::HW_MTU);
        }
        // Ceilings applied by this function only. `optimise_mtu` does
        // not take `min` with these values. TCP uses `TCPInterface.HW_MTU`.
        // 1048576 is above every tier and is not used when the tier is `None`.
        let ceiling = match kind.as_str() {
            "LocalServer" | "LocalClient" => 524_288,
            "TcpClient" | "TcpServer" => 262_144,
            "BackboneClient" | "BackboneServer" => 1_048_576,
            _ => return None,
        };
        let bitrate = self.with_control(address, |control| control.bitrate)?;
        let tier = match bitrate {
            1_000_000_000.. => 524_288,
            750_000_000.. => 262_144,
            400_000_000.. => 131_072,
            200_000_000.. => 65_536,
            100_000_000.. => 32_768,
            10_000_000.. => 16_384,
            5_000_000.. => 8_192,
            2_000_000.. => 4_096,
            1_000_000.. => 2_048,
            62_500.. => 1_024,
            _ => return None,
        };
        Some(tier.min(ceiling))
    }

    /// Snapshot of the statistics of all live interfaces.
    pub fn stats(&self) -> Vec<InterfaceStats> {
        self.ifaces
            .iter()
            .filter(|iface| !iface.stop.is_cancelled())
            .map(|iface| InterfaceStats {
                address: iface.address,
                name: iface.name.clone(),
                kind: iface.kind.clone(),
                sent: iface.stats.sent(),
                received: iface.stats.received(),
                tx_bytes: iface.stats.tx_bytes(),
                rx_bytes: iface.stats.rx_bytes(),
                online: iface.stats.online(),
                announces_received: iface.stats.announces_received(),
                announces_sent: iface.stats.announces_sent(),
                announce_bytes_received: iface.stats.announce_bytes_received(),
                announce_bytes_sent: iface.stats.announce_bytes_sent(),
                path_requests_received: iface.stats.path_requests_received(),
                path_requests_sent: iface.stats.path_requests_sent(),
                protocol_violations: iface.stats.protocol_violations(),
                ifac_violations: iface.stats.ifac_violations(),
                packet_filter_hits: iface.stats.packet_filter_hits(),
                rssi: iface.stats.rssi(),
                snr: iface.stats.snr(),
                quality: iface.stats.quality(),
            })
            .collect()
    }

    /// Store a constructor bitrate after `new_context` has inserted the
    /// generic default and before the worker is scheduled. An `async fn`
    /// body does not run until the task is polled, which is after `spawn`
    /// has returned.
    fn publish_constructor_bitrate<T: Interface>(&self, context: &InterfaceContext<T>) {
        if let Some(rate) = context.inner.lock().unwrap().constructor_bitrate() {
            self.set_iface_bitrate(&context.channel.address, rate);
        }
    }

    pub fn spawn<T: Interface, F, R>(&mut self, inner: T, worker: F) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.open(inner);
        self.launch(context, worker)
    }

    /// Spawn an interface worker registered under a human-readable `name`
    /// (the configuration name of the interface).
    pub fn spawn_named<T: Interface, F, R>(
        &mut self,
        name: impl AsRef<str>,
        inner: T,
        worker: F,
    ) -> AddressHash
    where
        F: FnOnce(InterfaceContext<T>) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let context = self.open_named(name, inner);
        self.launch(context, worker)
    }

    pub fn receiver(&self) -> Arc<tokio::sync::Mutex<InterfaceRxReceiver>> {
        self.rx_recv.clone()
    }

    pub fn cleanup(&mut self) {
        self.ifaces.retain(|iface| !iface.stop.is_cancelled());
    }

    pub async fn send(&self, message: TxMessage) {
        let is_announce = message.packet.header.packet_type == PacketType::Announce;
        let hops_delta = self.local_hops_delta.load(Ordering::Relaxed);
        let rewrite_hops = hops_delta != 0 && !self.connected_to_shared_instance();
        let transport_id = if rewrite_hops {
            *self.transport_identity.lock().expect("transport id")
        } else {
            None
        };

        for iface in &self.ifaces {
            let should_send = match message.tx_type {
                TxMessageType::Broadcast(address) => {
                    let mut should_send = true;
                    if let Some(address) = address {
                        should_send = address != iface.address;
                    }

                    // Announce forwarding policy between interface modes
                    // (Python `Transport.outbound` MODE_INTERNAL /
                    // MODE_ROAMING / MODE_BOUNDARY gating). Directly
                    // addressed transmissions (path responses) and locally
                    // originated announces bypass the policy.
                    if should_send && is_announce && message.packet.header.hops > 0 {
                        should_send = self.announce_forwarding_allowed(&iface.address, address);
                    }

                    should_send
                }
                TxMessageType::Direct(address) => address == iface.address,
            };

            if should_send && !iface.stop.is_cancelled() {
                // Egress airtime budgeting for forwarded announces
                // (Python announce cap + `Interface.announce_queue`).
                // Locally originated announces (hops == 0) are always sent.
                if is_announce && message.packet.header.hops > 0 {
                    let now = tokio::time::Instant::now();
                    let size = control::packet_wire_len(&message.packet);
                    let allowed = self.with_control(&iface.address, |control| {
                        if control.try_transmit_announce(size, now) {
                            control.sent_announce(now);
                            true
                        } else {
                            control.queue_announce((*message.packet).clone(), now);
                            false
                        }
                    });

                    if !allowed.unwrap_or(true) {
                        continue;
                    }
                }

                // Announce traffic stats (Python `Transport.outbound` calls
                // `interface.sent_announce` for every transmitted announce,
                // including locally originated ones).
                if is_announce {
                    let size = control::packet_wire_len(&message.packet);
                    iface.stats.count_announce_tx(size);
                }

                let mut outbound = message.clone();
                let local_client = self.is_local_client_iface(&iface.address);
                if rewrite_hops
                    && outbound.packet.header.hops == 0
                    && outbound.packet.header.destination_type != DestinationType::Plain
                    && outbound.packet.header.destination_type != DestinationType::Group
                    && !local_client
                    && iface.kind != "LocalServer"
                {
                    let upgrade = outbound.packet.header.packet_type == PacketType::Announce
                        && outbound.packet.header.header_type == HeaderType::Type1;
                    outbound.packet.header.hops = hops_delta;
                    if upgrade {
                        if let Some(transport_id) = transport_id {
                            outbound.packet.header.header_type = HeaderType::Type2;
                            outbound.packet.header.propagation_type = PropagationType::Transport;
                            outbound.packet.transport = Some(transport_id);
                        }
                    }
                }

                let _ = iface.tx_send.send(outbound).await;
            }
        }
    }

    /// Whether an announce received on `from_iface` (or locally originated
    /// when `None`) may be forwarded onto `to_iface`
    /// (Python `Transport.outbound` mode interaction rules).
    pub fn announce_forwarding_allowed(
        &self,
        to_iface: &AddressHash,
        from_iface: Option<AddressHash>,
    ) -> bool {
        let to_mode = self.iface_mode(to_iface);

        match to_mode {
            InterfaceMode::Internal => {
                // Only boundary-mode or explicitly enabled interfaces may
                // inject announces into internal-mode interfaces.
                match from_iface {
                    None => true,
                    Some(from) => {
                        let from_mode = self.iface_mode(&from);
                        from_mode == InterfaceMode::Boundary
                            || self
                                .with_control(&from, |control| {
                                    control.announces_to_internal == Some(true)
                                })
                                .unwrap_or(false)
                    }
                }
            }
            InterfaceMode::Roaming => match from_iface {
                None => true,
                Some(from) => {
                    let from_mode = self.iface_mode(&from);
                    from_mode != InterfaceMode::Roaming && from_mode != InterfaceMode::Boundary
                }
            },
            InterfaceMode::Boundary => match from_iface {
                None => true,
                Some(from) => self.iface_mode(&from) != InterfaceMode::Roaming,
            },
            _ => true,
        }
    }
}

impl Drop for InterfaceManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Stable identity of an interface across process restarts.
/// The runtime `AddressHash` from `new_channel_named` is a fresh random
/// seed and is not persisted.
///
/// The id is the interface kind, the statistics name, and the bind or
/// peer string when one was recorded. Types which record neither a
/// distinct name nor a bind or peer string still share an id.
fn stable_interface_id(kind: &str, name: &str, endpoint: &str) -> AddressHash {
    let mut label = String::with_capacity(kind.len() + name.len() + endpoint.len() + 2);
    label.push_str(kind);
    label.push('\0');
    label.push_str(name);
    if !endpoint.is_empty() {
        label.push('\0');
        label.push_str(endpoint);
    }
    AddressHash::new_from_slice(label.as_bytes())
}

fn iface_stable_id(iface: &LocalInterface) -> AddressHash {
    stable_interface_id(&iface.kind, &iface.name, &iface.endpoint)
}

/// Short type name of an interface, used as statistics `kind`.
fn interface_kind_name<T: ?Sized>() -> String {
    let full = std::any::type_name::<T>();
    full.rsplit("::").next().unwrap_or(full).to_string()
}

// ---------------------------------------------------------------------------
// Interface status snapshot for tooling (`rnstatus`, Phase 8 utilities).
//
// Per-interface statistics (Python `Interface.ifstats`: sent/received/txb/rxb
// counters plus names, kinds and online status) are implemented by
// [`InterfaceStats`] above (Phase 5.9); `IfaceStats` is kept as an alias for
// the utilities.
// ---------------------------------------------------------------------------

/// Status of one spawned interface, as reported to `rnstatus`.
pub type IfaceStats = InterfaceStats;

#[cfg(test)]
mod tests {
    use super::*;

    struct TestIface;

    impl Interface for TestIface {
        fn mtu() -> usize {
            500
        }
    }

    async fn test_worker(context: InterfaceContext<TestIface>) {
        let InterfaceContext { channel, .. } = context;
        let InterfaceChannel {
            address,
            rx_channel,
            mut tx_channel,
            stop,
            stats,
            ..
        } = channel;

        stats.set_online(true);

        loop {
            let packet = tokio::select! {
                _ = stop.cancelled() => break,
                Some(message) = tx_channel.recv() => *message.packet,
            };

            stats.count_tx(128);
            let _ = rx_channel.send(RxMessage { address, packet: Box::new(packet) }).await;
        }
    }

    #[tokio::test]
    async fn interface_stats_counters() {
        let mut manager = InterfaceManager::new(16);

        let address = manager.spawn_named("test iface", TestIface, test_worker);

        // let the worker come up and register itself online
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let stats = manager.stats();
        assert_eq!(stats.len(), 1);
        let stats = &stats[0];
        assert_eq!(stats.name, "test iface");
        assert_eq!(stats.kind, "TestIface");
        assert_eq!(stats.address, address);
        assert!(stats.online);

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Box::new(Packet::default()),
            })
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let stats = &manager.stats()[0];
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.tx_bytes, 128);

        manager.stop_iface(&address);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(manager.stats().is_empty());
    }

    #[tokio::test]
    async fn locally_originated_announce_counts_announces_sent() {
        // Python `Transport.outbound` calls `interface.sent_announce` for
        // every transmitted announce, including locally originated ones
        // (hops == 0). Regression test: own announces must show up in the
        // `announces_sent` counter.
        let mut manager = InterfaceManager::new(16);
        let address = manager.spawn_named("announce iface", TestIface, test_worker);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut packet = Packet::default();
        packet.header.packet_type = PacketType::Announce;
        packet.header.hops = 0;

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Box::new(packet),
            })
            .await;

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let stats = &manager.stats()[0];
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.announces_sent, 1);
        assert_eq!(stats.announce_bytes_sent, 19);

        manager.stop_iface(&address);
    }

    #[test]
    fn radio_quality_counters_default_to_unreported() {
        let counters = InterfaceCounters::default();
        assert_eq!(counters.rssi(), None);
        assert_eq!(counters.snr(), None);
        assert_eq!(counters.quality(), None);

        let stats = InterfaceStats {
            address: AddressHash::new_empty(),
            name: "rnode".into(),
            kind: "RnodeInterface".into(),
            sent: 0,
            received: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            online: true,
            announces_received: 0,
            announces_sent: 0,
            announce_bytes_received: 0,
            announce_bytes_sent: 0,
            path_requests_received: 0,
            path_requests_sent: 0,
            protocol_violations: 0,
            ifac_violations: 0,
            packet_filter_hits: 0,
            rssi: None,
            snr: None,
            quality: None,
        };
        assert_eq!(stats.rssi, None);
    }

    #[test]
    fn radio_quality_publish_keeps_previous_readings() {
        let counters = InterfaceCounters::default();
        // RNode-style telemetry: RSSI -87 dBm, SNR 9.25 dB, quality 75%.
        counters.set_radio_quality(Some(-87), Some(9.25), Some(75.0));
        assert_eq!(counters.rssi(), Some(-87));
        assert_eq!(counters.snr(), Some(9.25));
        assert_eq!(counters.quality(), Some(75.0));

        // A partial update (RSSI only) keeps the other readings.
        counters.set_radio_quality(Some(-90), None, None);
        assert_eq!(counters.rssi(), Some(-90));
        assert_eq!(counters.snr(), Some(9.25));
        assert_eq!(counters.quality(), Some(75.0));

        // Values round-trip through the snapshot.
        let counters = InterfaceCounters::default();
        counters.set_radio_quality(Some(-100), Some(-7.5), Some(0.0));
        assert_eq!(counters.rssi(), Some(-100));
        assert_eq!(counters.snr(), Some(-7.5));
        assert_eq!(counters.quality(), Some(0.0));
    }

    #[test]
    fn hardware_mtu_follows_bitrate_tiers() {
        // Python `Interface.optimise_mtu`, including the step just below
        // each threshold. Backbone's class MTU is above every tier, so
        // the reported value is the tier (never 1048576).
        let tiers = [
            (1_000_000_000, Some(524_288usize)),
            (999_999_999, Some(262_144)),
            (750_000_000, Some(262_144)),
            (749_999_999, Some(131_072)),
            (400_000_000, Some(131_072)),
            (399_999_999, Some(65_536)),
            (200_000_000, Some(65_536)),
            (199_999_999, Some(32_768)),
            (100_000_000, Some(32_768)),
            (99_999_999, Some(16_384)),
            (10_000_000, Some(16_384)),
            (9_999_999, Some(8_192)),
            (5_000_000, Some(8_192)),
            (4_999_999, Some(4_096)),
            (2_000_000, Some(4_096)),
            (1_999_999, Some(2_048)),
            (1_000_000, Some(2_048)),
            (999_999, Some(1_024)),
            (62_500, Some(1_024)),
            (62_499, None),
            (0, None),
        ];

        let mut manager = InterfaceManager::new(4);
        for (bitrate, expected) in tiers {
            for kind in ["BackboneClient", "BackboneServer"] {
                let channel = manager.new_channel_named(1, kind, kind);
                assert!(manager.set_iface_bitrate(&channel.address, bitrate));
                assert_eq!(
                    manager.iface_hw_mtu(&channel.address),
                    expected,
                    "{kind} at {bitrate}"
                );
            }
        }

        // Unset bitrate is the interface default 62500, which is the
        // 1024 tier, not the backbone class MTU.
        let unset = manager.new_channel_named(1, "bb", "BackboneClient");
        assert_eq!(manager.iface_hw_mtu(&unset.address), Some(1_024));

        for kind in ["TcpClient", "TcpServer"] {
            let channel = manager.new_channel_named(1, kind, kind);
            assert!(manager.set_iface_bitrate(&channel.address, 1_000_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(262_144));
            assert!(manager.set_iface_bitrate(&channel.address, 750_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(262_144));
            assert!(manager.set_iface_bitrate(&channel.address, 400_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(131_072));
            assert!(manager.set_iface_bitrate(&channel.address, 62_499));
            assert_eq!(manager.iface_hw_mtu(&channel.address), None);
        }

        for kind in ["LocalClient", "LocalServer"] {
            let channel = manager.new_channel_named(1, kind, kind);
            assert!(manager.set_iface_bitrate(&channel.address, 1_000_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(524_288));
            assert!(manager.set_iface_bitrate(&channel.address, 100_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(32_768));
            assert!(manager.set_iface_bitrate(&channel.address, 62_499));
            assert_eq!(manager.iface_hw_mtu(&channel.address), None);
        }

        for kind in ["AutoInterface", "AutoPeer"] {
            let channel = manager.new_channel_named(1, kind, kind);
            assert!(manager.set_iface_bitrate(&channel.address, 1_000_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(1_196));
            assert!(manager.set_iface_bitrate(&channel.address, 0));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(1_196));
        }

        for kind in ["WeaveInterface", "WeaveInterfacePeer"] {
            let channel = manager.new_channel_named(1, kind, kind);
            assert!(manager.set_iface_bitrate(&channel.address, 1_000_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(1_024));
            assert!(manager.set_iface_bitrate(&channel.address, 62_499));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(1_024));
            assert!(manager.set_iface_bitrate(&channel.address, 0));
            assert_eq!(manager.iface_hw_mtu(&channel.address), Some(1_024));
        }

        for kind in [
            "UdpInterface",
            "SerialInterface",
            "KissInterface",
            "TestIface",
        ] {
            let channel = manager.new_channel_named(1, kind, kind);
            assert!(manager.set_iface_bitrate(&channel.address, 1_000_000_000));
            assert_eq!(manager.iface_hw_mtu(&channel.address), None, "{kind}");
        }

        assert_eq!(manager.iface_hw_mtu(&AddressHash::new_empty()), None);
    }

    #[tokio::test]
    async fn stable_ids_follow_endpoint_and_skip_collisions() {
        use super::tcp_client::TcpClient;
        use super::udp::UdpInterface;

        let mut manager = InterfaceManager::new(4);

        let udp_a = manager.new_context(UdpInterface::new("127.0.0.1:1", None, false));
        let udp_a_addr = udp_a.channel.address;
        drop(udp_a);
        let udp_b = manager.new_context(UdpInterface::new("127.0.0.1:2", None, false));
        let udp_b_addr = udp_b.channel.address;
        drop(udp_b);

        let (map, ambiguous) = manager.classify_stable_ids();
        assert!(ambiguous.is_empty());
        assert_eq!(map.len(), 2, "unnamed UDP interfaces must not share an id");
        assert!(map.values().any(|address| *address == udp_a_addr));
        assert!(map.values().any(|address| *address == udp_b_addr));

        drop(manager.new_context(UdpInterface::new("127.0.0.1:1", None, false)));
        let (map, ambiguous) = manager.classify_stable_ids();
        assert!(
            !map.values().any(|address| *address == udp_a_addr),
            "two live interfaces with one id must not own persisted paths"
        );
        assert!(map.values().any(|address| *address == udp_b_addr));
        assert!(!ambiguous.is_empty());

        let named_a = manager.new_context(UdpInterface::new("127.0.0.1:9", None, false));
        let named_a_addr = named_a.channel.address;
        drop(named_a);
        manager.set_iface_name(&named_a_addr, "west");
        let named_b = manager.new_context(UdpInterface::new("127.0.0.1:9", None, false));
        let named_b_addr = named_b.channel.address;
        drop(named_b);
        manager.set_iface_name(&named_b_addr, "east");
        let (map, _) = manager.classify_stable_ids();
        assert!(map.values().any(|address| *address == named_a_addr));
        assert!(
            map.values().any(|address| *address == named_b_addr),
            "a unique config name plus the bind endpoint stays distinct"
        );

        let tcp_a = manager.new_context(TcpClient::new("10.0.0.1:80"));
        let tcp_a_addr = tcp_a.channel.address;
        drop(tcp_a);
        let tcp_b = manager.new_context(TcpClient::new("10.0.0.2:80"));
        let tcp_b_addr = tcp_b.channel.address;
        drop(tcp_b);
        let (map, _) = manager.classify_stable_ids();
        assert!(map.values().any(|address| *address == tcp_a_addr));
        assert!(map.values().any(|address| *address == tcp_b_addr));

        let same_a = manager.new_context(TcpClient::new("10.1.0.1:80"));
        let same_a_addr = same_a.channel.address;
        drop(same_a);
        manager.set_iface_name(&same_a_addr, "uplink");
        let same_b = manager.new_context(TcpClient::new("10.1.0.1:80"));
        let same_b_addr = same_b.channel.address;
        drop(same_b);
        manager.set_iface_name(&same_b_addr, "uplink");
        let (map, _) = manager.classify_stable_ids();
        assert!(
            !map.values()
                .any(|address| *address == same_a_addr || *address == same_b_addr),
            "interfaces that still share an id are skipped"
        );
    }

    #[tokio::test]
    async fn spawn_with_ifac_names_a_nonempty_endpoint() {
        use super::ifac::IfacKey;
        use super::tcp_client::TcpClient;

        let mut manager = InterfaceManager::new(4);
        let key = Arc::new(IfacKey::derive(Some("net"), Some("pass"), 8).expect("ifac"));
        let addressed = manager.spawn_with_ifac(
            TcpClient::new("192.0.2.10:4242"),
            TcpClient::spawn,
            Arc::clone(&key),
        );
        let bare = manager.spawn_with_ifac(TestIface, test_worker, key);
        let stats = manager.stats();
        let named = stats
            .iter()
            .find(|stat| stat.address == addressed)
            .expect("named client");
        assert_eq!(named.name, "192.0.2.10:4242");
        let unnamed = stats
            .iter()
            .find(|stat| stat.address == bare)
            .expect("unnamed iface");
        assert_eq!(unnamed.name, "TestIface");
        let (map, ambiguous) = manager.classify_stable_ids();
        assert!(ambiguous.is_empty());
        assert!(map.values().any(|address| *address == addressed));
    }
}
