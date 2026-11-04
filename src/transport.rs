use std::collections::HashMap;
use std::time::Duration;

use alloc::sync::Arc;
use rand_core::{OsRng, RngCore};
use reticulum_core::identity::Signer;
use tokio::sync::{broadcast, Mutex, MutexGuard};
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
#[cfg(not(test))]
use crate::channel::{self, Channel};
use crate::destination::link::{
    Link, LinkEventData, LinkEventSink, LinkExt, LinkExtHandlePacket, LinkHandleResult, LinkId,
    LinkPayload, LinkPayloadSink, LinkStatus, KEEPALIVE, STALE_GRACE, STALE_TIME,
};
use crate::destination::{
    DestinationAnnounce, DestinationDesc, DestinationHandleStatus, DestinationName,
    GroupInputDestination, GroupOutputDestination, PlainInputDestination, ProofStrategy,
    SingleInputDestination, SingleOutputDestination,
};
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::identity::{Identity, PrivateIdentity};
use crate::iface::{
    InterfaceManager, InterfaceMode, InterfaceRxReceiver, RxMessage, TxMessage, TxMessageType,
};
use crate::packet::{
    DestinationType, Header, HeaderType, Packet, PacketContext, PacketDataBuffer, PacketType,
    PACKET_MDU,
};
use crate::resource::{
    self,
    manager::{
        msgpack_bin, pack_request, pack_request_element, pack_response, packet_response_size,
        request_id as make_request_id, PendingRequest, RequestContext as RequestCtx,
        RequestEvent, RequestEventData, RequestHandlerConfig, RequestOptions, RequestResponse,
        ResourceManager, ResourceStrategy,
    },
    ResourceEvent, ResourceOptions, ResourceTx,
};
use crate::serde::Serialize;
use crate::storage::{
    KnownDestinations, KnownRatchets, Storage, DESTINATION_TABLE_FILE, PACKET_HASHLIST_FILE,
    TUNNELS_FILE,
};

mod announce_limits;
mod announce_table;
mod blackholes;
mod link_table;
mod management;
mod packet_cache;
mod path_requests;
mod path_table;
mod tunnels;

pub use blackholes::{BlackholeEntry, Blackholes, SharedBlackholes};

use self::announce_limits::AnnounceLimits;
use self::announce_table::AnnounceTable;
use self::link_table::LinkTable;
use self::packet_cache::PacketCache;
use self::path_requests::{create_path_request_destination, PathRequests, TagBytes};
use self::path_table::PathTable;
use self::tunnels::{TunnelPath, Tunnels};

pub use self::tunnels::{
    decode_tunnel_synthesize as decode_tunnel_synthesis, TUNNEL_SYNTHESIZE_LENGTH, TUNNEL_TIMEOUT,
};

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

/// Grace time before a path response announce is made, allows directly
/// reachable peers to respond first (Python `PATH_REQUEST_GRACE`).
pub const PATH_REQUEST_GRACE: Duration = Duration::from_millis(400);
/// Extra grace for roaming-mode interfaces (Python `PATH_REQUEST_RG`).
pub const PATH_REQUEST_RG: Duration = Duration::from_millis(1500);
/// Random window for announce rebroadcast (Python `PATHFINDER_RW`).
pub const PATHFINDER_RW: Duration = Duration::from_millis(500);

pub use path_requests::PATH_REQUEST_TIMEOUT;

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
    /// Whether the transport already decrypted the payload (SINGLE
    /// destinations); receivers must not decrypt again.
    pub decrypted: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TimerConfig {
    pub link_check: Duration,
    pub in_link_stale: Duration,
    pub in_link_close: Duration,
    pub out_link_restart: Duration,
    pub out_link_stale: Duration,
    pub out_link_close: Duration,
    pub out_link_repeat: Duration,
    pub out_link_keep: Duration,
    pub iface_cleanup: Duration,
    pub announces_retransmit: Duration,
    pub old_announces_retransmit: Duration,
    pub keep_packet_cached: Duration,
    pub packet_cache_cleanup: Duration,
    pub resource_watchdog: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            link_check: Duration::from_secs(1),
            // Unknown-RTT defaults. Once RTT is known the link replaces
            // these with `clamp(rtt * (360/1.75), 5, 360)` and `2 * keepalive`.
            in_link_stale: STALE_TIME,
            in_link_close: STALE_GRACE,
            out_link_restart: Duration::from_secs(60),
            out_link_stale: STALE_TIME,
            out_link_close: STALE_GRACE,
            out_link_repeat: Duration::from_secs(6),
            out_link_keep: KEEPALIVE,
            iface_cleanup: Duration::from_secs(10),
            announces_retransmit: Duration::from_secs(1),
            old_announces_retransmit: Duration::from_secs(60),
            keep_packet_cached: Duration::from_secs(180),
            packet_cache_cleanup: Duration::from_secs(90),
            resource_watchdog: Duration::from_secs(1),
        }
    }
}

pub struct TransportConfig {
    name: String,
    identity: PrivateIdentity,
    retransmit: bool,

    /// If `false`, `Transport` will replace known routes to distant destinations
    /// only if they are shorter (fewer hops) than the new one.
    /// If `true`, routes will also be replaced if the new route is equally long.
    /// So newer routes are preferred over older ones.
    reroute_eager: bool,

    /// Attempt to reopen lost links once they have been closed.
    restart_outlinks: bool,

    /// Resend announces of remote destinations at a slower pace once
    /// the initial round of announces is over.
    announce_forever: bool,

    /// Signal the next-hop hardware MTU in link requests
    /// (Python `Reticulum.link_mtu_discovery`, default enabled).
    link_mtu_discovery: bool,
    /// Inbound queue lengths per traffic class
    /// (Python `qlen_in_data`/`qlen_in_announce`/`qlen_in_pr`/`qlen_in_il`).
    inbound_queue_lengths: [usize; 4],

    /// Publish this node's blackhole list
    /// (Python `publish_blackhole_enabled`).
    blackhole_publish: bool,
    /// Remote identities whose persisted blackhole lists are trusted on
    /// reload (Python `Reticulum.blackhole_sources`).
    blackhole_sources: Vec<crate::hash::AddressHash>,

    /// Capacity of the internal event broadcast channels
    /// (announce/link/received-data/iface-message fan-out). Each slot of
    /// the data-bearing channels costs a full packet buffer, so RAM-
    /// constrained embedders set this low (e.g. 2); 16 matches the
    /// historical fixed value.
    pub channel_capacity: usize,
    /// Bound on retained announce packets (each cached announce costs a
    /// full packet buffer). 0 disables announce caching; RAM-constrained
    /// embedders set this low (e.g. 2). 8192 matches the historical cap.
    pub announce_cache_capacity: usize,
    /// Per-metric bound on retained per-packet radio stats (RSSI/SNR/
    /// quality) for the local-client RPC cache. 0 disables history —
    /// lookups then always return `None`. 512 matches Python
    /// `Transport.LOCAL_CLIENT_CACHE_MAXSIZE`.
    pub phy_cache_capacity: usize,
    /// Storage backend for identity & destination persistence. When unset,
    /// known destinations and ratchets are kept in memory only.
    storage: Option<std::sync::Arc<dyn Storage>>,

    /// Prove packets with implicit proofs (signature only) instead of
    /// explicit proofs (packet hash + signature). Defaults to `true`,
    /// matching Python `use_implicit_proof`.
    use_implicit_proof: bool,

    /// Rewrite hops-0 packets onto the wider network
    /// (Python `local_hops_delta`, default off). The sampled value is in `2..=7`.
    local_hops_delta: bool,

    /// Spawn the resource-transfer watchdog task. Its future carries
    /// inline resource packets (~2.5 KB of state machine); RAM-
    /// constrained embedders that never run resource transfers set
    /// this to false. Default true (Python parity).
    pub enable_resource_watchdog: bool,
    pub(crate) timer_config: TimerConfig,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    /// Announce app data (empty when the announce carried none).
    pub app_data: PacketDataBuffer,
    /// Public ratchet key carried by the announce, if any.
    pub ratchet: Option<[u8; reticulum_core::identity::RATCHET_KEY_LENGTH]>,
}

impl AnnounceEvent {
    /// Whether this announce matches a Python-style aspect filter
    /// (`AnnounceHandler(aspect_filter=...)`): true when the filter is
    /// `None`/empty, or when the announced destination's first aspect hash
    /// equals the hash of `app_name + "." + aspect`.
    pub async fn matches_aspect(&self, app_name: &str, aspect: Option<&str>) -> bool {
        let Some(aspect) = aspect else { return true };
        if aspect.is_empty() {
            return true;
        }
        let destination = self.destination.lock().await;
        let expected = DestinationName::new(app_name, aspect);
        expected.address_hash_for(&destination.identity) == destination.desc.address_hash
    }
}

#[derive(Clone)]
struct BroadcastLinkEventSink(broadcast::Sender<LinkEventData>);
impl From<broadcast::Sender<LinkEventData>> for BroadcastLinkEventSink {
    fn from(sender: broadcast::Sender<LinkEventData>) -> Self {
        Self(sender)
    }
}

impl LinkEventSink for BroadcastLinkEventSink {
    fn send(&self, event: LinkEventData) {
        let _ = self.0.send(event);
    }
}

#[derive(Clone)]
pub(crate) struct BroadcastLinkPayloadSink(broadcast::Sender<LinkPayload>);

impl From<broadcast::Sender<LinkPayload>> for BroadcastLinkPayloadSink {
    fn from(sender: broadcast::Sender<LinkPayload>) -> Self {
        Self(sender)
    }
}

impl LinkPayloadSink for BroadcastLinkPayloadSink {
    fn send(&self, payload: LinkPayload) {
        let _ = self.0.send(payload);
    }
}

/// Delivery proof event for a packet sent to a SINGLE destination
/// (Python `PacketReceipt` delivery callback).
#[derive(Clone, Debug)]
pub struct ReceiptEvent {
    /// Destination the proved packet was sent to.
    pub destination: AddressHash,
    /// Full hash of the proved packet.
    pub packet_hash: Hash,
}

/// Packet receipt status (Python `PacketReceipt.FAILED/SENT/DELIVERED/CULLED`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptStatus {
    Failed = 0x00,
    Sent = 0x01,
    Delivered = 0x02,
    Culled = 0xFF,
}

/// Observable receipt state. `timeout == None` is Python `timeout = -1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketReceiptInfo {
    pub status: ReceiptStatus,
    pub timeout: Option<Duration>,
    pub rtt: Option<Duration>,
}

/// A pending packet receipt (Python `PacketReceipt`).
#[derive(Clone)]
struct PacketReceipt {
    destination: AddressHash,
    packet_hash: Hash,
    /// Identity of the destination, used to validate the proof signature.
    identity: crate::identity::Identity,
    sent_at: time::Instant,
    /// `None` is Python `timeout = -1` (culled on the next check).
    timeout: Option<Duration>,
    status: ReceiptStatus,
    concluded_at: Option<time::Instant>,
}

/// Reverse-table entry (Python `IDX_RT_RCVD_IF`, `IDX_RT_OUTB_IF`, `IDX_RT_TIMESTAMP`).
struct ReverseEntry {
    received: AddressHash,
    outbound: AddressHash,
    at: time::Instant,
}

/// Reverse entries are removed after 8 minutes (Python `REVERSE_TIMEOUT`).
const REVERSE_TIMEOUT: Duration = Duration::from_secs(8 * 60);
/// Python `Transport.MAX_RECEIPTS`.
const MAX_RECEIPTS: usize = 1024;
/// Python `Packet.TIMEOUT_PER_HOP` / `DEFAULT_PER_HOP_TIMEOUT`.
const TIMEOUT_PER_HOP: Duration = Duration::from_secs(6);
/// Per-packet radio stats for the local-client RPC cache.
struct PhyCache {
    capacity: usize,
    rssi: std::collections::VecDeque<(Hash, f64)>,
    snr: std::collections::VecDeque<(Hash, f64)>,
    q: std::collections::VecDeque<(Hash, f64)>,
}

impl PhyCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            rssi: std::collections::VecDeque::new(),
            snr: std::collections::VecDeque::new(),
            q: std::collections::VecDeque::new(),
        }
    }

    fn record(&mut self, hash: Hash, rssi: Option<i16>, snr: Option<f32>, quality: Option<f32>) {
        if self.capacity == 0 {
            return;
        }
        if let Some(rssi) = rssi {
            push_phy(&mut self.rssi, self.capacity, hash, f64::from(rssi));
        }
        if let Some(snr) = snr {
            push_phy(&mut self.snr, self.capacity, hash, f64::from(snr));
        }
        if let Some(quality) = quality {
            push_phy(&mut self.q, self.capacity, hash, f64::from(quality));
        }
    }

    fn lookup(cache: &std::collections::VecDeque<(Hash, f64)>, hash: &Hash) -> Option<f64> {
        cache
            .iter()
            .rev()
            .find(|(key, _)| key == hash)
            .map(|(_, value)| *value)
    }
}

fn push_phy(cache: &mut std::collections::VecDeque<(Hash, f64)>, capacity: usize, hash: Hash, value: f64) {
    // Evict before pushing: pushing onto a full deque would double its
    // backing store instead of reusing the freed slot.
    if cache.len() == capacity {
        cache.pop_front();
    }
    cache.push_back((hash, value));
}

pub(crate) struct TransportHandler {
    config: TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    announce_tx: broadcast::Sender<AnnounceEvent>,

    path_table: PathTable,
    announce_table: AnnounceTable,
    channel_table: HashMap<LinkId, BroadcastLinkPayloadSink>,
    link_table: LinkTable,
    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    single_out_destinations: HashMap<AddressHash, Arc<Mutex<SingleOutputDestination>>>,
    plain_in_destinations: HashMap<AddressHash, Arc<Mutex<PlainInputDestination>>>,
    /// Inbound GROUP destinations with their symmetric keys
    /// (Python `Destination` GROUP with `prv`).
    group_in_destinations: HashMap<AddressHash, Arc<Mutex<GroupInputDestination>>>,

    announce_limits: AnnounceLimits,
    phy: PhyCache,

    out_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    /// Receiving interface of each established inbound link
    /// (endpoint view; the link table only covers intermediary relays).
    in_link_ifaces: HashMap<LinkId, AddressHash>,

    packet_cache: Mutex<PacketCache>,

    resources: ResourceManager,

    blackholes: SharedBlackholes,

    path_requests: PathRequests,

    /// Identity & destination persistence (Python `RNS.Reticulum.storagepath`).
    storage: Option<std::sync::Arc<dyn Storage>>,
    known_destinations: KnownDestinations,
    known_ratchets: KnownRatchets,

    /// Outbound SINGLE-destination packets awaiting a delivery proof
    /// (Python `Transport.receipts`).
    receipts: HashMap<AddressHash, PacketReceipt>,
    receipt_tx: broadcast::Sender<ReceiptEvent>,

    /// Ratchet file paths of local destinations with ratchets enabled
    /// (Python `Destination.ratchets_path`).
    destination_ratchet_paths: HashMap<AddressHash, String>,

    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,

    fixed_dest_path_requests: AddressHash,

    /// Fixed PLAIN destination for tunnel synthesis
    /// (Python `tunnel_synthesize_destination`).
    fixed_dest_tunnel_synthesize: AddressHash,

    /// Tunnel table (Python `Transport.tunnels`).
    tunnels: Tunnels,

    /// Identities allowed to use the remote management destination
    /// (Python `Transport.remote_management_allowed`).
    remote_management_allowed: Arc<std::sync::RwLock<Vec<AddressHash>>>,

    /// Trusted remote blackhole-list sources
    /// (Python `Reticulum.blackhole_sources`).
    blackhole_sources: Vec<AddressHash>,
    /// Prioritized inbound queues
    /// (Python `Transport.inbound_queues`).
    inbound_queues: std::sync::Arc<std::sync::Mutex<InboundQueues>>,
    cancel: CancellationToken,

    /// Return path for proofs (Python `Transport.reverse_table`).
    reverse_table: HashMap<AddressHash, ReverseEntry>,
    /// Previous online state of the shared-instance initiator link.
    shared_was_online: Option<bool>,
    /// Spawned local-client interfaces seen on the previous tick.
    seen_local_clients: Vec<AddressHash>,
    persisted_loaded: bool,
    shutdown_persisted: bool,
    /// Saved paths whose stable interface was not live yet.
    /// `None` means the destination table has not been read.
    unresolved_paths: Option<Vec<PersistedPath>>,
    /// Hashlist and tunnel table have been read for this load attempt.
    persisted_aux_loaded: bool,
}

#[derive(Clone)]
pub struct Transport {
    name: String,
    identity: PrivateIdentity,
    blackholes: SharedBlackholes,
    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,
    receipt_tx: broadcast::Sender<ReceiptEvent>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
}

impl TransportConfig {
    pub fn new<T: Into<String>>(name: T, identity: &PrivateIdentity) -> Self {
        Self {
            name: name.into(),
            identity: identity.clone(),
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            blackhole_publish: false,
            blackhole_sources: Vec::new(),
            link_mtu_discovery: true,
            inbound_queue_lengths: INBOUND_QUEUE_LENGTHS,
            storage: None,
            use_implicit_proof: true,
            local_hops_delta: false,
            enable_resource_watchdog: true,
            timer_config: TimerConfig::default(),
            channel_capacity: 16,
            announce_cache_capacity: 8192,
            phy_cache_capacity: 512,
        }
    }

    /// Set the storage backend used for known destinations, ratchets and
    /// identity files (Python `RNS.Reticulum.storagepath`).
    pub fn set_storage(mut self, storage: std::sync::Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Enable or disable implicit packet proofs
    /// (Python config `use_implicit_proof`).
    pub fn set_implicit_proof(mut self, implicit: bool) -> Self {
        self.use_implicit_proof = implicit;
        self
    }

    /// Rewrite hops on egress from this instance onto the wider network
    /// (Python config `local_hops_delta`). The sampled value is in `2..=7`.
    pub fn set_local_hops_delta(mut self, enabled: bool) -> Self {
        self.local_hops_delta = enabled;
        self
    }

    pub fn set_retransmit(mut self, retransmit: bool) -> Self {
        self.retransmit = retransmit;
        self
    }

    /// Whether this instance relays announces and routes traffic for
    /// other peers (Python `Reticulum.transport_enabled`). The separate
    /// `broadcast` flag was removed; announce retransmission expresses
    /// routing capability.
    pub fn is_transport_enabled(&self) -> bool {
        self.retransmit
    }

    pub fn set_reroute_eager(mut self, reroute_eager: bool) -> Self {
        self.reroute_eager = reroute_eager;
        self
    }

    pub fn set_restart_outlinks(mut self, restart_outlinks: bool) -> Self {
        self.restart_outlinks = restart_outlinks;
        self
    }

    pub fn set_announce_forever(mut self, announce_forever: bool) -> Self {
        self.announce_forever = announce_forever;
        self
    }

    /// Publish the blackhole list
    /// (Python `Reticulum.publish_blackhole_enabled`).
    pub fn set_blackhole_publish(mut self, publish: bool) -> Self {
        self.blackhole_publish = publish;
        self
    }

    /// Configure the inbound queue length of one traffic class
    /// (Python `qlen_in_*` configuration options).
    pub fn set_inbound_queue_length(mut self, class: TrafficClass, length: usize) -> Self {
        if length > 0 {
            self.inbound_queue_lengths[class as usize] = length;
        }
        self
    }

    /// Signal the next-hop hardware MTU in link requests when the
    /// next-hop interface supports MTU negotiation
    /// (Python `Reticulum.link_mtu_discovery`). When disabled, link
    /// requests always signal the protocol MTU.
    pub fn set_link_mtu_discovery(mut self, enabled: bool) -> Self {
        self.link_mtu_discovery = enabled;
        self
    }

    /// Trust persisted blackhole lists from these remote identities
    /// (Python `Reticulum.blackhole_sources`).
    pub fn set_blackhole_sources(mut self, sources: Vec<crate::hash::AddressHash>) -> Self {
        self.blackhole_sources = sources;
        self
    }

    pub fn set_timer_config(mut self, timer_config: TimerConfig) -> Self {
        self.timer_config = timer_config;
        self
    }

    pub fn build(self) -> Transport {
        Transport::new(self)
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            name: "tp".into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            retransmit: false,
            reroute_eager: false,
            restart_outlinks: false,
            announce_forever: false,
            blackhole_publish: false,
            blackhole_sources: Vec::new(),
            link_mtu_discovery: true,
            inbound_queue_lengths: INBOUND_QUEUE_LENGTHS,
            storage: None,
            use_implicit_proof: true,
            local_hops_delta: false,
            enable_resource_watchdog: true,
            timer_config: TimerConfig::default(),
            channel_capacity: 16,
            announce_cache_capacity: 8192,
            phy_cache_capacity: 512,
        }
    }
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        let cap = config.channel_capacity;
        let (announce_tx, _) = tokio::sync::broadcast::channel(cap);
        let (link_in_event_tx, _) = tokio::sync::broadcast::channel(cap);
        let (link_out_event_tx, _) = tokio::sync::broadcast::channel(cap);
        let (received_data_tx, _) = tokio::sync::broadcast::channel(cap);
        let (iface_messages_tx, _) = tokio::sync::broadcast::channel(cap);

        let local_hops_delta = if config.local_hops_delta {
            (OsRng.next_u32() as u8 % 6) + 2
        } else {
            0
        };
        // The central ingress mpsc carries inline ~2 KB packets per slot;
        // depth follows the embedded-scaled channel capacity (default 16).
        let iface_manager = InterfaceManager::new(cap.max(4));
        if local_hops_delta != 0 {
            iface_manager
                .set_local_hops_delta(local_hops_delta, Some(*config.identity.address_hash()));
        }

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let transport_id = if config.retransmit {
            Some(*config.identity.address_hash())
        } else {
            None
        };
        let path_requests = PathRequests::new(config.name.as_str(), transport_id);

        let path_request_dest = create_path_request_destination().desc.address_hash;

        let (receipt_tx, _) = tokio::sync::broadcast::channel(16);

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let reroute_eager = config.reroute_eager;
        let blackhole_publish = config.blackhole_publish;
        let blackhole_sources = config.blackhole_sources.clone();
        let inbound_queues = std::sync::Arc::new(std::sync::Mutex::new(InboundQueues::new(
            config.inbound_queue_lengths,
        )));
        let storage = config.storage.clone();
        let announce_cache_capacity = config.announce_cache_capacity;
        let phy_cache_capacity = config.phy_cache_capacity;
        let identity = config.identity.clone();
        let persisted_loaded = storage.is_none();
        let blackholes = std::sync::Arc::new(tokio::sync::RwLock::new(
            blackholes::Blackholes::new(blackhole_publish),
        ));
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            announce_table: AnnounceTable::new(),
            channel_table: HashMap::new(),
            link_table: LinkTable::new(),
            path_table: PathTable::new(reroute_eager),
            single_in_destinations: HashMap::new(),
            single_out_destinations: HashMap::new(),
            plain_in_destinations: HashMap::new(),
            group_in_destinations: HashMap::new(),
            announce_limits: AnnounceLimits::new(),
            phy: PhyCache::new(phy_cache_capacity),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            in_link_ifaces: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new(announce_cache_capacity)),
            resources: ResourceManager::new(),
            blackholes: blackholes.clone(),
            path_requests,
            tunnels: Tunnels::new(),
            remote_management_allowed: Arc::new(std::sync::RwLock::new(Vec::new())),
            blackhole_sources,
            inbound_queues,
            fixed_dest_tunnel_synthesize: tunnels::create_tunnel_synthesize_destination()
                .desc
                .address_hash,
            storage,
            known_destinations: KnownDestinations::new(),
            known_ratchets: KnownRatchets::new(),
            receipts: HashMap::new(),
            receipt_tx: receipt_tx.clone(),
            destination_ratchet_paths: HashMap::new(),
            announce_tx,
            link_in_event_tx: link_in_event_tx.clone().into(),
            link_out_event_tx: link_out_event_tx.clone().into(),
            received_data_tx: received_data_tx.clone(),
            fixed_dest_path_requests: path_request_dest,
            cancel: cancel.clone(),
            reverse_table: HashMap::new(),
            shared_was_online: None,
            seen_local_clients: Vec::new(),
            persisted_loaded,
            shutdown_persisted: false,
            unresolved_paths: None,
            persisted_aux_loaded: false,
        }));

        {
            let handler = handler.clone();
            tokio::spawn(manage_transport(
                handler,
                rx_receiver,
                iface_messages_tx.clone(),
            ))
        };

        Self {
            name,
            identity,
            blackholes,
            iface_manager,
            link_in_event_tx: link_in_event_tx.into(),
            link_out_event_tx: link_out_event_tx.into(),
            received_data_tx,
            receipt_tx,
            iface_messages_tx,
            handler,
            cancel,
        }
    }

    pub async fn outbound(&self, packet: &Packet) {
        let (packet, maybe_iface) = self
            .handler
            .lock()
            .await
            .path_table
            .handle_local_packet(packet);

        if let Some(iface) = maybe_iface {
            self.send_direct(iface, packet).await;
            log::trace!("Sent outbound packet to {}", iface);
        } else {
            // No known path: broadcast on every outgoing interface
            // (Python `Transport.outbound` else-branch).
            self.send_packet(packet).await;
        }
    }

    pub fn iface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.iface_manager.clone()
    }

    /// Control whether an owned destination accepts incoming link requests
    /// (Python `Destination.set_accepts_links`).
    pub async fn set_accepts_links(&self, destination: &AddressHash, accepts: bool) -> bool {
        let handler = self.handler.lock().await;
        match handler.single_in_destinations.get(destination) {
            Some(dest) => {
                dest.lock().await.set_accepts_links(accepts);
                true
            }
            None => false,
        }
    }

    /// Whether an owned destination accepts link requests.
    pub async fn destination_accepts_links(&self, destination: &AddressHash) -> Option<bool> {
        let destination = self
            .handler
            .lock()
            .await
            .single_in_destinations
            .get(destination)
            .cloned()?;
        let accepts_links = destination.lock().await.accepts_links();
        Some(accepts_links)
    }

    /// Access this transport's blackhole list.
    pub fn blackholes(&self) -> SharedBlackholes {
        self.blackholes.clone()
    }

    /// Blackhole an identity: its announces and paths are dropped
    /// (Python `Reticulum.blackhole_identity`). Locally sourced entries
    /// are persisted to `<storage>/blackhole/local` when storage is set.
    pub async fn blackhole_identity(
        &self,
        identity: AddressHash,
        until: Option<f64>,
        reason: Option<String>,
    ) {
        let handler = self.handler.lock().await;
        let own = *handler.config.identity.address_hash();
        let storage = handler.storage.clone();
        let mut blackholes = handler.blackholes.write().await;
        blackholes.blackhole(identity, own, until, reason);
        if let Some(storage) = storage {
            if let Err(error) = blackholes.persist_local(&*storage, &own) {
                log::error!(
                    "tp({}): could not persist blackhole list: {error:?}",
                    self.name
                );
            }
        }
        drop(blackholes);
        drop(handler);
        self.remove_blackholed_paths().await;
    }

    /// Remove an identity from the blackhole list
    /// (Python `Reticulum.unblackhole_identity`), persisting the local
    /// list afterwards.
    pub async fn unblackhole_identity(&self, identity: &AddressHash) -> bool {
        let handler = self.handler.lock().await;
        let own = *handler.config.identity.address_hash();
        let storage = handler.storage.clone();
        let mut blackholes = handler.blackholes.write().await;
        let removed = blackholes.unblackhole(identity);
        if removed {
            if let Some(storage) = storage {
                if let Err(error) = blackholes.persist_local(&*storage, &own) {
                    log::error!(
                        "tp({}): could not persist blackhole list: {error:?}",
                        self.name
                    );
                }
            }
        }
        removed
    }

    /// Load persisted blackhole lists into the table and drop paths of
    /// blackholed identities (Python `Transport.reload_blackhole`).
    pub async fn reload_blackholes(&self) -> usize {
        let handler = self.handler.lock().await;
        let own = *handler.config.identity.address_hash();
        let storage = handler.storage.clone();
        let Some(storage) = storage else {
            return 0;
        };
        let allowed = handler.blackhole_sources.clone();
        let mut blackholes = handler.blackholes.write().await;
        let loaded = blackholes.reload(&*storage, &own, &allowed);
        drop(blackholes);
        drop(handler);
        if loaded > 0 {
            log::info!("tp({}): loaded {loaded} blackholed identities", self.name);
            self.remove_blackholed_paths().await;
        }
        loaded
    }

    /// Persist a blackhole list fetched from a remote publisher
    /// (Python `Discovery.BlackholeUpdater` writes the response to
    /// `blackhole/<hex source identity>`).
    pub async fn persist_blackhole_source(&self, publisher: &AddressHash, packed: &[u8]) {
        let handler = self.handler.lock().await;
        let Some(storage) = handler.storage.clone() else {
            return;
        };
        let path = format!("blackhole/{}", publisher.to_hex_string());
        if let Err(error) = storage.write(&path, packed) {
            log::error!(
                "tp({}): could not persist blackhole source list: {error:?}",
                self.name
            );
        }
    }

    /// Drop every path-table entry whose destination belongs to a
    /// blackholed identity (Python `Transport.remove_blackholed_paths`).
    pub async fn remove_blackholed_paths(&self) -> usize {
        let mut handler = self.handler.lock().await;
        let blackholed: Vec<AddressHash> = handler.blackholes.read().await.blackholed_identities();
        let mut dropped = 0;
        let keys: Vec<AddressHash> = handler.path_table.iter().map(|(hash, _)| *hash).collect();
        for destination in keys {
            let Some(identity) = handler.known_destinations.recall_no_use(&destination) else {
                continue;
            };
            let identity_hash = identity.address_hash;
            if blackholed.contains(&identity_hash) && handler.path_table.drop_path(&destination) {
                dropped += 1;
            }
        }
        if dropped > 0 {
            log::info!(
                "tp({}): removed {dropped} destinations associated with blackholed identities from path table",
                self.name
            );
        }
        dropped
    }

    /// Whether an identity is blackholed.
    pub async fn is_blackholed(&self, identity: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .blackholes
            .read()
            .await
            .is_blackholed(identity)
    }

    /// Mark the path to a destination unresponsive
    /// (Python `Transport.mark_path_unresponsive`).
    pub async fn mark_path_unresponsive(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .mark_path_unresponsive(destination)
    }

    /// Mark the path to a destination responsive again.
    pub async fn mark_path_responsive(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .mark_path_responsive(destination)
    }

    /// Whether the path to a destination is marked unresponsive.
    pub async fn path_is_unresponsive(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .path_is_unresponsive(destination)
    }

    /// Forget the path to a destination (Python `Transport.drop_path`).
    pub async fn drop_path(&self, destination: &AddressHash) -> bool {
        self.handler.lock().await.path_table.drop_path(destination)
    }

    /// Backdate a path so the next cull removes it
    /// (Python `Transport.expire_path`). The row stays until that cull.
    pub async fn expire_path(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .expire_path(destination)
    }

    /// Forget all paths learned over an interface (Python `drop_all_via`).
    pub async fn drop_all_via(&self, iface: &AddressHash) -> usize {
        self.handler.lock().await.path_table.drop_all_via(iface)
    }

    /// Return any known path's destination hash (diagnostics/tests).
    pub async fn handler_public_path_probe(&self) -> Option<AddressHash> {
        self.handler.lock().await.path_table.any_destination()
    }

    /// Number of hops to a destination, if known.
    pub async fn hops_to(&self, destination: &AddressHash) -> Option<u8> {
        self.handler
            .lock()
            .await
            .path_table
            .get(destination)
            .map(|entry| entry.hops)
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    /// Subscribe to announces matching any of `aspects`
    /// (Python `Transport.register_announce_handler(AnnounceHandler(aspects))`).
    ///
    /// An announce for destination `app.aspect1.aspect2` matches an aspect
    /// filter of `aspect1` (Python semantics: the aspect filter is matched
    /// against the first aspect after the app name).
    pub async fn subscribe_announces(
        &self,
        app_name: &str,
        aspects: &[&str],
    ) -> broadcast::Receiver<AnnounceEvent> {
        // A filtered receiver is implemented as a forwarding task over the
        // unfiltered stream: subscribers get a private channel.
        let (tx, rx) = tokio::sync::broadcast::channel(64);
        let mut source = self.handler.lock().await.announce_tx.subscribe();

        let filters: Vec<DestinationName> = aspects
            .iter()
            .map(|aspect| DestinationName::new(app_name, aspect))
            .collect();
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    Ok(event) => {
                        let matches = if filters.is_empty() {
                            true
                        } else {
                            let destination = event.destination.lock().await;
                            filters.iter().any(|filter| {
                                filter.address_hash_for(&destination.identity)
                                    == destination.desc.address_hash
                            })
                        };
                        if matches && tx.send(event).is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        rx
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.handler.lock().await.send_packet(packet).await;
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        let handler = self.handler.lock().await;

        let announce = {
            let mut destination = destination.lock().await;
            destination.announce(OsRng, app_data)
        }
        .expect("valid announce packet");

        // Persist rotated destination ratchets
        // (Python `Destination.announce` -> `rotate_ratchets` ->
        // `_persist_ratchets`).
        let ratchet_path = handler
            .destination_ratchet_paths
            .get(&announce.destination)
            .cloned();
        let storage = handler.storage.clone();

        if let (Some(path), Some(storage)) = (ratchet_path, storage) {
            let destination = destination.lock().await;
            if let Some(ratchets) = destination.ratchets() {
                let mut ratchets = ratchets.to_vec();
                crate::storage::clean_destination_ratchets(
                    &mut ratchets,
                    destination.retained_ratchets,
                );

                if let Err(error) = crate::storage::save_destination_ratchets(
                    &*storage,
                    &path,
                    &destination.identity,
                    &ratchets,
                ) {
                    log::warn!(
                        "tp({}): could not persist ratchets for {}: {error:?}",
                        handler.config.name,
                        announce.destination
                    );
                }
            }
        }

        handler.send_packet(announce).await;
    }

    pub async fn send_broadcast(&self, packet: Packet, from_iface: Option<AddressHash>) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(from_iface),
                packet: Box::new(packet),
            })
            .await;
    }

    pub async fn send_direct(&self, addr: AddressHash, packet: Packet) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Direct(addr),
                packet: Box::new(packet),
            })
            .await;
    }

    pub async fn send_to_all_out_links(&self, payload: &[u8]) {
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_from_link(&mut link, packet).await;
                }
            }
        }
    }

    pub async fn send_to_out_links(&self, destination: &AddressHash, payload: &[u8]) -> Vec<Hash> {
        let mut sent_packets = vec![];
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    let hash = packet.hash();
                    handler.send_from_link(&mut link, packet).await;
                    sent_packets.push(hash);
                }
            }
        }

        if sent_packets.is_empty() {
            log::trace!(
                "tp({}): no output links for {} destination",
                self.name,
                destination
            );
        }

        sent_packets
    }

    pub async fn send_to_in_links(&self, destination: &AddressHash, payload: &[u8]) {
        let handler = self.handler.lock().await;
        let mut count = 0usize;
        for link in handler.in_links.values() {
            let mut link = link.lock().await;

            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_from_link(&mut link, packet).await;
                    count += 1;
                }
            }
        }

        if count == 0 {
            log::trace!(
                "tp({}): no input links for {} destination",
                self.name,
                destination
            );
        }
    }

    /// Inbound queue pressure snapshot: total queued items, per-class
    /// heights and per-class drop counters
    /// (Python `Transport.inbound_queues.snapshot()`).
    /// Configured inbound queue lengths per traffic class. A length of 0
    /// in config is left as the class default ([`INBOUND_QUEUE_LENGTHS`]).
    pub async fn inbound_queue_lengths(&self) -> [usize; 4] {
        self.handler.lock().await.config.inbound_queue_lengths
    }

    pub async fn inbound_queue_snapshot(&self) -> (usize, [usize; 4], [u64; 4]) {
        self.handler
            .lock()
            .await
            .inbound_queues
            .lock()
            .expect("inbound queue lock")
            .snapshot()
    }

    /// The lowest bitrate of all online interfaces
    /// (Python `Reticulum.get_lowest_interface_bitrate` /
    /// `Transport.lowest_interface_bitrate`).
    pub async fn lowest_interface_bitrate(&self) -> Option<u64> {
        self.iface_manager.lock().await.lowest_interface_bitrate()
    }

    /// A reasonable minimum path request timeout covering a full round
    /// trip for an MTU on the slowest online interface plus per-hop
    /// grace (Python `Reticulum.get_medium_path_timeout` /
    /// `Transport.medium_path_timeout`:
    /// `2*(MTU*8/max(bitrate, MINIMUM_BITRATE)) + DEFAULT_PER_HOP_TIMEOUT`,
    /// zero when the bitrate is unknown).
    pub async fn medium_path_timeout(&self) -> Duration {
        const MINIMUM_BITRATE: f64 = 5.0;
        const DEFAULT_PER_HOP_TIMEOUT: f64 = 6.0;
        let Some(bitrate) = self.lowest_interface_bitrate().await else {
            return Duration::ZERO;
        };
        let mtu = crate::packet::PROTOCOL_MTU as f64;
        let secs =
            2.0 * (mtu * 8.0 / (bitrate as f64).max(MINIMUM_BITRATE)) + DEFAULT_PER_HOP_TIMEOUT;
        Duration::from_secs_f64(secs)
    }

    pub async fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.find_out_link(link_id)
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.find_in_link(link_id)
    }

    pub async fn link(&self, destination: DestinationDesc) -> Arc<Mutex<Link>> {
        // NOTE: the handler guard is scoped tightly; holding it across
        // the whole establishment deadlocks (later statements here
        // re-lock it).
        let existing = {
            let handler = self.handler.lock().await;
            handler.out_links.get(&destination.address_hash).cloned()
        };

        if let Some(link) = existing {
            if link.lock().await.status() != LinkStatus::Closed {
                return link;
            } else {
                log::warn!("tp({}): link was closed", self.name);
            }
        }

        let mut link = Link::new(destination);

        // Signal the next-hop hardware MTU in the link request when MTU
        // discovery is enabled and the next-hop interface supports it
        // (Python `Link.__init__`:
        // `if RNS.Reticulum.link_mtu_discovery() and nh_hw_mtu:
        // signalling_bytes(nh_hw_mtu) else signalling_bytes(MTU)`).
        {
            let handler = self.handler.lock().await;
            if handler.config.link_mtu_discovery {
                // The next-hop interface, when a path is known; otherwise
                // fall back to the first interface for single-homed
                // clients.
                let next_hop_iface = handler
                    .path_table
                    .get(&destination.address_hash)
                    .map(|entry| entry.iface)
                    .or_else(|| {
                        handler
                            .iface_manager
                            .try_lock()
                            .ok()
                            .and_then(|manager| manager.first_iface_address())
                    });
                let next_hop = next_hop_iface
                    .and_then(|iface| {
                        handler
                            .iface_manager
                            .try_lock()
                            .ok()
                            .and_then(|manager| manager.iface_hw_mtu(&iface))
                    })
                    .unwrap_or(crate::packet::PROTOCOL_MTU);
                link.set_mtu(next_hop);
            }
        }

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
        );

        let link = Arc::new(Mutex::new(link));

        // Register BEFORE sending: a fast proof arriving between the send
        // and the insert would find no outbound link and be discarded
        // (Python registers the pending link before its request goes out).
        self.handler
            .lock()
            .await
            .out_links
            .insert(destination.address_hash, link.clone());

        // Python `Transport.outbound` addresses packets for destinations
        // more than one hop away as HEADER_2 carrying the next hop's
        // transport id (intermediary nodes only relay addressed packets),
        // and transmits single-hop paths unchanged. Unknown paths are
        // broadcast.
        if self
            .handler
            .lock()
            .await
            .path_table
            .contains(&destination.address_hash)
        {
            self.outbound(&packet).await;
        } else {
            self.send_packet(packet).await;
        }

        link
    }

    /// Consume `link` and wrap it in a new `Channel`.
    ///
    /// If successful, returns the new `Channel` and a receiver for
    /// its incomigng messages.
    ///
    /// Fails if there is already a `Channel` wrapping `link`.
    #[cfg(not(test))]
    pub async fn mk_channel<M>(
        &self,
        link: Arc<Mutex<Link>>,
    ) -> Result<(Channel<M>, broadcast::Receiver<M>), RnsError>
    where
        M: channel::Message,
    {
        Channel::new(self, link).await
    }

    #[allow(unused)] // mocked out in the test build, so the linter
                     // would complain about dead code
    pub(crate) async fn bind_link_to_channel(
        &self,
        id: LinkId,
    ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
        self.handler.lock().await.bind_link_to_channel(id).await
    }

    pub async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
        self.handler.lock().await.link_close(link_id).await
    }

    pub async fn request_path(
        &self,
        destination: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        self.handler
            .lock()
            .await
            .request_path(destination, on_iface, tag)
            .await
    }

    /// Request a path to the destination from the network and wait until
    /// the path is available or the timeout is reached
    /// (Python `RNS.Transport.await_path`).
    ///
    /// Returns `true` if a path to the destination was found.
    pub async fn await_path(
        &self,
        destination: &AddressHash,
        timeout: Option<Duration>,
        on_iface: Option<AddressHash>,
    ) -> bool {
        let deadline = time::Instant::now() + timeout.unwrap_or(PATH_REQUEST_TIMEOUT);

        if self.has_path(destination).await {
            return true;
        }

        self.request_path(destination, on_iface, None).await;

        while time::Instant::now() < deadline {
            if self.has_path(destination).await {
                return true;
            }

            time::sleep(Duration::from_millis(50)).await;
        }

        self.has_path(destination).await
    }

    /// Whether an automated path request for `destination` may be sent now,
    /// honouring `PATH_REQUEST_MI` (20 s minimum interval).
    pub async fn path_request_allowed(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_requests
            .request_allowed(destination)
    }

    pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_out_event_tx.0.subscribe()
    }

    pub fn in_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_in_event_tx.0.subscribe()
    }

    pub async fn events_for_link(&self, link_id: LinkId) -> broadcast::Receiver<LinkEventData> {
        let mut source = if self.handler.lock().await.in_links.contains_key(&link_id) {
            self.in_link_events()
        } else {
            self.out_link_events()
        };
        let (tx, rx) = broadcast::channel(16);
        tokio::spawn(async move {
            loop {
                match source.recv().await {
                    Ok(event) if event.id == link_id => {
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        rx
    }

    pub fn received_data_events(&self) -> broadcast::Receiver<ReceivedData> {
        self.received_data_tx.subscribe()
    }

    pub async fn add_destination(
        &self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<SingleInputDestination>> {
        let destination = SingleInputDestination::new(identity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    /// Subscribe to resource transfer events for all links.
    pub async fn resource_events(&self) -> broadcast::Receiver<ResourceEvent> {
        self.handler.lock().await.resources.events.subscribe()
    }

    /// Subscribe to request (request/response) events.
    pub async fn request_events(&self) -> broadcast::Receiver<RequestEventData> {
        self.handler
            .lock()
            .await
            .resources
            .request_events
            .subscribe()
    }

    /// Set the resource acceptance strategy for a link
    /// (Python `Link.set_resource_strategy`).
    pub async fn set_resource_strategy(&self, link_id: LinkId, strategy: ResourceStrategy) {
        self.handler
            .lock()
            .await
            .resources
            .set_resource_strategy(link_id, strategy);
    }

    /// Set the resource strategy for links without an explicit entry
    /// (Python `Link.ACCEPT_ALL`-style defaults; applies to inbound links
    /// the application never opened itself).
    pub async fn set_default_resource_strategy(&self, strategy: ResourceStrategy) {
        self.handler
            .lock()
            .await
            .resources
            .set_default_resource_strategy(strategy);
    }

    /// Register an application callback deciding whether an advertised
    /// resource should be accepted (Python `Link.set_resource_callback`).
    pub async fn set_resource_accept_callback(
        &self,
        link_id: LinkId,
        callback: resource::manager::ResourceAcceptCallback,
    ) {
        self.handler
            .lock()
            .await
            .resources
            .set_accept_callback(link_id, callback);
    }

    /// Register a handler for a request path on one of our inbound
    /// destinations (Python `Destination.register_request_handler`).
    pub async fn register_request_handler<F>(
        &self,
        destination: &AddressHash,
        path: &str,
        handler: F,
    ) where
        F: Fn(RequestCtx) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.handler
            .lock()
            .await
            .resources
            .register_request_handler(*destination, path, Arc::new(handler));
    }

    /// Register a request handler with Python's `allow`, `allowed_list` and
    /// `auto_compress` arguments. The handler may return a msgpack element
    /// or a file. [`Transport::register_request_handler`] stays allow-all
    /// and element-only so existing callers keep working.
    pub async fn register_request_handler_with_config<F>(
        &self,
        destination: &AddressHash,
        path: &str,
        config: RequestHandlerConfig,
        handler: F,
    ) where
        F: Fn(RequestCtx) -> Option<RequestResponse> + Send + Sync + 'static,
    {
        self.handler
            .lock()
            .await
            .resources
            .register_request_handler_with_config(*destination, path, config, Arc::new(handler));
    }

    /// Register an async request handler for a path on one of our inbound
    /// destinations. Async handlers keep the transport responsive for
    /// long-running work (e.g. remote command execution).
    ///
    /// The async future is awaited directly on the transport's async
    /// packet task (no blocking bridge), so it must be Send + 'static.
    pub async fn register_async_request_handler<F, Fut>(
        &self,
        destination: &AddressHash,
        path: &str,
        handler: F,
    ) where
        F: Fn(RequestCtx) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        let user_handler = std::sync::Arc::new(handler);
        // Async handlers are stored separately and awaited directly on the
        // async packet task — a blocking bridge would deadlock
        // current-thread runtimes.
        self.handler
            .lock()
            .await
            .resources
            .register_async_request_handler(
                *destination,
                path,
                Arc::new(move |ctx| {
                    let user_handler = user_handler.clone();
                    Box::pin(async move { user_handler(ctx).await })
                }),
            );
    }

    /// Send an arbitrary-size payload as a resource over an established
    /// link. Returns the full 32-byte resource hash — the same hash that
    /// identifies the resource in [`Transport::resource_events`] and is
    /// accepted by [`Transport::cancel_resource`].
    pub async fn send_resource(
        &self,
        link: &Arc<Mutex<Link>>,
        data: Vec<u8>,
    ) -> Result<crate::hash::Hash, RnsError> {
        self.send_resource_with_options(link, data, ResourceOptions::default())
            .await
    }

    /// Send an arbitrary-size payload as a resource with options
    /// (metadata, request id, response flag). Returns the resource hash.
    pub async fn send_resource_with_options(
        &self,
        link: &Arc<Mutex<Link>>,
        data: Vec<u8>,
        options: ResourceOptions,
    ) -> Result<crate::hash::Hash, RnsError> {
        let staged = crate::resource::outbound::OutgoingResource::stage_bytes(data, &options)?;
        self.enqueue_staged(link, staged, options).await
    }

    /// Send a file as a resource. Only the first segment is read before
    /// the advertisement; later segments are read as the transfer advances.
    pub async fn send_resource_from_path(
        &self,
        link: &Arc<Mutex<Link>>,
        path: &std::path::Path,
        options: ResourceOptions,
    ) -> Result<crate::hash::Hash, RnsError> {
        let staged = crate::resource::outbound::OutgoingResource::stage_path(path, &options)?;
        self.enqueue_staged(link, staged, options).await
    }

    /// Send a seekable stream as a resource. Seeking to discover the length
    /// does not read the body, and only the first segment is read before
    /// the advertisement. The reader does not need to be `Sync`.
    pub async fn send_resource_from_reader<R>(
        &self,
        link: &Arc<Mutex<Link>>,
        reader: R,
        options: ResourceOptions,
    ) -> Result<crate::hash::Hash, RnsError>
    where
        R: std::io::Read + std::io::Seek + Send + 'static,
    {
        let staged = crate::resource::outbound::OutgoingResource::stage_reader(reader, &options)?;
        self.enqueue_staged(link, staged, options).await
    }

    /// Spool a non-seekable stream to a temporary file and send that, so
    /// the bytes are not held as a single buffer. Spooling finishes before
    /// the transport handler lock is taken.
    pub async fn send_resource_from_read<R>(
        &self,
        link: &Arc<Mutex<Link>>,
        reader: R,
        options: ResourceOptions,
    ) -> Result<crate::hash::Hash, RnsError>
    where
        R: std::io::Read + Send + 'static,
    {
        let staged = crate::resource::outbound::OutgoingResource::stage_read(reader, &options)?;
        self.enqueue_staged(link, staged, options).await
    }

    /// Encrypt a staged resource, then lock the handler only to confirm the
    /// link is still active and to enqueue. The first-segment read already
    /// happened, so a slow source cannot stall packet ingress.
    async fn enqueue_staged(
        &self,
        link: &Arc<Mutex<Link>>,
        staged: crate::resource::outbound::StagedSource,
        options: ResourceOptions,
    ) -> Result<crate::hash::Hash, RnsError> {
        let resource = {
            let link_guard = link.lock().await;
            if link_guard.status() != LinkStatus::Active {
                return Err(RnsError::LinkNotReady);
            }
            crate::resource::outbound::OutgoingResource::finish_staged(
                staged,
                &link_guard,
                options,
            )?
        };
        let mut handler = self.handler.lock().await;
        let mut link_guard = link.lock().await;
        if link_guard.status() != LinkStatus::Active {
            return Err(RnsError::LinkNotReady);
        }
        enqueue_resource(&mut handler, &mut link_guard, resource).await
    }

    /// Cancel an outbound resource transfer on a link (Python
    /// `Resource.cancel` from the initiator): sends the RESOURCE_ICL
    /// packet and marks the transfer failed. Also cancels queued split
    /// segments of the same logical resource.
    pub async fn cancel_resource(
        &self,
        link_id: &LinkId,
        hash: &crate::hash::Hash,
    ) -> Result<(), RnsError> {
        let mut handler = self.handler.lock().await;
        let mut link = None;
        for candidate in handler.out_links.values().chain(handler.in_links.values()) {
            if candidate.lock().await.id() == link_id {
                link = Some(candidate.clone());
                break;
            }
        }
        let link = link.ok_or(RnsError::InvalidArgument)?;
        let link_guard = link.lock().await;
        // Cancel an outgoing transfer first; if none matches, fall back to
        // a receiver-side cancel of an incoming transfer.
        let outbound = handler.resources.cancel_outbound(&link_guard, hash);
        let tx = match outbound {
            Some(tx) => tx,
            None => handler
                .resources
                .cancel_inbound(&link_guard, hash)
                .ok_or(RnsError::ResourceMsg("no such resource on link"))?,
        };
        drop(link_guard);
        for packet in tx.packets {
            handler.send_packet(packet).await;
        }
        Ok(())
    }

    /// Send a request to the remote end of a link and await nothing (events
    /// arrive on `request_events`). Returns the request id
    /// (Python `Link.request`).
    pub async fn request(
        &self,
        link: &Arc<Mutex<Link>>,
        path: &str,
        data: &[u8],
    ) -> Result<AddressHash, RnsError> {
        let binned = msgpack_bin(data);
        self.request_element(link, path, Some(&binned)).await
    }

    /// [`Transport::request`] plus Python's per-request `timeout` and
    /// `max_response_size`. A timeout is armed when the request is
    /// delivered (immediately for a packet, after the request resource is
    /// proven otherwise) and fails the request on the resource watchdog.
    pub async fn request_with_options(
        &self,
        link: &Arc<Mutex<Link>>,
        path: &str,
        data: &[u8],
        options: RequestOptions,
    ) -> Result<AddressHash, RnsError> {
        self.dispatch_packed_request(link, pack_request(path, data), options)
            .await
    }

    /// [`request`](Self::request), but `element` is spliced as the third
    /// msgpack value instead of being wrapped in a bin. `None` is nil.
    pub async fn request_element(
        &self,
        link: &Arc<Mutex<Link>>,
        path: &str,
        element: Option<&[u8]>,
    ) -> Result<AddressHash, RnsError> {
        self.dispatch_packed_request(
            link,
            pack_request_element(path, element),
            RequestOptions::default(),
        )
        .await
    }

    async fn dispatch_packed_request(
        &self,
        link: &Arc<Mutex<Link>>,
        packed: Vec<u8>,
        options: RequestOptions,
    ) -> Result<AddressHash, RnsError> {
        let now = crate::resource::unix_time();

        // Build the request before taking the handler lock. A resource
        // request reads and encrypts its first segment here; the handler
        // lock is only held to send or enqueue.
        let link_guard = link.lock().await;
        if link_guard.status() != LinkStatus::Active {
            return Err(RnsError::LinkNotReady);
        }
        let link_id = *link_guard.id();

        if packed.len() <= link_guard.mdu() {
            let packet = link_guard.context_packet(&packed, PacketContext::Request)?;
            drop(link_guard);
            // A packet-carried request is tracked by its packet hashable
            // part (Python `PacketReceipt.truncated_hash`), which is the
            // id a responder echoes back. The response timer starts now.
            let rid = request_id_from_packet(&packet);
            let mut handler = self.handler.lock().await;
            handler.send_packet(packet).await;
            handler.resources.track_request(
                rid,
                PendingRequest {
                    link_id,
                    deadline: options.timeout.map(|timeout| now + timeout),
                    timeout: options.timeout,
                    max_response_size: options.max_response_size,
                },
            );
            return Ok(rid);
        }

        // A resource-carried request keeps the packed-payload id
        // (Python `Link.request` sets `request_id =
        // truncated_hash(packed_request)`). The response timer starts
        // when that resource is proven.
        let rid = make_request_id(&packed);
        let opts = ResourceOptions {
            request_id: Some(rid),
            is_response: false,
            timeout: options.timeout,
            ..Default::default()
        };
        let resource = crate::resource::outbound::OutgoingResource::new(packed, &link_guard, opts)?;
        drop(link_guard);
        let mut handler = self.handler.lock().await;
        let mut link_guard = link.lock().await;
        if link_guard.status() != LinkStatus::Active {
            return Err(RnsError::LinkNotReady);
        }
        enqueue_resource(&mut handler, &mut link_guard, resource).await?;
        handler.resources.track_request(
            rid,
            PendingRequest {
                link_id,
                deadline: None,
                timeout: options.timeout,
                max_response_size: options.max_response_size,
            },
        );
        Ok(rid)
    }

    /// Await a response for a previously sent request.
    ///
    /// A response that arrived between `request()` returning and this
    /// call subscribing is still delivered: completed responses are
    /// retained per request id by the transport until collected here
    /// (broadcast channels retain no history).
    pub async fn await_request_response(
        &self,
        request_id: AddressHash,
        timeout: core::time::Duration,
    ) -> Option<Vec<u8>> {
        // Subscribe first: a response arriving between the completed-map
        // check and the subscription would otherwise be stored and
        // broadcast with no receiver, and this loop would never recheck.
        let mut rx = self.request_events().await;

        // A response may already have completed.
        if let Some(result) = self.take_completed_response(request_id).await {
            return result;
        }
        let deadline = time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match time::timeout(remaining, rx.recv()).await {
                Ok(Ok(event)) => match event.event {
                    RequestEvent::Response {
                        request_id: rid,
                        data,
                        ..
                    } if rid == request_id => {
                        // Consumed through the event channel: drop any
                        // retained copy so long-running processes do not
                        // accumulate one buffer per completed request.
                        self.discard_completed_response(rid).await;
                        return Some(data);
                    }
                    RequestEvent::Failed { request_id: rid } if rid == request_id => {
                        self.discard_completed_response(rid).await;
                        return None;
                    }
                    _ => continue,
                },
                _ => return None,
            }
        }
    }

    /// Take a completed (arrived-before-awaiting) response for a request.
    async fn take_completed_response(&self, request_id: AddressHash) -> Option<Option<Vec<u8>>> {
        let mut handler = self.handler.lock().await;
        handler.resources.completed_responses.remove(&request_id)
    }

    /// Drop a retained response that was consumed through the event
    /// channel (prevents unbounded accumulation per completed request).
    async fn discard_completed_response(&self, request_id: AddressHash) {
        let mut handler = self.handler.lock().await;
        handler.resources.completed_responses.remove(&request_id);
    }

    /// Register a PLAIN (unencrypted broadcast) input destination
    /// (Python `RNS.Destination(None, IN, PLAIN, app, *aspects)`).
    pub async fn add_plain_destination(
        &mut self,
        name: DestinationName,
    ) -> Arc<Mutex<PlainInputDestination>> {
        let destination = PlainInputDestination::new(reticulum_core::identity::EmptyIdentity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add plain destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .plain_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    /// Register an inbound GROUP destination
    /// (Python `RNS.Destination(..., GROUP, ...)`).
    pub async fn add_group_destination(
        &mut self,
        name: DestinationName,
    ) -> Arc<Mutex<GroupInputDestination>> {
        let destination = GroupInputDestination::new(reticulum_core::identity::EmptyIdentity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp({}): add group destination {}", self.name, address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .group_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    /// Send a packet to a GROUP destination: encrypted with the group's
    /// symmetric key when `group_key` is provided, plaintext otherwise
    /// (Python `RNS.Packet(group_destination, data).send()`).
    pub async fn send_to_group_destination(
        &self,
        name: DestinationName,
        data: &[u8],
        group_key: Option<&[u8; reticulum_core::destination::GROUP_KEY_SIZE]>,
    ) -> Result<AddressHash, RnsError> {
        // With a group key the token adds IV (16) + HMAC (32) + CBC block
        // padding (up to 16): enforce the encrypted MDU so packets never
        // exceed the fixed 500-byte Reticulum MTU.
        let limit = if group_key.is_some() {
            crate::packet::PACKET_PROTOCOL_MDU
                .saturating_sub(crate::packet::TOKEN_OVERHEAD)
                .saturating_sub(crate::packet::AES128_BLOCKSIZE)
        } else {
            crate::packet::PACKET_PROTOCOL_MDU
        };
        if data.len() > limit {
            return Err(RnsError::InvalidArgument);
        }

        let mut destination =
            GroupOutputDestination::new(reticulum_core::identity::EmptyIdentity, name);
        if let Some(key) = group_key {
            destination.load_group_key(*key);
        }
        let address = destination.desc.address_hash;

        let mut packet_data = PacketDataBuffer::new();

        let mut buffer = [0u8; PACKET_MDU];
        match destination.encrypt_group(data, &mut buffer[..]) {
            Ok(token) => {
                let _ = packet_data.safe_write(token);
            }
            Err(_) => {
                // No group key loaded: plaintext (parity with Python
                // GROUP destinations that never load `prv`).
                let _ = packet_data.safe_write(data);
            }
        }

        let packet = Packet {
            header: Header {
                header_type: HeaderType::Type1,
                destination_type: DestinationType::Group,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            destination: address,
            data: packet_data,
            ..Default::default()
        };

        self.send_broadcast(packet, None).await;

        Ok(address)
    }

    /// Send an unencrypted packet to a PLAIN destination
    /// (Python `RNS.Packet(plain_destination, data).send()`).
    pub async fn send_to_plain_destination(
        &self,
        name: DestinationName,
        data: &[u8],
    ) -> Result<AddressHash, RnsError> {
        if data.len() > crate::packet::PACKET_PROTOCOL_MDU {
            return Err(RnsError::InvalidArgument);
        }
        let destination = PlainInputDestination::new(reticulum_core::identity::EmptyIdentity, name);
        let address = destination.desc.address_hash;

        let mut packet_data = PacketDataBuffer::new();
        let _ = packet_data.safe_write(data);

        let packet = Packet {
            header: Header {
                header_type: HeaderType::Type1,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: address,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        self.send_packet(packet).await;
        Ok(address)
    }

    /// Subscribe to delivery-proof events for packets sent to SINGLE
    /// destinations (Python `PacketReceipt` delivery callbacks).
    pub fn receipt_events(&self) -> broadcast::Receiver<ReceiptEvent> {
        self.receipt_tx.subscribe()
    }

    /// Send an encrypted packet to a known SINGLE destination
    /// (Python `RNS.Packet(destination, data).send()` for SINGLE
    /// destinations).
    ///
    /// The payload is encrypted to the destination identity, using its
    /// latest announced ratchet when one is known, and a packet receipt is
    /// kept so that a returned proof can be validated
    /// (see [`Transport::receipt_events`]). Returns the full packet hash.
    pub async fn send_to_destination(
        &self,
        destination_hash: &AddressHash,
        data: &[u8],
    ) -> Result<Hash, RnsError> {
        if data.len() > crate::packet::SINGLE_PLAINTEXT_MDU {
            return Err(RnsError::InvalidArgument);
        }
        let mut handler = self.handler.lock().await;

        let destination = handler
            .single_out_destinations
            .get(destination_hash)
            .cloned()
            .ok_or(RnsError::LinkNotReady)?;

        let destination = destination.lock().await;
        let identity = destination.desc.identity;

        let ratchet = {
            let now = unix_time_now();
            match handler.storage.clone() {
                Some(storage) => handler.known_ratchets.get(&*storage, destination_hash, now),
                None => handler.known_ratchets.get(
                    &*std::sync::Arc::new(crate::storage::MemoryStorage::new()),
                    destination_hash,
                    now,
                ),
            }
            .map(crate::identity::PublicKey::from)
        };

        let mut token = [0u8; PACKET_MDU];
        let token_len = identity
            .encrypt(OsRng, data, ratchet.as_ref(), &mut token[..])?
            .len();

        let mut packet_data = PacketDataBuffer::new();
        let _ = packet_data.safe_write(&token[..token_len]);

        let packet = Packet {
            header: Header {
                ifac_flag: crate::packet::IfacFlag::Open,
                context_flag: false,
                header_type: HeaderType::Type1,
                propagation_type: crate::packet::PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: *destination_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        let packet_hash = packet.hash();

        // Python creates a `PacketReceipt` for every outbound DATA packet.
        // Unknown paths use PATHFINDER_M hops, matching `Transport.hops_to`.
        let hops = handler
            .path_table
            .get(destination_hash)
            .map(|entry| entry.hops)
            .unwrap_or(PATHFINDER_M as u8);
        let bitrate = match handler
            .path_table
            .get(destination_hash)
            .map(|entry| entry.iface)
        {
            Some(iface) => handler
                .iface_manager
                .lock()
                .await
                .with_control(&iface, |control| control.bitrate)
                .unwrap_or(0),
            None => 0,
        };
        handler.receipts.insert(
            AddressHash::new_from_hash(&packet_hash),
            PacketReceipt {
                destination: *destination_hash,
                packet_hash,
                identity,
                sent_at: time::Instant::now(),
                timeout: Some(first_hop_timeout(bitrate) + TIMEOUT_PER_HOP * u32::from(hops)),
                status: ReceiptStatus::Sent,
                concluded_at: None,
            },
        );
        cull_receipts(&mut handler.receipts);

        let (packet, iface) = handler.path_table.handle_packet(&packet);
        if let Some(iface) = iface {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: Box::new(packet),
                })
                .await;
        } else {
            handler.send_packet(packet).await;
        }

        Ok(packet_hash)
    }

    /// Recall the identity announced for a destination hash
    /// (Python `Identity.recall`), preferring the known-destinations store
    /// and falling back to locally registered or announced destinations.
    pub async fn recall(
        &self,
        destination_hash: &AddressHash,
    ) -> Option<crate::identity::Identity> {
        let mut handler = self.handler.lock().await;
        let now = unix_time_now();

        if let Some(identity) = handler.known_destinations.recall(destination_hash, now) {
            persist_known_destinations(&mut handler);
            return Some(identity);
        }

        if let Some(destination) = handler.single_in_destinations.get(destination_hash) {
            let destination = destination.lock().await;
            return Some(destination.desc.identity);
        }

        if let Some(destination) = handler.single_out_destinations.get(destination_hash) {
            let destination = destination.lock().await;
            return Some(destination.desc.identity);
        }

        None
    }

    /// Last heard app data for a destination
    /// (Python `Identity.recall_app_data`).
    pub async fn recall_app_data(&self, destination_hash: &AddressHash) -> Option<Vec<u8>> {
        let mut handler = self.handler.lock().await;
        let app_data = handler
            .known_destinations
            .recall_app_data(destination_hash, unix_time_now());
        persist_known_destinations(&mut handler);
        app_data
    }

    /// Keep the data of a destination across cleanups
    /// (Python `Identity._retain_destination_data`).
    pub async fn retain_destination_data(&self, destination_hash: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;
        let retained = handler.known_destinations.retain(destination_hash);
        persist_known_destinations(&mut handler);
        retained
    }

    /// Stop retaining the data of a destination
    /// (Python `Identity._unretain_destination_data`).
    pub async fn unretain_destination_data(&self, destination_hash: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;
        let unretained = handler
            .known_destinations
            .unretain(destination_hash, unix_time_now());
        persist_known_destinations(&mut handler);
        unretained
    }

    /// Mark destination data as recently used
    /// (Python `Identity._used_destination_data`).
    pub async fn used_destination_data(&self, destination_hash: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;
        let used = handler
            .known_destinations
            .mark_used(destination_hash, unix_time_now());
        persist_known_destinations(&mut handler);
        used
    }

    /// Retain every known destination belonging to an identity
    /// (Python `Identity._retain_identity`).
    pub async fn retain_identity(&self, identity_hash: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;
        let retained = handler.known_destinations.retain_identity(identity_hash);
        persist_known_destinations(&mut handler);
        retained
    }

    /// Number of known destinations (Python
    /// `len(RNS.Identity.known_destinations)`).
    pub async fn known_destinations_len(&self) -> usize {
        self.handler.lock().await.known_destinations.len()
    }

    /// Persist the known-destinations store
    /// (Python `Identity.save_known_destinations`).
    pub async fn save_known_destinations(&self) -> Result<(), RnsError> {
        let mut handler = self.handler.lock().await;

        let storage = handler.storage.clone().ok_or(RnsError::Storage)?;

        handler.known_destinations.save(&*storage)
    }

    /// Load the known-destinations store from storage
    /// (Python `Identity.load_known_destinations`). Persisted blackhole
    /// lists are reloaded afterwards, exactly like Python's
    /// `Transport.start` ordering, so blackholed paths are dropped with
    /// the recalled-identity table available.
    pub async fn load_known_destinations(&self) -> Result<(), RnsError> {
        let mut handler = self.handler.lock().await;

        let storage = handler.storage.clone().ok_or(RnsError::Storage)?;

        handler.known_destinations.load(&*storage)?;

        // Python `Transport.start`: reload persisted blackhole lists once
        // the recalled identities are available, then drop blackholed
        // paths.
        drop(handler);
        self.reload_blackholes().await;

        Ok(())
    }

    /// The current ratchet key of a destination
    /// (Python `Identity.get_ratchet`).
    pub async fn get_ratchet(
        &self,
        destination_hash: &AddressHash,
    ) -> Option<[u8; reticulum_core::identity::RATCHET_KEY_LENGTH]> {
        let mut handler = self.handler.lock().await;

        let storage = handler
            .storage
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

        handler
            .known_ratchets
            .get(&*storage, destination_hash, unix_time_now())
    }

    /// The id of the current ratchet of a destination
    /// (Python `Identity.current_ratchet_id`).
    pub async fn current_ratchet_id(&self, destination_hash: &AddressHash) -> Option<[u8; 10]> {
        let mut handler = self.handler.lock().await;

        let storage = handler
            .storage
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

        handler
            .known_ratchets
            .current_ratchet_id(&*storage, destination_hash, unix_time_now())
    }

    /// Remove expired and unknown ratchets and stale known destinations
    /// (Python `Identity.clean_known_destinations` +
    /// `Identity._clean_ratchets`). Returns the number of removed ratchet
    /// files and stale destination hashes.
    pub async fn clean_known_destinations(&self) -> (usize, Vec<AddressHash>) {
        let mut handler = self.handler.lock().await;
        let now = unix_time_now();

        let storage = handler
            .storage
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

        let TransportHandler {
            path_table,
            known_destinations,
            known_ratchets,
            ..
        } = &mut *handler;

        let stale = known_destinations.clean(now, |hash| path_table.contains(hash));

        // Python removes the ratchet files of stale destinations.
        for hash in &stale {
            let path = format!("{}/{}", crate::storage::RATCHETS_DIR, hash.to_hex_string());
            storage.remove(&path);
        }

        // Python keeps ratchets only for destinations still present in the
        // known-destinations store.
        let known_hashes: std::collections::HashSet<AddressHash> = known_destinations
            .entries()
            .iter()
            .map(|(hash, _)| *hash)
            .collect();
        let removed_ratchets =
            known_ratchets.clean(&*storage, now, |hash| known_hashes.contains(hash));

        persist_known_destinations(&mut handler);

        (removed_ratchets, stale)
    }

    /// Enable ratchets on a local SINGLE destination, loading any retained
    /// private ratchet keys from `ratchets_path` and persisting rotations
    /// back to it (Python `Destination.enable_ratchets`).
    pub async fn enable_destination_ratchets(
        &self,
        destination_hash: &AddressHash,
        ratchets_path: &str,
    ) -> Result<(), RnsError> {
        let mut handler = self.handler.lock().await;

        let storage = handler.storage.clone().ok_or(RnsError::Storage)?;

        let destination = handler
            .single_in_destinations
            .get(destination_hash)
            .cloned()
            .ok_or(RnsError::InvalidArgument)?;

        let identity = destination.lock().await.desc.identity;

        let ratchets =
            crate::storage::load_destination_ratchets(&*storage, ratchets_path, &identity)?;
        let had_ratchets = !ratchets.is_empty();

        {
            let mut destination = destination.lock().await;
            destination.enable_ratchets(ratchets);
        }

        // Persist an empty ratchet file like Python does on first load.
        if !had_ratchets {
            let destination = destination.lock().await;
            let private_identity = destination.identity.clone();

            let mut ratchets = destination
                .ratchets()
                .map(|keys| keys.to_vec())
                .unwrap_or_default();
            crate::storage::clean_destination_ratchets(
                &mut ratchets,
                destination.retained_ratchets,
            );

            crate::storage::save_destination_ratchets(
                &*storage,
                ratchets_path,
                &private_identity,
                &ratchets,
            )?;
        }

        handler
            .destination_ratchet_paths
            .insert(*destination_hash, ratchets_path.to_string());

        Ok(())
    }

    pub async fn get_in_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleInputDestination>>> {
        self.handler
            .lock()
            .await
            .single_in_destinations
            .get(address)
            .cloned()
    }

    pub async fn get_out_destination(
        &self,
        address: &AddressHash,
    ) -> Option<Arc<Mutex<SingleOutputDestination>>> {
        self.handler
            .lock()
            .await
            .single_out_destinations
            .get(address)
            .cloned()
    }

    pub async fn has_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.has_destination(address)
    }

    pub async fn knows_destination(&self, address: &AddressHash) -> bool {
        self.handler.lock().await.knows_destination(address)
    }

    /// Observable receipt for an outbound packet hash.
    /// `timeout == None` is Python `timeout = -1`. `rtt` is set once the
    /// receipt has concluded (delivered, failed, or culled).
    pub async fn receipt(&self, packet_hash: &Hash) -> Option<PacketReceiptInfo> {
        let handler = self.handler.lock().await;
        handler
            .receipts
            .get(&AddressHash::new_from_hash(packet_hash))
            .map(receipt_info)
    }

    /// Set the receipt timeout. `None` is Python `set_timeout` of -1,
    /// which the next check concludes as culled.
    pub async fn set_receipt_timeout(&self, packet_hash: &Hash, timeout: Option<Duration>) -> bool {
        let mut handler = self.handler.lock().await;
        let Some(receipt) = handler
            .receipts
            .get_mut(&AddressHash::new_from_hash(packet_hash))
        else {
            return false;
        };
        receipt.timeout = timeout;
        true
    }

    /// Drop queued announces on every interface
    /// (Python `Transport.drop_announce_queues`).
    pub async fn drop_announce_queues(&self) {
        self.iface_manager.lock().await.drop_announce_queues();
    }

    /// Write the path table, tunnel table, and (when transport is
    /// enabled) the packet hashlist (Python `Transport.persist_data`).
    /// Skipped while connected to a shared instance.
    pub async fn persist_data(&self) {
        let mut handler = self.handler.lock().await;
        persist_handler(&mut handler).await;
    }

    /// Load persisted transport tables once interfaces are attached
    /// (Python loads them at startup, after interfaces exist).
    /// Paths whose interface is not up yet stay pending and are tried
    /// again when that interface is added.
    pub async fn load_persisted_state(&self) {
        let mut handler = self.handler.lock().await;
        handler.persisted_loaded = false;
        handler.unresolved_paths = None;
        handler.persisted_aux_loaded = false;
        load_persisted_state(&mut handler).await;
    }

    pub(crate) fn get_handler(&self) -> Arc<Mutex<TransportHandler>> {
        self.handler.clone()
    }

    /// Snapshot of per-interface statistics of all interfaces attached to
    /// this transport (counters, names, kinds and online status), the data
    /// source for `rnstatus`-style reporting (Phase 5.9).
    pub async fn interface_stats(&self) -> Vec<crate::iface::InterfaceStats> {
        self.iface_manager.lock().await.stats()
    }

    /// Snapshot the statistics of the interface a link is established over.
    ///
    /// Inbound (and relayed) links report the interface their link request
    /// arrived on; outbound links report the next-hop interface of the
    /// path toward their destination. Returns `None` for unknown links or
    /// when no interface can be determined (e.g. an unserved path).
    pub async fn interface_stats_for_link(
        &self,
        id: LinkId,
    ) -> Option<crate::iface::InterfaceStats> {
        let handler = self.handler.lock().await;
        let iface = handler
            .in_link_ifaces
            .get(&id)
            .copied()
            .or_else(|| handler.link_table.iface_of(&id))
            .or_else(|| {
                handler
                    .out_links
                    .iter()
                    .find(|(_, link)| link.try_lock().is_ok_and(|link| link.id() == &id))
                    .and_then(|(destination, _)| {
                        handler.path_table.get(destination).map(|entry| entry.iface)
                    })
            })?;
        drop(handler);
        self.iface_manager
            .lock()
            .await
            .stats()
            .into_iter()
            .find(|stats| stats.address == iface)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        if let Ok(mut handler) = self.handler.try_lock() {
            if !handler.shutdown_persisted && try_persist_handler(&mut handler) {
                handler.shutdown_persisted = true;
            }
        }
        self.cancel.cancel();
    }
}

impl TransportHandler {
    pub(crate) async fn send_packet(&self, packet: Packet) {
        let message = TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet: Box::new(packet),
        };

        self.send(message).await;
    }

    /// Send a packet that originated on `link`. Stamps `last_outbound`
    /// (and `last_keepalive` for keepalive context) before the bytes go
    /// out. Callers that already hold the link lock must use this: `send`
    /// only try-locks, and a held guard makes that miss.
    async fn send_from_link(&self, link: &mut Link, packet: Packet) {
        link.mark_outbound(packet.context == PacketContext::KeepAlive);
        self.send_packet(packet).await;
    }

    /// Python `Packet.send` sets `last_outbound` when the destination is a
    /// link. Link requests are addressed to a destination, so Python calls
    /// `had_outbound` explicitly; the same stamp is applied here when the
    /// link lock is free.
    fn note_unlocked_link_outbound(&self, packet: &Packet) {
        let is_keepalive = packet.context == PacketContext::KeepAlive;
        if packet.header.destination_type == DestinationType::Link {
            if let Some(link) = self.in_links.get(&packet.destination) {
                if let Ok(mut link) = link.try_lock() {
                    link.mark_outbound(is_keepalive);
                }
                return;
            }
            for link in self.out_links.values() {
                let Ok(mut link) = link.try_lock() else {
                    continue;
                };
                if link.id() == &packet.destination {
                    link.mark_outbound(is_keepalive);
                    return;
                }
            }
            return;
        }
        if packet.header.packet_type == PacketType::LinkRequest {
            if let Some(link) = self.out_links.get(&packet.destination) {
                if let Ok(mut link) = link.try_lock() {
                    link.mark_outbound(false);
                }
            }
        }
    }

    async fn send(&self, message: TxMessage) {
        // Early rejection of excessive hop counts
        // (Python `Transport._outbound`:
        // `if packet.hops > Transport.PATHFINDER_M-1: return False`).
        if message.packet.header.hops as usize > PATHFINDER_M - 1 {
            log::debug!(
                "tp({}): dropping outbound packet with excessive hop count {}",
                self.config.name,
                message.packet.header.hops
            );
            return;
        }
        self.note_unlocked_link_outbound(&message.packet);
        self.packet_cache.lock().await.update(&message.packet);
        self.iface_manager.lock().await.send(message).await;
    }

    fn has_destination(&self, address: &AddressHash) -> bool {
        self.single_in_destinations.contains_key(address)
    }

    fn knows_destination(&self, address: &AddressHash) -> bool {
        self.single_out_destinations.contains_key(address)
    }

    fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.out_links.get(link_id).cloned()
    }

    fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.in_links.get(link_id).cloned()
    }

    pub(crate) async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
        let link = if let Some(link) = self.find_in_link(&link_id) {
            Some((link, &self.link_in_event_tx))
        } else {
            self.find_out_link(&link_id)
                .map(|link| (link, &self.link_out_event_tx))
        };
        if let Some((link, event_tx)) = link {
            let mut link = link.lock().await;
            if let Some(packet) = link.teardown(event_tx)? {
                drop(link);
                self.send_packet(packet).await
            }
        } else {
            log::warn!("tp({}): close link {link_id} not found", self.config.name)
        }
        Ok(())
    }

    async fn filter_duplicate_packets(&self, packet: &Packet) -> bool {
        let mut allow_duplicate = false;

        // Python defers hash insertion for packets belonging to a
        // link-table entry, and for every link-request proof: on shared
        // media the same packet can legitimately be heard (and relayed)
        // more than once, and premature insertion would break link
        // transport.
        if self.link_table.contains_destination(&packet.destination)
            || (packet.header.packet_type == PacketType::Proof
                && packet.context == PacketContext::LinkRequestProof)
        {
            allow_duplicate = true;
        }

        match packet.header.packet_type {
            PacketType::Announce => {
                return true;
            }
            PacketType::LinkRequest => {
                allow_duplicate = true;
            }
            PacketType::Data => {
                allow_duplicate = packet.context == PacketContext::KeepAlive;
            }
            PacketType::Proof => {
                if packet.context == PacketContext::LinkRequestProof {
                    if let Some(link) = self.in_links.get(&packet.destination) {
                        if link.lock().await.status().not_yet_active() {
                            allow_duplicate = true;
                        }
                    }
                }
            }
        }

        let is_new = self.packet_cache.lock().await.update(packet);

        is_new || allow_duplicate
    }

    async fn request_path(
        &mut self,
        address: &AddressHash,
        on_iface: Option<AddressHash>,
        tag: Option<TagBytes>,
    ) {
        let packet = self.path_requests.generate(address, tag);

        self.send(TxMessage {
            tx_type: TxMessageType::Broadcast(on_iface),
            packet: Box::new(packet),
        })
        .await;
    }

    async fn bind_link_to_channel(
        &mut self,
        id: LinkId,
    ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
        if self.channel_table.contains_key(&id) {
            return Err(RnsError::ChannelError);
        }

        let (tx, rx) = broadcast::channel(16);
        self.channel_table.insert(id, tx.into());

        Ok(rx)
    }
}

/// Build a proof packet for a SINGLE-destination data packet
/// (Python `Packet.prove` + `Identity.prove`).
///
/// The proof is addressed to a synthetic destination derived from the
/// truncated packet hash and carried unencrypted. `proof_data` is the
/// signature alone for implicit proofs, or `packet_hash || signature` for
/// explicit ones.
fn create_single_destination_proof(
    handler: &TransportHandler,
    packet: &Packet,
    proof_strategy: ProofStrategy,
    sign_key: &crate::identity::SigningKey,
) -> Option<Packet> {
    // PROVE_APP is decided by `Destination::should_prove` at the call
    // site. This builder only emits a proof once that decision is All.
    let should_prove = match proof_strategy {
        ProofStrategy::None | ProofStrategy::App => false,
        ProofStrategy::All => true,
    };

    if !should_prove {
        return None;
    }

    let packet_hash = packet.hash();

    let signature = sign_key.sign(packet_hash.as_slice()).to_bytes();

    let mut packet_data = PacketDataBuffer::new();
    if handler.config.use_implicit_proof {
        let _ = packet_data.safe_write(&signature);
    } else {
        let _ = packet_data.safe_write(packet_hash.as_slice());
        let _ = packet_data.safe_write(&signature);
    }

    // Python `ProofDestination`: the truncated hash of the proved packet
    // addressed as a SINGLE destination.
    let proof_destination = AddressHash::new_from_hash(&packet_hash);

    Some(Packet {
        header: Header {
            ifac_flag: crate::packet::IfacFlag::Open,
            context_flag: false,
            header_type: HeaderType::Type1,
            propagation_type: crate::packet::PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Proof,
            hops: 0,
        },
        ifac: None,
        destination: proof_destination,
        transport: None,
        context: PacketContext::None,
        data: packet_data,
    })
}

/// Validate a proof for an outbound SINGLE-destination packet and emit a
/// [`ReceiptEvent`] (Python `PacketReceipt.validate_proof`).
fn validate_single_destination_proof(handler: &mut TransportHandler, packet: &Packet) -> bool {
    let Some(receipt) = handler.receipts.get(&packet.destination).cloned() else {
        return false;
    };

    let proof = packet.data.as_slice();
    let valid = if proof.len() == 64 {
        // Implicit proof: signature only
        crate::identity::Signature::from_slice(proof).is_ok_and(|signature| {
            receipt
                .identity
                .verify(receipt.packet_hash.as_slice(), &signature)
                .is_ok()
        })
    } else if proof.len() == 96 {
        // Explicit proof: packet hash + signature
        let proof_hash = &proof[..32];
        proof_hash == receipt.packet_hash.as_slice()
            && crate::identity::Signature::from_slice(&proof[32..]).is_ok_and(|signature| {
                receipt
                    .identity
                    .verify(receipt.packet_hash.as_slice(), &signature)
                    .is_ok()
            })
    } else {
        false
    };

    if valid {
        if let Some(stored) = handler.receipts.get_mut(&packet.destination) {
            stored.status = ReceiptStatus::Delivered;
            stored.concluded_at = Some(time::Instant::now());
        }
        let _ = handler.receipt_tx.send(ReceiptEvent {
            destination: receipt.destination,
            packet_hash: receipt.packet_hash,
        });
    }

    valid
}

async fn handle_proof<'a>(
    packet: &Packet,
    ingress_iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    // Resource proofs (receiver -> sender) are handled by the resource
    // engine; they are never encrypted (Python Packet.pack rules).
    if packet.context == PacketContext::ResourceProof {
        // `out_links` is keyed by destination hash while `in_links` is keyed
        // by link id, so scan for the link matching the packet destination.
        let mut link = None;
        for candidate in handler.out_links.values() {
            let id = *candidate.lock().await.id();
            if id == packet.destination {
                link = Some(candidate.clone());
                break;
            }
        }
        let link = link.or_else(|| handler.in_links.get(&packet.destination).cloned());
        if let Some(link) = link {
            let mut link_guard = link.lock().await;
            // Resource proofs return before link data handling. Refresh
            // inbound silence for an established link first.
            note_established_inbound(&mut link_guard, packet, false);
            let mut tx = ResourceTx::default();
            handler
                .resources
                .handle_proof(&link_guard, packet.data.as_slice(), &mut tx);
            for reply in tx.packets {
                handler.send_from_link(&mut link_guard, reply).await;
            }
            drop(link_guard);
            handler.resources.cleanup();
            // Locally terminated: no intermediary relay for this proof.
            return;
        }
        // No local link owns this proof: fall through to the link-table
        // relay below (Python routes every non-LRPROOF link packet).
    }

    relay_reverse_proof(packet, ingress_iface, &mut handler).await;

    // Proofs for our own outbound SINGLE-destination packets are addressed
    // to the truncated packet hash of the proved packet.
    if packet.header.destination_type == DestinationType::Single
        && handler.receipts.contains_key(&packet.destination)
        && validate_single_destination_proof(&mut handler, packet)
    {
        log::trace!(
            "tp({}): valid proof for packet {}",
            handler.config.name,
            packet.destination
        );
        return;
    }

    let mut local_proof_handled = false;
    let mut rebalanced_path: Option<(AddressHash, u8)> = None;
    for link in handler.out_links.values() {
        let link_id = *link.lock().await.id();
        if link_id != packet.destination {
            continue;
        }

        local_proof_handled = true;
        let mut link = link.lock().await;

        if let LinkHandleResult::Activated = link.handle_packet(
            &handler.link_out_event_tx,
            handler.channel_table.get(&link_id),
            packet,
            true,
        ) {
            // Initiator-side path rebalancing (Python updates
            // `link.expected_hops` and `IDX_PT_HOPS` when a validated
            // proof arrives with a different hop count than expected).
            let observed = packet.header.hops.saturating_add(1);
            rebalanced_path = Some((link.destination().address_hash, observed));

            let rtt_packet = link.create_rtt();
            handler.send_from_link(&mut link, rtt_packet).await;
        }
    }

    if let Some((destination, observed)) = rebalanced_path {
        if let Some(previous) = handler.path_table.get(&destination).map(|e| e.hops) {
            if previous != observed {
                log::debug!(
                    "tp({}): re-balancing path to {} from link proof ({} -> {})",
                    handler.config.name,
                    destination,
                    previous,
                    observed
                );
                handler.path_table.rebalance_hops(&destination, observed);
            }
        }
    }

    for link in handler.in_links.values() {
        let link_id = *link.lock().await.id();
        if link_id != packet.destination {
            continue;
        }

        local_proof_handled = true;
        let mut link = link.lock().await;

        link.handle_packet(
            &handler.link_in_event_tx,
            handler.channel_table.get(&link_id),
            packet,
            false,
        );
    }

    // Intermediary relay of link-message proofs (Python link-transport
    // handling covers every packet addressed to a link-table entry
    // except ANNOUNCE, LINKREQUEST and LRPROOF-context packets).
    if !local_proof_handled && packet.context != PacketContext::LinkRequestProof {
        if let Some((packet, iface)) = handler.link_table.route_link_packet(packet, ingress_iface) {
            log::trace!(
                "tp({}): forwarded link proof {}",
                handler.config.name,
                packet.destination
            );
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: Box::new(packet),
                })
                .await;
        }
    }

    // Link-request proofs for intermediary (relayed) links: validate the
    // destination's signature via the recalled identity and relay toward
    // the initiator (Python Transport.inbound LRPROOF handling).
    if packet.context == PacketContext::LinkRequestProof {
        let now = unix_time_now();
        let recalled = handler
            .known_destinations
            .recall(&packet.destination, now)
            .or_else(|| {
                // Fall back to the link entry's original destination when
                // the proof address (link id) has no known-destinations
                // entry.
                handler
                    .link_table
                    .original_destination_of(&packet.destination)
                    .and_then(|destination| handler.known_destinations.recall(&destination, now))
            });

        let outcome = handler
            .link_table
            .handle_lr_proof(packet, ingress_iface, recalled.as_ref());

        if let Some((destination, hops)) = outcome.path_hops_update {
            handler.path_table.rebalance_hops(&destination, hops);
        }

        if let Some((packet, iface)) = outcome.relay {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: Box::new(packet),
                })
                .await;
        }
    }
}

async fn send_to_next_hop<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    lookup: Option<AddressHash>,
    ingress: Option<AddressHash>,
) -> bool {
    let truncated = AddressHash::new_from_hash(&packet.hash());
    let is_link_request = packet.header.packet_type == PacketType::LinkRequest;
    let (mut packet, maybe_iface) = handler.path_table.handle_inbound_packet(packet, lookup);

    if let Some(iface) = maybe_iface {
        // Return path for a later proof (Python `reverse_table`). Link
        // requests are tracked in the link table instead.
        if !is_link_request {
            if let Some(received) = ingress {
                handler.reverse_table.insert(
                    truncated,
                    ReverseEntry {
                        received,
                        outbound: iface,
                        at: time::Instant::now(),
                    },
                );
            }
        }
        // Python clamps or removes the link-request MTU signalling
        // bytes when relaying onto interfaces that cannot negotiate a
        // path MTU (no AUTOCONFIGURE_MTU/FIXED_MTU, e.g. UDP, serial,
        // RNode, I2P: "disabling link MTU upgrade").
        if packet.header.packet_type == PacketType::LinkRequest {
            let supports_mtu = handler
                .iface_manager
                .lock()
                .await
                .iface_kind(&iface)
                .map(|kind| {
                    // Python AUTOCONFIGURE_MTU/FIXED_MTU interfaces:
                    // TCP, Backbone, local shared-instance links,
                    // AutoInterface and Weave. Everything else (UDP,
                    // serial, KISS, RNode, I2P, AX.25, pipes) disables
                    // the upgrade.
                    matches!(
                        kind.as_str(),
                        "TcpClient"
                            | "TcpServer"
                            | "BackboneClient"
                            | "BackboneServer"
                            | "AutoInterface"
                            | "LocalServer"
                            | "LocalClient"
                            | "WeaveInterface"
                            | "WeaveInterfacePeer"
                    )
                })
                .unwrap_or(false);

            if !supports_mtu {
                let len = packet.data.as_slice().len();
                // LR data = pub(32) + verify(32) [|| signalling(3)]
                if len == 32 + 32 + crate::destination::link::LINK_MTU_SIZE {
                    let mut data = PacketDataBuffer::new();
                    let _ = data.chain_write(&packet.data.as_slice()[..len - 3]);
                    packet.data = data;
                }
            }
        }

        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Box::new(packet),
            })
            .await;
    }

    maybe_iface.is_some()
}

async fn handle_keepalive_response<'a>(
    packet: &Packet,
    ingress_iface: AddressHash,
    handler: &mut MutexGuard<'a, TransportHandler>,
) -> bool {
    if packet.context == PacketContext::KeepAlive
        && packet.data.as_slice().first() == Some(&KEEP_ALIVE_RESPONSE)
    {
        let lookup = handler.link_table.handle_keepalive(packet, ingress_iface);

        if let Some((propagated, iface)) = lookup {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: Box::new(propagated),
                })
                .await;
        }

        return true;
    }

    false
}

async fn handle_resource_packet<'a>(
    packet: &Packet,
    link_arc: &Arc<Mutex<Link>>,
    transport_handler: &Arc<Mutex<TransportHandler>>,
    handler: &mut MutexGuard<'a, TransportHandler>,
) -> bool {
    use crate::packet::PacketContext as Ctx;

    let mut link = link_arc.lock().await;
    let handled = match packet.context {
        Ctx::ResourceAdvertisement => {
            let mut buffer = [0u8; PACKET_MDU];
            match link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plaintext) => {
                    let tx = handler
                        .resources
                        .handle_advertisement(&link, packet, plaintext);
                    for p in tx.packets {
                        handler.send_from_link(&mut link, p).await;
                    }
                    // an accepted request resource may need dispatch once done
                    true
                }
                Err(_) => false,
            }
        }
        Ctx::ResourceRequest => {
            let mut buffer = [0u8; PACKET_MDU];
            match link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plaintext) => {
                    let tx = handler.resources.handle_request_data(&link, plaintext);
                    for p in tx.packets {
                        handler.send_from_link(&mut link, p).await;
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Ctx::ResourceHashUpdate => {
            let mut buffer = [0u8; PACKET_MDU];
            match link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plaintext) => {
                    let tx = handler.resources.handle_hashmap_update(&link, plaintext);
                    for p in tx.packets {
                        handler.send_from_link(&mut link, p).await;
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Ctx::Resource => {
            let (part_tx, completed) = handler.resources.handle_part(&link, packet);
            for p in part_tx.packets {
                handler.send_from_link(&mut link, p).await;
            }
            if completed {
                let mut tx = crate::resource::ResourceTx::default();
                if let Some((_hash, data)) = handler.resources.assemble_completed(&link, &mut tx) {
                    for p in tx.packets {
                        handler.send_from_link(&mut link, p).await;
                    }
                    // Dispatch an inbound request resource to handlers
                    let request_data = data;
                    if let Some((_time, path_hash, req_payload)) =
                        crate::resource::manager::unpack_request(&request_data)
                    {
                        let rid = make_request_id(&request_data);
                        let link_for_dispatch = link_arc.clone();
                        drop(link);
                        handle_incoming_request(
                            &link_for_dispatch,
                            rid,
                            _time,
                            path_hash,
                            req_payload,
                            transport_handler,
                            handler,
                        )
                        .await;
                    }
                } else {
                    for p in tx.packets {
                        handler.send_from_link(&mut link, p).await;
                    }
                }
            }
            true
        }
        Ctx::ResourceProof => {
            let mut tx = ResourceTx::default();
            handler
                .resources
                .handle_proof(&link, packet.data.as_slice(), &mut tx);
            for reply in tx.packets {
                handler.send_from_link(&mut link, reply).await;
            }
            handler.resources.cleanup();
            true
        }
        Ctx::ResourceInitiatorCancel => {
            let mut buffer = [0u8; PACKET_MDU];
            if let Ok(plaintext) = link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                handler.resources.handle_cancel(&link, plaintext);
            }
            true
        }
        Ctx::ResourceReceiverCancel => {
            let mut buffer = [0u8; PACKET_MDU];
            if let Ok(plaintext) = link.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                handler.resources.handle_reject(&link, plaintext);
            }
            true
        }
        _ => false,
    };
    handled
}

/// Queue `resource` behind any transfer already running on the link, or
/// advertise it immediately. Callers already hold the handler and link locks.
async fn enqueue_resource(
    handler: &mut TransportHandler,
    link: &mut Link,
    mut resource: crate::resource::OutgoingResource,
) -> Result<Hash, RnsError> {
    let active = handler
        .resources
        .out
        .get(link.id())
        .is_some_and(|list| list.iter().any(|r| !r.status.is_concluded()));
    let mut tx = ResourceTx::default();
    if active {
        resource.status = crate::resource::ResourceStatus::Queued;
    } else {
        resource.advertise(link, &mut tx)?;
    }
    let hash = resource.hash;
    handler
        .resources
        .out
        .entry(*link.id())
        .or_default()
        .push(resource);
    for packet in tx.packets {
        handler.send_from_link(link, packet).await;
    }
    Ok(hash)
}

/// Send a request response as a packet or resource
/// (shared by the sync and async handler paths).
///
/// A msgpack element is wrapped as `[request_id, element]`. A file is
/// Python's `(BufferedReader, metadata)` return: the bytes go out as a
/// resource with no msgpack wrapper, using the handler's auto_compress.
async fn send_response<'a>(
    link: &mut Link,
    rid: &AddressHash,
    response: &RequestResponse,
    auto_compress: bool,
    auto_compress_limit: Option<usize>,
    handler: &mut MutexGuard<'a, TransportHandler>,
) {
    let opts = ResourceOptions {
        request_id: Some(*rid),
        is_response: true,
        auto_compress,
        auto_compress_limit,
        ..Default::default()
    };
    let resource = match response {
        RequestResponse::Element(element) => {
            let packed = pack_response(rid, element);
            if packed.len() <= link.mdu() {
                if let Ok(packet) = link.context_packet(&packed, PacketContext::Response) {
                    handler.send_from_link(link, packet).await;
                }
                return;
            }
            crate::resource::OutgoingResource::new(packed, link, opts)
        }
        RequestResponse::File { path, metadata } => {
            let mut opts = opts;
            opts.metadata = metadata.clone();
            crate::resource::OutgoingResource::from_path(path, link, opts)
        }
    };
    match resource {
        Ok(resource) => {
            if let Err(err) = enqueue_resource(handler, link, resource).await {
                log::debug!("tp: could not send response resource: {err:?}");
            }
        }
        Err(err) => log::debug!("tp: could not send response resource: {err:?}"),
    }
}

async fn handle_incoming_request<'a>(
    link_arc: &Arc<Mutex<Link>>,
    rid: AddressHash,
    requested_at: f64,
    path_hash: AddressHash,
    request_data: Vec<u8>,
    transport_handler: &Arc<Mutex<TransportHandler>>,
    handler: &mut MutexGuard<'a, TransportHandler>,
) {
    let mut link = link_arc.lock().await;
    let destination = link.destination().address_hash;
    let remote_identity = link.remote_identity();

    // Async handlers run WITHOUT the transport/link locks held: snapshot
    // the inputs, drop the link guard, run the future on the runtime, and
    // send the response afterwards. Awaiting user code while holding both
    // locks deadlocked any handler that re-entered transport APIs
    // (send_packet/request/send_resource) and stalled all packet
    // processing for slow handlers.
    if let Some(async_fn) = handler
        .resources
        .async_request_handler(&destination, &path_hash)
    {
        // Async handlers have no allow policy. They send with the default
        // compress values; the sync config path is what restricts peers.
        let link_id = *link.id();
        drop(link);

        // Async handlers run on the runtime WITHOUT the transport lock:
        // awaiting user code while holding the handler guard stalls all
        // packet processing and deadlocks handlers that re-enter
        // transport APIs. The response is sent once the future resolves
        // and the lock is re-acquired.
        let link_arc = link_arc.clone();
        let transport_handler = transport_handler.clone();
        tokio::spawn(async move {
            let response = async_fn(RequestCtx {
                path_hash,
                data: request_data,
                request_id: rid,
                link_id,
                remote_identity,
                requested_at,
            })
            .await;

            if let Some(response) = response {
                let mut handler = transport_handler.lock().await;
                let mut link = link_arc.lock().await;
                send_response(
                    &mut link,
                    &rid,
                    &RequestResponse::Element(response),
                    true,
                    None,
                    &mut handler,
                )
                .await;
            }
        });
        return;
    }

    let Some(registered) = handler.resources.request_handler(&destination, &path_hash) else {
        log::trace!("tp: no handler for request path {path_hash}");
        return;
    };
    if !registered.allows(&remote_identity) {
        log::debug!("tp: request from peer not allowed");
        return;
    }
    let auto_compress = registered.config.auto_compress;
    let auto_compress_limit = registered.config.auto_compress_limit;

    let response = registered.call(RequestCtx {
        path_hash,
        data: request_data,
        request_id: rid,
        link_id: *link.id(),
        remote_identity,
        requested_at,
    });

    if let Some(response) = response {
        send_response(
            &mut link,
            &rid,
            &response,
            auto_compress,
            auto_compress_limit,
            handler,
        )
        .await;
    }
}

/// The request id of a packet-carried request
/// (Python `PacketReceipt.truncated_hash` over `Packet.get_hashable_part`):
/// truncated SHA-256 of `[flags & 0x0F] ++ destination ++ context ++ data`.
fn request_id_from_packet(packet: &Packet) -> AddressHash {
    let mut hashable = Vec::with_capacity(2 + 16 + 1 + packet.data.len());
    // Python packs `(header_type << 6) | (context_flag << 5) |
    // (transport_type << 4) | (destination_type << 2) | packet_type`
    // and masks the byte with 0x0F, keeping destination type and
    // packet type.
    let flags = ((packet.header.header_type as u8) << 6)
        | ((packet.header.context_flag as u8) << 5)
        | ((packet.header.propagation_type as u8) << 4)
        | ((packet.header.destination_type as u8) << 2)
        | (packet.header.packet_type as u8);
    hashable.push(flags & 0x0f);
    hashable.extend_from_slice(packet.destination.as_slice());
    hashable.push(packet.context as u8);
    hashable.extend_from_slice(packet.data.as_slice());
    make_request_id(&hashable)
}

async fn handle_request_or_response_packet<'a>(
    packet: &Packet,
    link: &Arc<Mutex<Link>>,
    transport_handler: &Arc<Mutex<TransportHandler>>,
    handler: &mut MutexGuard<'a, TransportHandler>,
) -> bool {
    let link_guard = link.lock().await;
    let mut buffer = [0u8; PACKET_MDU];
    let Ok(plaintext) = link_guard.decrypt(packet.data.as_slice(), &mut buffer[..]) else {
        return false;
    };

    match packet.context {
        PacketContext::Request => {
            let Some((time, path_hash, data)) = crate::resource::manager::unpack_request(plaintext)
            else {
                log::debug!("tp: could not unpack request payload");
                return false;
            };
            // The request id a packet-carried request is known by is the
            // truncated hash of the *packet's hashable part*
            // (Python `Packet.get_hashable_part`:
            // `[flags & 0x0F] ++ raw[2:]` = flags-nibble, destination,
            // context, data), NOT a hash of the packed payload — that
            // scheme is only used for resource-carried requests
            // (`Link.request` sets `request_id =
            // truncated_hash(packed_request)` there).
            let rid = request_id_from_packet(packet);
            drop(link_guard);
            handle_incoming_request(link, rid, time, path_hash, data, transport_handler, handler)
                .await;
            true
        }
        PacketContext::Response => {
            let Some((rid, response)) = crate::resource::manager::unpack_response(plaintext) else {
                return false;
            };
            // Python `handle_response` only accepts a response while the
            // request receipt is still pending. A late packet after a
            // timeout (the receipt was already removed) is ignored.
            if !handler.resources.pending_requests.contains_key(&rid) {
                return true;
            }
            // `len(umsgpack.packb(response_data)) - 2`.
            let size = packet_response_size(plaintext).unwrap_or(response.len());
            if !handler.resources.response_size_allowed(&rid, size) {
                handler.resources.fail_request(rid);
                return true;
            }
            // Retain the completed response so an `await_request_response`
            // call that has not subscribed yet still observes it.
            handler
                .resources
                .completed_responses
                .insert(rid, Some(response.clone()));
            handler
                .resources
                .request_events
                .send(RequestEventData {
                    link_id: packet.destination,
                    event: RequestEvent::Response {
                        request_id: rid,
                        data: response,
                        metadata: None,
                    },
                })
                .ok();
            handler.resources.pending_requests.remove(&rid);
            true
        }
        _ => false,
    }
}

/// Fulfill a cache request from the local packet cache
/// (Python `Transport.cache_request_packet`): a 32-byte packet hash is
/// looked up; if found, the cached packet is replayed into transport
/// processing. Announces are replayed as announces.
async fn handle_cache_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
) -> bool {
    let data = packet.data.as_slice();

    if data.len() != crate::packet::HASHLENGTH_BYTES {
        return false;
    }

    let request_hash = crate::hash::Hash::new_from_slice(data);
    let cached = handler
        .packet_cache
        .lock()
        .await
        .get_cached_announce(&request_hash);

    match cached {
        Some(cached) => {
            log::trace!(
                "tp({}): cache request hit for {}",
                handler.config.name,
                cached.destination
            );

            // Only announces are ever force-cached
            // (Python `should_cache` currently disables general caching),
            // so replay through announce processing.
            handle_announce(&cached, handler, packet.destination).await;

            true
        }
        None => false,
    }
}

/// Python `Link.__receive` sets `last_inbound` before dispatch, for every
/// packet on an open link except an initiator's own `0xFF`.
fn note_established_inbound(link: &mut Link, packet: &Packet, out_link: bool) {
    if !matches!(link.status(), LinkStatus::Active | LinkStatus::Stale) {
        return;
    }
    if out_link
        && packet.context == PacketContext::KeepAlive
        && packet.data.as_slice().first() == Some(&KEEP_ALIVE_REQUEST)
    {
        return;
    }
    link.touch();
}

async fn handle_data<'a>(
    packet: &Packet,
    ingress_iface: AddressHash,
    transport_handler: Arc<Mutex<TransportHandler>>,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let transport_handler = &transport_handler;
    let mut data_handled = false;

    // Cache requests: if this instance can fulfill the request from its
    // local packet cache, replay the cached packet and stop processing
    // (Python `Transport.inbound`: `if packet.context == CACHE_REQUEST:
    // if Transport.cache_request_packet(packet): return`).
    if packet.context == PacketContext::CacheRequest
        && handle_cache_request(packet, &mut handler).await
    {
        return;
    }

    if packet.header.destination_type == DestinationType::Link {
        let mut local_out_link_handled = false;

        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            // Local responder link: fully handled below; intermediary
            // link-table routing must not also try to forward it
            // (Python delivers endpoint link data to the local link).
            local_out_link_handled = true;
            // Refresh inbound silence before resource/request/cache
            // handlers return. Pending links are left alone.
            {
                let mut established = link.lock().await;
                note_established_inbound(&mut established, packet, false);
            }
            if handle_resource_packet(packet, &link, transport_handler, &mut handler).await {
                return;
            }
            if handle_request_or_response_packet(packet, &link, transport_handler, &mut handler)
                .await
            {
                return;
            }

            let mut link = link.lock().await;
            // A cache request arriving over an established link is
            // answered with the cached packet contents
            // (Python link receive: `get_cached_packet` and resend).
            if packet.context == PacketContext::CacheRequest
                && packet.data.as_slice().len() == crate::packet::HASHLENGTH_BYTES
            {
                let request_hash = crate::hash::Hash::new_from_slice(packet.data.as_slice());
                let cached = handler
                    .packet_cache
                    .lock()
                    .await
                    .get_cached_announce(&request_hash);
                if let Some(cached) = cached {
                    if let Ok(response) = link.data_packet(cached.data.as_slice()) {
                        handler.send_from_link(&mut link, response).await;
                        return;
                    }
                }
            }

            let channel_tx = handler.channel_table.get(link.id());

            // Python `Link.receive` calls `proof_requested` only for
            // context NONE. CHANNEL is proved with no callback. Every
            // other link context ignores the callback. PROVE_ALL still
            // proves NONE without asking the callback.
            let proof_strategy = handler
                .single_in_destinations
                .get(&link.destination().address_hash)
                .and_then(|destination| destination.try_lock().ok())
                .map(|destination| {
                    let strategy = destination.proof_strategy();
                    let app_prove = packet.context == PacketContext::None
                        && strategy == ProofStrategy::App
                        && destination.should_prove(packet);
                    (strategy, app_prove)
                });

            let result = link.handle_packet(&handler.link_in_event_tx, channel_tx, packet, false);

            match result {
                LinkHandleResult::KeepAlive
                    if link.keepalive_reply_due(handler.config.timer_config.out_link_keep) =>
                {
                    // Python answers 0xFF only when outbound has been idle
                    // for a keepalive interval.
                    let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                    handler.send_from_link(&mut link, packet).await;
                }
                LinkHandleResult::MessageReceived(proof) => {
                    let (strategy, app_prove) =
                        proof_strategy.unwrap_or((ProofStrategy::None, false));
                    let should_prove = match packet.context {
                        PacketContext::Channel => true,
                        PacketContext::None => match strategy {
                            ProofStrategy::None => false,
                            ProofStrategy::App => app_prove,
                            ProofStrategy::All => true,
                        },
                        _ => false,
                    };

                    if should_prove {
                        if let Some(proof) = proof {
                            handler.send_from_link(&mut link, proof).await;
                        }
                    }
                }
                _ => {}
            }
        }

        let mut out_links: Vec<Arc<Mutex<Link>>> = Vec::new();
        for link in handler.out_links.values() {
            let id = *link.lock().await.id();
            if id == packet.destination {
                out_links.push(link.clone());
            }
        }

        for link in out_links {
            let link_id = *link.lock().await.id();

            if link_id == packet.destination {
                {
                    let mut established = link.lock().await;
                    note_established_inbound(&mut established, packet, true);
                }
                if handle_resource_packet(packet, &link, transport_handler, &mut handler).await {
                    local_out_link_handled = true;
                    data_handled = true;
                    continue;
                }
                if handle_request_or_response_packet(packet, &link, transport_handler, &mut handler)
                    .await
                {
                    local_out_link_handled = true;
                    data_handled = true;
                    continue;
                }

                let mut link = link.lock().await;

                let result = link.handle_packet(
                    &handler.link_out_event_tx,
                    handler.channel_table.get(&link_id),
                    packet,
                    true,
                );

                if let LinkHandleResult::MessageReceived(Some(proof)) = result {
                    handler.send_from_link(&mut link, proof).await;
                }

                local_out_link_handled = true;
                data_handled = true;
            }
        }

        if !local_out_link_handled
            && handle_keepalive_response(packet, ingress_iface, &mut handler).await
        {
            return;
        }

        if !local_out_link_handled {
            // Intermediary link-data routing (Python "Link transport
            // handling"): direction + hop-count aware, using the link
            // table, not the path table.
            if let Some((packet, iface)) =
                handler.link_table.route_link_packet(packet, ingress_iface)
            {
                log::trace!(
                    "tp({}): forwarded link packet {}",
                    handler.config.name,
                    packet.destination
                );
                handler
                    .send(TxMessage {
                        tx_type: TxMessageType::Direct(iface),
                        packet: Box::new(packet),
                    })
                    .await;
            } else {
                log::trace!(
                    "tp({}): could not route link packet {}",
                    handler.config.name,
                    packet.destination
                );
            }
        }
    }

    if packet.header.destination_type == DestinationType::Group {
        // GROUP destinations are addressed by name hash like PLAIN ones;
        // payloads are encrypted with the destination's symmetric group
        // key when one is loaded (Python `Destination.prv`).
        if let Some(destination) = handler.group_in_destinations.get(&packet.destination) {
            let destination = destination.lock().await;
            let mut buffer = [0u8; PACKET_MDU];

            let data = if destination.group_encrypted() {
                match destination.decrypt_group(packet.data.as_slice(), &mut buffer[..]) {
                    Ok(plain) => PacketDataBuffer::new_from_slice(plain),
                    Err(error) => {
                        log::debug!(
                            "tp({}): could not decrypt group packet for {}: {error:?}",
                            handler.config.name,
                            packet.destination
                        );
                        return;
                    }
                }
            } else {
                packet.data.clone()
            };

            data_handled = true;

            handler
                .received_data_tx
                .send(ReceivedData {
                    destination: packet.destination,
                    data,
                    // Group payloads were decrypted when a key is loaded;
                    // receivers must not decrypt again.
                    decrypted: destination.group_encrypted(),
                })
                .ok();
        }
    }

    if packet.header.destination_type == DestinationType::Plain {
        if let Some(_destination) = handler.plain_in_destinations.get(&packet.destination) {
            data_handled = true;

            handler
                .received_data_tx
                .send(ReceivedData {
                    destination: packet.destination,
                    data: packet.data.clone(),
                    decrypted: false,
                })
                .ok();
        }
        // Plain packets are never routed elsewhere: everyone on a shared
        // interface receives them directly.
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            // Python `Destination.receive`: SINGLE-destination packets are
            // encrypted to the destination identity (optionally via its
            // announced ratchet), so decrypt before delivering.
            let destination = destination.lock().await;
            let mut buffer = [0u8; PACKET_MDU];
            match destination.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                Ok(plain_text) => {
                    let data = PacketDataBuffer::new_from_slice(plain_text);

                    handler
                        .received_data_tx
                        .send(ReceivedData {
                            destination: packet.destination,
                            data,
                            decrypted: true,
                        })
                        .ok();

                    // Ordinary data proofs follow `Destination::should_prove`
                    // (PROVE_ALL always, PROVE_APP only when the callback
                    // asks, PROVE_NONE never). Link proofs stay outside this.
                    let sign_key = destination.sign_key().clone();
                    if destination.should_prove(packet) {
                        if let Some(proof) = create_single_destination_proof(
                            &handler,
                            packet,
                            ProofStrategy::All,
                            &sign_key,
                        ) {
                            handler.send_packet(proof).await;
                        }
                    }
                }
                Err(error) => {
                    log::debug!(
                        "tp({}): could not decrypt packet for {}: {error:?}",
                        handler.config.name,
                        packet.destination
                    );
                }
            }
        } else if packet.transport == Some(*handler.config.identity.address_hash()) {
            // Path forwarding only applies to packets addressed to this
            // instance (Python `transport_id == Transport.identity.hash`).
            data_handled = send_to_next_hop(packet, &mut handler, None, Some(ingress_iface)).await;
        }
    }

    if data_handled {
        log::trace!(
            "tp({}): handle data request for {} dst={:2x} ctx={:2x}",
            handler.config.name,
            packet.destination,
            packet.header.destination_type as u8,
            packet.context as u8,
        );
    }
}

async fn handle_announce<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if handler.has_destination(&packet.destination) {
        // destination is local
        return;
    }

    // Ingress control (Python `Transport.inbound` announce path):
    // sample the announce, and hold it if the interface is currently
    // ingress limiting. Waiting path requests and discovery requests
    // exempt the announce for the life of that deadline. KISS, serial
    // and RNode interfaces are never ingress-limited.
    {
        handler
            .iface_manager
            .lock()
            .await
            .received_announce(&iface, packet.data.as_slice().len() + 18);

        let known_path = handler.path_table.get(&packet.destination).is_some();
        let pending_request = handler.path_requests.has_pending(&packet.destination);
        let discovery_waiting = handler.path_requests.discovery_pending(&packet.destination);
        let exempt = {
            let manager = handler.iface_manager.lock().await;
            manager
                .iface_kind(&iface)
                .is_some_and(|kind| ingress_exempt_kind(&kind))
        };

        if !known_path && !pending_request && !discovery_waiting && !exempt {
            let limited = {
                let manager = handler.iface_manager.lock().await;
                manager
                    .with_control(&iface, |control| {
                        control.should_ingress_limit(time::Instant::now())
                    })
                    .unwrap_or(false)
            };

            if limited {
                {
                    let manager = handler.iface_manager.lock().await;
                    manager.with_control(&iface, |control| {
                        control.hold_announce(packet, PATHFINDER_M as u8)
                    });
                }
                log::trace!(
                    "tp({}): holding announce for {} due to ingress limiting",
                    handler.config.name,
                    packet.destination
                );
                return;
            }
        }
    }

    let interface_rate = {
        let manager = handler.iface_manager.lock().await;
        manager.with_control(&iface, |control| {
            control
                .announce_rate_target
                .map(|target| announce_limits::AnnounceRateLimit {
                    target,
                    grace: control.announce_rate_grace.unwrap_or(0),
                    penalty: control.announce_rate_penalty,
                })
        })
    };
    let blocked_until = match interface_rate.flatten() {
        Some(limit) => handler
            .announce_limits
            .check_limited(&packet.destination, limit),
        None => handler.announce_limits.check(&packet.destination),
    };
    // A rate hit suppresses rebroadcast only. The path is still installed.
    let rate_blocked = blocked_until.is_some();
    if let Some(blocked_until) = blocked_until {
        log::info!(
            "tp({}): blocking rebroadcast of announce from {} for {} seconds",
            handler.config.name,
            packet.destination,
            blocked_until.as_secs(),
        );
    }

    // Blackhole check uses the announced identity hash and runs before
    // the signature check (Python `Identity.validate_announce` returns
    // "blackholed" without verifying). An invalid signature is a
    // protocol violation; a blackholed identity is not.
    let Some(identity_hash) = announced_identity_hash(packet) else {
        handler
            .iface_manager
            .lock()
            .await
            .count_protocol_violation(&iface);
        return;
    };
    if handler
        .blackholes
        .read()
        .await
        .is_blackholed(&identity_hash)
    {
        log::debug!(
            "tp({}): dropping announce from blackholed identity {}",
            handler.config.name,
            identity_hash
        );
        return;
    }

    let Ok((destination, announce)) = DestinationAnnounce::validate(packet) else {
        handler
            .iface_manager
            .lock()
            .await
            .count_protocol_violation(&iface);
        return;
    };
    {
        let dest_hash = destination.identity.address_hash;
        let public_key = destination.identity.to_bytes();

        let destination = Arc::new(Mutex::new(destination));

        // Python `Identity.remember(packet.get_hash(), destination_hash,
        // public_key, app_data)`: track announced destinations for later
        // recall, persisting to storage when configured.
        let now = unix_time_now();
        handler.known_destinations.remember(
            packet.hash().to_bytes(),
            packet.destination,
            public_key,
            announce.app_data.map(|data| data.to_vec()),
            now,
        );
        persist_known_destinations(handler);

        // Python `Identity._remember_ratchet` for announces carrying a
        // ratchet key.
        if let Some(ratchet) = announce.ratchet {
            let storage = handler
                .storage
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(crate::storage::MemoryStorage::new()));

            if let Err(error) =
                handler
                    .known_ratchets
                    .remember(&*storage, packet.destination, ratchet, now)
            {
                log::warn!(
                    "tp({}): could not persist ratchet for {}: {error:?}",
                    handler.config.name,
                    packet.destination
                );
            }
        }

        if !handler
            .single_out_destinations
            .contains_key(&packet.destination)
        {
            log::trace!(
                "tp({}): new announce for {}",
                handler.config.name,
                packet.destination
            );

            handler
                .single_out_destinations
                .insert(packet.destination, destination.clone());
        }

        // Cache the announce for later path responses and cache requests
        // (Python `Transport.cache(force_cache=True, packet_type="announce")`).
        handler.packet_cache.lock().await.cache_announce(packet);

        if !rate_blocked {
            handler
                .announce_table
                .add(packet, packet.destination, dest_hash);
        }

        // If we have a waiting discovery path request for this destination,
        // answer it immediately with a path response announce on the
        // requesting interface (Python `discovery_path_requests` handling).
        if let Some(requesting_ifaces) = handler.path_requests.clear_discovery(&packet.destination)
        {
            let hops = packet.header.hops + 1;
            // Python sends the path response to every interface that
            // batched onto the in-flight discovery request (1.5.0
            // batching), falling back to the announce ingress.
            let mut targets = requesting_ifaces;
            if targets.is_empty() {
                targets.push(iface);
            }
            for to_iface in targets {
                handler.announce_table.add_response(
                    packet.destination,
                    to_iface,
                    hops,
                    Duration::ZERO,
                );
            }
            log::trace!(
                "tp({}): got matching announce, answering waiting discovery path request for {}",
                handler.config.name,
                packet.destination
            );
        }

        let (mode, gravity) = {
            let manager = handler.iface_manager.lock().await;
            let mode = manager.iface_mode(&iface);
            let gravity = manager
                .with_control(&iface, |control| control.gravity)
                .unwrap_or(0);
            (mode, gravity)
        };
        handler.path_table.handle_announce_with_mode(
            packet,
            packet.transport,
            iface,
            mode,
            Some(gravity),
        );

        // If the receiving interface is a tunnel, associate the path with
        // the tunnel for later restore
        // (Python announce handling: `paths[destination_hash] = [...]`).
        let tunnel_id = {
            let manager = handler.iface_manager.lock().await;
            manager.iface_tunnel(&iface)
        };
        if let Some(tunnel_id) = tunnel_id {
            let expires = crate::time::now() + path_table::PATHFINDER_E;
            handler.tunnels.associate_path(
                &tunnel_id,
                packet.destination,
                TunnelPath {
                    received_from: dest_hash,
                    hops: packet.header.hops + 1,
                    expires,
                    packet_hash: packet.hash(),
                },
                time::Instant::now(),
            );
        }

        let retransmit = handler.config.retransmit && !rate_blocked;
        if retransmit {
            let transport_id = *handler.config.identity.address_hash();
            // Keyed by the announced destination hash (identity hash is
            // the received_from/routing value).
            if let Some(message) = handler
                .announce_table
                .new_packet(&packet.destination, &transport_id)
            {
                handler.send(message).await;
            }
        }

        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            app_data: PacketDataBuffer::new_from_slice(announce.app_data.unwrap_or(&[])),
            ratchet: announce.ratchet,
        });
    }
}

/// Current unix time in seconds as f64 (Python `time.time()`).
fn unix_time_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or_default()
}

/// Persist the known-destinations store when storage is configured and
/// entries changed (Python `Identity.save_known_destinations`).
fn persist_known_destinations(handler: &mut MutexGuard<'_, TransportHandler>) {
    let Some(storage) = handler.storage.clone() else {
        return;
    };

    if let Err(error) = handler.known_destinations.save(&*storage) {
        log::warn!(
            "tp({}): could not save known destinations: {error:?}",
            handler.config.name
        );
    }
}

async fn handle_path_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    let request = match handler.path_requests.decode(packet.data.as_slice()) {
        Some(request) => request,
        None => return,
    };

    // Ingress sampling (Python `packet.receiving_interface.received_path_request()`).
    handler
        .iface_manager
        .lock()
        .await
        .received_path_request(&iface, packet.data.as_slice().len() + 18);

    // The destination is local to this system: announce it directly to the
    // requestor as a path response (Python `local_destination.announce(path_response=True)`).
    if let Some(dest) = handler.single_in_destinations.get(&request.destination) {
        let response = dest
            .lock()
            .await
            .path_response(OsRng, None)
            .expect("valid path response");

        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Box::new(response),
            })
            .await;

        log::trace!(
            "tp({}): answering path request for {}, destination is local to this system",
            handler.config.name,
            request.destination
        );

        return;
    }

    if handler.config.retransmit {
        // The path is known: schedule a path response announce after a
        // grace period (Python `Transport.path_request` "path is known").
        if let Some(entry) = handler.path_table.get(&request.destination) {
            // Don't answer if the next hop is the requestor itself
            // (circular request suppression).
            if let Some(requestor_id) = request.requesting_transport {
                if requestor_id == entry.received_from {
                    log::trace!(
                        "tp({}): dropping circular path request from {}",
                        handler.config.name,
                        request.destination
                    );
                    return;
                }
            }

            // Roaming-mode interfaces don't answer path requests when the
            // next hop is on the same roaming-mode interface.
            let mode = handler.iface_manager.lock().await.iface_mode(&iface);
            if mode == InterfaceMode::Roaming && entry.iface == iface {
                log::trace!(
                    "tp({}): not answering path request on roaming-mode interface, next hop is on same interface",
                    handler.config.name
                );
                return;
            }

            // Directly reachable peers answer first: wait the grace
            // period, longer on roaming-mode interfaces. Requests from
            // local clients (or whose next hop is a local client
            // interface) are answered immediately (Python sets
            // `retransmit_timeout = now` for those).
            let from_local_client = {
                let manager = handler.iface_manager.lock().await;
                manager.is_local_client_iface(&iface) || manager.is_local_client_iface(&entry.iface)
            };
            let grace = if from_local_client {
                Duration::ZERO
            } else {
                PATH_REQUEST_GRACE
                    + if mode == InterfaceMode::Roaming {
                        PATH_REQUEST_RG
                    } else {
                        Duration::ZERO
                    }
            };

            let hops = entry.hops;

            handler
                .announce_table
                .add_response(request.destination, iface, hops, grace);

            log::trace!(
                "tp({}): answering path request for {}, path is known ({} hops, grace {:?})",
                handler.config.name,
                request.destination,
                hops,
                grace
            );

            return;
        }
    }

    // The destination is unknown. Branch order follows Python
    // `Transport.path_request`:
    //   1. request from a local client: forward on all other interfaces
    //   2. receiving mode warrants path discovery: gated recursive search
    //   3. otherwise: forward to local clients, or ignore
    let from_local_client = {
        let manager = handler.iface_manager.lock().await;
        manager.is_local_client_iface(&iface)
    };

    if from_local_client {
        log::trace!(
            "tp({}): forwarding path request from local client for {} to all other interfaces",
            handler.config.name,
            request.destination
        );
        // Local clients still forward when a discovery is already in
        // flight; the helper only lengthens the deadline and records
        // this requestor.
        let timeout = medium_discovery_timeout(handler).await;
        handler.path_requests.register_discovery_with_timeout(
            &request.destination,
            Some(iface),
            timeout,
        );

        let interfaces = handler.iface_manager.lock().await.live_iface_addresses();
        for (other, online) in interfaces {
            if other == iface || !online {
                continue;
            }
            handler
                .iface_manager
                .lock()
                .await
                .sent_path_request(&other, 0);
            handler
                .request_path(&request.destination, Some(other), None)
                .await;
        }
        return;
    }

    // `should_search_for_unknown`: the receiving interface mode warrants
    // active path discovery
    // (Python `DISCOVER_PATHS_FOR`, `recursive_prs` or boundary mode with
    // `BOUNDARY_SEARCH_MODES`).
    // Outer `None`: this interface mode does not search at all.
    // Inner `None`: search all interfaces; inner `Some`: restrict the
    // search to these interface modes.
    let search_plan: Option<Option<Vec<InterfaceMode>>> = {
        let manager = handler.iface_manager.lock().await;
        manager
            .with_control(&iface, |control| {
                if control.recursive_prs
                    || InterfaceMode::DISCOVER_PATHS_FOR.contains(&control.mode)
                {
                    Some(None)
                } else if control.mode == InterfaceMode::Boundary {
                    Some(Some(InterfaceMode::BOUNDARY_SEARCH_MODES.to_vec()))
                } else {
                    None
                }
            })
            .unwrap_or(None)
    };

    // `search` is Some when a recursive search should be performed;
    // its inner value restricts the search to specific interface modes.
    let search: Option<Option<Vec<InterfaceMode>>> = search_plan;

    if let Some(search_modes) = search {
        // Abort recursive path request if the receiving interface has a
        // path-request burst active (Python `should_ingress_limit_pr`).
        // KISS, serial and RNode are exempt inside transport.
        let ingress_limited = {
            let manager = handler.iface_manager.lock().await;
            let exempt = manager
                .iface_kind(&iface)
                .is_some_and(|kind| ingress_exempt_kind(&kind));
            !exempt
                && manager
                    .with_control(&iface, |control| {
                        control.should_ingress_limit_pr(time::Instant::now())
                    })
                    .unwrap_or(false)
        };
        if ingress_limited {
            log::trace!(
                "tp({}): not sending recursive path request due to active ingress limiting",
                handler.config.name
            );
            return;
        }

        let timeout = medium_discovery_timeout(handler).await;
        let started = handler.path_requests.register_discovery_with_timeout(
            &request.destination,
            Some(iface),
            timeout,
        );
        if !started {
            log::trace!(
                "tp({}): there is already a waiting path request for {}",
                handler.config.name,
                request.destination
            );
            return;
        }

        log::trace!(
            "tp({}): attempting to discover unknown path to {} on behalf of path request",
            handler.config.name,
            request.destination
        );

        // Forward the path request on all interfaces except the requestor
        // interface, reusing the tag to avoid loops.
        let tag = request.tag_bytes.clone();

        let interfaces = handler.iface_manager.lock().await.live_iface_addresses();
        for (other, online) in interfaces {
            if other == iface || !online {
                continue;
            }

            if let Some(modes) = &search_modes {
                let mode = handler.iface_manager.lock().await.iface_mode(&other);
                if !modes.contains(&mode) {
                    continue;
                }
            }

            // Respect path-request egress control on the outgoing interface
            // (Python `should_egress_limit_pr`).
            let egress_limited = {
                let manager = handler.iface_manager.lock().await;
                manager
                    .with_control(&other, |control| {
                        control.should_egress_limit_pr(time::Instant::now())
                    })
                    .unwrap_or(false)
            };
            if egress_limited {
                log::trace!(
                    "tp({}): not sending recursive path request due to active egress limiting",
                    handler.config.name
                );
                continue;
            }

            handler
                .iface_manager
                .lock()
                .await
                .sent_path_request(&other, 0);
            handler
                .request_path(&request.destination, Some(other), Some(tag.clone()))
                .await;
        }

        return;
    }

    // Forward the path request to local clients when it did not originate
    // from one (Python: "Forwarding path request to local clients").
    let local_clients = handler
        .iface_manager
        .lock()
        .await
        .local_client_iface_addresses();
    if !from_local_client && !local_clients.is_empty() {
        log::trace!(
            "tp({}): forwarding path request for {} to local clients",
            handler.config.name,
            request.destination
        );
        for client_iface in local_clients {
            handler
                .iface_manager
                .lock()
                .await
                .sent_path_request(&client_iface, 0);
            handler
                .request_path(&request.destination, Some(client_iface), None)
                .await;
        }
        return;
    }

    log::trace!(
        "tp({}): ignoring path request for {}, no path known",
        handler.config.name,
        request.destination
    );
}

async fn handle_fixed_destinations<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) -> bool {
    if packet.destination == handler.fixed_dest_path_requests {
        handle_path_request(packet, handler, iface).await;
        true
    } else if packet.destination == handler.fixed_dest_tunnel_synthesize {
        handle_tunnel_synthesize(packet, handler, iface).await;
        true
    } else {
        false
    }
}

/// Handle a tunnel synthesis packet on the fixed PLAIN destination
/// (Python `Transport.tunnel_synthesize_handler` -> `handle_tunnel`).
async fn handle_tunnel_synthesize<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    let Some(synthesis) = tunnels::decode_tunnel_synthesize(packet.data.as_slice()) else {
        log::debug!(
            "tp({}): ignoring malformed tunnel synthesis packet",
            handler.config.name
        );
        return;
    };

    let tunnel_id = synthesis.tunnel_id;

    // Python restore rules: restore a tunnel path when the current path
    // is unknown, expired, or not better (fewer hops) than the tunnel
    // path.
    let handling = handler
        .tunnels
        .handle_tunnel(tunnel_id, iface, time::Instant::now());
    let mut restored = 0;
    if let tunnels::TunnelHandling::Restored { candidates } = handling {
        let now = crate::time::now();
        let mut declined = Vec::new();

        for (destination, path) in candidates {
            let should_restore = match handler.path_table.get(&destination) {
                None => true,
                Some(entry) => {
                    let expired =
                        path_table::path_age(now, entry.timestamp) >= path_table::PATHFINDER_E;
                    expired || path.hops <= entry.hops
                }
            };

            if should_restore {
                handler.path_table.insert_restored(
                    destination,
                    path.received_from,
                    path.hops,
                    iface,
                    path.packet_hash,
                );
                restored += 1;
            } else {
                declined.push(destination);
            }
        }

        handler.tunnels.finish_restore(&tunnel_id, &declined);
    }

    handler
        .iface_manager
        .lock()
        .await
        .set_iface_tunnel(&iface, Some(tunnel_id));

    log::info!(
        "tp({}): tunnel endpoint {} established on {} (restored {} paths)",
        handler.config.name,
        tunnel_id,
        iface,
        restored
    );
}

async fn handle_link_request_as_destination<'a>(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let mut destination = destination.lock().await;
    let proof_strategy = destination.proof_strategy();

    if !destination.accepts_links() {
        log::debug!(
            "tp({}): dropping link request for {} (accepts_links = false)",
            handler.config.name,
            packet.destination
        );
        return;
    }
    match destination.handle_packet(packet) {
        DestinationHandleStatus::LinkProof => {
            let link_id = LinkId::from(packet);
            if !handler.in_links.contains_key(&link_id) {
                log::trace!(
                    "tp({}): send proof to {}",
                    handler.config.name,
                    packet.destination
                );

                let link = Link::new_from_request(
                    packet,
                    destination.sign_key().clone(),
                    destination.desc,
                );

                if let Ok(mut link) = link {
                    // Link request proofs are always sent; message proofs
                    // follow the destination's proof strategy.
                    link.prove_messages(proof_strategy != ProofStrategy::None);

                    let proof = link.prove(&handler.link_in_event_tx);
                    handler.send_from_link(&mut link, proof).await;

                    log::debug!(
                        "tp({}): save input link {} for destination {}",
                        handler.config.name,
                        link.id(),
                        link.destination().address_hash
                    );

                    handler.in_link_ifaces.insert(*link.id(), iface);
                    handler
                        .in_links
                        .insert(*link.id(), Arc::new(Mutex::new(link)));
                }
            }
        }
        DestinationHandleStatus::None => {}
    }
}

async fn handle_link_request_as_intermediate<'a>(
    received_from: AddressHash,
    next_hop: AddressHash,
    next_hop_iface: AddressHash,
    remaining_hops: u8,
    packet: &Packet,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let next_hop_bitrate = handler
        .iface_manager
        .lock()
        .await
        .with_control(&next_hop_iface, |control| control.bitrate)
        .unwrap_or(0);
    handler.link_table.add(
        packet,
        packet.destination,
        received_from,
        next_hop,
        next_hop_iface,
        remaining_hops,
        next_hop_bitrate,
    );

    send_to_next_hop(packet, &mut handler, None, None).await;
}

async fn handle_link_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    handler: MutexGuard<'a, TransportHandler>,
) {
    if let Some(destination) = handler
        .single_in_destinations
        .get(&packet.destination)
        .cloned()
    {
        log::trace!(
            "tp({}): handle link request for {}",
            handler.config.name,
            packet.destination
        );

        handle_link_request_as_destination(destination, packet, iface, handler).await;
    } else if let Some(entry) = handler.path_table.next_hop_full(&packet.destination) {
        // Python relays link requests only when the packet is addressed
        // to this instance (the `transport_id == Transport.identity.hash`
        // gate); unaddressed requests for remote destinations are
        // dropped so shared media does not produce duplicate relays.
        let addressed_to_us = packet.transport == Some(*handler.config.identity.address_hash());
        if !addressed_to_us {
            log::trace!(
                "tp({}): dropping unaddressed link request for remote destination {}",
                handler.config.name,
                packet.destination
            );
            return;
        }

        log::trace!(
            "tp({}): handle link request for remote destination {}",
            handler.config.name,
            packet.destination
        );

        let (next_hop, next_hop_iface) = entry;
        let remaining_hops = handler
            .path_table
            .get(&packet.destination)
            .map(|e| e.hops)
            .unwrap_or(1);
        handle_link_request_as_intermediate(
            iface,
            next_hop,
            next_hop_iface,
            remaining_hops,
            packet,
            handler,
        )
        .await;
    } else {
        log::trace!(
            "tp({}): dropping link request to unknown destination {}",
            handler.config.name,
            packet.destination
        );
    }
}

async fn handle_check_links<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let mut links_to_remove: Vec<AddressHash> = Vec::new();
    let timer_config = handler.config.timer_config;

    // Clean up input links. Inbound silence is per link: 720s until RTT
    // is known, then `2 * keepalive(rtt)`. Close follows `close_grace`
    // (the watchdog cap of 5s).
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        let stale_after = link.effective_stale(timer_config.in_link_stale);
        let close_after =
            stale_after.saturating_add(timer_config.in_link_close.min(link.close_grace()));
        match link.status() {
            LinkStatus::Active if link.elapsed() >= stale_after => {
                link.stale();
            }
            LinkStatus::Stale if link.elapsed() >= close_after => {
                if let Some(packet) =
                    link.teardown(&handler.link_in_event_tx)
                        .unwrap_or_else(|err| {
                            log::error!(
                                "tp({}): teardown stale in-link error: {err:?}",
                                handler.config.name
                            );
                            None
                        })
                {
                    handler.send_from_link(&mut link, packet).await
                }
                links_to_remove.push(*link_entry.0);
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(addr);
        handler.in_link_ifaces.remove(addr);
    }

    links_to_remove.clear();

    let mut expired_links: Vec<AddressHash> = Vec::new();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        // Only the initiator emits keepalive 0xFF. Send it before the
        // stale check so the final probe still goes out (Python watchdog
        // order). The send does not count as inbound activity.
        if link.keepalive_due(timer_config.out_link_keep) {
            let packet = link.keep_alive_packet(KEEP_ALIVE_REQUEST);
            handler.send_from_link(&mut link, packet).await;
        }

        let stale_after = link.effective_stale(timer_config.out_link_stale);
        let close_after =
            stale_after.saturating_add(timer_config.out_link_close.min(link.close_grace()));

        match link.status() {
            LinkStatus::Active if link.elapsed() >= stale_after => {
                link.stale();
            }
            LinkStatus::Stale => {
                if handler.config.restart_outlinks {
                    if link.elapsed() > timer_config.out_link_restart {
                        link.restart();
                    }
                } else if link.elapsed() >= close_after {
                    if let Some(packet) =
                        link.teardown(&handler.link_out_event_tx)
                            .unwrap_or_else(|err| {
                                log::error!(
                                    "tp({}): teardown stale out-link error: {err:?}",
                                    handler.config.name
                                );
                                None
                            })
                    {
                        handler.send_from_link(&mut link, packet).await
                    }
                    links_to_remove.push(*link_entry.0);
                }
            }
            LinkStatus::Pending if link.elapsed() > timer_config.out_link_repeat => {
                // Python `Link.__init__` waits `get_first_hop_timeout`
                // (one MTU of airtime plus 6s) plus
                // `ESTABLISHMENT_TIMEOUT_PER_HOP * max(1, hops)`.
                // That first-hop timeout already includes one MTU; this
                // deadline does not add a second one.
                let link_destination = link.destination().address_hash;
                let hops = handler
                    .path_table
                    .get(&link_destination)
                    .map(|entry| entry.hops)
                    .unwrap_or(1);
                let next_iface = handler
                    .path_table
                    .get(&link_destination)
                    .map(|entry| entry.iface);
                let bitrate = match next_iface {
                    Some(iface) => handler
                        .iface_manager
                        .lock()
                        .await
                        .with_control(&iface, |control| control.bitrate)
                        .unwrap_or(0),
                    None => 0,
                };
                let establishment_timeout =
                    first_hop_timeout(bitrate) + TIMEOUT_PER_HOP * u32::from(hops.max(1));

                if link.elapsed() > establishment_timeout {
                    log::warn!(
                        "tp({}): link establishment timed out for {}, closing and rediscovering path",
                        handler.config.name,
                        link.id()
                    );
                    if let Some(packet) = link.teardown(&handler.link_out_event_tx).ok().flatten() {
                        handler.send_from_link(&mut link, packet).await;
                    }
                    expired_links.push(link_destination);
                    links_to_remove.push(*link_entry.0);
                } else {
                    log::warn!(
                        "tp({}): repeat link request {}",
                        handler.config.name,
                        link.id()
                    );
                    // `request` resets the establishment clock. The packet
                    // is not link-addressed, so stamp outbound here.
                    let packet = link.request();
                    handler.send_from_link(&mut link, packet).await;
                }
            }
            LinkStatus::Closed => {
                link.close(&handler.link_out_event_tx);
                links_to_remove.push(*link_entry.0);
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.out_links.remove(addr);
    }

    // Python closes a pending link that never activated and, when this
    // instance is not a transport, expires the path and rediscovers it.
    // The request is sent only when `PATH_REQUEST_MI` allows it and this
    // instance is not attached to a shared instance. The path is not
    // marked unresponsive here.
    for destination in expired_links {
        let shared = handler
            .iface_manager
            .lock()
            .await
            .connected_to_shared_instance();
        if handler.config.retransmit
            || shared
            || !handler.path_requests.request_allowed(&destination)
        {
            continue;
        }
        handler.path_table.expire_path(&destination);
        let packet = handler.path_requests.generate(&destination, None);
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Box::new(packet),
            })
            .await;
    }
}

async fn handle_cleanup<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();

    // Expire unused tunnel entries (Python `Transport.jobs`).
    let removed = handler.tunnels.clean(time::Instant::now());
    if removed > 0 {
        log::debug!(
            "tp({}): removed {removed} expired tunnel entries",
            handler.config.name
        );
    }

    // Receipt lifetimes are the receipt timeout, not the packet-cache
    // window. The link-check loop concludes them.
}

async fn retransmit_announces<'a>(
    mut handler: MutexGuard<'a, TransportHandler>,
    retransmit_old: bool,
) {
    let transport_id = *handler.config.identity.address_hash();
    let messages = handler.announce_table.tx_to_retransmit(&transport_id);

    for message in messages {
        handler.send(message).await;
    }

    if retransmit_old {
        let messages = handler.announce_table.tx_to_retransmit_old(&transport_id);

        for message in messages {
            handler.send(message).await;
        }
    }
}

/// Inbound traffic classes, scanned in this order by the drainer
/// (Python `Transport.TC_*`; lower index drains first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Data = 0,
    Announce = 1,
    PathRequest = 2,
    IngressLimited = 3,
}

/// Default inbound queue lengths
/// (Python `INBOUND_DA/AN/PR/IL_QUEUE_LENGTH`). A configured length of 0
/// means that class is unset and uses this default.
pub const INBOUND_QUEUE_LENGTHS: [usize; 4] = [1024, 128, 128, 8];

/// The prioritized inbound queue backend
/// (Python `Transport.InboundQueues`): one bounded deque per traffic
/// class, drops (and counts) on overflow, drained strictly in class
/// order.
#[derive(Debug)]
pub struct InboundQueues {
    queues: [std::collections::VecDeque<RxMessage>; 4],
    sizes: [usize; 4],
    dropped: [u64; 4],
}

impl Default for InboundQueues {
    fn default() -> Self {
        Self::new(INBOUND_QUEUE_LENGTHS)
    }
}

impl InboundQueues {
    pub fn new(sizes: [usize; 4]) -> Self {
        let mut sizes = sizes;
        for (index, size) in sizes.iter_mut().enumerate() {
            if *size == 0 {
                *size = INBOUND_QUEUE_LENGTHS[index];
            }
        }
        Self {
            queues: Default::default(),
            sizes,
            dropped: [0; 4],
        }
    }

    /// Enqueue by class; a full queue drops the item and counts it
    /// (Python `put` raises `Full` after incrementing `_dropped`).
    pub fn put(&mut self, class: TrafficClass, item: RxMessage) -> bool {
        let idx = class as usize;
        let queue = &mut self.queues[idx];
        if queue.len() >= self.sizes[idx] {
            self.dropped[idx] += 1;
            return false;
        }
        queue.push_back(item);
        true
    }

    /// Pop the next item, highest-priority class first.
    pub fn get(&mut self) -> Option<RxMessage> {
        for queue in &mut self.queues {
            if let Some(item) = queue.pop_front() {
                return Some(item);
            }
        }
        None
    }

    /// Total queued items, per-class heights and drop counters
    /// (Python `snapshot`).
    pub fn snapshot(&self) -> (usize, [usize; 4], [u64; 4]) {
        let heights = [
            self.queues[0].len(),
            self.queues[1].len(),
            self.queues[2].len(),
            self.queues[3].len(),
        ];
        (heights.iter().sum(), heights, self.dropped)
    }

    pub fn enqueue_and_drain(&mut self, incoming: RxMessage) -> Vec<RxMessage> {
        let class = Self::classify(&incoming.packet, &AddressHash::new([0; 16]), false);
        self.put(class, incoming);
        let mut out = Vec::new();
        while let Some(item) = self.get() {
            out.push(item);
        }
        out
    }

    /// Classify an inbound packet
    /// (Python `Transport.preprocess_inbound` traffic class selection).
    ///
    /// Path requests are DATA addressed to `path_request_dest`. An
    /// ingress-limited path request uses [`TrafficClass::IngressLimited`].
    /// Cache requests stay in the data class.
    pub fn classify(
        packet: &Packet,
        path_request_dest: &AddressHash,
        ingress_limited: bool,
    ) -> TrafficClass {
        if packet.header.packet_type == PacketType::Announce {
            return TrafficClass::Announce;
        }
        if packet.header.packet_type == PacketType::Data && packet.destination == *path_request_dest
        {
            if ingress_limited {
                return TrafficClass::IngressLimited;
            }
            return TrafficClass::PathRequest;
        }
        TrafficClass::Data
    }
}

/// The early packet filter (Python `Transport.packet_filter`).
/// Returns `false` when the packet must be dropped; violation-worthy
/// conditions are accounted on the interface by the caller when this
/// function reports them through the second return value.
fn packet_filter_violation(packet: &Packet) -> Option<&'static str> {
    use reticulum_core::packet::DestinationType;
    match packet.header.destination_type {
        DestinationType::Plain => {
            if packet.header.packet_type != PacketType::Announce {
                if packet.header.hops > 1 {
                    return Some("Transported PLAIN packet with hops > 1");
                }
            } else {
                return Some("Announce packet with PLAIN type");
            }
        }
        DestinationType::Group => {
            if packet.header.packet_type != PacketType::Announce {
                if packet.header.hops > 1 {
                    return Some("Transported GROUP packet with hops > 1");
                }
            } else {
                return Some("Announce packet with GROUP type");
            }
        }
        _ => {}
    }
    None
}

/// Combined check: `true` when the packet passes the filter.
fn packet_filter(packet: &Packet) -> bool {
    packet_filter_violation(packet).is_none()
}

/// KISS (including AX.25), serial and RNode interfaces do not ingress-limit.
fn ingress_exempt_kind(kind: &str) -> bool {
    matches!(
        kind,
        "KissInterface" | "SerialInterface" | "RnodeInterface" | "RnodeMultiInterface"
    )
}

fn announced_identity_hash(packet: &Packet) -> Option<AddressHash> {
    let data = packet.data.as_slice();
    if data.len() < 64 {
        return None;
    }
    let identity = Identity::new_from_slices(&data[..32], &data[32..64]);
    Some(identity.address_hash)
}

/// Python `Transport.first_hop_timeout`: MTU airtime plus 6s, or 6s when
/// the next-hop bitrate is unknown.
fn first_hop_timeout(bitrate: u64) -> Duration {
    if bitrate == 0 {
        return Duration::from_secs(6);
    }
    Duration::from_secs_f64(crate::packet::PROTOCOL_MTU as f64 * (8.0 / bitrate as f64) + 6.0)
}

async fn medium_discovery_timeout(handler: &TransportHandler) -> Duration {
    const MINIMUM_BITRATE: f64 = 5.0;
    match handler
        .iface_manager
        .lock()
        .await
        .lowest_interface_bitrate()
    {
        Some(bitrate) if bitrate > 0 => {
            let mtu = crate::packet::PROTOCOL_MTU as f64;
            Duration::from_secs_f64(2.0 * (mtu * 8.0 / (bitrate as f64).max(MINIMUM_BITRATE)) + 6.0)
        }
        _ => Duration::ZERO,
    }
}

async fn ingress_limited_path_request(handler: &TransportHandler, message: &RxMessage) -> bool {
    let packet = &message.packet;
    if packet.header.packet_type != PacketType::Data
        || packet.destination != handler.fixed_dest_path_requests
    {
        return false;
    }
    let manager = handler.iface_manager.lock().await;
    if manager
        .iface_kind(&message.address)
        .is_some_and(|kind| ingress_exempt_kind(&kind))
    {
        return false;
    }
    manager
        .with_control(&message.address, |control| {
            control.should_ingress_limit_pr(time::Instant::now())
        })
        .unwrap_or(false)
}

fn receipt_info(receipt: &PacketReceipt) -> PacketReceiptInfo {
    PacketReceiptInfo {
        status: receipt.status,
        timeout: receipt.timeout,
        rtt: receipt
            .concluded_at
            .and_then(|at| at.checked_duration_since(receipt.sent_at)),
    }
}

/// How long a concluded receipt stays readable by `receipt()`.
/// Link checks run every second; callers poll for a few seconds.
const RECEIPT_CONCLUDED_GRACE: Duration = Duration::from_secs(5);

fn check_receipts(receipts: &mut HashMap<AddressHash, PacketReceipt>) {
    let now = time::Instant::now();
    for receipt in receipts.values_mut() {
        if receipt.status != ReceiptStatus::Sent {
            continue;
        }
        let timed_out = match receipt.timeout {
            None => true,
            Some(timeout) => receipt.sent_at.elapsed() >= timeout,
        };
        if timed_out {
            receipt.status = if receipt.timeout.is_none() {
                ReceiptStatus::Culled
            } else {
                ReceiptStatus::Failed
            };
            receipt.concluded_at = Some(now);
        }
    }
    cull_receipts(receipts);
}

/// Drop concluded receipts after [`RECEIPT_CONCLUDED_GRACE`]. While the
/// map is over [`MAX_RECEIPTS`], drop the oldest in-flight receipts until
/// it fits. `SENT` receipts under the cap stay until their timeout.
fn cull_receipts(receipts: &mut HashMap<AddressHash, PacketReceipt>) {
    let now = time::Instant::now();
    receipts.retain(|_, receipt| match receipt.status {
        ReceiptStatus::Sent => true,
        _ => match receipt.concluded_at {
            Some(at) => now.saturating_duration_since(at) < RECEIPT_CONCLUDED_GRACE,
            None => false,
        },
    });
    while receipts.len() > MAX_RECEIPTS {
        let oldest_inflight = receipts
            .iter()
            .filter(|(_, receipt)| receipt.status == ReceiptStatus::Sent)
            .min_by_key(|(_, receipt)| receipt.sent_at)
            .map(|(key, _)| *key);
        let Some(key) = oldest_inflight.or_else(|| {
            receipts
                .iter()
                .min_by_key(|(_, receipt)| receipt.concluded_at.unwrap_or(receipt.sent_at))
                .map(|(key, _)| *key)
        }) else {
            break;
        };
        receipts.remove(&key);
    }
}

async fn relay_reverse_proof(
    packet: &Packet,
    ingress: AddressHash,
    handler: &mut TransportHandler,
) {
    if packet.context == PacketContext::ResourceProof
        || packet.context == PacketContext::LinkRequestProof
    {
        return;
    }
    let Some((received, outbound)) = handler
        .reverse_table
        .get(&packet.destination)
        .map(|entry| (entry.received, entry.outbound))
    else {
        return;
    };
    let (from_local, proof_for_local, hops_delta) = {
        let manager = handler.iface_manager.lock().await;
        (
            manager.is_local_client_iface(&ingress),
            manager.is_local_client_iface(&received),
            manager
                .local_hops_delta
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    };
    if !(handler.config.retransmit || from_local || proof_for_local) {
        return;
    }
    handler.reverse_table.remove(&packet.destination);
    if ingress == outbound {
        let mut outbound_packet = packet.clone();
        // Python writes `local_hops_delta` when the proof came from a
        // local client toward the wider network. `send` only rewrites
        // hops 0, so the sampled value has to be applied here.
        outbound_packet.header.hops = if from_local && !proof_for_local && hops_delta != 0 {
            hops_delta
        } else {
            packet.header.hops.saturating_add(1)
        };
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(received),
                packet: Box::new(outbound_packet),
            })
            .await;
    }
}

async fn note_shared_instance(handler: &mut TransportHandler) {
    let (online, clients) = {
        let manager = handler.iface_manager.lock().await;
        (
            manager.connected_to_shared_instance(),
            manager.local_client_iface_addresses(),
        )
    };
    match handler.shared_was_online {
        None => {
            handler.shared_was_online = Some(online);
            handler.seen_local_clients = clients;
        }
        Some(was) => {
            if was && !online {
                shared_connection_disappeared(handler).await;
            } else if !was && online {
                shared_connection_reappeared(handler).await;
            }
            handler.shared_was_online = Some(online);
            let gone: Vec<AddressHash> = handler
                .seen_local_clients
                .iter()
                .copied()
                .filter(|iface| !clients.contains(iface))
                .collect();
            for iface in gone {
                drop_local_client(handler, &iface).await;
            }
            handler.seen_local_clients = clients;
        }
    }
}

async fn shared_connection_disappeared(handler: &mut TransportHandler) {
    let inbound: Vec<_> = handler.in_links.values().cloned().collect();
    for link in inbound {
        let mut link = link.lock().await;
        if let Ok(Some(packet)) = link.teardown(&handler.link_in_event_tx) {
            handler.send_from_link(&mut link, packet).await;
        }
    }
    let outbound: Vec<_> = handler.out_links.values().cloned().collect();
    for link in outbound {
        let mut link = link.lock().await;
        if let Ok(Some(packet)) = link.teardown(&handler.link_out_event_tx) {
            handler.send_from_link(&mut link, packet).await;
        }
    }
    handler.in_links.clear();
    handler.out_links.clear();
    handler.in_link_ifaces.clear();
    handler.announce_table.clear();
    handler.path_table.clear();
    handler.reverse_table.clear();
    handler.link_table.clear();
    handler.tunnels.clear();
}

async fn shared_connection_reappeared(handler: &mut TransportHandler) {
    if !handler
        .iface_manager
        .lock()
        .await
        .connected_to_shared_instance()
    {
        return;
    }
    let destinations: Vec<_> = handler.single_in_destinations.values().cloned().collect();
    for destination in destinations {
        if let Ok(packet) = destination.lock().await.path_response(OsRng, None) {
            handler.send_packet(packet).await;
        }
    }
}

async fn drop_local_client(handler: &mut TransportHandler, iface: &AddressHash) {
    handler.path_table.drop_all_via(iface);
    handler.announce_table.drop_responses_to(iface);
    handler.link_table.drop_iface(iface);
    handler.tunnels.drop_iface(iface);
    handler
        .reverse_table
        .retain(|_, entry| entry.received != *iface && entry.outbound != *iface);
    let dead: Vec<_> = handler
        .in_link_ifaces
        .iter()
        .filter(|(_, bound)| *bound == iface)
        .map(|(id, _)| *id)
        .collect();
    for id in dead {
        if let Some(link) = handler.in_links.remove(&id) {
            let mut link = link.lock().await;
            if let Ok(Some(packet)) = link.teardown(&handler.link_in_event_tx) {
                handler.send_from_link(&mut link, packet).await;
            }
        }
        handler.in_link_ifaces.remove(&id);
    }
}

fn serialize_packet(packet: &Packet) -> Option<Vec<u8>> {
    let mut scratch = [0u8; 2048];
    let mut output = OutputBuffer::new(&mut scratch);
    packet.serialize(&mut output).ok()?;
    Some(output.as_slice().to_vec())
}

fn value_bin(value: &rmpv::Value) -> Option<&[u8]> {
    match value {
        rmpv::Value::Binary(bytes) => Some(bytes.as_slice()),
        _ => None,
    }
}

fn value_addr(value: &rmpv::Value) -> Option<AddressHash> {
    let bytes = value_bin(value)?;
    let array: [u8; 16] = bytes.try_into().ok()?;
    Some(AddressHash::new(array))
}

fn value_hash(value: &rmpv::Value) -> Option<Hash> {
    let bytes = value_bin(value)?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    Some(Hash::new(array))
}

fn value_f64(value: &rmpv::Value) -> Option<f64> {
    if let Some(number) = value.as_f64() {
        return Some(number);
    }
    if let Some(number) = value.as_i64() {
        return Some(number as f64);
    }
    value.as_u64().map(|number| number as f64)
}

fn write_hashlist(storage: &dyn Storage, hashes: &[Hash]) -> bool {
    let mut raw = Vec::with_capacity(hashes.len() * 32);
    for hash in hashes {
        raw.extend_from_slice(hash.as_slice());
    }
    match storage.write(PACKET_HASHLIST_FILE, &raw) {
        Ok(()) => true,
        Err(err) => {
            log::error!("failed to write {PACKET_HASHLIST_FILE}: {err:?}");
            false
        }
    }
}

/// One destination-table row. Live paths and paths still waiting for an
/// interface share this field list.
// Python-parity parameter set; grouping would churn the stacked diff.
#[allow(clippy::too_many_arguments)]
fn destination_table_row(
    destination: &[u8],
    stable_iface: &[u8],
    hops: u64,
    learned_unix: u64,
    mode: u64,
    gravity: Option<i64>,
    unresponsive: bool,
    blobs: Vec<rmpv::Value>,
    announce: Option<Vec<u8>>,
    received_from: &[u8],
    packet_hash: &[u8],
    expires_unix: Option<f64>,
) -> rmpv::Value {
    let mut fields = vec![
        rmpv::Value::Binary(destination.to_vec()),
        rmpv::Value::Binary(stable_iface.to_vec()),
        rmpv::Value::from(hops),
        rmpv::Value::from(learned_unix),
        rmpv::Value::from(mode),
        match gravity {
            Some(gravity) => rmpv::Value::from(gravity),
            None => rmpv::Value::Nil,
        },
        rmpv::Value::Boolean(unresponsive),
        rmpv::Value::Array(blobs),
        match announce {
            Some(bytes) => rmpv::Value::Binary(bytes),
            None => rmpv::Value::Nil,
        },
        rmpv::Value::Binary(received_from.to_vec()),
        rmpv::Value::Binary(packet_hash.to_vec()),
    ];
    // Absolute expiry, separate from the sliding learn time. Rows written
    // before this field omit it and are restored from the learn time.
    if let Some(expires_unix) = expires_unix {
        fields.push(rmpv::Value::from(expires_unix));
    }
    rmpv::Value::Array(fields)
}

fn write_path_table(
    handler: &TransportHandler,
    cache: &PacketCache,
    storage: &dyn Storage,
    iface_ids: &HashMap<AddressHash, AddressHash>,
) -> bool {
    let now = crate::time::now();
    let unix_now = crate::time::unix_time_as_secs();
    let mut entries = Vec::new();
    for (destination, entry) in handler.path_table.iter() {
        let Some(iface) = iface_ids.get(&entry.iface).copied() else {
            continue;
        };
        let age = path_table::path_age(now, entry.timestamp).as_secs();
        let learned_unix = unix_now.saturating_sub(age);
        let announce = cache
            .get_cached_announce(&entry.packet_hash)
            .and_then(|packet| serialize_packet(&packet));
        let blobs = entry.random_blobs[entry.random_blobs.len().saturating_sub(32)..]
            .iter()
            .map(|blob| rmpv::Value::Binary(blob.to_vec()))
            .collect();
        entries.push(destination_table_row(
            destination.as_slice(),
            iface.as_slice(),
            u64::from(entry.hops),
            learned_unix,
            entry.mode as u64,
            entry.gravity,
            entry.unresponsive,
            blobs,
            announce,
            entry.received_from.as_slice(),
            entry.packet_hash.as_slice(),
            Some(entry.expires_unix),
        ));
    }
    // Paths whose interface was not live at load time are not in the
    // table yet. Writing the table without them would drop them for good.
    if let Some(pending) = &handler.unresolved_paths {
        for path in pending {
            if handler.path_table.get(&path.destination).is_some() {
                continue;
            }
            let blobs = path
                .blobs
                .iter()
                .map(|blob| rmpv::Value::Binary(blob.to_vec()))
                .collect();
            entries.push(destination_table_row(
                path.destination.as_slice(),
                path.stable_iface.as_slice(),
                u64::from(path.hops),
                path.stored_unix,
                u64::from(path.mode),
                path.gravity,
                path.unresponsive,
                blobs,
                Some(path.announce.clone()),
                path.received_from.as_slice(),
                path.packet_hash.as_slice(),
                path.expires_unix,
            ));
        }
    }
    let mut buf = Vec::new();
    if rmpv::encode::write_value(&mut buf, &rmpv::Value::Array(entries)).is_err() {
        return false;
    }
    match storage.write(DESTINATION_TABLE_FILE, &buf) {
        Ok(()) => true,
        Err(err) => {
            log::error!("failed to write {DESTINATION_TABLE_FILE}: {err:?}");
            false
        }
    }
}

fn write_tunnel_table(
    handler: &TransportHandler,
    storage: &dyn Storage,
    iface_ids: &HashMap<AddressHash, AddressHash>,
) -> bool {
    let now_instant = time::Instant::now();
    let now = crate::time::now();
    let mut tunnels = Vec::new();
    for (tunnel_id, entry) in handler.tunnels.iter() {
        let remaining = entry
            .expires
            .saturating_duration_since(now_instant)
            .as_secs();
        let mut paths = Vec::new();
        for (destination, path) in &entry.paths {
            paths.push(rmpv::Value::Array(vec![
                rmpv::Value::Binary(destination.as_slice().to_vec()),
                rmpv::Value::Binary(path.received_from.as_slice().to_vec()),
                rmpv::Value::from(u64::from(path.hops)),
                rmpv::Value::from(path.expires.saturating_sub(now).as_secs()),
                rmpv::Value::Binary(path.packet_hash.as_slice().to_vec()),
            ]));
        }
        let stable_iface = entry.iface.and_then(|iface| iface_ids.get(&iface).copied());
        tunnels.push(rmpv::Value::Array(vec![
            rmpv::Value::Binary(tunnel_id.as_slice().to_vec()),
            match stable_iface {
                Some(iface) => rmpv::Value::Binary(iface.as_slice().to_vec()),
                None => rmpv::Value::Nil,
            },
            rmpv::Value::from(remaining),
            rmpv::Value::Array(paths),
        ]));
    }
    let mut buf = Vec::new();
    if rmpv::encode::write_value(&mut buf, &rmpv::Value::Array(tunnels)).is_err() {
        return false;
    }
    match storage.write(TUNNELS_FILE, &buf) {
        Ok(()) => true,
        Err(err) => {
            log::error!("failed to write {TUNNELS_FILE}: {err:?}");
            false
        }
    }
}

async fn persist_handler(handler: &mut TransportHandler) -> bool {
    let Some(storage) = handler.storage.clone() else {
        return true;
    };
    let iface_ids = {
        let manager = handler.iface_manager.lock().await;
        if manager.connected_to_shared_instance() {
            return true;
        }
        manager.stable_iface_map()
    };
    let cache = handler.packet_cache.lock().await;
    let hash_ok = if handler.config.retransmit {
        write_hashlist(&*storage, &cache.hashes())
    } else {
        true
    };
    let path_ok = write_path_table(handler, &cache, &*storage, &iface_ids);
    drop(cache);
    hash_ok && path_ok && write_tunnel_table(handler, &*storage, &iface_ids)
}

fn try_persist_handler(handler: &mut TransportHandler) -> bool {
    let Some(storage) = handler.storage.clone() else {
        return true;
    };
    let Ok(manager) = handler.iface_manager.try_lock() else {
        return false;
    };
    if manager.connected_to_shared_instance() {
        return true;
    }
    let iface_ids = manager.stable_iface_map();
    drop(manager);
    let Ok(cache) = handler.packet_cache.try_lock() else {
        return false;
    };
    let hash_ok = if handler.config.retransmit {
        write_hashlist(&*storage, &cache.hashes())
    } else {
        true
    };
    let path_ok = write_path_table(handler, &cache, &*storage, &iface_ids);
    drop(cache);
    hash_ok && path_ok && write_tunnel_table(handler, &*storage, &iface_ids)
}

async fn shutdown_persist(handler: &Arc<Mutex<TransportHandler>>) {
    let mut handler = handler.lock().await;
    if handler.shutdown_persisted {
        return;
    }
    if persist_handler(&mut handler).await {
        handler.shutdown_persisted = true;
    }
}

/// One path-table row read from storage, not yet bound to a live interface.
struct PersistedPath {
    destination: AddressHash,
    stable_iface: AddressHash,
    hops: u8,
    /// Unix time the path was learned. Zero means the field was missing.
    stored_unix: u64,
    mode: u8,
    gravity: Option<i64>,
    unresponsive: bool,
    blobs: Vec<[u8; 10]>,
    announce: Vec<u8>,
    received_from: AddressHash,
    packet_hash: Hash,
    /// Absolute expiry. `None` is a row written before this element existed.
    expires_unix: Option<f64>,
}

fn parse_persisted_paths(bytes: &[u8]) -> Vec<PersistedPath> {
    let Ok(value) = rmpv::decode::read_value(&mut &bytes[..]) else {
        return Vec::new();
    };
    let Some(entries) = value.as_array() else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    for entry in entries {
        let Some(fields) = entry.as_array() else {
            continue;
        };
        if fields.len() < 11 {
            continue;
        }
        let (Some(destination), Some(stable_iface)) =
            (value_addr(&fields[0]), value_addr(&fields[1]))
        else {
            continue;
        };
        let Some(announce) = value_bin(&fields[8]) else {
            continue;
        };
        let Some(received_from) = value_addr(&fields[9]) else {
            continue;
        };
        let Some(packet_hash) = value_hash(&fields[10]) else {
            continue;
        };
        let blobs = fields[7]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        let bytes = value_bin(item)?;
                        if bytes.len() != 10 {
                            return None;
                        }
                        let mut blob = [0u8; 10];
                        blob.copy_from_slice(bytes);
                        Some(blob)
                    })
                    .collect()
            })
            .unwrap_or_default();
        paths.push(PersistedPath {
            destination,
            stable_iface,
            hops: fields[2].as_u64().unwrap_or(0) as u8,
            stored_unix: fields[3].as_u64().unwrap_or(0),
            mode: fields[4].as_u64().unwrap_or(1) as u8,
            gravity: fields[5].as_i64(),
            unresponsive: fields[6].as_bool().unwrap_or(false),
            blobs,
            announce: announce.to_vec(),
            received_from,
            packet_hash,
            expires_unix: fields.get(11).and_then(value_f64),
        });
    }
    paths
}

async fn restore_persisted_path(
    handler: &mut TransportHandler,
    path: &PersistedPath,
    iface: AddressHash,
) {
    let mut input = InputBuffer::new(&path.announce);
    let Ok(packet) = Packet::deserialize(&mut input) else {
        return;
    };
    if let Some(identity) = announced_identity_hash(&packet) {
        if handler.blackholes.read().await.is_blackholed(&identity) {
            return;
        }
    }
    // The path-table hop count is already the in-memory view. Cache the
    // announce bytes unchanged so a later save does not add another hop.
    handler.packet_cache.lock().await.cache_announce(&packet);
    let unix_now = crate::time::unix_time_as_secs();
    let now_ns = path_table::monotonic_ns(crate::time::now());
    let stored_unix = if path.stored_unix == 0 {
        unix_now
    } else {
        path.stored_unix
    };
    let age_secs = unix_now.saturating_sub(stored_unix);
    let age_ns = (age_secs as u128)
        .saturating_mul(1_000_000_000)
        .min(i64::MAX as u128) as i64;
    let mode = InterfaceMode::from_u8(path.mode).unwrap_or(InterfaceMode::Full);
    let lifetime = path_table::path_lifetime(mode).as_secs_f64();
    // A stored expiry is restored as written. Only rows that predate the
    // field are rebuilt from the learn time plus the mode lifetime.
    let expires_unix = match path.expires_unix {
        Some(expires) => expires,
        None => {
            let base = if path.stored_unix == 0 {
                unix_now
            } else {
                path.stored_unix
            };
            base as f64 + lifetime
        }
    };
    handler.path_table.restore(
        path.destination,
        path_table::PathEntry {
            received_from: path.received_from,
            hops: path.hops,
            iface,
            timestamp: now_ns.saturating_sub(age_ns),
            unresponsive: path.unresponsive,
            packet_hash: path.packet_hash,
            mode,
            expires_unix,
            random_blobs: path.blobs.clone(),
            gravity: path.gravity,
        },
    );
}

async fn load_persisted_state(handler: &mut TransportHandler) {
    if handler.persisted_loaded {
        return;
    }
    let Some(storage) = handler.storage.clone() else {
        handler.persisted_loaded = true;
        return;
    };
    let (stable_to_live, ambiguous) = {
        let manager = handler.iface_manager.lock().await;
        if manager.connected_to_shared_instance() {
            handler.persisted_loaded = true;
            return;
        }
        manager.classify_stable_ids()
    };
    // No interface yet. An empty map must retry; do not commit.
    if stable_to_live.is_empty() && ambiguous.is_empty() {
        return;
    }
    if !handler.config.retransmit {
        handler.persisted_loaded = true;
        return;
    }
    if !handler.persisted_aux_loaded {
        if let Some(raw) = storage.read(PACKET_HASHLIST_FILE) {
            let mut cache = handler.packet_cache.lock().await;
            for chunk in raw.as_chunks::<32>().0 {
                cache.remember_hash(Hash::new(*chunk));
            }
        }
    }
    if handler.unresolved_paths.is_none() {
        let paths = match storage.read(DESTINATION_TABLE_FILE) {
            Some(bytes) => parse_persisted_paths(&bytes),
            None => Vec::new(),
        };
        handler.unresolved_paths = Some(paths);
    }
    let pending = handler.unresolved_paths.take().unwrap_or_default();
    let mut waiting = Vec::new();
    for path in pending {
        if ambiguous.contains(&path.stable_iface) {
            // Several live interfaces share this id. Skip the path rather
            // than attaching it to whichever interface was registered last.
            continue;
        }
        let Some(iface) = stable_to_live.get(&path.stable_iface).copied() else {
            waiting.push(path);
            continue;
        };
        restore_persisted_path(handler, &path, iface).await;
    }
    // Keep entries whose interface is not up yet and try them again when
    // one is added. `persisted_loaded` stays false until every saved path
    // has been restored or skipped, so the first interface cannot drop the
    // rest. An empty interface map already returned above.
    if waiting.is_empty() {
        handler.unresolved_paths = None;
        handler.persisted_loaded = true;
    } else {
        handler.unresolved_paths = Some(waiting);
    }
    if !handler.persisted_aux_loaded {
        if let Some(bytes) = storage.read(TUNNELS_FILE) {
            if let Ok(value) = rmpv::decode::read_value(&mut bytes.as_slice()) {
                if let Some(tunnels) = value.as_array() {
                    let now = crate::time::now();
                    let now_instant = time::Instant::now();
                    for tunnel in tunnels {
                        let Some(fields) = tunnel.as_array() else {
                            continue;
                        };
                        if fields.len() < 4 {
                            continue;
                        }
                        let Some(tunnel_id) = value_addr(&fields[0]) else {
                            continue;
                        };
                        let remaining = fields[2].as_u64().unwrap_or(0);
                        let mut paths = std::collections::BTreeMap::new();
                        if let Some(items) = fields[3].as_array() {
                            for item in items {
                                let Some(path_fields) = item.as_array() else {
                                    continue;
                                };
                                if path_fields.len() < 5 {
                                    continue;
                                }
                                let (Some(destination), Some(received_from), Some(packet_hash)) = (
                                    value_addr(&path_fields[0]),
                                    value_addr(&path_fields[1]),
                                    value_hash(&path_fields[4]),
                                ) else {
                                    continue;
                                };
                                paths.insert(
                                    destination,
                                    TunnelPath {
                                        received_from,
                                        hops: path_fields[2].as_u64().unwrap_or(0) as u8,
                                        expires: now
                                            + Duration::from_secs(
                                                path_fields[3].as_u64().unwrap_or(0),
                                            ),
                                        packet_hash,
                                    },
                                );
                            }
                        }
                        if paths.is_empty() {
                            continue;
                        }
                        // The stored interface is not bound until a live
                        // synthesis packet arrives (Python stores `None`).
                        handler.tunnels.insert(
                            tunnel_id,
                            tunnels::TunnelEntry {
                                iface: None,
                                paths,
                                expires: now_instant + Duration::from_secs(remaining),
                            },
                        );
                    }
                }
            }
        }
        handler.persisted_aux_loaded = true;
    }
}

async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();
    let retransmit = handler.lock().await.config.retransmit;
    let timer_config = handler.lock().await.config.timer_config;
    let enable_resource_watchdog = handler.lock().await.config.enable_resource_watchdog;

    let mut last_retransmit_old = if handler.lock().await.config.announce_forever {
        Some(time::Instant::now() - timer_config.old_announces_retransmit)
    } else {
        None
    };

    let inbound_queues = handler.lock().await.inbound_queues.clone();
    let _packet_task = {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let inbound_queues = inbound_queues.clone();

        log::trace!(
            "tp({}): start packet task",
            handler.lock().await.config.name
        );

        tokio::spawn(async move {
            let handler_arc = handler.clone();
            loop {
                let mut rx_receiver = rx_receiver.lock().await;

                if cancel.is_cancelled() {
                    shutdown_persist(&handler_arc).await;
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        shutdown_persist(&handler_arc).await;
                        break;
                    },
                    Some(message) = rx_receiver.recv() => {
                        // Pull the rest of the burst, then drain in class
                        // order so a data packet is not stuck behind an
                        // announce that arrived in the same batch
                        // (Python `InboundQueues.get`).
                        let mut batch = vec![message];
                        while let Ok(next) = rx_receiver.try_recv() {
                            batch.push(next);
                        }
                        let drained = {
                            let handler_guard = handler.lock().await;
                            let path_request_dest = handler_guard.fixed_dest_path_requests;
                            let mut classified = Vec::with_capacity(batch.len());
                            for message in batch {
                                let limited = ingress_limited_path_request(&handler_guard, &message).await;
                                let class = InboundQueues::classify(
                                    &message.packet,
                                    &path_request_dest,
                                    limited,
                                );
                                classified.push((class, message));
                            }
                            drop(handler_guard);
                            let mut queues = inbound_queues
                                .lock()
                                .expect("inbound queue lock");
                            for (class, message) in classified {
                                queues.put(class, message);
                            }
                            let mut out = Vec::new();
                            while let Some(item) = queues.get() {
                                out.push(item);
                            }
                            out
                        };
                        for message in drained {
                        if iface_messages_tx.receiver_count() > 0 {
                            let _ = iface_messages_tx.send(message.clone());
                        }

                        // Borrow, don't unbox: a Packet value held across
                        // these awaits is ~2 KB inline in the task's
                        // state machine (9 KB total), which no embedded
                        // heap can fragment-proof. `message` outlives the
                        // arm; &&Packet deref-coerces at every &Packet
                        // call site below.
                        let packet = &*message.packet;

                        let mut handler = handler.lock().await;

                        if PACKET_TRACE {
                            log::debug!("tp: << rx({}) = {} {}", message.address, packet, packet.hash());
                        }

                        {
                            let manager = handler.iface_manager.lock().await;
                            if let Some(stat) = manager
                                .stats()
                                .into_iter()
                                .find(|stat| stat.address == message.address)
                            {
                                let rssi = stat.rssi;
                                let snr = stat.snr;
                                let quality = stat.quality;
                                drop(manager);
                                if rssi.is_some() || snr.is_some() || quality.is_some() {
                                    handler.phy.record(packet.hash(), rssi, snr, quality);
                                }
                            }
                        }

                        // Early packet filter with protocol-violation
                        // accounting (Python 1.5.0 `Transport.packet_filter`
                        // + `Interface.protocol_violation`).
                        if !packet_filter(packet) {
                            let manager = handler.iface_manager.lock().await;
                            manager.count_packet_filter_hit(&message.address);
                            manager.count_protocol_violation(&message.address);
                            continue;
                        }

                        if handle_fixed_destinations(
                            packet,
                            &mut handler,
                            message.address
                        ).await {
                            continue;
                        }

                        // Filter packets in transport addressed to other
                        // instances (Python `packet_filter`): directed
                        // type-2 data must not be processed by every
                        // router that hears it.
                        if packet.header.header_type == HeaderType::Type2
                            && packet.header.packet_type != PacketType::Announce
                        {
                            if let Some(transport_id) = packet.transport {
                                let own = *handler.config.identity.address_hash();
                                if transport_id != own {
                                    log::trace!(
                                        "tp({}): ignored packet in transport for other instance {}",
                                        handler.config.name,
                                        transport_id
                                    );
                                    continue;
                                }
                            }
                        }

                        if !handler.filter_duplicate_packets(packet).await {
                            log::debug!(
                                "tp({}): dropping duplicate packet: dst={}, ctx={:?}, type={:?}",
                                handler.config.name,
                                packet.destination,
                                packet.context,
                                packet.header.packet_type
                            );
                            continue;
                        }


                        // NOTE: Python transport nodes never blindly repeat
                        // received packets. Every relayed packet class is
                        // handled explicitly with re-addressing and hop
                        // accounting (announces via the announce table,
                        // link requests/proofs/link data via the link
                        // table, addressed data via the path table).
                        //
                        // Only the designated next hop processes in-transit packets:
                        // nodes that merely overhear them on shared-medium (radio)
                        // interfaces must ignore them, otherwise forwarded packets
                        // circulate (e.g. LinkRequest ping-pong between originator and
                        // relay).
                        //
                        // A node accepts an in-transit packet when the transport field
                        // designates it as the next hop. For relay next hops this is the
                        // node's own identity hash; for the final hop to a non-relay
                        // destination host (whose announce carried no transport id) the
                        // path table records the destination address itself, so we also
                        // accept when it matches a locally hosted destination.
                        if let Some(transport) = packet.transport {
                            if packet.header.destination_type != DestinationType::Link
                                && packet.header.packet_type != PacketType::Announce
                                && packet.header.packet_type != PacketType::Proof
                                && transport != *handler.config.identity.address_hash()
                                && !handler.has_destination(&transport)
                            {
                                log::trace!(
                                    "tp({}): ignoring in-transit packet not addressed to this node: dst={}, type={:?}",
                                    handler.config.name,
                                    packet.destination,
                                    packet.header.packet_type
                                );
                                continue;
                            }
                        }

                        match packet.header.packet_type {
                            PacketType::Announce => handle_announce(
                                packet,
                                &mut handler,
                                message.address
                            ).await,
                            PacketType::LinkRequest => handle_link_request(
                                packet,
                                message.address,
                                handler
                            ).await,
                            PacketType::Proof => handle_proof(packet, message.address, handler).await,
                            PacketType::Data => handle_data(
                                packet,
                                message.address,
                                handler_arc.clone(),
                                handler,
                            )
                            .await,
                        }
                        }
                    }
                };
            }
        })
    };

    // Interface control ticker (Python drives these with
    // `threading.Timer`s and the 1s transport jobs):
    // * releases ingress-held announces back into processing
    //   (`Interface.process_held_announces`),
    // * transmits queued announces when the airtime budget allows
    //   (`Interface.process_announce_queue`),
    // * transmits grace-delayed path responses.
    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(Duration::from_millis(100)) => {
                        let mut handler = handler.lock().await;

                        load_persisted_state(&mut handler).await;
                        note_shared_instance(&mut handler).await;

                        let released = {
                            let manager = handler.iface_manager.lock().await;
                            manager.release_held_announces()
                        };
                        // Box the loop-held packet: an inline Packet
                        // (~2 KB) held across the await below lands in
                        // this task's state machine, and the resulting
                        // 9 KB task spawn OOMs on fragmented embedded
                        // heaps (observed on ESP32-S3).
                        let released: Vec<_> = released
                            .into_iter()
                            .map(|(iface, packet)| (iface, Box::new(packet)))
                            .collect();
                        for (iface, packet) in released {
                            log::trace!(
                                "tp({}): releasing held announce packet from {}",
                                handler.config.name,
                                iface
                            );
                            handle_announce(&packet, &mut handler, iface).await;
                        }

                        // Drained announces transmit directly on their
                        // interface; they must not re-enter the outbound
                        // announce-cap gate.
                        handler.iface_manager.lock().await.process_announce_queues().await;

                        // Interfaces that came up (I2P peers, backbone
                        // clients, RNodeMulti transports) request tunnel
                        // synthesis via `wants_tunnel`
                        // (Python `Transport.synthesize_tunnel`).
                        let synth = {
                            let manager = handler.iface_manager.lock().await;
                            manager.interfaces_wanting_tunnel()
                        };
                        for iface in synth {
                            let already_bound = handler
                                .iface_manager
                                .lock()
                                .await
                                .iface_tunnel(&iface)
                                .is_some();
                            if already_bound {
                                continue;
                            }

                            let transport_id =
                                if handler.config.retransmit {
                                    Some(*handler.config.identity.address_hash())
                                } else {
                                    None
                                };

                            let packet = Box::new(tunnels::synthesize_tunnel_packet(
                                &handler.config.identity,
                                &iface,
                                handler.fixed_dest_tunnel_synthesize,
                                transport_id,
                            ));

                            handler.iface_manager.lock().await.set_iface_wants_tunnel(&iface, false);

                            log::debug!(
                                "tp({}): synthesizing tunnel for interface {iface}",
                                handler.config.name
                            );

                            handler
                                .send(TxMessage {
                                    tx_type: TxMessageType::Direct(iface),
                                    packet,
                                })
                                .await;
                        }
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    // Python caps each watchdog sleep at WATCHDOG_MAX_SLEEP.
                    // link_check is already 1s; the min keeps a longer
                    // configured check from missing a 5s keepalive.
                    _ = time::sleep(timer_config.link_check.min(crate::destination::link::WATCHDOG_MAX_SLEEP)) => {
                        let mut handler = handler.lock().await;
                        check_receipts(&mut handler.receipts);
                        handle_check_links(handler).await;
                    }
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.iface_cleanup) => {
                        handle_cleanup(handler.lock().await).await;
                    }
                }
            }
        });
    }

    // Table culling (Python `Transport.jobs` runs every
    // `tables_cull_interval` = 5 s): link-table entries past their proof
    // timeout or idle lifetime, and stale paths, are removed promptly so
    // topology changes converge.
    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(Duration::from_secs(5)) => {
                        let mut handler = handler.lock().await;

                        let live = {
                            let manager = handler.iface_manager.lock().await;
                            manager
                                .live_iface_addresses()
                                .into_iter()
                                .map(|(address, _)| address)
                                .collect::<Vec<_>>()
                        };
                        handler.reverse_table.retain(|_, entry| {
                            entry.at.elapsed() < REVERSE_TIMEOUT
                                && live.contains(&entry.received)
                                && live.contains(&entry.outbound)
                        });
                        handler.path_table.drop_ifaces_not_in(&live);

                        let stale_links = handler.link_table.remove_stale();
                        let retransmit = handler.config.retransmit;
                        for entry in stale_links {
                            let destination = entry.original_destination;
                            let has_path = handler.path_table.contains(&destination);
                            let hops = handler.path_table.get(&destination).map(|path| path.hops);
                            let allowed = handler.path_requests.request_allowed(&destination);
                            let mut rediscover = false;
                            let mut exclude: Option<AddressHash> = None;
                            if !has_path || (allowed && entry.taken_hops == 0) {
                                rediscover = true;
                            } else if allowed && (hops == Some(1) || entry.taken_hops == 1) {
                                rediscover = true;
                                exclude = Some(entry.receiving_iface);
                                let mode = handler
                                    .iface_manager
                                    .lock()
                                    .await
                                    .iface_mode(&entry.receiving_iface);
                                if retransmit && mode != InterfaceMode::Boundary {
                                    handler.path_table.mark_path_unresponsive(&destination);
                                }
                            }
                            if rediscover {
                                if !retransmit {
                                    handler.path_table.expire_path(&destination);
                                }
                                let packet = handler.path_requests.generate(&destination, None);
                                handler
                                    .send(TxMessage {
                                        tx_type: TxMessageType::Broadcast(exclude),
                                        packet: Box::new(packet),
                                    })
                                    .await;
                            }
                        }

                        // Expire stale paths (Python `Transport.expire_paths`).
                        let expired = handler.path_table.expire_paths();
                        if expired > 0 {
                            log::info!(
                                "tp({}): expired {} stale path(s)",
                                handler.config.name,
                                expired
                            );
                        }
                    },
                }
            }
        });
    }

    {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.packet_cache_cleanup) => {
                        let handler = handler.lock().await;

                        handler
                            .packet_cache
                            .lock()
                            .await
                            .release(timer_config.keep_packet_cached);

                        // Clean expired blackhole entries
                        // (Python `blackhole_check_interval` job).
                        handler.blackholes.write().await.clean();
                    },
                }
            }
        });
    }

    // Resource watchdog: retry/timeouts for active transfers, cleanup of
    // concluded ones. Runs faster than the cache cleanup to keep transfer
    // latency low (Python ticks every WATCHDOG_MAX_SLEEP = 1s).
    // The task's future carries inline resource packets (~2.5 KB); RAM-
    // constrained embedders that never run resource transfers disable it.
    if enable_resource_watchdog {
    {
        let handler = handler.clone();
        let cancel = cancel.clone();
        let resource_tick = timer_config
            .resource_watchdog
            .min(crate::resource::WATCHDOG_MAX_SLEEP);

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(resource_tick) => {
                        let mut handler = handler.lock().await;

                        let all_links: HashMap<LinkId, Arc<Mutex<Link>>> = handler
                            .in_links
                            .iter()
                            .chain(handler.out_links.iter())
                            .map(|(id, link)| (*id, link.clone()))
                            .collect();

                        let tx = handler.resources.check(&all_links);
                        for packet in tx.packets {
                            handler.send_packet(packet).await;
                        }
                        handler.resources.cleanup();
                    },
                }
            }
        });
    }
    }

    if retransmit {
        let handler = handler.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    _ = time::sleep(timer_config.announces_retransmit) => {
                        let mut retransmit_old = false;

                        if let Some(instant) = last_retransmit_old {
                            let now = time::Instant::now();
                            if now - instant > timer_config.old_announces_retransmit {
                                retransmit_old = true;
                                last_retransmit_old = Some(now);
                            }
                        }

                        retransmit_announces(handler.lock().await, retransmit_old).await;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    #[test]
    fn inbound_queues_drain_in_class_order() {
        let mut queues = InboundQueues::new([2, 2, 2, 2]);
        // A data item queued first is still drained after an announce
        // that arrived later (announces have higher priority).
        let data = test_rx_message(PacketType::Data);
        let announce = test_rx_message(PacketType::Announce);
        let mut drained = queues.enqueue_and_drain(data);
        drained.extend(queues.enqueue_and_drain(announce));
        // Both drain immediately in the single-message case; the class
        // ORDER matters only when items are queued behind each other.
        assert_eq!(drained.len(), 2);
    }

    #[test]
    fn inbound_queues_drop_when_full() {
        let mut queues = InboundQueues::new([1, 1, 1, 1]);
        // Fill the announce class beyond its size.
        queues.put(
            TrafficClass::Announce,
            test_rx_message(PacketType::Announce),
        );
        queues.put(
            TrafficClass::Announce,
            test_rx_message(PacketType::Announce),
        );
        let (total, heights, dropped) = queues.snapshot();
        assert_eq!(heights[TrafficClass::Announce as usize], 1);
        assert_eq!(dropped[TrafficClass::Announce as usize], 1);
        assert_eq!(total, 1);
    }

    #[test]
    fn announce_classifies_higher_than_data() {
        let path_requests = create_path_request_destination().desc.address_hash;
        assert_eq!(
            InboundQueues::classify(&test_packet(PacketType::Announce), &path_requests, false),
            TrafficClass::Announce
        );
        assert_eq!(
            InboundQueues::classify(&test_packet(PacketType::Data), &path_requests, false),
            TrafficClass::Data
        );
        let mut request = test_packet(PacketType::Data);
        request.destination = path_requests;
        assert_eq!(
            InboundQueues::classify(&request, &path_requests, false),
            TrafficClass::PathRequest
        );
        assert_eq!(
            InboundQueues::classify(&request, &path_requests, true),
            TrafficClass::IngressLimited
        );
        let mut cache = test_packet(PacketType::Data);
        cache.context = PacketContext::CacheRequest;
        assert_eq!(
            InboundQueues::classify(&cache, &path_requests, true),
            TrafficClass::Data
        );
    }

    #[test]
    fn zero_length_uses_python_defaults() {
        let queues = InboundQueues::new([0, 0, 0, 0]);
        assert_eq!(queues.sizes, [1024, 128, 128, 8]);
    }

    #[test]
    fn data_drains_before_announce() {
        let mut queues = InboundQueues::new([2, 2, 2, 2]);
        queues.put(
            TrafficClass::Announce,
            test_rx_message(PacketType::Announce),
        );
        queues.put(TrafficClass::Data, test_rx_message(PacketType::Data));
        assert_eq!(
            queues.get().unwrap().packet.header.packet_type,
            PacketType::Data
        );
        assert_eq!(
            queues.get().unwrap().packet.header.packet_type,
            PacketType::Announce
        );
    }

    fn test_packet(packet_type: PacketType) -> Packet {
        Packet {
            header: crate::packet::Header {
                packet_type,
                ..Default::default()
            },
            ifac: None,
            destination: crate::hash::AddressHash::new_from_rand(rand_core::OsRng),
            transport: None,
            context: PacketContext::None,
            data: Default::default(),
        }
    }

    fn test_rx_message(packet_type: PacketType) -> RxMessage {
        RxMessage {
            address: crate::hash::AddressHash::new_from_rand(rand_core::OsRng),
            packet: Box::new(test_packet(packet_type)),
        }
    }
}

#[cfg(test)]
mod phy_tests {
    use super::*;

    fn hash(byte: u8) -> Hash {
        Hash::new([byte; 32])
    }

    #[test]
    fn lookup_returns_recent_and_misses_evicted() {
        let mut cache = PhyCache::new(2);
        cache.record(hash(1), Some(-70), None, None);
        cache.record(hash(2), Some(-60), None, None);
        // Third record evicts the oldest (hash 1).
        cache.record(hash(3), Some(-50), None, None);

        assert_eq!(PhyCache::lookup(&cache.rssi, &hash(1)), None);
        assert_eq!(PhyCache::lookup(&cache.rssi, &hash(2)), Some(-60.0));
        assert_eq!(PhyCache::lookup(&cache.rssi, &hash(3)), Some(-50.0));
    }

    #[test]
    fn metrics_retain_independent_histories() {
        let mut cache = PhyCache::new(1);
        cache.record(hash(1), Some(-70), Some(8.0), Some(0.9));
        // Capacity applies per metric; rssi evicts its own oldest only.
        cache.record(hash(2), Some(-60), None, None);

        assert_eq!(PhyCache::lookup(&cache.rssi, &hash(1)), None);
        assert_eq!(PhyCache::lookup(&cache.rssi, &hash(2)), Some(-60.0));
        assert_eq!(PhyCache::lookup(&cache.snr, &hash(1)), Some(8.0));
        assert_eq!(PhyCache::lookup(&cache.q, &hash(1)), Some(f64::from(0.9_f32)));
        assert_eq!(PhyCache::lookup(&cache.snr, &hash(2)), None);
    }

    #[test]
    fn zero_capacity_disables_history() {
        let mut cache = PhyCache::new(0);
        cache.record(hash(1), Some(-70), Some(8.0), Some(0.9));

        assert!(cache.rssi.is_empty());
        assert!(cache.snr.is_empty());
        assert!(cache.q.is_empty());
        assert_eq!(PhyCache::lookup(&cache.rssi, &hash(1)), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::destination::link::LinkEvent;
    use crate::packet::HeaderType;
    use rand_core::OsRng;

    #[test]
    fn persisted_expires_is_independent_of_learn_time() {
        let fresh = destination_table_row(
            &[1u8; 16],
            &[2u8; 16],
            3,
            1_700_000_000,
            1,
            None,
            false,
            Vec::new(),
            Some(vec![9, 9]),
            &[3u8; 16],
            &[4u8; 32],
            Some(1_800_000_000.5),
        );
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &rmpv::Value::Array(vec![fresh])).unwrap();
        let paths = parse_persisted_paths(&buf);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].stored_unix, 1_700_000_000);
        assert_eq!(paths[0].expires_unix, Some(1_800_000_000.5));

        let old = destination_table_row(
            &[1u8; 16],
            &[2u8; 16],
            3,
            1_700_000_000,
            1,
            None,
            false,
            Vec::new(),
            Some(vec![9, 9]),
            &[3u8; 16],
            &[4u8; 32],
            None,
        );
        let mut buf = Vec::new();
        rmpv::encode::write_value(&mut buf, &rmpv::Value::Array(vec![old])).unwrap();
        let paths = parse_persisted_paths(&buf);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].stored_unix, 1_700_000_000);
        assert!(paths[0].expires_unix.is_none());
    }

    #[tokio::test]
    async fn synchronous_accessors_are_safe_inside_a_runtime() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let transport = TransportConfig::new("accessors", &identity).build();

        assert_eq!(
            transport.identity_private().to_hex_string(),
            identity.to_hex_string()
        );
        let _blackholes = transport.blackholes();
        assert_eq!(transport.identity_hash().await, *identity.address_hash());
        assert_eq!(transport.instance_name().await, "accessors");

        let destination = transport
            .add_destination(
                identity,
                DestinationName::new("test", "accessor.destination"),
            )
            .await;
        let address = destination.lock().await.desc.address_hash;
        assert_eq!(
            transport.destination_accepts_links(&address).await,
            Some(true)
        );
    }

    #[tokio::test]
    async fn announce_subscriptions_filter_by_complete_destination_name() {
        let transport = TransportConfig::default().build();
        let mut filtered = transport
            .subscribe_announces("example", &["wanted.aspect"])
            .await;

        let first_identity = PrivateIdentity::new_from_rand(OsRng);
        let second_identity = PrivateIdentity::new_from_rand(OsRng);
        let unrelated = SingleOutputDestination::new(
            *first_identity.as_identity(),
            DestinationName::new("example", "other.aspect"),
        );
        let first_match = SingleOutputDestination::new(
            *first_identity.as_identity(),
            DestinationName::new("example", "wanted.aspect"),
        );
        let second_match = SingleOutputDestination::new(
            *second_identity.as_identity(),
            DestinationName::new("example", "wanted.aspect"),
        );

        let sender = transport.handler.lock().await.announce_tx.clone();
        for destination in [unrelated, first_match, second_match] {
            assert!(sender
                .send(AnnounceEvent {
                    destination: Arc::new(Mutex::new(destination)),
                    app_data: PacketDataBuffer::new(),
                    ratchet: None,
                })
                .is_ok());
        }

        let first = time::timeout(Duration::from_secs(1), filtered.recv())
            .await
            .expect("first matching announce")
            .unwrap();
        let second = time::timeout(Duration::from_secs(1), filtered.recv())
            .await
            .expect("second matching announce")
            .unwrap();
        let addresses = [
            first.destination.lock().await.desc.address_hash,
            second.destination.lock().await.desc.address_hash,
        ];
        assert!(addresses.contains(
            &DestinationName::new("example", "wanted.aspect")
                .address_hash_for(first_identity.as_identity())
        ));
        assert!(addresses.contains(
            &DestinationName::new("example", "wanted.aspect")
                .address_hash_for(second_identity.as_identity())
        ));
        assert!(time::timeout(Duration::from_millis(50), filtered.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn single_proofs_accept_only_exact_implicit_and_explicit_forms() {
        let transport = TransportConfig::default().build();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let destination = AddressHash::new_from_slice(&[7; 32]);
        let packet_hash = Hash::new_from_slice(b"pending proof");
        let proof_destination = AddressHash::new_from_hash(&packet_hash);
        let receipt = PacketReceipt {
            destination,
            packet_hash,
            identity: *identity.as_identity(),
            sent_at: time::Instant::now(),
            timeout: Some(Duration::from_secs(6)),
            status: ReceiptStatus::Sent,
            concluded_at: None,
        };
        let handler = transport.get_handler();

        for length in (0..64).chain(65..96).chain(97..100) {
            let packet = Packet {
                destination: proof_destination,
                data: PacketDataBuffer::new_from_slice(&vec![0; length]),
                ..Default::default()
            };
            let mut handler = handler.lock().await;
            handler.receipts.insert(proof_destination, receipt.clone());
            assert!(!validate_single_destination_proof(&mut handler, &packet));
            assert!(handler.receipts.contains_key(&proof_destination));
        }

        let signature = identity.sign(packet_hash.as_slice());
        let implicit = Packet {
            destination: proof_destination,
            data: PacketDataBuffer::new_from_slice(&signature.to_bytes()),
            ..Default::default()
        };
        let mut handler = handler.lock().await;
        handler.receipts.insert(proof_destination, receipt.clone());
        assert!(validate_single_destination_proof(&mut handler, &implicit));

        let mut explicit_data = Vec::with_capacity(96);
        explicit_data.extend_from_slice(packet_hash.as_slice());
        explicit_data.extend_from_slice(&signature.to_bytes());
        let explicit = Packet {
            destination: proof_destination,
            data: PacketDataBuffer::new_from_slice(&explicit_data),
            ..Default::default()
        };
        handler.receipts.insert(proof_destination, receipt);
        assert!(validate_single_destination_proof(&mut handler, &explicit));
    }

    #[tokio::test]
    async fn plain_and_single_payload_limits_are_enforced_before_buffering() {
        let transport = TransportConfig::default().build();
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let output = SingleOutputDestination::new(
            *identity.as_identity(),
            DestinationName::new("test", "single.payload-bound"),
        );
        let address = output.desc.address_hash;
        transport
            .handler
            .lock()
            .await
            .single_out_destinations
            .insert(address, Arc::new(Mutex::new(output)));

        assert!(transport
            .send_to_destination(&address, &vec![0; crate::packet::SINGLE_PLAINTEXT_MDU])
            .await
            .is_ok());
        assert!(matches!(
            transport
                .send_to_destination(&address, &vec![0; crate::packet::SINGLE_PLAINTEXT_MDU + 1])
                .await,
            Err(RnsError::InvalidArgument)
        ));
        assert!(matches!(
            transport
                .send_to_destination(&address, &vec![0; crate::packet::PACKET_MDU + 100])
                .await,
            Err(RnsError::InvalidArgument)
        ));

        let plain_name = DestinationName::new("test", "plain.payload-bound");
        assert!(transport
            .send_to_plain_destination(plain_name, &vec![0; crate::packet::PACKET_PROTOCOL_MDU])
            .await
            .is_ok());
        assert!(matches!(
            transport
                .send_to_plain_destination(
                    plain_name,
                    &vec![0; crate::packet::PACKET_PROTOCOL_MDU + 1]
                )
                .await,
            Err(RnsError::InvalidArgument)
        ));
    }

    #[tokio::test]
    async fn events_for_link_drops_unrelated_link_events() {
        let transport = TransportConfig::default().build();
        let wanted = AddressHash::new_from_slice(&[11; 32]);
        let unrelated = AddressHash::new_from_slice(&[12; 32]);
        let destination = AddressHash::new_from_slice(&[13; 32]);
        let mut events = transport.events_for_link(wanted).await;

        transport.link_out_event_tx.send(LinkEventData {
            id: unrelated,
            address_hash: destination,
            event: LinkEvent::Closed,
        });
        transport.link_out_event_tx.send(LinkEventData {
            id: wanted,
            address_hash: destination,
            event: LinkEvent::Activated,
        });

        let event = time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("matching link event")
            .unwrap();
        assert_eq!(event.id, wanted);
        assert!(matches!(event.event, LinkEvent::Activated));
        assert!(time::timeout(Duration::from_millis(50), events.recv())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn drop_duplicates() {
        let transport = TransportConfig::default().set_retransmit(true).build();

        let handler = transport.get_handler();

        let _source1 = AddressHash::new_from_slice(&[1u8; 32]);
        let _source2 = AddressHash::new_from_slice(&[2u8; 32]);
        let next_hop_iface = AddressHash::new_from_slice(&[3u8; 32]);
        let destination = AddressHash::new_from_slice(&[4u8; 32]);

        let mut announce: Packet = Default::default();
        announce.header.header_type = HeaderType::Type2;
        announce.header.packet_type = PacketType::Announce;
        announce.header.hops = 3;
        announce.transport = Some(destination);

        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&announce)
                .await
        );

        let mut handler_guard = handler.lock().await;
        handle_announce(&announce, &mut handler_guard, next_hop_iface).await;
        drop(handler_guard);

        let data_packet: Packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"foo"),
            destination,
            ..Default::default()
        };
        let duplicate: Packet = data_packet.clone();

        let different_packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"bar"),
            ..data_packet
        };

        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&data_packet)
                .await
        );
        assert!(
            !handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await
        );
        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&different_packet)
                .await
        );

        tokio::time::sleep(Duration::from_secs(2)).await;
        handler
            .lock()
            .await
            .packet_cache
            .lock()
            .await
            .release(Duration::from_secs(1));

        // Packet should have been removed from cache (stale)
        assert!(
            handler
                .lock()
                .await
                .filter_duplicate_packets(&duplicate)
                .await
        );
    }
}
// ---------------------------------------------------------------------------
// Read-only introspection API for the Phase 7/8 utilities (rnpath, rnstatus).
//
// Everything below is append-only: none of the routing/handling functions
// above are modified. These mirror the Python `RNS.Transport` /
// `RNS.Reticulum` introspection helpers used by `rnpath` and `rnstatus`
// (`has_path`, `hops_to`, `next_hop`, `next_hop_interface`,
// `get_path_table`, `get_link_count`, `Reticulum.transport_id`).
// ---------------------------------------------------------------------------

/// One entry of the path table snapshot
/// (Python `Reticulum.get_path_table()` dict entries:
/// `hash`, `hops`, `via`, `interface`).
/// Snapshot of one tunnel table entry (Python `get_tunnel_table`).
#[derive(Debug, Clone)]
pub struct TunnelTableSnapshotEntry {
    /// Id of the tunnel (`full_hash(pub_key || iface_hash)`).
    pub tunnel_id: AddressHash,
    /// Interface the tunnel is currently bound to (`None` when voided).
    pub iface: Option<AddressHash>,
    /// Number of paths associated with the tunnel.
    pub paths: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PathTableSnapshotEntry {
    /// Destination hash the path leads to.
    pub destination: AddressHash,
    /// Hops to the destination.
    pub hops: u8,
    /// Transport instance (or the destination itself when directly
    /// connected) the path is routed through (`received_from`).
    pub via: AddressHash,
    /// Interface address the path is routed over.
    pub iface: AddressHash,
    /// Whether the path is marked unresponsive (Python
    /// `mark_path_unresponsive`; new announces clear it).
    pub unresponsive: bool,
    /// Seconds since the path was learned (Python reports an absolute
    /// `timestamp`; the transport time base is monotonic since start).
    pub age_secs: u64,
    /// Hash of the announce packet that created/refreshed the path.
    pub announce_hash: crate::hash::Hash,
    /// Unix expiry recorded when the path was inserted.
    pub expires_unix: f64,
}

/// One announce-rate entry (Python `Reticulum.get_rate_table`).
/// `blocked_for` and `since_last` are durations from now. `timestamps` is
/// the announce window as unix times, oldest first, at most 16.
#[derive(Debug, Clone, PartialEq)]
pub struct RateTableEntry {
    pub destination: AddressHash,
    pub violations: u32,
    pub blocked_for: Option<std::time::Duration>,
    pub since_last: std::time::Duration,
    pub timestamps: Vec<f64>,
}

/// Link table counters (Python `get_link_count` and the separate count of
/// established inbound/outbound links kept by `Transport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkCounts {
    /// Entries in the transport link table (pending + active).
    pub link_table: usize,
    /// Fully established inbound links.
    pub inbound: usize,
    /// Fully established outbound links.
    pub outbound: usize,
}

impl Transport {
    /// Whether a path to `destination` is currently known
    /// (Python `RNS.Transport.has_path`).
    pub async fn has_path(&self, destination: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .path_table
            .get(destination)
            .is_some()
    }

    /// Next hop for `destination`: the transport instance hash to route
    /// through (`via`) and the interface address to send on
    /// (Python `RNS.Transport.next_hop` + `next_hop_interface`).
    pub async fn next_hop(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.handler
            .lock()
            .await
            .path_table
            .next_hop_full(destination)
    }

    /// Snapshot of the whole path table
    /// (Python `Reticulum.get_path_table`). Paths older than
    /// `PATHFINDER_E` (one week) are expired by the cleanup task.
    pub async fn path_table_snapshot(&self) -> Vec<PathTableSnapshotEntry> {
        let now = crate::time::now();
        let handler = self.handler.lock().await;
        handler
            .path_table
            .iter()
            .map(|(destination, entry)| PathTableSnapshotEntry {
                destination: *destination,
                hops: entry.hops,
                via: entry.received_from,
                iface: entry.iface,
                unresponsive: entry.unresponsive,
                age_secs: path_table::path_age(now, entry.timestamp).as_secs(),
                announce_hash: entry.packet_hash,
                expires_unix: entry.expires_unix,
            })
            .collect()
    }

    /// Announce rate-limit table (Python `Reticulum.get_rate_table`).
    /// Empty only when nothing has been rate-limited.
    pub async fn rate_table_snapshot(&self) -> Vec<RateTableEntry> {
        let handler = self.handler.lock().await;
        handler
            .announce_limits
            .snapshot()
            .into_iter()
            .map(
                |(destination, violations, blocked_for, since_last, timestamps)| RateTableEntry {
                    destination,
                    violations,
                    blocked_for,
                    since_last,
                    timestamps,
                },
            )
            .collect()
    }

    /// Validated rows in the transport link table
    /// (Python `Transport.active_link_count`).
    pub async fn active_link_count(&self) -> usize {
        self.handler.lock().await.link_table.validated_len()
    }

    /// Cached radio RSSI for `hash`, or `None` on a miss.
    pub async fn packet_rssi(&self, hash: &Hash) -> Option<f64> {
        let handler = self.handler.lock().await;
        PhyCache::lookup(&handler.phy.rssi, hash)
    }

    /// Cached radio SNR for `hash`, or `None` on a miss.
    pub async fn packet_snr(&self, hash: &Hash) -> Option<f64> {
        let handler = self.handler.lock().await;
        PhyCache::lookup(&handler.phy.snr, hash)
    }

    /// Cached radio quality for `hash`, or `None` on a miss.
    pub async fn packet_q(&self, hash: &Hash) -> Option<f64> {
        let handler = self.handler.lock().await;
        PhyCache::lookup(&handler.phy.q, hash)
    }

    /// Link table / link counters (Python `get_link_count` plus
    /// inbound/outbound established link counts).
    pub async fn link_counts(&self) -> LinkCounts {
        let handler = self.handler.lock().await;
        LinkCounts {
            link_table: handler.link_table.len(),
            inbound: handler.in_links.len(),
            outbound: handler.out_links.len(),
        }
    }

    /// Synthesize a tunnel for an interface: announce the signed
    /// `pub_key || iface_hash || random_hash || signature` payload on the
    /// fixed `rnstransport.tunnel.synthesize` destination, directly on the
    /// interface (Python `Transport.synthesize_tunnel`).
    pub async fn synthesize_tunnel(&self, iface: AddressHash) -> Result<(), RnsError> {
        let handler = self.handler.lock().await;

        let transport_id = if handler.config.retransmit {
            Some(*handler.config.identity.address_hash())
        } else {
            None
        };

        let packet = tunnels::synthesize_tunnel_packet(
            &handler.config.identity,
            &iface,
            handler.fixed_dest_tunnel_synthesize,
            transport_id,
        );

        handler
            .iface_manager
            .lock()
            .await
            .set_iface_wants_tunnel(&iface, false);

        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet: Box::new(packet),
            })
            .await;

        Ok(())
    }

    /// Unbind a tunnel from its interface while keeping its learned paths
    /// for a later restore (Python `Transport.void_tunnel_interface`).
    pub async fn void_tunnel(&self, tunnel_id: &AddressHash) -> bool {
        let mut handler = self.handler.lock().await;

        if let Some(iface) = handler.tunnels.get(tunnel_id).and_then(|e| e.iface) {
            handler
                .iface_manager
                .lock()
                .await
                .set_iface_tunnel(&iface, None);
        }

        handler.tunnels.void(tunnel_id)
    }

    /// Snapshot of the tunnel table: tunnel id, bound interface, number of
    /// associated paths (Python `Reticulum.get_tunnel_table`).
    pub async fn tunnel_table_snapshot(&self) -> Vec<TunnelTableSnapshotEntry> {
        let handler = self.handler.lock().await;
        handler
            .tunnels
            .iter()
            .map(|(tunnel_id, entry)| TunnelTableSnapshotEntry {
                tunnel_id: *tunnel_id,
                iface: entry.iface,
                paths: entry.paths.len(),
            })
            .collect()
    }

    /// Enable the remote management destination
    /// `rnstransport.remote.management` with `/status` and `/path`
    /// request handlers (Python `Transport.remote_management_destination`).
    ///
    /// Requests are restricted to link-identified peers on the allow list
    /// (Python `ALLOW_LIST`); add identities via
    /// [`Transport::remote_management_allow`].
    pub async fn enable_remote_management(&self) -> Arc<Mutex<SingleInputDestination>> {
        let identity = self.handler.lock().await.config.identity.clone();

        let snapshot = Arc::new(std::sync::RwLock::new(
            management::ManagementSnapshot::default(),
        ));
        let allowed = self.handler.lock().await.remote_management_allowed.clone();
        let destination = self
            .add_destination(identity, management::remote_management_name())
            .await;
        let address = destination.lock().await.desc.address_hash;

        // /status handler
        {
            let snapshot = snapshot.clone();
            let allowed = allowed.clone();
            self.register_request_handler(&address, "/status", move |ctx| {
                if !management::identity_allowed(
                    ctx.remote_identity.as_ref(),
                    &allowed.read().unwrap(),
                ) {
                    return None;
                }
                let include_links = matches!(
                    management::decode_management_request(&ctx.data),
                    management::ManagementRequest::Status {
                        include_links: true
                    }
                );
                Some(management::status_response(
                    &snapshot.read().unwrap(),
                    include_links,
                ))
            })
            .await;
        }

        // /path handler
        {
            let snapshot = snapshot.clone();
            let allowed = allowed.clone();
            self.register_request_handler(&address, "/path", move |ctx| {
                if !management::identity_allowed(
                    ctx.remote_identity.as_ref(),
                    &allowed.read().unwrap(),
                ) {
                    return None;
                }
                match management::decode_management_request(&ctx.data) {
                    management::ManagementRequest::PathTable {
                        destination,
                        max_hops,
                    } => Some(management::path_table_response(
                        &snapshot.read().unwrap(),
                        destination.as_deref(),
                        max_hops,
                    )),
                    management::ManagementRequest::Rates { destination } => {
                        Some(management::rates_response(
                            &snapshot.read().unwrap(),
                            destination.as_deref(),
                        ))
                    }
                    _ => None,
                }
            })
            .await;
        }

        // Refresh the snapshot periodically.
        let handler = self.handler.clone();
        tokio::spawn(async move {
            loop {
                let handler = handler.lock().await;
                let (stats, iface_extra) = {
                    let manager = handler.iface_manager.lock().await;
                    let stats = manager.stats();
                    let iface_extra = stats
                        .iter()
                        .map(|stat| {
                            let (mode, bitrate) = manager
                                .with_control(&stat.address, |control| {
                                    (control.mode as u8, control.bitrate)
                                })
                                .unwrap_or((0x01, 62_500));
                            let radio = manager.radio_telemetry(&stat.address);
                            management::IfaceStatusExtra {
                                mode,
                                bitrate,
                                mtu: manager.iface_hw_mtu(&stat.address).map(|mtu| mtu as u64),
                                airtime_short: radio.airtime_short,
                                airtime_long: radio.airtime_long,
                                channel_load_short: radio.channel_load_short,
                                channel_load_long: radio.channel_load_long,
                            }
                        })
                        .collect();
                    (stats, iface_extra)
                };
                let paths = handler
                    .path_table
                    .iter()
                    .map(|(destination, entry)| PathTableSnapshotEntry {
                        destination: *destination,
                        hops: entry.hops,
                        via: entry.received_from,
                        iface: entry.iface,
                        unresponsive: entry.unresponsive,
                        age_secs: path_table::path_age(crate::time::now(), entry.timestamp)
                            .as_secs(),
                        announce_hash: entry.packet_hash,
                        expires_unix: entry.expires_unix,
                    })
                    .collect();
                let blackholes = handler.blackholes.read().await.pack_table();

                *snapshot.write().unwrap() = management::ManagementSnapshot {
                    stats,
                    iface_extra,
                    paths,
                    link_counts: (
                        handler.link_table.len(),
                        handler.in_links.len(),
                        handler.out_links.len(),
                    ),
                    blackholes,
                };
                drop(handler);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        log::info!(
            "tp({}): enabled remote management on {}",
            self.name,
            address
        );

        destination
    }

    /// Add an identity to the remote-management allow list
    /// (Python `Transport.remote_management_allowed`).
    pub async fn remote_management_allow(&self, identity: AddressHash) {
        self.handler
            .lock()
            .await
            .remote_management_allowed
            .write()
            .unwrap()
            .push(identity);
    }

    /// Enable the probe destination `rnstransport.probe`
    /// (Python `Transport.probe_destination`: no links, PROVE_ALL —
    /// `rnprobe` measures round-trip times against it).
    pub async fn enable_probe_destination(&self) -> Arc<Mutex<SingleInputDestination>> {
        let identity = self.handler.lock().await.config.identity.clone();

        let destination = management::probe_destination(&identity);
        let address = destination.desc.address_hash;
        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .await
            .single_in_destinations
            .insert(address, destination.clone());

        log::info!(
            "tp({}): transport instance will respond to probe requests on {}",
            self.name,
            address
        );

        destination
    }

    /// Enable blackhole-list publishing on `rnstransport.info.blackhole`
    /// with the `/list` request handler
    /// (Python `Transport.blackhole_destination`).
    pub async fn enable_blackhole_publishing(&self) -> Arc<Mutex<SingleInputDestination>> {
        let identity = self.handler.lock().await.config.identity.clone();

        let snapshot = Arc::new(std::sync::RwLock::new(
            management::ManagementSnapshot::default(),
        ));
        let destination = self
            .add_destination(identity, management::blackhole_info_name())
            .await;
        let address = destination.lock().await.desc.address_hash;

        {
            let snapshot = snapshot.clone();
            self.register_request_handler(&address, "/list", move |_ctx| {
                Some(management::encode_blackhole_list(
                    &snapshot.read().unwrap().blackholes,
                ))
            })
            .await;
        }

        // Refresh periodically alongside remote management.
        let handler = self.handler.clone();
        tokio::spawn(async move {
            loop {
                let blackholes = handler.lock().await.blackholes.read().await.pack_table();
                snapshot.write().unwrap().blackholes = blackholes;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        log::info!(
            "tp({}): enabled blackhole list publishing on {}",
            self.name,
            address
        );

        destination
    }

    /// Enable or disable announce retransmission after the instance exists.
    ///
    /// Shared-instance tools stay at the configured flag until the local
    /// client is online, then clear it. A failed attach restores the flag
    /// before configured interfaces are opened.
    pub async fn set_retransmit(&self, retransmit: bool) {
        self.handler.lock().await.config.retransmit = retransmit;
    }

    /// Hash of the identity this transport instance runs with
    /// (Python `Reticulum.transport_id` / the daemon's transport identity).
    pub async fn identity_hash(&self) -> AddressHash {
        *self.handler.lock().await.config.identity.address_hash()
    }

    /// Name of this transport instance (`TransportConfig::name`).
    pub async fn instance_name(&self) -> String {
        self.handler.lock().await.config.name.clone()
    }

    /// The private identity of this transport instance
    /// (for subsystems that need to announce or sign on its behalf).
    pub fn identity_private(&self) -> PrivateIdentity {
        self.identity.clone()
    }
}
