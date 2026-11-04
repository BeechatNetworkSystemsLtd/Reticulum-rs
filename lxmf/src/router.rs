//! LxmRouter - the LXMF delivery and propagation layer over the async
//! `reticulum` transport.
//!
//! This module ports the protocol-visible parts of `LXMF/LXMF/LXMRouter.py`
//! onto the Rust `reticulum` crate's tokio-based transport:
//!
//! * creation of the `lxmf.delivery` and `lxmf.propagation` SINGLE
//!   destinations and their announce app-data
//! * delivery announce handling (stamp cost tracking, identity recall)
//! * propagation node announce handling (peer configuration)
//! * outbound direct delivery over an established link, sending the packed
//!   message as a link data packet
//! * inbound ingestion with signature validation, stamp enforcement and
//!   dedup by message hash / transient id
//! * delivery receipts and send failures via a tokio broadcast channel
//!
//! Resource-backed delivery and the propagation `/get` and `/offer` request
//! paths are implemented. Ratchets, backchannel identification, and
//! opportunistic packet delivery receipts remain separate integration points.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkEventData, LinkId, LinkStatus};
use reticulum::destination::{DestinationDesc, ProofStrategy, SingleInputDestination};
use reticulum::hash::{AddressHash, Hash, HASH_SIZE};
use reticulum::identity::{Identity, PrivateIdentity};
use reticulum::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketDataBuffer,
    PacketType, PropagationType,
};
use reticulum::resource::{ResourceStatus, ResourceStrategy};
use reticulum::transport::{AnnounceEvent, ReceivedData, Transport};
use tokio::sync::{broadcast, Mutex};
use tokio::time::{timeout, Duration};

use crate::error::LxmfError;
use crate::fields::{FieldValue, Fields, FIELD_TICKET, SF_COMPRESSION};
use crate::message::{
    decrypt_for_identity, encrypt_for_identity, full_hash, LXMessage, DELIVERED, DIRECT, FAILED,
    LXMF_OVERHEAD, OPPORTUNISTIC, OUTBOUND, PROPAGATED, RESOURCE, SENDING, SENT, TICKET_EXPIRY,
    TICKET_INTERVAL, TICKET_LENGTH, TICKET_RENEW,
};
use crate::peer::{
    PeerData, ERROR_INVALID_DATA, ERROR_INVALID_KEY, ERROR_NOT_FOUND, ERROR_NO_ACCESS,
    ERROR_NO_IDENTITY, MESSAGE_GET_PATH, OFFER_REQUEST_PATH, SYNC_REQUEST_PATH,
    UNPEER_REQUEST_PATH,
};
use crate::stamper;
use crate::APP_NAME;
use crate::{
    compression_support_from_app_data, delivery_destination_hash, delivery_name,
    display_name_from_app_data, pack_announce_app_data, pack_propagation_node_app_data,
    pn_announce_data_from_app_data, propagation_name, stamp_cost_from_app_data, to_hex,
    DESTINATION_LENGTH, URI_SCHEMA,
};

/// Router tuning and policy constants (`LXMRouter` class constants).
/// Maximum outbound delivery attempts per message.
pub const MAX_DELIVERY_ATTEMPTS: u32 = 5;
/// Router job loop interval in seconds.
pub const PROCESSING_INTERVAL: u64 = 4;
/// Seconds between delivery attempts.
pub const DELIVERY_RETRY_WAIT: f64 = 10.0;
/// Seconds to wait after issuing a path request.
pub const PATH_REQUEST_WAIT: f64 = 7.0;
/// Attempts before a path is requested for pathless destinations.
pub const MAX_PATHLESS_TRIES: u32 = 1;
/// Maximum inactivity on direct links before teardown.
pub const LINK_MAX_INACTIVITY: u64 = 10 * 60;
/// Maximum inactivity on propagation links before teardown.
pub const P_LINK_MAX_INACTIVITY: u64 = 3 * 60;

/// Message store entry expiry in seconds (30 days).
pub const MESSAGE_EXPIRY: f64 = 30.0 * 24.0 * 60.0 * 60.0;
/// Known outbound stamp cost expiry in seconds (45 days).
pub const STAMP_COST_EXPIRY: f64 = 45.0 * 24.0 * 60.0 * 60.0;

/// Delay before the propagation node announces itself, in seconds.
pub const NODE_ANNOUNCE_DELAY: u64 = 20;

/// Default maximum number of propagation peers.
pub const MAX_PEERS: usize = 20;
/// Default peering stamp cost.
pub const PEERING_COST: i64 = 18;
/// Maximum peering cost accepted from remote nodes.
pub const MAX_PEERING_COST: i64 = 26;
/// Minimum configurable propagation stamp cost.
pub const PROPAGATION_COST_MIN: i64 = 13;
/// Default propagation stamp cost flexibility.
pub const PROPAGATION_COST_FLEX: i64 = 3;
/// Default propagation stamp cost.
pub const PROPAGATION_COST: i64 = 16;
/// Default per-transfer propagation limit in kilobytes.
pub const PROPAGATION_LIMIT: i64 = 256;
/// Default per-sync propagation limit in kilobytes.
pub const SYNC_LIMIT: i64 = PROPAGATION_LIMIT * 40;
/// Default delivery resource limit in kilobytes.
pub const DELIVERY_LIMIT: i64 = 1000;

/// Path request timeout for propagation transfers, in seconds.
pub const PR_PATH_TIMEOUT: f64 = 10.0;
/// Throttle period applied to out-of-cost sync offers, in seconds.
pub const PN_STAMP_THROTTLE: f64 = 180.0;

/// Propagation transfer states (client side).
/// Propagation transfer state: idle.
pub const PR_IDLE: u8 = 0x00;
/// Propagation transfer state: path requested.
pub const PR_PATH_REQUESTED: u8 = 0x01;
/// Propagation transfer state: link establishing.
pub const PR_LINK_ESTABLISHING: u8 = 0x02;
/// Propagation transfer state: link established.
pub const PR_LINK_ESTABLISHED: u8 = 0x03;
/// Propagation transfer state: request sent.
pub const PR_REQUEST_SENT: u8 = 0x04;
/// Propagation transfer state: receiving.
pub const PR_RECEIVING: u8 = 0x05;
/// Propagation transfer state: response received.
pub const PR_RESPONSE_RECEIVED: u8 = 0x06;
/// Propagation transfer state: complete.
pub const PR_COMPLETE: u8 = 0x07;
/// Propagation transfer state: no path to node.
pub const PR_NO_PATH: u8 = 0xf0;
/// Propagation transfer state: link failed.
pub const PR_LINK_FAILED: u8 = 0xf1;
/// Propagation transfer state: transfer failed.
pub const PR_TRANSFER_FAILED: u8 = 0xf2;
/// Propagation transfer state: no identity received.
pub const PR_NO_IDENTITY_RCVD: u8 = 0xf3;
/// Propagation transfer state: access denied.
pub const PR_NO_ACCESS: u8 = 0xf4;
/// Propagation transfer state: failed.
pub const PR_FAILED: u8 = 0xfe;

/// Request all available messages from a propagation node.
pub const PR_ALL_MESSAGES: u8 = 0x00;

/// Signal value used by clients to flag duplicate delivery.
pub const DUPLICATE_SIGNAL: &str = "lxmf_duplicate";

/// Events emitted by the router on its broadcast channel.
#[derive(Clone, Debug)]
pub enum LxmEvent {
    /// A locally destined message was ingested and validated.
    Received(LXMessage),
    /// A locally destined message was received but had already been
    /// delivered before (deduplicated by message hash).
    Duplicate(LXMessage),
    /// An outbound message was acknowledged by the recipient
    /// (link packet proof received).
    DeliveryReceipt {
        /// Hash of the acknowledged message.
        message_hash: Hash,
    },
    /// An outbound message could not be delivered.
    SendFailed {
        /// Hash of the message that failed.
        message_hash: Hash,
        /// Why the delivery failed.
        reason: SendFailure,
    },
    /// An announce relevant to LXMF was received.
    Announce(AnnounceInfo),
    /// A propagated message was accepted into the local message store.
    PropagationStored {
        /// Transient id of the stored message.
        transient_id: Hash,
        /// Work value of the propagation stamp.
        stamp_value: u64,
    },
    /// Progress or completion of a client download from a propagation node.
    PropagationTransfer(PropagationTransferState),
}

/// Observable state of a client propagation-node download.
#[derive(Clone, Debug, PartialEq)]
pub struct PropagationTransferState {
    /// Protocol state (`PR_*`).
    pub state: u8,
    /// Transfer progress between zero and one.
    pub progress: f64,
    /// Bytes received in the last response.
    pub size: usize,
    /// Number of newly ingested messages, when complete.
    pub last_result: Option<usize>,
    /// Number of duplicates in the last download.
    pub last_duplicates: usize,
}

impl Default for PropagationTransferState {
    fn default() -> Self {
        Self {
            state: PR_IDLE,
            progress: 0.0,
            size: 0,
            last_result: None,
            last_duplicates: 0,
        }
    }
}

/// Reasons an outbound message failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SendFailure {
    /// No identity/path known for the destination yet; a path request was
    /// issued. The message stays queued and delivery is retried when an
    /// announce is received.
    PathUnknown,
    /// The transport link could not be established.
    LinkFailed,
    /// No delivery receipt was received before the timeout elapsed.
    DeliveryTimeout,
    /// The message requires resource transfer, which is not implemented yet.
    ResourceUnsupported,
    /// A resource-backed delivery was attempted but the transfer failed.
    ResourceFailed,
    /// No identity is known for the destination (path unknown).
    NoPath,
    /// No outbound propagation node has been configured.
    NoPropagationNode,
    /// The message was malformed or could not be packed.
    Invalid(String),
}

/// Parsed announce information surfaced through [`LxmEvent::Announce`].
#[derive(Clone, Debug)]
pub enum AnnounceInfo {
    /// An "lxmf.delivery" destination announced itself.
    Delivery {
        /// Destination hash of the announcing "lxmf.delivery" destination.
        destination_hash: AddressHash,
        /// The announced identity.
        identity: Identity,
        /// Display name from the announce app-data.
        display_name: Option<String>,
        /// Stamp cost required by the destination.
        stamp_cost: Option<u8>,
        /// Whether the destination signals resource compression support.
        compression_support: bool,
    },
    /// An "lxmf.propagation" destination announced itself with valid
    /// propagation node data.
    PropagationNode {
        /// Destination hash of the announcing "lxmf.propagation" destination.
        destination_hash: AddressHash,
        /// The announced identity.
        identity: Identity,
        /// Parsed propagation node configuration.
        info: crate::PropagationNodeInfo,
    },
}

/// A stored propagation entry (message store index), mirroring the layout
/// of `LXMRouter.propagation_entries` values.
#[derive(Clone, Debug)]
pub struct PropagationEntry {
    /// Destination hash of the message recipient.
    pub destination_hash: AddressHash,
    /// Path of the stored (stamped) message data.
    pub file_path: PathBuf,
    /// Unix timestamp of reception.
    pub received: f64,
    /// Size of the stored data in bytes.
    pub size: usize,
    /// Work value of the propagation stamp.
    pub stamp_value: u64,
}

/// Router configuration.
#[derive(Clone)]
pub struct RouterConfig {
    /// Drop messages with invalid or missing stamps when the delivery
    /// destination has a stamp cost configured.
    pub enforce_stamps: bool,
    /// Operate as a propagation node (store and serve propagated messages).
    pub propagation_node: bool,
    /// Per-transfer propagation limit in kilobytes.
    pub propagation_transfer_limit: i64,
    /// Per-sync propagation limit in kilobytes.
    pub propagation_sync_limit: i64,
    /// Required propagation stamp cost.
    pub propagation_stamp_cost: i64,
    /// Accepted propagation stamp cost flexibility.
    pub propagation_stamp_cost_flexibility: i64,
    /// Required peering cost.
    pub peering_cost: i64,
    /// Maximum peering cost accepted from remote nodes.
    pub max_peering_cost: i64,
    /// Maximum number of propagation peers.
    pub max_peers: usize,
    /// Keep already-present message ids on the remote node during downloads.
    pub retain_synced_on_node: bool,
    /// Maximum messages accepted in one client download response.
    pub delivery_per_transfer_limit: i64,
    /// Maximum simultaneous accepted inbound peer sync resources.
    pub propagation_max_inbound_syncs: usize,
    /// Identities allowed to use propagation control request paths.
    pub control_allowed: Vec<AddressHash>,
    /// How long to wait for a delivery receipt before declaring failure.
    pub delivery_timeout: Duration,
    /// How long to wait for link activation.
    pub link_timeout: Duration,
    /// Capacity of the router event broadcast channel. Each slot holds a
    /// full LxmEvent (~1 KB), so RAM-constrained embedders set this low
    /// (e.g. 4); 256 matches the historical fixed value.
    pub event_channel_capacity: usize,
}

impl RouterConfig {
    /// Timeout for resource-backed deliveries: delivery timeout plus a
    /// generous transfer allowance.
    pub fn resource_timeout(&self) -> u64 {
        self.delivery_timeout.as_secs().max(30) * 3
    }
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enforce_stamps: false,
            propagation_node: false,
            propagation_transfer_limit: PROPAGATION_LIMIT,
            propagation_sync_limit: SYNC_LIMIT,
            propagation_stamp_cost: PROPAGATION_COST,
            propagation_stamp_cost_flexibility: PROPAGATION_COST_FLEX,
            peering_cost: PEERING_COST,
            max_peering_cost: MAX_PEERING_COST,
            max_peers: MAX_PEERS,
            retain_synced_on_node: false,
            delivery_per_transfer_limit: DELIVERY_LIMIT,
            propagation_max_inbound_syncs: 10,
            control_allowed: Vec::new(),
            delivery_timeout: Duration::from_secs(LINK_MAX_INACTIVITY),
            event_channel_capacity: 256,
            link_timeout: Duration::from_secs(30),
        }
    }
}

/// Configuration of the local "lxmf.delivery" destination.
#[derive(Clone, Default)]
pub struct DeliveryConfig {
    /// Delivery identity. Defaults to the router identity.
    pub identity: Option<PrivateIdentity>,
    /// Display name announced in the delivery app-data.
    pub display_name: Option<String>,
    /// Stamp cost required from senders to this destination.
    pub stamp_cost: Option<u8>,
}

struct DeliveryDestination {
    identity: PrivateIdentity,
    destination: Arc<Mutex<SingleInputDestination>>,
    address_hash: AddressHash,
    display_name: Option<String>,
    stamp_cost: Option<u8>,
}

#[derive(Default)]
struct Tickets {
    outbound: HashMap<AddressHash, (f64, [u8; TICKET_LENGTH])>,
    inbound: HashMap<AddressHash, Vec<(f64, [u8; TICKET_LENGTH])>>,
    last_deliveries: HashMap<AddressHash, f64>,
}

/// A message waiting for outbound delivery.
struct OutboundEntry {
    destination_hash: AddressHash,
    message: Arc<Mutex<LXMessage>>,
    source: PrivateIdentity,
}

/// Mutable router state.
struct RouterState {
    /// Destination hash to identity, the `RNS.Identity.recall` equivalent
    /// backed by received announces.
    known_identities: HashMap<AddressHash, Identity>,
    outbound_stamp_costs: HashMap<AddressHash, (f64, u8)>,
    locally_delivered: HashMap<Hash, f64>,
    locally_processed: HashMap<Hash, f64>,
    propagation_entries: HashMap<Hash, PropagationEntry>,
    peers: HashMap<AddressHash, PeerData>,
    tickets: Tickets,
    ignored_list: Vec<AddressHash>,
    outbound_propagation_node: Option<AddressHash>,
    /// Pending outbound messages awaiting a path or announce.
    pending_outbound: Vec<OutboundEntry>,
}

impl RouterState {
    fn new() -> Self {
        Self {
            known_identities: HashMap::new(),
            outbound_stamp_costs: HashMap::new(),
            locally_delivered: HashMap::new(),
            locally_processed: HashMap::new(),
            propagation_entries: HashMap::new(),
            peers: HashMap::new(),
            tickets: Tickets::default(),
            ignored_list: Vec::new(),
            outbound_propagation_node: None,
            pending_outbound: Vec::new(),
        }
    }
}

/// The LXMF router.
pub struct LxmRouter {
    transport: Transport,
    identity: PrivateIdentity,
    propagation_destination: Arc<Mutex<SingleInputDestination>>,
    propagation_destination_hash: AddressHash,
    delivery: Mutex<Option<DeliveryDestination>>,
    /// Inbound links activated specifically for our delivery destination.
    delivery_links: Mutex<HashSet<LinkId>>,
    storage_path: PathBuf,
    message_path: PathBuf,
    name: Option<String>,
    config: RouterConfig,
    state: Arc<Mutex<RouterState>>,
    events: broadcast::Sender<LxmEvent>,
    propagation_transfer: Arc<Mutex<PropagationTransferState>>,
    propagation_download: Mutex<Option<tokio::task::JoinHandle<()>>>,
    accepted_offer_links: Mutex<HashSet<LinkId>>,
}

impl LxmRouter {
    /// Create a new LXMF router. The transport is consumed and remains
    /// accessible through [`LxmRouter::transport`].
    ///
    /// A "lxmf.propagation" SINGLE destination is always registered (as in
    /// the Python implementation). When `delivery` is given, a
    /// "lxmf.delivery" destination is registered for it
    /// (`LXMRouter.register_delivery_identity`); note that the Rust
    /// transport requires destinations to be registered at construction
    /// time, so this cannot be done later on an owned router.
    pub async fn new<T: AsRef<Path>, N: Into<String>>(
        transport: Transport,
        identity: PrivateIdentity,
        storage_path: T,
        name: Option<N>,
        delivery: Option<DeliveryConfig>,
        config: RouterConfig,
    ) -> Arc<Self> {
        let storage_path = storage_path.as_ref().join(APP_NAME);
        let message_path = storage_path.join("messages");

        let _ = std::fs::create_dir_all(&storage_path);
        if config.propagation_node {
            let _ = std::fs::create_dir_all(&message_path);
        }

        let propagation_destination = transport
            .add_destination(identity.clone(), propagation_name())
            .await;
        let propagation_destination_hash = propagation_destination.lock().await.desc.address_hash;

        let (events, _) = broadcast::channel(config.event_channel_capacity);

        let mut state = RouterState::new();
        // Self-recall so that locally generated echoes resolve
        state.known_identities.insert(
            delivery_destination_hash(identity.as_identity()),
            *identity.as_identity(),
        );

        // Restore persisted caches
        load_hash_time_map(&storage_path.join("local_deliveries"))
            .into_iter()
            .for_each(|(k, v)| {
                state.locally_delivered.insert(k, v);
            });
        load_hash_time_map(&storage_path.join("locally_processed"))
            .into_iter()
            .for_each(|(k, v)| {
                state.locally_processed.insert(k, v);
            });

        let delivery_destination = if let Some(delivery_config) = delivery {
            let delivery_identity = delivery_config.identity.unwrap_or_else(|| identity.clone());
            let destination = transport
                .add_destination(delivery_identity.clone(), delivery_name())
                .await;
            destination.lock().await.proof_strategy = ProofStrategy::All;
            let address_hash = destination.lock().await.desc.address_hash;
            state
                .known_identities
                .insert(address_hash, *delivery_identity.as_identity());

            log::debug!("Registered LXMF delivery destination {address_hash}");

            Some(DeliveryDestination {
                identity: delivery_identity,
                destination,
                address_hash,
                display_name: delivery_config.display_name,
                stamp_cost: delivery_config
                    .stamp_cost
                    .filter(|cost| (1..255).contains(cost)),
            })
        } else {
            None
        };

        let router = Arc::new(Self {
            transport,
            identity: identity.clone(),
            propagation_destination,
            propagation_destination_hash,
            delivery: Mutex::new(delivery_destination),
            delivery_links: Mutex::new(HashSet::new()),
            storage_path,
            message_path,
            name: name.map(Into::into),
            config,
            state: Arc::new(Mutex::new(state)),
            events,
            propagation_transfer: Arc::new(Mutex::new(PropagationTransferState::default())),
            propagation_download: Mutex::new(None),
            accepted_offer_links: Mutex::new(HashSet::new()),
        });

        router.register_propagation_handlers().await;

        router.spawn_watchers();

        router
    }

    fn spawn_watchers(self: &Arc<Self>) {
        let router = self.clone();
        tokio::spawn(async move {
            router.announce_watcher().await;
        });

        let router = self.clone();
        tokio::spawn(async move {
            router.received_data_watcher().await;
        });

        let router = self.clone();
        tokio::spawn(async move {
            router.link_event_watcher().await;
        });

        let router = self.clone();
        tokio::spawn(async move {
            router.resource_event_watcher().await;
        });
    }

    async fn register_propagation_handlers(self: &Arc<Self>) {
        let router = Arc::clone(self);
        self.transport
            .register_async_request_handler(
                &self.propagation_destination_hash,
                MESSAGE_GET_PATH,
                move |ctx| {
                    let router = Arc::clone(&router);
                    async move { Some(router.handle_message_get(ctx).await) }
                },
            )
            .await;

        let router = Arc::clone(self);
        self.transport
            .register_async_request_handler(
                &self.propagation_destination_hash,
                OFFER_REQUEST_PATH,
                move |ctx| {
                    let router = Arc::clone(&router);
                    async move { Some(router.handle_offer(ctx).await) }
                },
            )
            .await;

        let router = Arc::clone(self);
        self.transport
            .register_async_request_handler(
                &self.propagation_destination_hash,
                SYNC_REQUEST_PATH,
                move |ctx| {
                    let router = Arc::clone(&router);
                    async move { Some(router.handle_control(ctx, true).await) }
                },
            )
            .await;

        let router = Arc::clone(self);
        self.transport
            .register_async_request_handler(
                &self.propagation_destination_hash,
                UNPEER_REQUEST_PATH,
                move |ctx| {
                    let router = Arc::clone(&router);
                    async move { Some(router.handle_control(ctx, false).await) }
                },
            )
            .await;
    }

    async fn handle_offer(&self, ctx: reticulum::resource::RequestContext) -> Vec<u8> {
        let Some(remote) = ctx.remote_identity else {
            return pack_field(&FieldValue::Int(ERROR_NO_IDENTITY as i64));
        };
        if !self.config.propagation_node
            || self.accepted_offer_links.lock().await.len()
                >= self.config.propagation_max_inbound_syncs
        {
            return pack_field(&FieldValue::Int(ERROR_NO_ACCESS as i64));
        }
        let mut rd = ctx.data.as_slice();
        let Ok(FieldValue::Array(parts)) = FieldValue::unpack(&mut rd) else {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        };
        if parts.len() != 2 {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        }
        let FieldValue::Bin(key) = &parts[0] else {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        };
        let Ok(offered) = field_hashes(parts.get(1)) else {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        };
        let mut peering_id = Vec::with_capacity(HASH_SIZE);
        peering_id.extend_from_slice(self.identity.address_hash().as_slice());
        peering_id.extend_from_slice(remote.address_hash.as_slice());
        if !stamper::validate_peering_key(&peering_id, key, self.config.peering_cost.max(0) as u32)
        {
            return pack_field(&FieldValue::Int(ERROR_INVALID_KEY as i64));
        }
        let entries = self.state.lock().await.propagation_entries.clone();
        let wanted: Vec<Hash> = offered
            .into_iter()
            .filter(|id| !entries.contains_key(id))
            .collect();
        if wanted.is_empty() {
            return pack_field(&FieldValue::Bool(false));
        }
        self.accepted_offer_links.lock().await.insert(ctx.link_id);
        pack_field(&hashes_field(&wanted))
    }

    async fn handle_control(
        &self,
        ctx: reticulum::resource::RequestContext,
        sync: bool,
    ) -> Vec<u8> {
        let Some(remote) = ctx.remote_identity else {
            return pack_field(&FieldValue::Int(ERROR_NO_IDENTITY as i64));
        };
        if !self.config.control_allowed.contains(&remote.address_hash) {
            return pack_field(&FieldValue::Int(ERROR_NO_ACCESS as i64));
        }
        let mut rd = ctx.data.as_slice();
        let Ok(FieldValue::Bin(raw_destination)) = FieldValue::unpack(&mut rd) else {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        };
        if raw_destination.len() != HASH_SIZE / 2 {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        }
        let mut bytes = [0u8; HASH_SIZE / 2];
        bytes.copy_from_slice(&raw_destination);
        let destination = AddressHash::new(bytes);
        if !self.state.lock().await.peers.contains_key(&destination) {
            return pack_field(&FieldValue::Int(ERROR_NOT_FOUND as i64));
        }
        if sync {
            if let Some(peer) = self.state.lock().await.peers.get_mut(&destination) {
                peer.last_sync_attempt = 0.0;
            }
        } else {
            self.unpeer(&destination, None).await;
        }
        pack_field(&FieldValue::Bool(true))
    }

    async fn handle_message_get(&self, ctx: reticulum::resource::RequestContext) -> Vec<u8> {
        let Some(remote_identity) = ctx.remote_identity else {
            return pack_field(&FieldValue::Int(ERROR_NO_IDENTITY as i64));
        };
        let mut rd = ctx.data.as_slice();
        let Ok(FieldValue::Array(parts)) = FieldValue::unpack(&mut rd) else {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        };
        if !(2..=3).contains(&parts.len()) {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        }
        let destination_hash = delivery_name().address_hash_for(&remote_identity);
        let wants = field_hashes(parts.first());
        let haves = field_hashes(parts.get(1));
        if wants.is_err() || haves.is_err() {
            return pack_field(&FieldValue::Int(ERROR_INVALID_DATA as i64));
        }
        let wants = wants.unwrap();
        let haves = haves.unwrap();

        if parts[0] == FieldValue::Nil && parts[1] == FieldValue::Nil {
            let mut entries: Vec<(Hash, usize)> = self
                .state
                .lock()
                .await
                .propagation_entries
                .iter()
                .filter(|(_, entry)| entry.destination_hash == destination_hash)
                .map(|(id, entry)| (*id, entry.size))
                .collect();
            entries.sort_by_key(|(_, size)| *size);
            return pack_field(&hashes_field(
                &entries.into_iter().map(|(id, _)| id).collect::<Vec<_>>(),
            ));
        }

        if !haves.is_empty() {
            let paths = {
                let mut state = self.state.lock().await;
                let ids: Vec<Hash> = haves
                    .iter()
                    .copied()
                    .filter(|id| {
                        state
                            .propagation_entries
                            .get(id)
                            .is_some_and(|e| e.destination_hash == destination_hash)
                    })
                    .collect();
                ids.into_iter()
                    .filter_map(|id| state.propagation_entries.remove(&id).map(|e| e.file_path))
                    .collect::<Vec<_>>()
            };
            for path in paths {
                let _ = std::fs::remove_file(path);
            }
        }
        if wants.is_empty() {
            return pack_field(&FieldValue::Bool(true));
        }

        let client_limit = parts
            .get(2)
            .and_then(FieldValue::as_int)
            .unwrap_or(self.config.delivery_per_transfer_limit)
            .max(0) as usize
            * 1000;
        let server_limit = self.config.propagation_transfer_limit.max(0) as usize * 1000;
        let limit = client_limit.min(server_limit);
        let entries = self.state.lock().await.propagation_entries.clone();
        let mut total = 24usize;
        let mut messages = Vec::new();
        for id in wants {
            let Some(entry) = entries
                .get(&id)
                .filter(|e| e.destination_hash == destination_hash)
            else {
                continue;
            };
            let Ok(mut data) = std::fs::read(&entry.file_path) else {
                continue;
            };
            if data.len() >= stamper::STAMP_SIZE {
                data.truncate(data.len() - stamper::STAMP_SIZE);
            }
            let packed_size = data.len() + 16;
            if packed_size > server_limit || total + packed_size > limit {
                continue;
            }
            total += packed_size;
            messages.push(FieldValue::Bin(data));
        }
        pack_field(&FieldValue::Array(messages))
    }

    /// Access the underlying transport (for interface setup, path requests
    /// and announces).
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Subscribe to router events.
    pub fn subscribe(&self) -> broadcast::Receiver<LxmEvent> {
        self.events.subscribe()
    }

    /// The router identity.
    pub fn identity(&self) -> &PrivateIdentity {
        &self.identity
    }

    /// The propagation destination hash of this router.
    pub fn propagation_destination_hash(&self) -> AddressHash {
        self.propagation_destination_hash
    }

    /// The propagation destination (for announces).
    pub fn propagation_destination(&self) -> &Arc<Mutex<SingleInputDestination>> {
        &self.propagation_destination
    }

    /// The delivery destination hash, if a delivery identity was registered.
    pub async fn delivery_destination_hash(&self) -> Option<AddressHash> {
        self.delivery.lock().await.as_ref().map(|d| d.address_hash)
    }

    /// The delivery destination (for announces), if registered.
    pub async fn delivery_destination(&self) -> Option<Arc<Mutex<SingleInputDestination>>> {
        self.delivery
            .lock()
            .await
            .as_ref()
            .map(|d| d.destination.clone())
    }

    /// The configured inbound stamp cost of the delivery destination.
    pub async fn inbound_stamp_cost(&self) -> Option<u8> {
        self.delivery
            .lock()
            .await
            .as_ref()
            .and_then(|d| d.stamp_cost)
    }

    /// Set the inbound stamp cost of the delivery destination
    /// (`LXMRouter.set_inbound_stamp_cost`).
    pub async fn set_inbound_stamp_cost(&self, stamp_cost: Option<u8>) {
        let mut delivery = self.delivery.lock().await;
        if let Some(delivery) = delivery.as_mut() {
            delivery.stamp_cost = stamp_cost.filter(|cost| (1..255).contains(cost));
        }
    }

    /// Announce the delivery destination
    /// (`LXMRouter.announce` for the delivery destination).
    pub async fn announce_delivery(&self) {
        let delivery = self.delivery.lock().await;
        let Some(delivery) = delivery.as_ref() else {
            return;
        };

        let app_data = pack_announce_app_data(
            delivery.display_name.as_deref(),
            delivery.stamp_cost,
            delivery_supported_functionality(),
        );

        self.transport
            .send_announce(&delivery.destination, Some(&app_data))
            .await;
    }

    /// Announce the propagation destination
    /// (`LXMRouter.announce_propagation_node`).
    pub async fn announce_propagation_node(&self) {
        let app_data = self.get_propagation_node_app_data();
        self.transport
            .send_announce(&self.propagation_destination, Some(&app_data))
            .await;
    }

    /// Pack the propagation node announce data
    /// (`LXMRouter.get_propagation_node_app_data`).
    pub fn get_propagation_node_app_data(&self) -> Vec<u8> {
        let mut metadata = Fields::new();
        if let Some(name) = &self.name {
            metadata.insert(
                crate::fields::PN_META_NAME,
                FieldValue::Bin(name.as_bytes().to_vec()),
            );
        }

        pack_propagation_node_app_data(
            false, // Legacy LXMF PN support
            crate::message::now_as_f64() as i64,
            self.config.propagation_node,
            self.config.propagation_transfer_limit,
            self.config.propagation_sync_limit,
            (
                self.config.propagation_stamp_cost,
                self.config.propagation_stamp_cost_flexibility,
                self.config.peering_cost,
            ),
            &FieldValue::Map(
                metadata
                    .iter()
                    .map(|(k, v)| (FieldValue::Int(*k as i64), v.clone()))
                    .collect(),
            ),
        )
    }

    /// Set the outbound stamp cost learned from an announce
    /// (`LXMRouter.update_stamp_cost`).
    pub async fn update_stamp_cost(&self, destination_hash: &AddressHash, stamp_cost: Option<u8>) {
        if let Some(stamp_cost) = stamp_cost {
            log::debug!("Updating outbound stamp cost for {destination_hash} to {stamp_cost}");
            let mut state = self.state.lock().await;
            state.outbound_stamp_costs.insert(
                *destination_hash,
                (crate::message::now_as_f64(), stamp_cost),
            );
            save_stamp_costs(&self.storage_path, &state.outbound_stamp_costs);
        }
    }

    /// Get the last known outbound stamp cost for a destination
    /// (`LXMRouter.get_outbound_stamp_cost`).
    pub async fn get_outbound_stamp_cost(&self, destination_hash: &AddressHash) -> Option<u8> {
        self.state
            .lock()
            .await
            .outbound_stamp_costs
            .get(destination_hash)
            .map(|(_, cost)| *cost)
    }

    /// Set the active outbound propagation node
    /// (`LXMRouter.set_active_propagation_node`).
    pub async fn set_active_propagation_node(&self, destination_hash: AddressHash) {
        self.state.lock().await.outbound_propagation_node = Some(destination_hash);
    }

    /// Get the configured outbound propagation node.
    pub async fn get_outbound_propagation_node(&self) -> Option<AddressHash> {
        self.state.lock().await.outbound_propagation_node
    }

    /// Current client propagation download state.
    pub async fn propagation_transfer_state(&self) -> PropagationTransferState {
        self.propagation_transfer.lock().await.clone()
    }

    /// Request available messages from the configured outbound propagation node.
    /// The operation runs in the background and reports progress through
    /// [`LxmEvent::PropagationTransfer`].
    pub async fn request_messages_from_propagation_node(
        self: &Arc<Self>,
        max_messages: Option<u32>,
    ) {
        self.cancel_propagation_node_requests().await;
        let router = Arc::clone(self);
        let handle = tokio::spawn(async move {
            router.run_propagation_download(max_messages).await;
        });
        *self.propagation_download.lock().await = Some(handle);
    }

    /// Cancel an active propagation-node download and reset it to idle.
    pub async fn cancel_propagation_node_requests(&self) {
        if let Some(handle) = self.propagation_download.lock().await.take() {
            handle.abort();
        }
        self.set_propagation_transfer(PropagationTransferState::default())
            .await;
    }

    async fn set_propagation_transfer(&self, value: PropagationTransferState) {
        *self.propagation_transfer.lock().await = value.clone();
        self.emit(LxmEvent::PropagationTransfer(value));
    }

    async fn run_propagation_download(self: Arc<Self>, max_messages: Option<u32>) {
        let Some(node) = self.get_outbound_propagation_node().await else {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_FAILED,
                ..Default::default()
            })
            .await;
            return;
        };
        if !self.transport.has_path(&node).await {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_PATH_REQUESTED,
                ..Default::default()
            })
            .await;
            self.transport.request_path(&node, None, None).await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs_f64(PR_PATH_TIMEOUT);
            while !self.transport.has_path(&node).await && tokio::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if !self.transport.has_path(&node).await {
                self.set_propagation_transfer(PropagationTransferState {
                    state: PR_NO_PATH,
                    ..Default::default()
                })
                .await;
                return;
            }
        }
        let Some(identity) = self.transport.recall(&node).await else {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_NO_IDENTITY_RCVD,
                ..Default::default()
            })
            .await;
            return;
        };
        self.set_propagation_transfer(PropagationTransferState {
            state: PR_LINK_ESTABLISHING,
            ..Default::default()
        })
        .await;
        let link = self
            .transport
            .link(DestinationDesc {
                identity,
                address_hash: node,
                name: propagation_name(),
            })
            .await;
        let link_id = *link.lock().await.id();
        let mut link_events = self.transport.out_link_events();
        let active = if link.lock().await.status() == LinkStatus::Active {
            true
        } else {
            timeout(self.config.link_timeout, async {
                loop {
                    match link_events.recv().await {
                        Ok(event) if event.id == link_id => match event.event {
                            LinkEvent::Activated => return true,
                            LinkEvent::Closed => return false,
                            _ => continue,
                        },
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => return false,
                    }
                }
            })
            .await
            .unwrap_or(false)
        };
        if !active {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_LINK_FAILED,
                ..Default::default()
            })
            .await;
            return;
        }
        if let Ok(packet) = link.lock().await.identify(&self.identity) {
            self.transport.send_packet(packet).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.set_propagation_transfer(PropagationTransferState {
            state: PR_LINK_ESTABLISHED,
            ..Default::default()
        })
        .await;

        let list_request = pack_field(&FieldValue::Array(vec![FieldValue::Nil, FieldValue::Nil]));
        let Ok(rid) = self
            .transport
            .request(&link, MESSAGE_GET_PATH, &list_request)
            .await
        else {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_TRANSFER_FAILED,
                ..Default::default()
            })
            .await;
            return;
        };
        self.set_propagation_transfer(PropagationTransferState {
            state: PR_REQUEST_SENT,
            ..Default::default()
        })
        .await;
        let Some(response) = self
            .transport
            .await_request_response(rid, self.config.delivery_timeout)
            .await
        else {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_TRANSFER_FAILED,
                ..Default::default()
            })
            .await;
            return;
        };
        let Ok(available) = unpack_hash_list(&response) else {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_FAILED,
                ..Default::default()
            })
            .await;
            return;
        };
        let mut wants = Vec::new();
        let mut haves = Vec::new();
        for id in available {
            if self.has_message(&id).await {
                haves.push(id);
            } else {
                wants.push(id);
            }
        }
        if let Some(max) = max_messages {
            wants.truncate(max as usize);
        }
        if self.config.retain_synced_on_node {
            haves.clear();
        }
        if wants.is_empty() {
            if !haves.is_empty() {
                let _ = self.send_get_ack(&link, &haves).await;
            }
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_COMPLETE,
                progress: 1.0,
                last_result: Some(0),
                ..Default::default()
            })
            .await;
            return;
        }
        let fetch = FieldValue::Array(vec![
            hashes_field(&wants),
            hashes_field(&haves),
            FieldValue::Int(self.config.delivery_per_transfer_limit),
        ]);
        let Ok(rid) = self
            .transport
            .request(&link, MESSAGE_GET_PATH, &pack_field(&fetch))
            .await
        else {
            return;
        };
        self.set_propagation_transfer(PropagationTransferState {
            state: PR_RECEIVING,
            ..Default::default()
        })
        .await;
        let Some(response) = self
            .transport
            .await_request_response(rid, self.config.delivery_timeout)
            .await
        else {
            self.set_propagation_transfer(PropagationTransferState {
                state: PR_TRANSFER_FAILED,
                ..Default::default()
            })
            .await;
            return;
        };
        let size = response.len();
        let Ok(messages) = unpack_bin_list(&response) else {
            return;
        };
        let mut accepted = 0;
        let mut duplicates = 0;
        let mut received_ids = Vec::new();
        for message in messages {
            let id = full_hash(&message);
            if self.has_message(&id).await {
                duplicates += 1;
            } else if self
                .lxmf_propagation(&message, true, false, None, None, None)
                .await
                .unwrap_or(false)
            {
                accepted += 1;
            }
            received_ids.push(id);
        }
        received_ids.extend(haves);
        let _ = self.send_get_ack(&link, &received_ids).await;
        self.set_propagation_transfer(PropagationTransferState {
            state: PR_COMPLETE,
            progress: 1.0,
            size,
            last_result: Some(accepted),
            last_duplicates: duplicates,
        })
        .await;
    }

    async fn send_get_ack(
        &self,
        link: &Arc<Mutex<reticulum::destination::link::Link>>,
        haves: &[Hash],
    ) -> Result<(), ()> {
        let data = pack_field(&FieldValue::Array(vec![
            FieldValue::Nil,
            hashes_field(haves),
        ]));
        self.transport
            .request(link, MESSAGE_GET_PATH, &data)
            .await
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Whether we already have a given message (by message hash).
    pub async fn has_message(&self, hash: &Hash) -> bool {
        self.state.lock().await.locally_delivered.contains_key(hash)
    }

    /// Add a destination to the ignore list (`LXMRouter.ignore_destination`).
    pub async fn ignore_destination(&self, destination_hash: AddressHash) {
        self.state.lock().await.ignored_list.push(destination_hash);
    }

    /// Remove a destination from the ignore list.
    pub async fn unignore_destination(&self, destination_hash: AddressHash) {
        self.state
            .lock()
            .await
            .ignored_list
            .retain(|hash| hash != &destination_hash);
    }

    ////////////////////////////////////////////////////////////
    // Tickets                                                //
    ////////////////////////////////////////////////////////////

    /// Generate an inbound ticket for a destination
    /// (`LXMRouter.generate_ticket`). Returns `(expires, ticket)`.
    pub async fn generate_ticket(
        &self,
        destination_hash: &AddressHash,
    ) -> Option<(f64, [u8; TICKET_LENGTH])> {
        let now = crate::message::now_as_f64();

        let mut state = self.state.lock().await;

        if let Some(last_delivery) = state.tickets.last_deliveries.get(destination_hash) {
            if now - last_delivery < TICKET_INTERVAL {
                log::debug!(
                    "A ticket for {destination_hash} was already delivered recently, not including another ticket yet"
                );
                return None;
            }
        }

        let existing = state
            .tickets
            .inbound
            .get(destination_hash)
            .cloned()
            .unwrap_or_default();
        for (expires, ticket) in existing {
            if expires - now > TICKET_RENEW {
                log::debug!(
                    "Found generated ticket for {destination_hash} with enough validity left, re-using this one"
                );
                return Some((expires, ticket));
            }
        }

        log::debug!("No generated tickets for {destination_hash} with enough validity found, generating a new one");
        let expires = now + TICKET_EXPIRY;
        let mut ticket = [0u8; TICKET_LENGTH];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut ticket);

        state
            .tickets
            .inbound
            .entry(*destination_hash)
            .or_default()
            .push((expires, ticket));
        save_tickets(&self.storage_path, &state.tickets);

        Some((expires, ticket))
    }

    /// Remember a ticket received from a remote peer
    /// (`LXMRouter.remember_ticket`).
    pub async fn remember_ticket(
        &self,
        destination_hash: &AddressHash,
        expires: f64,
        ticket: [u8; TICKET_LENGTH],
    ) {
        let mut state = self.state.lock().await;
        state
            .tickets
            .outbound
            .insert(*destination_hash, (expires, ticket));
        save_tickets(&self.storage_path, &state.tickets);
    }

    /// Record that a ticket was delivered to a destination
    /// (`LXMRouter.available_tickets["last_deliveries"]` update).
    pub async fn record_ticket_delivery(&self, destination_hash: &AddressHash) {
        let mut state = self.state.lock().await;
        state
            .tickets
            .last_deliveries
            .insert(*destination_hash, crate::message::now_as_f64());
        save_tickets(&self.storage_path, &state.tickets);
    }

    /// Get a valid outbound ticket for a destination
    /// (`LXMRouter.get_outbound_ticket`).
    pub async fn get_outbound_ticket(
        &self,
        destination_hash: &AddressHash,
    ) -> Option<[u8; TICKET_LENGTH]> {
        let state = self.state.lock().await;
        let (expires, ticket) = state.tickets.outbound.get(destination_hash)?;
        if *expires > crate::message::now_as_f64() {
            Some(*ticket)
        } else {
            None
        }
    }

    /// Get all valid inbound tickets issued to a destination
    /// (`LXMRouter.get_inbound_tickets`).
    pub async fn get_inbound_tickets(
        &self,
        destination_hash: &AddressHash,
    ) -> Vec<[u8; TICKET_LENGTH]> {
        let now = crate::message::now_as_f64();
        let state = self.state.lock().await;
        state
            .tickets
            .inbound
            .get(destination_hash)
            .map(|tickets| {
                tickets
                    .iter()
                    .filter(|(expires, _)| now < *expires)
                    .map(|(_, ticket)| *ticket)
                    .collect()
            })
            .unwrap_or_default()
    }

    ////////////////////////////////////////////////////////////
    // Outbound                                               //
    ////////////////////////////////////////////////////////////

    /// Queue an outbound message and attempt delivery
    /// (`LXMRouter.handle_outbound` followed by a `process_outbound` pass).
    ///
    /// The message is packed with `source` (the private identity of the
    /// local delivery destination) and delivered according to its method:
    ///
    /// * `OPPORTUNISTIC`: encrypted single packet to the delivery
    ///   destination. Packet delivery proofs are not yet surfaced by the
    ///   transport, so no [`LxmEvent::DeliveryReceipt`] is emitted.
    /// * `DIRECT`: the packed message is sent as a link data packet; the
    ///   recipient's proof is surfaced as [`LxmEvent::DeliveryReceipt`].
    /// * `PROPAGATED`: the propagation container is sent to the configured
    ///   outbound propagation node over a link.
    ///
    /// If the destination identity is not yet known, a path request is
    /// issued, the message is queued, and delivery is retried when an
    /// announce for the destination arrives.
    pub async fn send(
        self: &Arc<Self>,
        message: &mut LXMessage,
        source: &PrivateIdentity,
    ) -> Result<(), LxmfError> {
        let destination_hash = message.destination_hash;

        if message.desired_method == Some(PROPAGATED)
            && self.state.lock().await.outbound_propagation_node.is_none()
        {
            let message_hash = message.hash;
            message.state = FAILED;
            if let Some(hash) = message_hash {
                self.emit(LxmEvent::SendFailed {
                    message_hash: hash,
                    reason: SendFailure::NoPropagationNode,
                });
            }
            return Err(LxmfError::UnsupportedMethod);
        }

        // Autoconfigure the stamp cost from the latest announce
        if message.stamp_cost.is_none() {
            let stamp_cost = self.get_outbound_stamp_cost(&destination_hash).await;
            if let Some(stamp_cost) = stamp_cost {
                log::debug!(
                    "No stamp cost set on LXM to {destination_hash}, autoconfigured to {stamp_cost}, as required by latest announce"
                );
                message.stamp_cost = Some(stamp_cost);
            }
        }

        message.state = OUTBOUND;

        // If an outbound ticket is available for this
        // destination, attach it to the message.
        let outbound_ticket = self.get_outbound_ticket(&destination_hash).await;
        if let Some(ticket) = outbound_ticket {
            log::debug!("Applied outbound ticket for {destination_hash}");
            message.outbound_ticket = Some(ticket);
            if message.defer_stamp {
                message.defer_stamp = false;
            }
        }

        // If requested, include a ticket to allow the
        // destination to reply without generating a stamp.
        if message.include_ticket {
            if let Some((expires, ticket)) = self.generate_ticket(&destination_hash).await {
                message.fields.insert(
                    FIELD_TICKET,
                    FieldValue::Array(vec![
                        FieldValue::F64(expires),
                        FieldValue::Bin(ticket.to_vec()),
                    ]),
                );
            }
        }

        if message.packed.is_none() {
            match message.desired_method {
                Some(PROPAGATED) => {
                    message.pack_propagation(source, OsRng)?;
                }
                _ => message.pack(source)?,
            }
        }

        message.determine_transport_encryption();

        // Record ticket delivery statistics once the message goes out
        if message.include_ticket && message.fields.contains_key(FIELD_TICKET) {
            self.record_ticket_delivery(&destination_hash).await;
        }

        let entry = OutboundEntry {
            destination_hash,
            message: Arc::new(Mutex::new(message.clone())),
            source: source.clone(),
        };

        self.process_outbound(entry).await;

        Ok(())
    }

    /// Deliver a large message as a resource transfer over an established
    /// link (Python `LXMessage.__as_resource`).
    async fn deliver_as_resource(
        self: &Arc<Self>,
        destination_hash: &AddressHash,
        message: &Arc<Mutex<LXMessage>>,
        source: &PrivateIdentity,
    ) -> Result<(), SendFailure> {
        let _ = source;

        let identity = {
            let state = self.state.lock().await;
            state.known_identities.get(destination_hash).copied()
        };
        let Some(identity) = identity else {
            // No path yet: request and queue like the packet path.
            self.transport
                .request_path(destination_hash, None, None)
                .await;
            let mut state = self.state.lock().await;
            state.pending_outbound.push(OutboundEntry {
                destination_hash: *destination_hash,
                message: message.clone(),
                source: source.clone(),
            });
            return Ok(());
        };

        let packed = {
            let m = message.lock().await;
            m.packed.clone()
        };
        let Some(packed) = packed else {
            return Err(SendFailure::Invalid("message not packed".into()));
        };

        {
            let mut m = message.lock().await;
            m.state = SENDING;
            m.progress = 0.5;
        }

        let desc = DestinationDesc {
            identity,
            address_hash: *destination_hash,
            name: delivery_name(),
        };

        let router = self.clone();
        let payload = packed;
        let destination = *destination_hash;
        let message = Arc::clone(message);
        tokio::spawn(async move {
            router
                .deliver_resource_over_link(desc, destination, message, payload)
                .await;
        });

        Ok(())
    }

    /// Establish the link and transfer the packed message as a resource.
    async fn deliver_resource_over_link(
        self: &Arc<Self>,
        desc: DestinationDesc,
        destination_hash: AddressHash,
        message: Arc<Mutex<LXMessage>>,
        payload: Vec<u8>,
    ) {
        let mut events = self.transport.out_link_events();

        let link = self.transport.link(desc).await;
        let link_id = *link.lock().await.id();

        let mut active = link.lock().await.status() == LinkStatus::Active;
        if !active {
            let activated = timeout(self.config.link_timeout, async {
                loop {
                    match events.recv().await {
                        Ok(LinkEventData { id, event, .. }) if id == link_id => match event {
                            LinkEvent::Activated => return true,
                            LinkEvent::Closed => return false,
                            _ => {}
                        },
                        Ok(_) => continue,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return false,
                    }
                }
            })
            .await
            .unwrap_or(false);
            active = activated;
        }

        if !active {
            log::debug!("LXMF resource delivery: link to {destination_hash} failed");
            self.fail(&message, SendFailure::LinkFailed).await;
            return;
        }

        let mut resource_events = self.transport.resource_events().await;

        let result = self.transport.send_resource(&link, payload).await;
        let resource_hash = match result {
            Ok(hash) => hash,
            Err(err) => {
                log::debug!("LXMF resource delivery failed to start: {err:?}");
                self.fail(&message, SendFailure::ResourceFailed).await;
                return;
            }
        };

        let timeout_at = tokio::time::Instant::now()
            + std::time::Duration::from_secs(self.config.resource_timeout());

        loop {
            if tokio::time::Instant::now() > timeout_at {
                self.fail(&message, SendFailure::ResourceFailed).await;
                return;
            }
            match timeout(std::time::Duration::from_secs(1), resource_events.recv()).await {
                Ok(Ok(event)) => {
                    if event.hash.as_slice() == resource_hash.as_slice() {
                        match event.status {
                            ResourceStatus::Complete => {
                                let mut m = message.lock().await;
                                m.state = SENT;
                                m.progress = 1.0;
                                log::debug!("LXMF resource delivery to {destination_hash} sent");
                                return;
                            }
                            ResourceStatus::Failed
                            | ResourceStatus::Corrupt
                            | ResourceStatus::Rejected => {
                                self.fail(&message, SendFailure::ResourceFailed).await;
                                return;
                            }
                            _ => continue,
                        }
                    }
                }
                _ => continue,
            }
        }
    }

    /// Attempt delivery of a single queued message
    /// (the per-message part of `LXMRouter.process_outbound`).
    async fn process_outbound(self: &Arc<Self>, entry: OutboundEntry) {
        let OutboundEntry {
            destination_hash,
            message,
            source,
        } = entry;

        let method = message.lock().await.method;
        let representation = message.lock().await.representation;

        // Messages larger than a single link packet are delivered as a
        // resource transfer over the link (Python `LXMessage.__as_resource`).
        if representation == RESOURCE && method == DIRECT {
            if let Err(err) = self
                .deliver_as_resource(&destination_hash, &message, &source)
                .await
            {
                log::debug!("resource delivery failed: {err:?}");
                self.fail(&message, SendFailure::ResourceUnsupported).await;
            }
            return;
        }
        if representation == RESOURCE {
            // Resource delivery to propagation nodes is not supported yet.
            self.fail(&message, SendFailure::ResourceUnsupported).await;
            return;
        }

        // Resolve the destination identity for encryption and link setup
        let link_destination_hash = if method == PROPAGATED {
            match self.get_outbound_propagation_node().await {
                Some(hash) => hash,
                None => {
                    self.fail(&message, SendFailure::NoPropagationNode).await;
                    return;
                }
            }
        } else {
            destination_hash
        };

        let destination_identity = {
            let state = self.state.lock().await;
            state.known_identities.get(&link_destination_hash).copied()
        };

        let Some(identity) = destination_identity else {
            // No identity known yet: request a path and queue the message
            // for retry on the next announce.
            log::debug!(
                "No path to {link_destination_hash} known, requesting path and deferring message"
            );
            self.transport
                .request_path(&link_destination_hash, None, None)
                .await;
            {
                let mut state = self.state.lock().await;
                state.pending_outbound.push(OutboundEntry {
                    destination_hash: link_destination_hash,
                    message,
                    source,
                });
            }
            return;
        };

        match method {
            OPPORTUNISTIC => {
                let (packed, message_hash) = {
                    let mut message = message.lock().await;
                    message.destination_identity = Some(identity);
                    (message.packed.clone(), message.hash)
                };
                let Some(packed) = packed else {
                    self.fail(&message, SendFailure::Invalid("message not packed".into()))
                        .await;
                    return;
                };

                // Python: RNS.Packet(destination, self.packed[DESTINATION_LENGTH:])
                let token =
                    match encrypt_for_identity(OsRng, &identity, &packed[DESTINATION_LENGTH..]) {
                        Ok(token) => token,
                        Err(e) => {
                            self.fail(&message, SendFailure::Invalid(e.to_string()))
                                .await;
                            return;
                        }
                    };

                let packet = Packet {
                    header: Header {
                        ifac_flag: IfacFlag::Open,
                        header_type: HeaderType::Type1,
                        propagation_type: PropagationType::Broadcast,
                        destination_type: DestinationType::Single,
                        packet_type: PacketType::Data,
                        hops: 0,
                        context_flag: false,
                    },
                    ifac: None,
                    destination: destination_hash,
                    transport: None,
                    context: PacketContext::None,
                    data: {
                        let mut buffer = PacketDataBuffer::new();
                        if buffer.write(&token).is_err() {
                            self.fail(&message, SendFailure::Invalid("packet too large".into()))
                                .await;
                            return;
                        }
                        buffer
                    },
                };

                self.transport.send_packet(packet).await;

                let mut message = message.lock().await;
                message.state = SENT;
                message.progress = 0.5;
                log::debug!("Sent opportunistic LXMF message {message_hash:?}");
            }
            DIRECT | PROPAGATED => {
                let name = if method == PROPAGATED {
                    propagation_name()
                } else {
                    delivery_name()
                };

                let desc = DestinationDesc {
                    identity,
                    address_hash: link_destination_hash,
                    name,
                };

                let payload = {
                    let message = message.lock().await;
                    if method == PROPAGATED {
                        message.propagation_packed.clone()
                    } else {
                        message.packed.clone()
                    }
                };

                let Some(payload) = payload else {
                    self.fail(&message, SendFailure::Invalid("message not packed".into()))
                        .await;
                    return;
                };

                {
                    let mut message = message.lock().await;
                    message.state = SENDING;
                    message.progress = 0.5;
                }

                let router = self.clone();
                tokio::spawn(async move {
                    router
                        .deliver_over_link(desc, link_destination_hash, message, payload)
                        .await;
                });
            }
            _ => {
                self.fail(&message, SendFailure::Invalid("unsupported method".into()))
                    .await;
            }
        }
    }

    /// Deliver `payload` to `destination` over a link, waiting for the
    /// recipient's proof and emitting the corresponding events.
    async fn deliver_over_link(
        self: &Arc<Self>,
        desc: DestinationDesc,
        destination_hash: AddressHash,
        message: Arc<Mutex<LXMessage>>,
        payload: Vec<u8>,
    ) {
        let mut events = self.transport.out_link_events();

        let link = self.transport.link(desc).await;
        let link_id = *link.lock().await.id();

        // Wait for the link to become active
        let mut active = link.lock().await.status() == LinkStatus::Active;
        if !active {
            let activated = timeout(self.config.link_timeout, async {
                loop {
                    match events.recv().await {
                        Ok(LinkEventData { id, event, .. }) if id == link_id => match event {
                            LinkEvent::Activated => return true,
                            LinkEvent::Closed => return false,
                            _ => {}
                        },
                        Ok(_) => continue,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => return false,
                    }
                }
            })
            .await;

            active = matches!(activated, Ok(true));
            if !active {
                log::warn!("Link to {destination_hash} did not activate in time");
                {
                    let mut message = message.lock().await;
                    message.state = OUTBOUND;
                }
                self.fail(&message, SendFailure::LinkFailed).await;
                return;
            }
        }

        let packet = {
            let link = link.lock().await;
            match link.data_packet(&payload) {
                Ok(packet) => packet,
                Err(e) => {
                    log::error!("Could not create link data packet: {e:?}");
                    self.fail(&message, SendFailure::LinkFailed).await;
                    return;
                }
            }
        };

        let packet_hash = packet.hash();
        self.transport.send_packet(packet).await;
        log::debug!("Sent LXMF link data packet {packet_hash} to {destination_hash}");

        // Wait for the recipient's proof of the packet
        let proved = timeout(self.config.delivery_timeout, async {
            loop {
                match events.recv().await {
                    Ok(LinkEventData {
                        id,
                        event: LinkEvent::Proof(hash),
                        ..
                    }) if id == link_id && hash == packet_hash => return true,
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return false,
                }
            }
        })
        .await;

        let message_hash = message.lock().await.hash;
        match proved {
            Ok(true) => {
                log::debug!("Delivery receipt received for {message_hash:?}");
                {
                    let mut message = message.lock().await;
                    message.state = DELIVERED;
                    message.progress = 1.0;
                }
                if let Some(hash) = message_hash {
                    self.emit(LxmEvent::DeliveryReceipt { message_hash: hash });
                }
            }
            _ => {
                log::warn!("No delivery receipt for {message_hash:?} before timeout");
                {
                    let mut message = message.lock().await;
                    message.state = OUTBOUND;
                }
                if let Some(hash) = message_hash {
                    self.emit(LxmEvent::SendFailed {
                        message_hash: hash,
                        reason: SendFailure::DeliveryTimeout,
                    });
                }
            }
        }
    }

    async fn fail(&self, message: &Arc<Mutex<LXMessage>>, reason: SendFailure) {
        let (message_hash, state) = {
            let mut message = message.lock().await;
            message.progress = 0.0;
            if message.state != crate::REJECTED {
                message.state = FAILED;
            }
            (message.hash, message.state)
        };
        log::debug!("LXMF message delivery failed ({reason:?}), state now {state}");
        if let Some(hash) = message_hash {
            self.emit(LxmEvent::SendFailed {
                message_hash: hash,
                reason,
            });
        }
    }

    fn emit(&self, event: LxmEvent) {
        let _ = self.events.send(event);
    }

    ////////////////////////////////////////////////////////////
    // Inbound                                                //
    ////////////////////////////////////////////////////////////

    /// Ingest locally destined LXMF data (`LXMRouter.lxmf_delivery`).
    ///
    /// Returns whether the message was delivered (as opposed to being
    /// deduplicated, ignored or dropped).
    ///
    /// Note that, exactly as in the Python reference implementation,
    /// messages with unverified signatures are still delivered; clients
    /// must check `signature_validated` / `unverified_reason`.
    pub async fn lxmf_delivery(
        &self,
        lxmf_data: &[u8],
        method: Option<u8>,
        ratchet_id: Option<AddressHash>,
        no_stamp_enforcement: bool,
        allow_duplicate: bool,
    ) -> Result<bool, LxmfError> {
        if self.delivery.lock().await.is_none() {
            // No local delivery destination for this message
            return Ok(false);
        }

        let known = {
            let state = self.state.lock().await;
            state.known_identities.clone()
        };

        let mut message =
            LXMessage::unpack_from_bytes_with(lxmf_data, &|hash| known.get(hash).copied())?;

        // A connected sender could address a valid LXMF message to a
        // third party; only messages addressed to this router's delivery
        // destination are emitted locally (everything else would be a
        // cross-destination injection).
        {
            let delivery = self.delivery.lock().await;
            if let Some(destination) = delivery.as_ref() {
                if message.destination_hash != destination.address_hash {
                    log::warn!(
                        "lxmf: ignoring message for foreign destination {}",
                        message.destination_hash
                    );
                    return Ok(false);
                }
            }
        }

        if let Some(ratchet_id) = ratchet_id {
            message.ratchet_id = Some(ratchet_id);
        }
        if let Some(method) = method {
            message.method = method;
        }

        // Transport encryption bookkeeping (LXMF delivery destinations are
        // SINGLE destinations or LINK-carried, both Curve25519 encrypted).
        message.transport_encrypted = true;
        message.transport_encryption = Some(crate::message::TransportEncryption::Curve25519);

        // Remember included tickets from verified sources
        if message.signature_validated {
            if let Some(FieldValue::Array(items)) = message.fields.get(FIELD_TICKET).cloned() {
                if items.len() > 1 {
                    if let (Some(expires), Some(FieldValue::Bin(ticket))) =
                        (items[0].as_f64(), items.get(1))
                    {
                        if crate::message::now_as_f64() < expires && ticket.len() == TICKET_LENGTH {
                            let mut entry = [0u8; TICKET_LENGTH];
                            entry.copy_from_slice(ticket);
                            self.remember_ticket(&message.source_hash, expires, entry)
                                .await;
                        }
                    }
                }
            }
        }

        // Stamp enforcement
        let required_stamp_cost = self.inbound_stamp_cost().await;
        if let Some(required_stamp_cost) = required_stamp_cost {
            let tickets = self.get_inbound_tickets(&message.source_hash).await;
            let valid = message.validate_stamp(Some(required_stamp_cost), Some(&tickets));
            message.stamp_valid = valid;
            message.stamp_checked = true;

            if !valid {
                if no_stamp_enforcement {
                    log::debug!(
                        "Received {message} with invalid stamp, but allowing anyway, since stamp enforcement was temporarily disabled"
                    );
                } else if self.config.enforce_stamps {
                    log::debug!("Dropping {message} with invalid stamp");
                    return Ok(false);
                } else {
                    log::debug!(
                        "Received {message} with invalid stamp, but allowing anyway, since stamp enforcement is disabled"
                    );
                }
            } else {
                log::debug!("Received {message} with valid stamp");
            }
        }

        // Ignore list
        {
            let state = self.state.lock().await;
            if state.ignored_list.contains(&message.source_hash) {
                log::debug!("Ignored message from {}", message.source_hash);
                return Ok(false);
            }
        }

        // Deduplication by message hash
        let message_hash = message.hash.ok_or(LxmfError::InvalidFormat)?;
        let now = crate::message::now_as_f64();
        {
            let mut state = self.state.lock().await;
            if !allow_duplicate && state.locally_delivered.contains_key(&message_hash) {
                log::debug!(
                    "Ignored already received message from {}",
                    message.source_hash
                );
                drop(state);
                self.emit(LxmEvent::Duplicate(message));
                return Ok(false);
            }
            state.locally_delivered.insert(message_hash, now);
            save_hash_time_map(
                &self.storage_path.join("local_deliveries"),
                &state.locally_delivered,
            );

            // Remove from pending outbound bookkeeping if present
            state
                .pending_outbound
                .retain(|entry| match entry.message.try_lock() {
                    Ok(message) => message.hash != Some(message_hash),
                    Err(_) => true,
                });
        }

        self.emit(LxmEvent::Received(message));
        Ok(true)
    }

    /// Ingest propagated (or paper) LXMF transport data
    /// (`LXMRouter.lxmf_propagation`).
    #[allow(clippy::too_many_arguments)]
    pub async fn lxmf_propagation(
        &self,
        lxmf_data: &[u8],
        is_paper_message: bool,
        allow_duplicate: bool,
        from_peer: Option<&AddressHash>,
        stamp_value: Option<u64>,
        stamp_data: Option<&[u8]>,
    ) -> Result<bool, LxmfError> {
        if lxmf_data.len() < LXMF_OVERHEAD {
            return Ok(false);
        }

        let transient_id = full_hash(lxmf_data);

        let now = crate::message::now_as_f64();
        let duplicate;
        {
            let mut state = self.state.lock().await;
            duplicate = state.propagation_entries.contains_key(&transient_id)
                || state.locally_processed.contains_key(&transient_id);
            if !duplicate || allow_duplicate {
                state.locally_processed.insert(transient_id, now);
                save_hash_time_map(
                    &self.storage_path.join("locally_processed"),
                    &state.locally_processed,
                );
            }
        }

        if duplicate && !allow_duplicate {
            return Ok(false);
        }

        let destination_hash = AddressHash::new(
            lxmf_data[..DESTINATION_LENGTH]
                .try_into()
                .map_err(|_| LxmfError::InvalidFormat)?,
        );

        let local_delivery = {
            let delivery = self.delivery.lock().await;
            delivery
                .as_ref()
                .filter(|delivery_dest| destination_hash == delivery_dest.address_hash)
                .map(|delivery_dest| delivery_dest.identity.clone())
        };

        if let Some(delivery_identity) = local_delivery {
            // Locally destined message: decrypt and deliver
            let encrypted = &lxmf_data[DESTINATION_LENGTH..];
            if let Ok(decrypted) = decrypt_for_identity(&delivery_identity, encrypted) {
                let mut delivery_data = Vec::with_capacity(DESTINATION_LENGTH + decrypted.len());
                delivery_data.extend_from_slice(&lxmf_data[..DESTINATION_LENGTH]);
                delivery_data.extend_from_slice(&decrypted);

                self.lxmf_delivery(
                    &delivery_data,
                    Some(PROPAGATED),
                    None,
                    is_paper_message,
                    allow_duplicate,
                )
                .await
                .ok();

                let mut state = self.state.lock().await;
                state.locally_delivered.insert(transient_id, now);
                return Ok(true);
            }
        }

        self.store_propagated(
            transient_id,
            destination_hash,
            lxmf_data,
            stamp_value,
            stamp_data,
            from_peer,
        )
        .await;

        Ok(true)
    }

    async fn store_propagated(
        &self,
        transient_id: Hash,
        destination_hash: AddressHash,
        lxmf_data: &[u8],
        stamp_value: Option<u64>,
        stamp_data: Option<&[u8]>,
        _from_peer: Option<&AddressHash>,
    ) {
        if !self.config.propagation_node {
            log::debug!(
                "Received propagated LXMF message {transient_id}, but this instance is not hosting a propagation node, discarding message."
            );
            return;
        }

        let received = crate::message::now_as_f64();
        let value_component = match stamp_value {
            Some(value) if value > 0 => format!("_{value}"),
            _ => String::new(),
        };
        let file_name = format!(
            "{}_{received}{value_component}",
            to_hex(transient_id.as_slice())
        );
        let file_path = self.message_path.join(file_name);

        let mut stamped_data = lxmf_data.to_vec();
        if let Some(stamp_data) = stamp_data {
            stamped_data.extend_from_slice(stamp_data);
        }

        if let Err(e) = std::fs::write(&file_path, &stamped_data) {
            log::error!("Could not write propagated message to store: {e}");
            return;
        }

        let size = stamped_data.len();
        let mut state = self.state.lock().await;
        state.propagation_entries.insert(
            transient_id,
            PropagationEntry {
                destination_hash,
                file_path,
                received,
                size,
                stamp_value: stamp_value.unwrap_or(0),
            },
        );
        for peer in state.peers.values_mut() {
            if !peer.handled_ids.contains(&transient_id)
                && !peer.unhandled_ids.contains(&transient_id)
            {
                peer.unhandled_ids.push(transient_id);
            }
        }

        self.emit(LxmEvent::PropagationStored {
            transient_id,
            stamp_value: stamp_value.unwrap_or(0),
        });
    }

    /// Ingest a paper message URI (`LXMRouter.ingest_lxm_uri`). The local
    /// delivery identity decrypts the message.
    pub async fn ingest_lxm_uri(
        self: &Arc<Self>,
        uri: &str,
        allow_duplicate: bool,
    ) -> Result<bool, LxmfError> {
        let prefix = format!("{URI_SCHEMA}://");
        if !uri.to_ascii_lowercase().starts_with(&prefix) {
            log::error!("Cannot ingest LXM, invalid URI provided.");
            return Ok(false);
        }

        let encoded = uri[prefix.len()..].replace('/', "");
        let lxmf_data = crate::message::base64_urlsafe_decode(&encoded)?;
        let transient_id = full_hash(&lxmf_data);

        let result = self
            .lxmf_propagation(&lxmf_data, true, allow_duplicate, None, None, None)
            .await;

        if matches!(result, Ok(true)) {
            log::debug!("LXM with transient ID {transient_id} was ingested.");
            Ok(true)
        } else {
            log::debug!("No valid LXM could be ingested from the provided URI");
            Ok(false)
        }
    }

    /// Handle an inbound propagation sync transfer
    /// (`LXMRouter.propagation_packet` data format):
    /// `msgpack([remote_timebase, [lxm_data || stamp, ...]])`.
    ///
    /// All stamps are validated against the locally configured minimum
    /// accepted cost, and validated messages are ingested through
    /// [`LxmRouter::lxmf_propagation`]. Returns the number of accepted
    /// messages.
    pub async fn handle_propagation_transfer(&self, data: &[u8]) -> Result<usize, LxmfError> {
        let mut rd: &[u8] = data;
        let unpacked = FieldValue::unpack(&mut rd)?;
        let FieldValue::Array(items) = unpacked else {
            return Err(LxmfError::InvalidFormat);
        };
        if items.len() < 2 {
            return Err(LxmfError::InvalidFormat);
        }

        let FieldValue::Array(messages) = &items[1] else {
            return Err(LxmfError::InvalidFormat);
        };

        let min_accepted_cost = 0.max(
            self.config.propagation_stamp_cost - self.config.propagation_stamp_cost_flexibility,
        ) as u32;

        let mut accepted = 0;
        for message in messages {
            let FieldValue::Bin(transient_data) = message else {
                continue;
            };
            if let Some(validated) = stamper::validate_pn_stamp(transient_data, min_accepted_cost) {
                self.lxmf_propagation(
                    &validated.lxm_data,
                    false,
                    false,
                    None,
                    Some(validated.value),
                    Some(&validated.stamp),
                )
                .await
                .ok();
                accepted += 1;
            }
        }

        Ok(accepted)
    }

    /// Peer with a propagation node announced in an app-data blob
    /// (`LXMRouter.peer`).
    #[allow(clippy::too_many_arguments)]
    pub async fn peer(
        &self,
        destination_hash: AddressHash,
        timestamp: i64,
        propagation_transfer_limit: i64,
        propagation_sync_limit: Option<i64>,
        propagation_stamp_cost: i64,
        propagation_stamp_cost_flexibility: i64,
        peering_cost: i64,
        metadata: Option<FieldValue>,
    ) {
        if peering_cost > self.config.max_peering_cost {
            log::debug!(
                "Not peering with {destination_hash}, since its peering cost of {peering_cost} exceeds local maximum of {}",
                self.config.max_peering_cost
            );
            return;
        }

        let mut state = self.state.lock().await;

        if let Some(peer) = state.peers.get_mut(&destination_hash) {
            if timestamp > peer.peering_timebase {
                peer.alive = true;
                peer.metadata = metadata;
                peer.peering_timebase = timestamp;
                peer.last_heard = crate::message::now_as_f64();
                peer.propagation_stamp_cost = Some(propagation_stamp_cost);
                peer.propagation_stamp_cost_flexibility = Some(propagation_stamp_cost_flexibility);
                peer.peering_cost = Some(peering_cost);
                peer.propagation_transfer_limit = Some(propagation_transfer_limit as f64);
                peer.propagation_sync_limit =
                    propagation_sync_limit.or(Some(propagation_transfer_limit));
                log::debug!("Peering config updated for {destination_hash}");
            }
        } else if state.peers.len() < self.config.max_peers {
            let mut peer = PeerData::new(destination_hash);
            peer.alive = true;
            peer.metadata = metadata;
            peer.last_heard = crate::message::now_as_f64();
            peer.propagation_stamp_cost = Some(propagation_stamp_cost);
            peer.propagation_stamp_cost_flexibility = Some(propagation_stamp_cost_flexibility);
            peer.peering_cost = Some(peering_cost);
            peer.propagation_transfer_limit = Some(propagation_transfer_limit as f64);
            peer.propagation_sync_limit =
                propagation_sync_limit.or(Some(propagation_transfer_limit));
            peer.unhandled_ids
                .extend(state.propagation_entries.keys().copied());
            state.peers.insert(destination_hash, peer);
            log::debug!("Peered with {destination_hash}");
        } else {
            log::debug!("Max peers reached, not peering with {destination_hash}");
        }
    }

    /// Break peering with a node (`LXMRouter.unpeer`).
    pub async fn unpeer(&self, destination_hash: &AddressHash, timestamp: Option<i64>) {
        let timestamp = timestamp.unwrap_or_else(|| crate::message::now_as_f64() as i64);
        let mut state = self.state.lock().await;
        if let Some(peer) = state.peers.get(destination_hash) {
            if timestamp >= peer.peering_timebase {
                state.peers.remove(destination_hash);
                log::debug!("Broke peering with {destination_hash}");
            }
        }
    }

    /// Snapshot of the current peer table.
    pub async fn peers(&self) -> HashMap<AddressHash, PeerData> {
        self.state.lock().await.peers.clone()
    }

    /// Snapshot of the propagation message store index.
    pub async fn propagation_entries(&self) -> HashMap<Hash, PropagationEntry> {
        self.state.lock().await.propagation_entries.clone()
    }

    /// Remove expired propagation messages and their peer queue references.
    pub async fn clean_message_store(&self) -> usize {
        let cutoff = crate::message::now_as_f64() - MESSAGE_EXPIRY;
        let (removed, paths) = {
            let mut state = self.state.lock().await;
            let ids: Vec<Hash> = state
                .propagation_entries
                .iter()
                .filter(|(_, entry)| entry.received < cutoff)
                .map(|(id, _)| *id)
                .collect();
            let paths = ids
                .iter()
                .filter_map(|id| state.propagation_entries.remove(id).map(|e| e.file_path))
                .collect::<Vec<_>>();
            for peer in state.peers.values_mut() {
                peer.handled_ids.retain(|id| !ids.contains(id));
                peer.unhandled_ids.retain(|id| !ids.contains(id));
            }
            (ids.len(), paths)
        };
        for path in paths {
            let _ = std::fs::remove_file(path);
        }
        removed
    }

    ////////////////////////////////////////////////////////////
    // Watchers                                               //
    ////////////////////////////////////////////////////////////

    async fn announce_watcher(self: Arc<Self>) {
        let mut announces = self.transport.recv_announces().await;

        loop {
            let Ok(event) = announces.recv().await else {
                return;
            };
            self.handle_announce(event).await;
        }
    }

    async fn handle_announce(self: &Arc<Self>, event: AnnounceEvent) {
        let AnnounceEvent {
            destination,
            app_data,
            ratchet: _,
        } = event;

        let (identity, address_hash, name_hash) = {
            let destination = destination.lock().await;
            (
                destination.desc.identity,
                destination.desc.address_hash,
                destination.desc.name.as_name_hash_slice().to_vec(),
            )
        };

        let app_data = app_data.as_slice();

        // Remember the announced identity for signature validation
        // (the RNS.Identity.recall equivalent).
        {
            let mut state = self.state.lock().await;
            state.known_identities.insert(address_hash, identity);
        }

        if name_hash.as_slice() == delivery_name().as_name_hash_slice() {
            // lxmf.delivery announce
            let stamp_cost = stamp_cost_from_app_data(Some(app_data));
            self.update_stamp_cost(&address_hash, stamp_cost).await;

            self.emit(LxmEvent::Announce(AnnounceInfo::Delivery {
                destination_hash: address_hash,
                identity,
                display_name: display_name_from_app_data(Some(app_data)),
                stamp_cost,
                compression_support: compression_support_from_app_data(Some(app_data)),
            }));

            // Trigger delivery of any pending outbound messages to this
            // destination (LXMFDeliveryAnnounceHandler behaviour).
            let pending = {
                let mut state = self.state.lock().await;
                let mut matched = Vec::new();
                let mut remaining = Vec::new();
                for entry in state.pending_outbound.drain(..) {
                    if entry.destination_hash == address_hash {
                        matched.push(entry);
                    } else {
                        remaining.push(entry);
                    }
                }
                state.pending_outbound = remaining;
                matched
            };

            for entry in pending {
                let router = self.clone();
                tokio::spawn(async move {
                    router.process_outbound(entry).await;
                });
            }
        } else if name_hash.as_slice() == propagation_name().as_name_hash_slice() {
            if let Some(info) = pn_announce_data_from_app_data(Some(app_data)) {
                if self.config.propagation_node {
                    self.peer(
                        address_hash,
                        info.timebase,
                        info.propagation_transfer_limit,
                        Some(info.propagation_sync_limit),
                        info.stamp_cost,
                        info.stamp_cost_flexibility,
                        info.peering_cost,
                        Some(info.metadata.clone()),
                    )
                    .await;
                }

                self.emit(LxmEvent::Announce(AnnounceInfo::PropagationNode {
                    destination_hash: address_hash,
                    identity,
                    info,
                }));
            }
        }
    }

    async fn received_data_watcher(self: Arc<Self>) {
        let mut received = self.transport.received_data_events();

        loop {
            let Ok(ReceivedData {
                destination,
                data,
                decrypted,
            }) = received.recv().await
            else {
                return;
            };

            let delivery_identity = {
                let delivery = self.delivery.lock().await;
                let Some(delivery_dest) = delivery.as_ref() else {
                    continue;
                };
                if destination != delivery_dest.address_hash {
                    continue;
                }
                delivery_dest.identity.clone()
            };

            // Opportunistic delivery: the transport already decrypts
            // SINGLE-destination packets (Python `Destination.receive`
            // parity) and delivers the plaintext without the destination
            // hash prefix. Fall back to decrypting the raw token ourselves
            // when the transport could not (e.g. another node's token relayed
            // through a transport node).
            let plaintext: Vec<u8> = if decrypted {
                // The transport already decrypted the SINGLE-destination
                // packet (Python `Destination.receive` parity).
                data.as_slice().to_vec()
            } else {
                match decrypt_for_identity(&delivery_identity, data.as_slice()) {
                    Ok(plaintext) => plaintext.to_vec(),
                    Err(e) => {
                        log::debug!("Could not decrypt opportunistic LXMF data: {e}");
                        continue;
                    }
                }
            };

            let mut lxmf_data = Vec::with_capacity(DESTINATION_LENGTH + plaintext.len());
            lxmf_data.extend_from_slice(destination.as_slice());
            lxmf_data.extend_from_slice(&plaintext);

            self.lxmf_delivery(&lxmf_data, Some(OPPORTUNISTIC), None, false, false)
                .await
                .ok();
        }
    }

    /// links and ingest them as LXMF messages.
    async fn resource_event_watcher(self: Arc<Self>) {
        let mut events = self.transport.resource_events().await;

        loop {
            let Ok(event) = events.recv().await else {
                return;
            };

            if event.status != ResourceStatus::Complete {
                continue;
            }

            if self
                .accepted_offer_links
                .lock()
                .await
                .remove(&event.link_id)
            {
                if let Some(data) = event.data {
                    let _ = self.handle_propagation_transfer(&data).await;
                }
                continue;
            }

            if !self.delivery_links.lock().await.contains(&event.link_id) {
                continue;
            }

            if let Some(data) = event.data {
                log::debug!(
                    "LXMF resource of {} bytes completed on link {}, ingesting",
                    data.len(),
                    event.link_id
                );
                self.lxmf_delivery(&data, Some(DIRECT), None, false, false)
                    .await
                    .ok();
            }
        }
    }

    async fn link_event_watcher(self: Arc<Self>) {
        let mut events = self.transport.in_link_events();

        loop {
            let Ok(event) = events.recv().await else {
                return;
            };

            match event.event {
                LinkEvent::Activated => {
                    let is_delivery_destination = {
                        let delivery = self.delivery.lock().await;
                        delivery
                            .as_ref()
                            .is_some_and(|dest| event.address_hash == dest.address_hash)
                    };
                    if !is_delivery_destination {
                        continue;
                    }
                    self.delivery_links.lock().await.insert(event.id);
                    // Make the responder side prove link data packets so
                    // that senders receive delivery receipts, and accept
                    // resource transfers (large messages arrive as
                    // resources, Python `LXMessage.__as_resource`).
                    self.transport
                        .set_resource_strategy(event.id, ResourceStrategy::All)
                        .await;
                    if let Some(link) = self.transport.find_in_link(&event.id).await {
                        link.lock().await.prove_messages(true);
                    }
                }
                LinkEvent::Data(payload) => {
                    // Direct delivery over an established link: the payload
                    // is the full packed LXMF message.
                    let is_delivery_destination = {
                        let delivery = self.delivery.lock().await;
                        delivery
                            .as_ref()
                            .is_some_and(|dest| event.address_hash == dest.address_hash)
                    };
                    if !is_delivery_destination {
                        continue;
                    }
                    self.lxmf_delivery(payload.as_slice(), Some(DIRECT), None, false, false)
                        .await
                        .ok();
                }
                LinkEvent::Closed => {
                    self.delivery_links.lock().await.remove(&event.id);
                }
                _ => {}
            }
        }
    }
}

fn pack_field(value: &FieldValue) -> Vec<u8> {
    let mut out = Vec::new();
    value.pack(&mut out);
    out
}

fn hashes_field(ids: &[Hash]) -> FieldValue {
    FieldValue::Array(
        ids.iter()
            .map(|id| FieldValue::Bin(id.as_slice().to_vec()))
            .collect(),
    )
}

fn field_hashes(value: Option<&FieldValue>) -> Result<Vec<Hash>, ()> {
    match value {
        Some(FieldValue::Nil) => Ok(Vec::new()),
        Some(FieldValue::Array(values)) => values
            .iter()
            .map(|value| match value {
                FieldValue::Bin(bytes) if bytes.len() == HASH_SIZE => {
                    let mut hash = [0u8; HASH_SIZE];
                    hash.copy_from_slice(bytes);
                    Ok(Hash::new(hash))
                }
                _ => Err(()),
            })
            .collect(),
        _ => Err(()),
    }
}

fn unpack_hash_list(data: &[u8]) -> Result<Vec<Hash>, ()> {
    let mut rd = data;
    let value = FieldValue::unpack(&mut rd).map_err(|_| ())?;
    field_hashes(Some(&value))
}

fn unpack_bin_list(data: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    let mut rd = data;
    match FieldValue::unpack(&mut rd).map_err(|_| ())? {
        FieldValue::Array(values) => values
            .into_iter()
            .map(|value| match value {
                FieldValue::Bin(bytes) => Ok(bytes),
                _ => Err(()),
            })
            .collect(),
        _ => Err(()),
    }
}

////////////////////////////////////////////////////////////////////////////
// Persistence helpers                                                    //
////////////////////////////////////////////////////////////////////////////

fn save_hash_time_map(path: &Path, map: &HashMap<Hash, f64>) {
    let entries: Vec<(FieldValue, FieldValue)> = map
        .iter()
        .map(|(hash, time)| {
            (
                FieldValue::Bin(hash.as_slice().to_vec()),
                FieldValue::F64(*time),
            )
        })
        .collect();

    let mut out = Vec::with_capacity(16 + 48 * entries.len());
    FieldValue::Map(entries).pack(&mut out);

    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &out).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn load_hash_time_map(path: &Path) -> HashMap<Hash, f64> {
    let mut result = HashMap::new();

    let Ok(data) = std::fs::read(path) else {
        return result;
    };

    let mut rd: &[u8] = &data;
    let Ok(FieldValue::Map(entries)) = FieldValue::unpack(&mut rd) else {
        return result;
    };

    for (key, value) in entries {
        if let (FieldValue::Bin(key), FieldValue::F64(time)) = (key, value) {
            if key.len() == HASH_SIZE {
                let mut hash = [0u8; HASH_SIZE];
                hash.copy_from_slice(&key);
                result.insert(Hash::new(hash), time);
            }
        }
    }

    result
}

fn save_stamp_costs(path: &Path, costs: &HashMap<AddressHash, (f64, u8)>) {
    let entries: Vec<(FieldValue, FieldValue)> = costs
        .iter()
        .map(|(hash, (time, cost))| {
            (
                FieldValue::Bin(hash.as_slice().to_vec()),
                FieldValue::Array(vec![FieldValue::F64(*time), FieldValue::Int(*cost as i64)]),
            )
        })
        .collect();

    let mut out = Vec::with_capacity(16 + 64 * entries.len());
    FieldValue::Map(entries).pack(&mut out);

    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &out).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn save_tickets(path: &Path, tickets: &Tickets) {
    let outbound = FieldValue::Map(
        tickets
            .outbound
            .iter()
            .map(|(hash, (expires, ticket))| {
                (
                    FieldValue::Bin(hash.as_slice().to_vec()),
                    FieldValue::Array(vec![
                        FieldValue::F64(*expires),
                        FieldValue::Bin(ticket.to_vec()),
                    ]),
                )
            })
            .collect(),
    );

    let inbound = FieldValue::Map(
        tickets
            .inbound
            .iter()
            .map(|(hash, entries)| {
                (
                    FieldValue::Bin(hash.as_slice().to_vec()),
                    FieldValue::Map(
                        entries
                            .iter()
                            .map(|(expires, ticket)| {
                                (
                                    FieldValue::Bin(ticket.to_vec()),
                                    FieldValue::Array(vec![FieldValue::F64(*expires)]),
                                )
                            })
                            .collect(),
                    ),
                )
            })
            .collect(),
    );

    let last_deliveries = FieldValue::Map(
        tickets
            .last_deliveries
            .iter()
            .map(|(hash, time)| {
                (
                    FieldValue::Bin(hash.as_slice().to_vec()),
                    FieldValue::F64(*time),
                )
            })
            .collect(),
    );

    let container = FieldValue::Map(vec![
        (FieldValue::Str("outbound".into()), outbound),
        (FieldValue::Str("inbound".into()), inbound),
        (FieldValue::Str("last_deliveries".into()), last_deliveries),
    ]);

    let mut out = Vec::new();
    container.pack(&mut out);

    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &out).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Functionality list advertised in the delivery announce; compression is
/// signalled only when this build can actually compress/decompress.
fn delivery_supported_functionality() -> &'static [u8] {
    if cfg!(feature = "bz2") {
        &[SF_COMPRESSION]
    } else {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_advertises_compression_exactly_when_available() {
        let app_data =
            pack_announce_app_data(Some("Test"), None, delivery_supported_functionality());
        assert_eq!(
            compression_support_from_app_data(Some(&app_data)),
            cfg!(feature = "bz2")
        );
    }
}
