use std::collections::HashMap;
use std::time::Duration;

use alloc::sync::Arc;
use rand_core::{OsRng, RngCore};
use tokio::sync::{broadcast, Mutex, MutexGuard};
use tokio::time;
use tokio_util::sync::CancellationToken;

#[cfg(not(test))]
use crate::channel::{self, Channel};
use crate::destination::link::{Link, LinkEventData, LinkEventSink, LinkExt, LinkExtHandlePacket,
    LinkHandleResult, LinkId, LinkPayload, LinkPayloadSink, LinkStatus, validate_proof_packet};
use crate::destination::{DestinationAnnounce, DestinationDesc, DestinationHandleStatus,
    DestinationName, GroupInputDestination, SingleInputDestination, SingleOutputDestination};
use crate::crypt::group::GroupKey;
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::identity::{GroupIdentity, PrivateIdentity};
use crate::iface::{InterfaceManager, InterfaceRxReceiver, RxMessage, TxMessage, TxMessageType};
use crate::packet::{DestinationType, Packet, PacketContext, PacketDataBuffer, PacketType,
    PACKET_MDU};

mod announce_limits;
mod announce_table;
mod link_table;
mod packet_cache;
mod path_requests;
mod path_table;

use self::announce_limits::AnnounceLimits;
pub use self::announce_limits::AnnounceRateLimit;
use self::announce_table::AnnounceTable;
use self::link_table::LinkTable;
use self::packet_cache::PacketCache;
use self::path_requests::{create_path_request_destination, PathRequests, TagBytes};
use self::path_table::PathTable;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops
const REPROVE_WINDOW: Duration = Duration::from_secs(60);
const REPROVE_GAP: Duration = Duration::from_secs(2);
const PATH_ASK_GAP: Duration = Duration::from_secs(10);
/// Most remote destinations kept (paths, announces); the least recently heard goes, unless
/// we have a link to it.
pub const MAX_DESTINATIONS: usize = 1024;
/// Most in-links at once; when full, the idlest is closed.
const MAX_IN_LINKS: usize = 1024;
/// Link event slots of the multi-hop profile; a Data event pins up to ~2 KB until all lag past it.
const MULTIHOP_LINK_EVENTS: usize = 2048;

// Other constants
const KEEP_ALIVE_REQUEST: u8 = 0xFF;
const KEEP_ALIVE_RESPONSE: u8 = 0xFE;

#[derive(Clone)]
pub struct ReceivedData {
    pub destination: AddressHash,
    pub data: PacketDataBuffer,
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
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            link_check: Duration::from_secs(1),
            in_link_stale: Duration::from_secs(10),
            in_link_close: Duration::from_secs(5),
            out_link_restart: Duration::from_secs(60),
            out_link_stale: Duration::from_secs(10),
            out_link_close: Duration::from_secs(5),
            out_link_repeat: Duration::from_secs(6),
            out_link_keep: Duration::from_secs(5),
            iface_cleanup: Duration::from_secs(10),
            announces_retransmit: Duration::from_secs(1),
            old_announces_retransmit: Duration::from_secs(60),
            keep_packet_cached: Duration::from_secs(180),
            packet_cache_cleanup: Duration::from_secs(90),
        }
    }
}

/// Sizes the transport's channels, see [`ChannelCapacity::for_network`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkProfile {
    /// Upstream capacities.
    #[default]
    Default,
    /// Small buffers for memory-constrained leaf nodes.
    Minimal,
    /// Large buffers for relays in a busy multi-hop mesh.
    MultiHop,
}

/// Capacities of the transport's channels, in messages (each at least 1). Broadcast channels
/// preallocate their capacity; a subscriber further behind loses the oldest (`Lagged`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelCapacity {
    pub announces: usize,
    /// In-link and out-link events; they carry all link data, so too small loses data.
    pub link_events: usize,
    pub received_data: usize,
    pub iface_messages: usize,
    pub iface_rx: usize,
    /// Per interface; 1 paces the transport by the interface instead of queueing stale packets.
    pub iface_tx: usize,
    pub link_payloads: usize,
}

impl ChannelCapacity {
    pub const fn for_network(profile: NetworkProfile) -> Self {
        match profile {
            NetworkProfile::Default => Self {
                announces: 16,
                link_events: 16,
                received_data: 16,
                iface_messages: 16,
                iface_rx: 16,
                iface_tx: 1,
                link_payloads: 16,
            },
            NetworkProfile::Minimal => Self {
                announces: 8,
                link_events: 32,
                received_data: 8,
                iface_messages: 4,
                iface_rx: 8,
                iface_tx: 1,
                link_payloads: 8,
            },
            NetworkProfile::MultiHop => Self {
                announces: 1024,
                link_events: MULTIHOP_LINK_EVENTS,
                received_data: 512,
                iface_messages: 64,
                iface_rx: 64,
                iface_tx: 1,
                link_payloads: 64,
            },
        }
    }
}

impl Default for ChannelCapacity {
    fn default() -> Self {
        Self::for_network(NetworkProfile::Default)
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

    /// Attempt to reopen stale links. Not compatible with Python nodes in the link
    /// path, which drop repeated link requests.
    restart_outlinks: bool,

    /// Resend announces of remote destinations at a slower pace once
    /// the initial round of announces is over.
    announce_forever: bool,

    /// Multi-hop GROUP messaging: relayed GROUP packets are accepted, and with
    /// `retransmit` GROUP packets are also relayed to other nodes. Not compatible
    /// with Python nodes, which drop relayed GROUP packets. Off by default.
    group_forwarding: bool,

    announce_rate_limit: Option<AnnounceRateLimit>,

    timer_config: TimerConfig,

    channel_capacity: ChannelCapacity,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    pub app_data: PacketDataBuffer,
    /// Hops the announce travelled to reach this node (0: a direct neighbour).
    pub hops: u8,
    /// The relaying node's transport identity, if relayed.
    pub transport_id: Option<AddressHash>,
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
pub (crate) struct BroadcastLinkPayloadSink(broadcast::Sender<LinkPayload>);

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
    /// Copies of announced destinations, so relays verify proofs without locking them.
    announced: HashMap<AddressHash, DestinationDesc>,
    group_in_destinations: HashMap<AddressHash, Arc<Mutex<GroupInputDestination>>>,
    /// Previous key of a rotated GROUP destination, accepted until the instant.
    group_previous_keys: HashMap<AddressHash, (GroupKey, time::Instant)>,
    /// In-links we proved: first and last proof time.
    proofs: HashMap<LinkId, (time::Instant, time::Instant)>,
    /// Last path request per unknown destination we were asked to relay a link to.
    path_asked: HashMap<AddressHash, time::Instant>,

    announce_limits: AnnounceLimits,

    out_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    /// Interface of each local link, which all its packets are sent on: the
    /// interface the link request was received on for in-links, and the one the
    /// proof was received on for out-links
    link_ifaces: HashMap<LinkId, AddressHash>,

    packet_cache: Mutex<PacketCache>,

    path_requests: PathRequests,

    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,

    fixed_dest_path_requests: AddressHash,

    cancel: CancellationToken,
}

pub struct Transport {
    name: String,
    link_in_event_tx: BroadcastLinkEventSink,
    link_out_event_tx: BroadcastLinkEventSink,
    received_data_tx: broadcast::Sender<ReceivedData>,
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
            group_forwarding: false,
            announce_rate_limit: None,
            timer_config: TimerConfig::default(),
            channel_capacity: ChannelCapacity::default(),
        }
    }

    pub fn set_retransmit(mut self, retransmit: bool) -> Self {
        self.retransmit = retransmit;
        self
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

    pub fn set_group_forwarding(mut self, group_forwarding: bool) -> Self {
        self.group_forwarding = group_forwarding;
        self
    }

    pub fn set_announce_rate_limit(mut self, rate_limit: Option<AnnounceRateLimit>) -> Self {
        self.announce_rate_limit = rate_limit;
        self
    }

    pub fn set_timer_config(mut self, timer_config: TimerConfig) -> Self {
        self.timer_config = timer_config;
        self
    }

    pub fn set_channel_capacity(mut self, channel_capacity: ChannelCapacity) -> Self {
        self.channel_capacity = channel_capacity;
        self
    }

    /// Same as `set_channel_capacity(ChannelCapacity::for_network(profile))`.
    pub fn set_network_profile(mut self, profile: NetworkProfile) -> Self {
        self.channel_capacity = ChannelCapacity::for_network(profile);
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
            group_forwarding: false,
            announce_rate_limit: None,
            timer_config: Default::default(),
            channel_capacity: Default::default(),
        }
    }
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        let capacity = config.channel_capacity;
        let (announce_tx, _) = tokio::sync::broadcast::channel(capacity.announces);
        let (link_in_event_tx, _) = tokio::sync::broadcast::channel(capacity.link_events);
        let (link_out_event_tx, _) = tokio::sync::broadcast::channel(capacity.link_events);
        let (received_data_tx, _) = tokio::sync::broadcast::channel(capacity.received_data);
        let (iface_messages_tx, _) = tokio::sync::broadcast::channel(capacity.iface_messages);

        let iface_manager = InterfaceManager::with_tx_capacity(capacity.iface_rx, capacity.iface_tx);

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let transport_id = if config.retransmit {
            Some(*config.identity.address_hash())
        } else {
            None
        };
        let path_requests = PathRequests::new(config.name.as_str(), transport_id);

        let path_request_dest = create_path_request_destination().desc.address_hash;

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let reroute_eager = config.reroute_eager;
        let announce_rate_limit = config.announce_rate_limit;
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            announce_table: AnnounceTable::new(MAX_DESTINATIONS),
            channel_table: HashMap::new(),
            link_table: LinkTable::new(),
            path_table: PathTable::new(reroute_eager),
            single_in_destinations: HashMap::new(),
            single_out_destinations: HashMap::new(),
            announced: HashMap::new(),
            group_in_destinations: HashMap::new(),
            group_previous_keys: HashMap::new(),
            proofs: HashMap::new(),
            path_asked: HashMap::new(),
            announce_limits: AnnounceLimits::new(announce_rate_limit),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            link_ifaces: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new()),
            path_requests,
            announce_tx,
            link_in_event_tx: link_in_event_tx.clone().into(),
            link_out_event_tx: link_out_event_tx.clone().into(),
            received_data_tx: received_data_tx.clone(),
            fixed_dest_path_requests: path_request_dest,
            cancel: cancel.clone(),
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
            iface_manager,
            link_in_event_tx: link_in_event_tx.into(),
            link_out_event_tx: link_out_event_tx.into(),
            received_data_tx,
            iface_messages_tx,
            handler,
            cancel,
        }
    }

    pub async fn outbound(&self, packet: &Packet) {
        let (packet, maybe_iface) = self.handler.lock().await.path_table.handle_packet(packet);

        if let Some(iface) = maybe_iface {
            self.send_direct(iface, packet).await;
            log::trace!("Sent outbound packet to {}", iface);
        }

        // TODO handle other cases
    }

    pub fn iface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.iface_manager.clone()
    }

    pub fn iface_rx(&self) -> broadcast::Receiver<RxMessage> {
        self.iface_messages_tx.subscribe()
    }

    pub async fn recv_announces(&self) -> broadcast::Receiver<AnnounceEvent> {
        self.handler.lock().await.announce_tx.subscribe()
    }

    pub async fn send_packet(&self, packet: Packet) {
        self.handler.lock().await.send_packet(packet).await;
    }

    pub async fn send_announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        self.handler
            .lock()
            .await
            .send_packet(
                destination
                    .lock()
                    .await
                    .announce(OsRng, app_data)
                    .expect("valid announce packet"),
            )
            .await;
    }

    pub async fn send_broadcast(&self, packet: Packet, from_iface: Option<AddressHash>) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(from_iface),
                packet,
            })
            .await;
    }

    pub async fn send_direct(&self, addr: AddressHash, packet: Packet) {
        self.handler
            .lock()
            .await
            .send(TxMessage {
                tx_type: TxMessageType::Direct(addr),
                packet,
            })
            .await;
    }

    pub async fn send_to_all_out_links(&self, payload: &[u8]) {
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                }
            }
        }
    }

    pub async fn send_to_out_links(&self, destination: &AddressHash, payload: &[u8]) -> Vec<Hash> {
        let mut sent_packets = vec![];
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
            let link = link.lock().await;
            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
                    sent_packets.push(packet.hash());
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
            let link = link.lock().await;

            if link.destination().address_hash == *destination
                && link.status() == LinkStatus::Active
            {
                let packet = link.data_packet(payload);
                if let Ok(packet) = packet {
                    handler.send_packet(packet).await;
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

    pub async fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.find_out_link(link_id).await
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.find_in_link(link_id)
    }

    pub async fn link(&self, destination: DestinationDesc) -> Arc<Mutex<Link>> {
        let link = self
            .handler
            .lock()
            .await
            .out_links
            .get(&destination.address_hash)
            .cloned();

        if let Some(link) = link {
            if link.lock().await.status() != LinkStatus::Closed {
                return link;
            } else {
                log::warn!("tp({}): link was closed", self.name);
            }
        }

        let mut link = Link::new(destination);

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
        );

        let link = Arc::new(Mutex::new(link));

        self.send_packet(packet).await;

        let mut handler = self.handler.lock().await;
        // the closed link it replaces is no longer seen by the link check: forget its iface here
        if let Some(closed) = handler.out_links.insert(destination.address_hash, link.clone()) {
            let closed_id = *closed.lock().await.id();
            handler.link_ifaces.remove(&closed_id);
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
    pub async fn mk_channel<M>(&self, link: Arc<Mutex<Link>>)
        -> Result<(Channel<M>, broadcast::Receiver<M>), RnsError>
    where M: channel::Message
    {
        Channel::new(self, link).await
    }

    #[allow(unused)]  // mocked out in the test build, so the linter
                      // would complain about dead code
    pub (crate) async fn bind_link_to_channel(
        &self,
        id: LinkId
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

    pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_out_event_tx.0.subscribe()
    }

    pub fn in_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_in_event_tx.0.subscribe()
    }

    pub async fn events_for_link(&self, link_id: LinkId) -> broadcast::Receiver<LinkEventData> {
        if self.handler.lock().await.in_links.contains_key(&link_id) {
            self.in_link_events()
        } else {
            self.out_link_events()
        }
    }

    pub fn received_data_events(&self) -> broadcast::Receiver<ReceivedData> {
        self.received_data_tx.subscribe()
    }

    pub async fn add_destination(
        &mut self,
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

    pub async fn add_group_destination(
        &mut self,
        identity: GroupIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<GroupInputDestination>> {
        let destination = GroupInputDestination::new(identity, name);
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

    /// Encrypts `data` for the group and sends it as one GROUP packet.
    pub async fn send_group(
        &self,
        destination: &Arc<Mutex<GroupInputDestination>>,
        data: &[u8],
    ) -> Result<(), RnsError> {
        let packet = destination.lock().await.data_packet(OsRng, data)?;
        self.send_packet(packet).await;
        Ok(())
    }

    /// Rotates a GROUP destination's key; the previous key is still accepted for
    /// `keep_previous`. False if the destination is unknown.
    pub async fn set_group_key(
        &self,
        address: &AddressHash,
        key: GroupKey,
        keep_previous: Duration,
    ) -> bool {
        let mut handler = self.handler.lock().await;
        let now = time::Instant::now();
        handler.group_previous_keys.retain(|_, (_, until)| *until > now);
        let Some(destination) = handler.group_in_destinations.get(address).cloned() else {
            return false;
        };
        let mut destination = destination.lock().await;
        let previous = destination.identity.key().clone();
        destination.identity.replace_key(key);
        drop(destination);
        handler
            .group_previous_keys
            .insert(*address, (previous, time::Instant::now() + keep_previous));
        true
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

    pub(crate) fn get_handler(&self) -> Arc<Mutex<TransportHandler>> {
        self.handler.clone()
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TransportHandler {
    /// Sends a packet originating from this node: packets of a local link on the
    /// interface of the link, packets for a destination with a known path on the
    /// interface of the path, and any other packets are sent on all interfaces
    pub(crate) async fn send_packet(&self, packet: Packet) {
        let message = if let Some(iface) = self.link_ifaces.get(&packet.destination) {
            TxMessage { tx_type: TxMessageType::Direct(*iface), packet }
        } else {
            match self.path_table.handle_packet(&packet) {
                (packet, Some(iface)) => TxMessage { tx_type: TxMessageType::Direct(iface), packet },
                (packet, None) => TxMessage { tx_type: TxMessageType::Broadcast(None), packet },
            }
        };

        self.send(message).await;
    }

    async fn send(&self, message: TxMessage) {
        self.packet_cache.lock().await.update(&message.packet);
        self.iface_manager.lock().await.send(message).await;
    }

    /// Whether the packet is in transport with this node as the next hop. Only such
    /// packets are forwarded to remote destinations.
    fn addressed_to_this_node(&self, packet: &Packet) -> bool {
        packet.transport == Some(*self.config.identity.address_hash())
    }

    fn has_destination(&self, address: &AddressHash) -> bool {
        self.single_in_destinations.contains_key(address)
    }

    fn knows_destination(&self, address: &AddressHash) -> bool {
        self.single_out_destinations.contains_key(address)
    }

    /// By link id, falling back to the destination address (out-links are keyed by it).
    async fn find_out_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        for link in self.out_links.values() {
            if link.lock().await.id() == link_id {
                return Some(link.clone());
            }
        }
        self.out_links.get(link_id).cloned()
    }

    fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.in_links.get(link_id).cloned()
    }

    /// Forgets the least recently heard remote destinations beyond `MAX_DESTINATIONS`,
    /// except those we have an out-link to.
    fn forget_destinations_over_cap(&mut self) {
        while self.path_table.len() > MAX_DESTINATIONS {
            let Some(destination) = self
                .path_table
                .least_recently_heard(|destination| !self.out_links.contains_key(destination))
            else {
                break;
            };

            log::debug!("tp({}): forgetting destination {}", self.config.name, destination);

            self.path_table.remove(&destination);
            self.announced.remove(&destination);
            self.single_out_destinations.remove(&destination);
            self.announce_table.remove(&destination);
            self.announce_limits.remove(&destination);
        }
    }

    /// Makes room for one more in-link within `MAX_IN_LINKS`: drops closed ones, then
    /// closes the idlest.
    async fn make_room_for_in_link(&mut self) {
        let mut closed = Vec::new();
        let mut idlest: Option<(Duration, LinkId)> = None;
        for (link_id, link) in &self.in_links {
            let link = link.lock().await;
            if link.status() == LinkStatus::Closed {
                closed.push(*link_id);
            } else if idlest.map_or(true, |(idle, _)| link.elapsed() > idle) {
                idlest = Some((link.elapsed(), *link_id));
            }
        }
        if self.in_links.len() - closed.len() >= MAX_IN_LINKS {
            if let Some((_, link_id)) = idlest {
                log::debug!("tp({}): too many in-links, closing {}", self.config.name, link_id);
                self.in_links[&link_id].lock().await.close(&self.link_in_event_tx);
                closed.push(link_id);
            }
        }
        for link_id in &closed {
            self.in_links.remove(link_id);
            self.link_ifaces.remove(link_id);
            self.channel_table.remove(link_id);
        }
    }

    pub(crate) async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
        let link = if let Some(link) = self.find_in_link(&link_id) {
            Some((link, &self.link_in_event_tx))
        } else {
            self.find_out_link(&link_id).await.map(|link| (link, &self.link_out_event_tx))
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

        match packet.header.packet_type {
            PacketType::Announce => {
                return true;
            }
            PacketType::LinkRequest => {
                allow_duplicate = true;
            }
            PacketType::Data => {
                allow_duplicate = packet.context == PacketContext::KeepAlive;
                if packet.header.destination_type == DestinationType::Link
                    && self.link_table.relays(&packet.destination)
                {
                    return allow_duplicate || !self.packet_cache.lock().await.contains(packet);
                }
            }
            PacketType::Proof => {
                if packet.context == PacketContext::LinkRequestProof {
                    let mut requester = false;
                    for link in self.out_links.values() {
                        let link = link.lock().await;
                        if *link.id() == packet.destination && link.status().not_yet_active() {
                            requester = true;
                        }
                    }
                    allow_duplicate = requester || self.link_table.accepts_repeat_proof(packet);
                }
            },
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
            packet,
        })
        .await;
    }

    async fn bind_link_to_channel(
        &mut self,
        id: LinkId
    ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
        if self.channel_table.contains_key(&id) {
            return Err(RnsError::ChannelError);
        }

        let (tx, rx) = broadcast::channel(self.config.channel_capacity.link_payloads);
        self.channel_table.insert(id, tx.into());

        Ok(rx)
    }
}

async fn handle_proof<'a>(
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>
) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    let mut rtt_packets = Vec::new();
    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        let link_id = *link.id();

        if let LinkHandleResult::Activated = link.handle_packet(
            &handler.link_out_event_tx,
            handler.channel_table.get(&link_id),
            packet,
            true
        ) {
            rtt_packets.push((link_id, link.create_rtt()));
        }
    }

    for (link_id, rtt_packet) in rtt_packets {
        handler.link_ifaces.insert(link_id, iface);
        handler.send_packet(rtt_packet).await;
    }

    for link in handler.in_links.values() {
        let mut link = link.lock().await;
        let link_id = *link.id();

        link.handle_packet(
            &handler.link_in_event_tx,
            handler.channel_table.get(&link_id),
            packet,
            false
        );
    }

    // other proofs on a link (message proofs) are transported in both directions
    let maybe_packet = if packet.context == PacketContext::LinkRequestProof {
        // Relays forward only proofs the destination signed.
        let genuine = handler
            .link_table
            .destination_of(&packet.destination)
            .and_then(|destination| handler.announced.get(&destination))
            .is_some_and(|desc| validate_proof_packet(desc, &packet.destination, packet).is_ok());
        if genuine { handler.link_table.handle_proof(packet) } else { None }
    } else {
        handler.link_table.handle_link_packet(packet, iface)
    };

    if let Some((packet, iface)) = maybe_packet {
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet,
            })
            .await;
    }
}

async fn send_to_next_hop<'a>(
    packet: &Packet,
    handler: &MutexGuard<'a, TransportHandler>,
) -> bool {
    if !handler.addressed_to_this_node(packet) {
        log::trace!(
            "tp({}): not forwarding packet for {}, not addressed to this node",
            handler.config.name,
            packet.destination
        );
        return false;
    }

    let (packet, maybe_iface) = handler.path_table.handle_inbound_packet(packet);

    if let Some(iface) = maybe_iface {
        handler
            .send(TxMessage {
                tx_type: TxMessageType::Direct(iface),
                packet,
            })
            .await;
    }

    maybe_iface.is_some()
}

async fn handle_data<'a>(
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let mut data_handled = false;

    if packet.header.destination_type == DestinationType::Link {
        let mut local_out_link_handled = false;

        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            let mut link = link.lock().await;
            let channel_tx = handler.channel_table.get(link.id());

            let result = link.handle_packet(
                &handler.link_in_event_tx,
                channel_tx,
                packet,
                false
            );

            match result {
                LinkHandleResult::KeepAlive => {
                    let packet = link.keep_alive_packet(KEEP_ALIVE_RESPONSE);
                    handler.send_packet(packet).await;
                }
                LinkHandleResult::MessageReceived(Some(proof)) => {
                    handler.send_packet(proof).await;
                }
                _ => {}
            }
        }

        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            let link_id = *link.id();

            if link_id == packet.destination {
                let result = link.handle_packet(
                    &handler.link_out_event_tx,
                    handler.channel_table.get(&link_id),
                    packet,
                    true
                );

                if let LinkHandleResult::MessageReceived(Some(proof)) = result {
                    handler.send_packet(proof).await;
                }

                local_out_link_handled = true;
                data_handled = true;
            }
        }

        if !local_out_link_handled {
            if let Some((packet, out_iface)) = handler.link_table.handle_link_packet(packet, iface) {
                log::trace!(
                    "tp({}): forwarded packet to remote link {}",
                    handler.config.name,
                    packet.destination
                );

                handler
                    .send(TxMessage {
                        tx_type: TxMessageType::Direct(out_iface),
                        packet,
                    })
                    .await;
            }
        }
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(_destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            handler.received_data_tx.send(ReceivedData {
                destination: packet.destination,
                data: packet.data,
            }).ok();
        } else {
            data_handled = send_to_next_hop(packet, &handler).await;
        }
    }

    if packet.header.destination_type == DestinationType::Group {
        if handler.config.group_forwarding {
            // relayed on all interfaces including the one it was received on, so
            // that single radio nodes relay too; each node relays a packet only
            // once, since copies already in the packet cache are dropped
            if handler.config.retransmit && (packet.header.hops as usize) + 1 < PATHFINDER_M {
                let mut forwarded = *packet;
                forwarded.header.hops = forwarded.header.hops.saturating_add(1);

                log::trace!(
                    "tp({}): forwarding GROUP packet {} with {} hops",
                    handler.config.name,
                    packet.hash(),
                    forwarded.header.hops
                );

                handler.send(TxMessage {
                    tx_type: TxMessageType::Broadcast(None),
                    packet: forwarded,
                }).await;
            }
        } else if packet.header.hops > 0 {
            log::debug!(
                "tp({}): dropped GROUP packet {} with {} hops",
                handler.config.name,
                packet.hash(),
                packet.header.hops
            );
            return;
        }

        if let Some(destination) = handler
            .group_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            let mut buffer = [0u8; PACKET_MDU];
            let mut previous_buffer = [0u8; PACKET_MDU];
            let decrypted = destination
                .lock()
                .await
                .decrypt(OsRng, packet.data.as_slice(), &mut buffer);
            let decrypted = match decrypted {
                Ok(plain_text) => Ok(plain_text),
                Err(err) => match handler.group_previous_keys.get(&packet.destination) {
                    Some((key, until)) if time::Instant::now() < *until => key
                        .decrypt(OsRng, packet.data.as_slice(), &mut previous_buffer)
                        .map_err(|_| err),
                    _ => Err(err),
                },
            };
            match decrypted
            {
                Ok(plain_text) => {
                    handler.received_data_tx.send(ReceivedData {
                        destination: packet.destination,
                        data: PacketDataBuffer::new_from_slice(plain_text),
                    }).ok();
                }
                Err(err) => log::debug!(
                    "tp({}): the GROUP destination {} could not decrypt data: {:?}",
                    handler.config.name,
                    packet.destination,
                    err
                ),
            }
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
    mut handler: MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    // PLAIN and GROUP destinations can not be announced
    if packet.header.destination_type == DestinationType::Plain
        || packet.header.destination_type == DestinationType::Group
    {
        log::debug!(
            "tp({}): dropped invalid {:?} announce for {}",
            handler.config.name,
            packet.header.destination_type,
            packet.destination
        );
        return;
    }

    if handler.has_destination(&packet.destination) {
        // destination is local
        return;
    }

    if packet.header.hops as usize >= PATHFINDER_M {
        log::debug!(
            "tp({}): dropped announce for {} with {} hops",
            handler.config.name,
            packet.destination,
            packet.header.hops
        );
        return;
    }

    let Ok((destination, app_data)) = DestinationAnnounce::validate(packet) else {
        return;
    };
    let dest_hash = packet.destination;

    // every copy heard from other nodes may complete a pending retransmission,
    // even if the announce itself is not new
    if handler.config.retransmit {
        handler.announce_table.heard_rebroadcast(&dest_hash, packet.header.hops);
    }

    if !handler
        .path_table
        .handle_announce(packet, packet.transport, iface)
    {
        log::trace!(
            "tp({}): ignored announce for {}, heard before or older",
            handler.config.name,
            packet.destination
        );
        return;
    }

    handler.announced.insert(packet.destination, destination.desc);
    let destination = Arc::new(Mutex::new(destination));

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

    handler.forget_destinations_over_cap();

    // the rate limit only blocks retransmission, the path is updated anyway
    if let Some(blocked_until) = handler.announce_limits.check(&packet.destination) {
        log::debug!(
            "tp({}): too many announces from {}, not retransmitted for {} seconds",
            handler.config.name,
            packet.destination,
            blocked_until.as_secs(),
        );
    } else {
        handler.announce_table.add(packet, dest_hash);

        if handler.config.retransmit {
            let transport_id = *handler.config.identity.address_hash();
            if let Some(message) = handler.announce_table.new_packet(&dest_hash, &transport_id) {
                handler.send(message).await;
            }
        }
    }

    let _ = handler.announce_tx.send(AnnounceEvent {
        destination,
        app_data: PacketDataBuffer::new_from_slice(app_data),
        hops: packet.header.hops,
        transport_id: packet.transport,
    });
}

async fn handle_path_request<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) {
    if let Some(request) = handler.path_requests.decode(packet.data.as_slice()) {
        if let Some(dest) = handler.single_in_destinations.get(&request.destination) {
            let response = dest
                .lock()
                .await
                .path_response(OsRng, None)
                .expect("valid path response");

            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Direct(iface),
                    packet: response,
                })
                .await;

            log::trace!(
                "tp({}): send direct path response over {}",
                handler.config.name,
                iface
            );

            return;
        }

        if handler.config.retransmit {
            if let Some(entry) = handler.path_table.get(&request.destination) {
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

                let hops = entry.hops;

                handler
                    .announce_table
                    .add_response(request.destination, iface, hops);

                log::trace!(
                    "tp({}): scheduled remote path response to {} ({} hops) over {}",
                    handler.config.name,
                    request.destination,
                    hops,
                    iface
                );

                return;
            }
        }

        if let Some(packet) =
            handler
                .path_requests
                .generate_recursive(&request.destination, Some(iface), None)
        {
            handler
                .send(TxMessage {
                    tx_type: TxMessageType::Broadcast(Some(iface)),
                    packet,
                })
                .await;
        }
    }
}

async fn handle_fixed_destinations<'a>(
    packet: &Packet,
    handler: &mut MutexGuard<'a, TransportHandler>,
    iface: AddressHash,
) -> bool {
    if packet.destination == handler.fixed_dest_path_requests {
        handle_path_request(packet, handler, iface).await;
        true
    } else {
        false
    }
}

async fn handle_link_request_as_destination<'a>(
    destination: Arc<Mutex<SingleInputDestination>>,
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>,
) {
    let mut destination = destination.lock().await;
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
                    handler.make_room_for_in_link().await;
                    handler.link_ifaces.insert(*link.id(), iface);
                    handler.send_packet(link.prove(&handler.link_in_event_tx)).await;
                    let now = time::Instant::now();
                    handler.proofs.insert(*link.id(), (now, now));

                    log::debug!(
                        "tp({}): save input link {} for destination {}",
                        handler.config.name,
                        link.id(),
                        link.destination().address_hash
                    );

                    handler
                        .in_links
                        .insert(*link.id(), Arc::new(Mutex::new(link)));
                }
            } else if let Some(link) = handler.in_links.get(&link_id).cloned() {
                // A repeated request means our proof was lost: prove again, within limits,
                // and never for a closed link (requests can be replayed).
                let now = time::Instant::now();
                let allowed = handler.proofs.get(&link_id).is_some_and(|(first, last)| {
                    now.duration_since(*first) < REPROVE_WINDOW && now.duration_since(*last) >= REPROVE_GAP
                });
                let mut link = link.lock().await;
                if allowed && link.status() == LinkStatus::Active {
                    let proof = link.prove(&handler.link_in_event_tx);
                    drop(link);
                    if let Some(entry) = handler.proofs.get_mut(&link_id) {
                        entry.1 = now;
                    }
                    log::debug!("tp({}): repeated request, prove {link_id} again", handler.config.name);
                    handler.send_packet(proof).await;
                }
            }
        }
        DestinationHandleStatus::None => {}
    }
}

async fn handle_link_request<'a>(
    packet: &Packet,
    iface: AddressHash,
    mut handler: MutexGuard<'a, TransportHandler>
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
    } else if !handler.addressed_to_this_node(packet) {
        log::trace!(
            "tp({}): dropping link request for {}, not addressed to this node",
            handler.config.name,
            packet.destination
        );
    } else if let Some(entry) = handler.path_table.get(&packet.destination) {
        // handle link request as intermediate
        log::trace!(
            "tp({}): handle link request for remote destination {}",
            handler.config.name,
            packet.destination
        );
        let (next_hop, next_hop_iface, remaining_hops) = (entry.received_from, entry.iface, entry.hops);
        handler.link_table.add(
            packet,
            iface,
            next_hop,
            next_hop_iface,
            remaining_hops,
        );
        send_to_next_hop(packet, &handler).await;
    } else {
        // Addressed to us but no path (we restarted): ask for it, so the next repeat passes.
        log::debug!(
            "tp({}): link request to unknown destination {}, asking for its path",
            handler.config.name,
            packet.destination
        );
        let now = time::Instant::now();
        let asked = handler.path_asked.get(&packet.destination).is_some_and(|at| now.duration_since(*at) < PATH_ASK_GAP);
        if !asked {
            handler.path_asked.insert(packet.destination, now);
            handler.request_path(&packet.destination, None, None).await;
        }
    }
}

async fn handle_check_links<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let mut links_to_remove: Vec<AddressHash> = Vec::new();
    let timer_config = handler.config.timer_config;

    // Clean up input links
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        match link.status() {
            LinkStatus::Active if link.elapsed() > timer_config.in_link_stale => {
                link.stale();
            }
            LinkStatus::Stale if link.elapsed() > timer_config.in_link_stale + timer_config.in_link_close => {
                if let Some(packet) = link.teardown(&handler.link_in_event_tx).unwrap_or_else(|err| {
                    log::error!("tp({}): teardown stale in-link error: {err:?}", handler.config.name);
                    None
                }) {
                    handler.send_packet(packet).await
                }
                links_to_remove.push(*link_entry.0);
            }
            LinkStatus::Closed => links_to_remove.push(*link_entry.0),
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(addr);
        handler.link_ifaces.remove(addr);
    }
    let now = time::Instant::now();
    handler.proofs.retain(|_, (first, _)| now.duration_since(*first) < REPROVE_WINDOW);
    handler.path_asked.retain(|_, at| now.duration_since(*at) < PATH_ASK_GAP);

    links_to_remove.clear();
    // out-links are kept by destination, their interfaces by link id
    let mut closed_link_ids = Vec::new();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        match link.status() {
            LinkStatus::Active if link.elapsed() > timer_config.out_link_stale => {
                link.stale();
            }
            LinkStatus::Stale => {
                if handler.config.restart_outlinks {
                    if link.elapsed() > timer_config.out_link_restart {
                        link.restart();
                    }
                } else if link.elapsed() > timer_config.out_link_stale + timer_config.out_link_close {
                    if let Some(packet) = link.teardown(&handler.link_out_event_tx).unwrap_or_else(|err| {
                        log::error!(
                            "tp({}): teardown stale out-link error: {err:?}",
                            handler.config.name
                        );
                        None
                    }) {
                        handler.send_packet(packet).await
                    }
                    links_to_remove.push(*link_entry.0);
                    closed_link_ids.push(*link.id());
                }
            }
            LinkStatus::Pending
                if link.elapsed() > timer_config.out_link_repeat + Duration::from_millis(OsRng.next_u32() as u64 % 1000) =>
            {
                log::debug!(
                    "tp({}): repeat link request {}",
                    handler.config.name,
                    link.id()
                );
                handler.send_packet(link.request()).await;
            }
            LinkStatus::Closed => {
                link.close(&handler.link_out_event_tx);
                links_to_remove.push(*link_entry.0);
                closed_link_ids.push(*link.id());
            }
            _ => {}
        }
    }

    for addr in &links_to_remove {
        handler.out_links.remove(addr);
    }

    for link_id in &closed_link_ids {
        handler.link_ifaces.remove(link_id);
    }
}

async fn handle_keep_links<'a>(handler: MutexGuard<'a, TransportHandler>) {
    for link in handler.out_links.values() {
        let link = link.lock().await;

        if matches!(link.status(), LinkStatus::Active | LinkStatus::Stale) {
            handler
                .send_packet(link.keep_alive_packet(KEEP_ALIVE_REQUEST))
                .await;
        }
    }
}

async fn handle_cleanup<'a>(handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();
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

async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();
    let retransmit = handler.lock().await.config.retransmit;
    let timer_config = handler.lock().await.config.timer_config;

    let mut last_retransmit_old = if handler.lock().await.config.announce_forever {
        Some(time::Instant::now() - timer_config.old_announces_retransmit)
    } else {
        None
    };

    let _packet_task = {
        let handler = handler.clone();
        let cancel = cancel.clone();

        log::trace!(
            "tp({}): start packet task",
            handler.lock().await.config.name
        );

        tokio::spawn(async move {
            loop {
                let mut rx_receiver = rx_receiver.lock().await;

                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    Some(message) = rx_receiver.recv() => {
                        let _ = iface_messages_tx.send(message);

                        let packet = message.packet;

                        let mut handler = handler.lock().await;

                        if PACKET_TRACE {
                            log::debug!("tp: << rx({}) = {} {}", message.address, packet, packet.hash());
                        }

                        if handle_fixed_destinations(
                            &packet,
                            &mut handler,
                            message.address
                        ).await {
                            continue;
                        }

                        // Before the duplicate filter: an overheard copy must not hide ours.
                        // Only the designated next hop processes in-transit packets:
                        // nodes that merely overhear them on shared-medium (radio)
                        // interfaces must ignore them, otherwise forwarded packets
                        // circulate (e.g. LinkRequest ping-pong between originator and
                        // relay).
                        //
                        // A packet in transport is only accepted by the node it is
                        // addressed to, the next hop. Packets on the last hop to their
                        // destination and link packets have no transport id.
                        if let Some(transport) = packet.transport {
                            if packet.header.packet_type != PacketType::Announce
                                && transport != *handler.config.identity.address_hash()
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

                        if !handler.filter_duplicate_packets(&packet).await {
                            log::debug!(
                                "tp({}): dropping duplicate packet: dst={}, ctx={:?}, type={:?}",
                                handler.config.name,
                                packet.destination,
                                packet.context,
                                packet.header.packet_type
                            );
                            continue;
                        }

                        match packet.header.packet_type {
                            PacketType::Announce => handle_announce(
                                &packet,
                                handler,
                                message.address
                            ).await,
                            PacketType::LinkRequest => handle_link_request(
                                &packet,
                                message.address,
                                handler
                            ).await,
                            PacketType::Proof => handle_proof(
                                &packet,
                                message.address,
                                handler
                            ).await,
                            PacketType::Data => handle_data(
                                &packet,
                                message.address,
                                handler
                            ).await,
                        }
                    }
                };
            }
        })
    };

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
                    _ = time::sleep(timer_config.link_check) => {
                        handle_check_links(handler.lock().await).await;
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
                    _ = time::sleep(timer_config.out_link_keep) => {
                        handle_keep_links(handler.lock().await).await;
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
                        let mut handler = handler.lock().await;

                        handler
                            .packet_cache
                            .lock()
                            .await
                            .release(timer_config.keep_packet_cached);

                        handler.link_table.remove_stale();
                        handler.path_requests.remove_stale();
                    },
                }
            }
        });
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
mod tests {
    use super::*;

    use crate::packet::HeaderType;

    #[tokio::test]
    async fn the_network_profile_sizes_the_channels() {
        assert_eq!(TransportConfig::default().channel_capacity, ChannelCapacity::for_network(NetworkProfile::Default));
        for profile in [NetworkProfile::Default, NetworkProfile::Minimal, NetworkProfile::MultiHop] {
            let capacity = ChannelCapacity::for_network(profile);
            let transport = TransportConfig::default().set_network_profile(profile).build();
            let handler = transport.handler.lock().await;
            assert_eq!(handler.config.channel_capacity, capacity);
            // one announce more than the capacity: the subscriber loses the oldest
            let mut announces = handler.announce_tx.subscribe();
            let destination = Arc::new(Mutex::new(SingleOutputDestination::new(
                *PrivateIdentity::new_from_rand(OsRng).as_identity(),
                DestinationName::new("test", "profile"),
            )));
            for _ in 0..=capacity.announces {
                let event = AnnounceEvent { destination: destination.clone(), app_data: PacketDataBuffer::new(), hops: 0, transport_id: None };
                handler.announce_tx.send(event).ok().expect("subscribed");
            }
            assert_eq!(announces.recv().await.err(), Some(broadcast::error::RecvError::Lagged(1)), "{profile:?}");
        }
    }

    #[tokio::test]
    async fn drop_duplicates() {
        let transport = TransportConfig::default()
            .set_retransmit(true)
            .build();

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

        handle_announce(&announce, handler.lock().await, next_hop_iface).await;

        let data_packet: Packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"foo"),
            destination,
            ..Default::default()
        };
        let duplicate: Packet = data_packet;

        let different_packet = Packet {
            data: PacketDataBuffer::new_from_slice(b"bar"),
            .. data_packet
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

    fn group_identity(key: GroupKey) -> GroupIdentity {
        let identity = PrivateIdentity::new_from_name("group");
        GroupIdentity::new(*identity.as_identity(), key)
    }

    #[tokio::test]
    async fn group_key_rotation_keeps_the_previous_key_for_a_while() {
        let mut transport = TransportConfig::default().build();
        let handler = transport.get_handler();
        let mut received_data = transport.received_data_events();
        let name = DestinationName::new("example", "group");
        let old = GroupKey::new_rand(OsRng);
        let new = GroupKey::new_rand(OsRng);

        let destination = transport.add_group_destination(group_identity(old.clone()), name).await;
        let address = destination.lock().await.desc.address_hash;
        assert!(transport.set_group_key(&address, new.clone(), Duration::from_millis(200)).await);
        assert_eq!(destination.lock().await.desc.address_hash, address);

        let old_sender = GroupInputDestination::new(group_identity(old), name);
        let new_sender = GroupInputDestination::new(group_identity(new), name);
        for (sender, text) in [(&new_sender, &b"new"[..]), (&old_sender, &b"old"[..])] {
            let packet = sender.data_packet(OsRng, text).unwrap();
            handle_data(&packet, AddressHash::new_empty(), handler.lock().await).await;
            assert_eq!(received_data.try_recv().expect("delivered").data.as_slice(), text);
        }

        // After the grace period the old key is refused.
        tokio::time::sleep(Duration::from_millis(250)).await;
        let packet = old_sender.data_packet(OsRng, b"late").unwrap();
        handle_data(&packet, AddressHash::new_empty(), handler.lock().await).await;
        assert!(received_data.try_recv().is_err());

        // What we send is encrypted with the new key.
        let sent = destination.lock().await.data_packet(OsRng, b"mine").unwrap();
        let mut buffer = [0u8; PACKET_MDU];
        assert_eq!(new_sender.decrypt(OsRng, sent.data.as_slice(), &mut buffer).unwrap(), b"mine");
        assert!(!transport.set_group_key(&AddressHash::new_empty(), GroupKey::new_rand(OsRng), Duration::ZERO).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_repeated_link_request_is_proved_again_only_soon_and_never_revives_a_closed_link() {
        let mut transport = TransportConfig::default().build();
        let handler = transport.get_handler();
        let destination = transport.add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "reprove")).await;
        let desc = destination.lock().await.desc;
        let request = Link::new(desc).request();
        let link_id = LinkId::from(&request);
        let iface = AddressHash::new([1; 16]);

        handle_link_request_as_destination(destination.clone(), &request, iface, handler.lock().await).await;
        let first = handler.lock().await.proofs[&link_id];
        // Repeated at once: not proved again.
        handle_link_request_as_destination(destination.clone(), &request, iface, handler.lock().await).await;
        assert_eq!(handler.lock().await.proofs[&link_id].1, first.1);
        // A gap later (a lost proof): proved again.
        time::advance(REPROVE_GAP).await;
        handle_link_request_as_destination(destination.clone(), &request, iface, handler.lock().await).await;
        assert!(handler.lock().await.proofs[&link_id].1 > first.1);

        // Closed: not proved nor revived. Once removed, the request makes a new link.
        let link = handler.lock().await.in_links[&link_id].clone();
        {
            let handler = handler.lock().await;
            link.lock().await.close(&handler.link_in_event_tx);
        }
        time::advance(REPROVE_GAP).await;
        handle_link_request_as_destination(destination.clone(), &request, iface, handler.lock().await).await;
        assert_eq!(link.lock().await.status(), LinkStatus::Closed);
        handle_check_links(handler.lock().await).await;
        assert!(!handler.lock().await.in_links.contains_key(&link_id));
        handle_link_request_as_destination(destination.clone(), &request, iface, handler.lock().await).await;
        let renewed = handler.lock().await.in_links[&link_id].clone();
        assert_eq!(renewed.lock().await.status(), LinkStatus::Active, "a new link for the restarted request");
    }

    #[tokio::test]
    async fn a_relay_without_a_path_asks_for_it_once_in_a_while() {
        // A link request addressed through us to a destination we do not know (we restarted).
        let relay = TransportConfig::default().set_retransmit(true).build();
        let handler = relay.get_handler();
        let relay_id = *handler.lock().await.config.identity.address_hash();
        let mut elsewhere = TransportConfig::default().build();
        let destination = elsewhere.add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "unknown")).await;
        let desc = destination.lock().await.desc;
        let mut request = Link::new(desc).request();
        request.header.header_type = HeaderType::Type2;
        request.transport = Some(relay_id);

        handle_link_request(&request, AddressHash::new([1; 16]), handler.lock().await).await;
        let first = handler.lock().await.path_asked.get(&desc.address_hash).copied().expect("asked for the path");
        handle_link_request(&request, AddressHash::new([1; 16]), handler.lock().await).await;
        assert_eq!(handler.lock().await.path_asked[&desc.address_hash], first, "not again at once");

        // a request not addressed to us (overheard) asks nothing
        let other = elsewhere.add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "other")).await;
        let mut overheard = Link::new(other.lock().await.desc).request();
        overheard.header.header_type = HeaderType::Type2;
        overheard.transport = Some(AddressHash::new([7; 16]));
        handle_link_request(&overheard, AddressHash::new([1; 16]), handler.lock().await).await;
        assert!(!handler.lock().await.path_asked.contains_key(&other.lock().await.desc.address_hash));
    }

    #[tokio::test]
    async fn a_relay_forwards_only_link_proofs_the_destination_signed() {
        // The destination lives on another node; the relay knows it from its announce.
        let mut elsewhere = TransportConfig::default().build();
        let destination = elsewhere.add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "relayed")).await;
        let (desc, sign_key) = {
            let destination = destination.lock().await;
            (destination.desc, destination.sign_key().clone())
        };
        let relay = TransportConfig::default().build();
        let handler = relay.get_handler();
        handler.lock().await.announced.insert(desc.address_hash, desc);

        let request = Link::new(desc).request();
        let (initiator_side, destination_side) = (AddressHash::new([1; 16]), AddressHash::new([2; 16]));
        handler.lock().await.link_table.add(&request, initiator_side, AddressHash::new([3; 16]), destination_side, 1);
        let genuine = {
            let handler = handler.lock().await;
            Link::new_from_request(&request, sign_key, desc).unwrap().prove(&handler.link_in_event_tx)
        };
        let mut forged = genuine;
        forged.data.as_mut_slice()[0] ^= 1;

        handle_proof(&forged, destination_side, handler.lock().await).await;
        assert!(!handler.lock().await.link_table.validated(&genuine.destination), "a forged proof validates nothing");
        handle_proof(&genuine, destination_side, handler.lock().await).await;
        assert!(handler.lock().await.link_table.validated(&genuine.destination), "the genuine proof validates the link");
    }

    #[tokio::test]
    async fn multi_hop_link_events_lag_past_the_capacity() {
        let transport = TransportConfig::default().set_network_profile(NetworkProfile::MultiHop).build();
        let mut events = transport.in_link_events();
        for _ in 0..=MULTIHOP_LINK_EVENTS {
            transport.link_in_event_tx.send(LinkEventData {
                id: AddressHash::new_empty(),
                address_hash: AddressHash::new_empty(),
                event: crate::destination::link::LinkEvent::Closed,
            });
        }
        assert_eq!(events.recv().await.err(), Some(broadcast::error::RecvError::Lagged(1)));
    }

    fn announce_of_a_new_destination() -> (Packet, DestinationDesc) {
        let destination = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("test", "flood"),
        );
        (destination.announce(OsRng, None).unwrap(), destination.desc)
    }

    #[tokio::test]
    async fn remote_destinations_are_capped_and_linked_ones_kept() {
        let transport = TransportConfig::default().build();
        let handler = transport.get_handler();
        let iface = AddressHash::new([1; 16]);

        // heard first, so least recently, but we have a link to it
        let (announce, linked) = announce_of_a_new_destination();
        handle_announce(&announce, handler.lock().await, iface).await;
        handler.lock().await.out_links.insert(linked.address_hash, Arc::new(Mutex::new(Link::new(linked))));
        let (announce, unlinked) = announce_of_a_new_destination();
        handle_announce(&announce, handler.lock().await, iface).await;

        let mut newest = None;
        for _ in 0..MAX_DESTINATIONS {
            let (announce, desc) = announce_of_a_new_destination();
            handle_announce(&announce, handler.lock().await, iface).await;
            newest = Some(desc.address_hash);
        }

        let handler = handler.lock().await;
        assert_eq!(handler.path_table.len(), MAX_DESTINATIONS);
        assert_eq!(handler.announced.len(), MAX_DESTINATIONS);
        assert_eq!(handler.single_out_destinations.len(), MAX_DESTINATIONS);
        assert!(handler.knows_destination(&linked.address_hash), "linked: kept");
        assert!(!handler.knows_destination(&unlinked.address_hash), "least recently heard: forgotten");
        assert!(handler.knows_destination(&newest.unwrap()));
    }

    #[tokio::test(start_paused = true)]
    async fn in_links_are_capped_and_the_idlest_goes() {
        let mut transport = TransportConfig::default().set_network_profile(NetworkProfile::MultiHop).build();
        let handler = transport.get_handler();
        let destination = transport.add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "inlinks")).await;
        let mut events = transport.in_link_events();
        let iface = AddressHash::new([1; 16]);

        let mut link_ids = Vec::new();
        for _ in 0..(MAX_IN_LINKS + 5) {
            let request = Link::new(destination.lock().await.desc).request();
            handle_link_request_as_destination(destination.clone(), &request, iface, handler.lock().await).await;
            link_ids.push(LinkId::from(&request));
            time::advance(Duration::from_millis(1)).await;
        }

        let handler = handler.lock().await;
        assert_eq!(handler.in_links.len(), MAX_IN_LINKS);
        assert_eq!(handler.link_ifaces.len(), MAX_IN_LINKS);
        assert!(!handler.in_links.contains_key(&link_ids[0]), "the idlest went");
        assert!(handler.in_links.contains_key(link_ids.last().unwrap()));
        let mut closed = 0;
        while let Ok(event) = events.try_recv() {
            closed += matches!(event.event, crate::destination::link::LinkEvent::Closed) as usize;
        }
        assert_eq!(closed, 5, "the apps hear the closed links");
    }

    #[tokio::test]
    async fn relinking_a_closed_link_forgets_its_interface() {
        let transport = TransportConfig::default().build();
        let handler = transport.get_handler();
        let (_, desc) = announce_of_a_new_destination();

        let closed = transport.link(desc).await;
        let closed_id = *closed.lock().await.id();
        handler.lock().await.link_ifaces.insert(closed_id, AddressHash::new([1; 16]));
        closed.lock().await.set_status(LinkStatus::Closed);

        let renewed = transport.link(desc).await;
        assert_ne!(*renewed.lock().await.id(), closed_id);
        assert!(!handler.lock().await.link_ifaces.contains_key(&closed_id));
    }

    #[tokio::test]
    async fn group_data_delivery() {
        let mut transport = TransportConfig::default().build();
        let handler = transport.get_handler();
        let mut received_data = transport.received_data_events();

        let key = GroupKey::new_rand(OsRng);
        let name = DestinationName::new("example", "group");

        let destination = transport
            .add_group_destination(group_identity(key.clone()), name)
            .await;
        let address = destination.lock().await.desc.address_hash;

        // Packet from another member, received directly
        let sender = GroupInputDestination::new(group_identity(key), name);
        let packet = sender.data_packet(OsRng, b"hello group").unwrap();

        handle_data(&packet, AddressHash::new_empty(), handler.lock().await).await;

        let data = received_data.try_recv().expect("delivered group data");
        assert_eq!(data.destination, address);
        assert_eq!(data.data.as_slice(), b"hello group");

        // GROUP packets are never transported
        let mut transported = sender.data_packet(OsRng, b"transported").unwrap();
        transported.header.hops = 1;

        handle_data(&transported, AddressHash::new_empty(), handler.lock().await).await;
        assert!(received_data.try_recv().is_err());

        // Packets encrypted with another key are not delivered
        let other_sender =
            GroupInputDestination::new(group_identity(GroupKey::new_rand(OsRng)), name);
        let packet = other_sender.data_packet(OsRng, b"wrong key").unwrap();

        handle_data(&packet, AddressHash::new_empty(), handler.lock().await).await;
        assert!(received_data.try_recv().is_err());
    }
}
