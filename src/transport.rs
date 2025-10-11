use alloc::sync::Arc;
use packet_cache::PacketCache;
use path_table::PathTable;
use rand_core::OsRng;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time;
use tokio_util::sync::CancellationToken;

use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;

use crate::destination::link::Link;
use crate::destination::link::LinkEventData;
use crate::destination::link::LinkHandleResult;
use crate::destination::link::LinkId;
use crate::destination::link::LinkStatus;
use crate::destination::DestinationAnnounce;
use crate::destination::DestinationDesc;
use crate::destination::DestinationHandleStatus;
use crate::destination::DestinationName;
use crate::destination::SingleInputDestination;
use crate::destination::SingleOutputDestination;

use crate::hash::AddressHash;
use crate::identity::PrivateIdentity;

use crate::iface::InterfaceManager;
use crate::iface::InterfaceRxReceiver;
use crate::iface::RxMessage;
use crate::iface::TxMessage;
use crate::iface::TxMessageType;

use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::PacketDataBuffer;
use crate::packet::{Packet, PacketType};

mod packet_cache;
mod path_table;

// TODO: Configure via features
const PACKET_TRACE: bool = false;
pub const PATHFINDER_M: usize = 128; // Max hops

const INTERVAL_LINKS_CHECK: Duration = Duration::from_secs(1);
const INTERVAL_INPUT_LINK_CLEANUP: Duration = Duration::from_secs(20);
const INTERVAL_OUTPUT_LINK_RESTART: Duration = Duration::from_secs(60);
const INTERVAL_OUTPUT_LINK_REPEAT: Duration = Duration::from_secs(6);
const INTERVAL_OUTPUT_LINK_KEEP: Duration = Duration::from_secs(5);
const INTERVAL_IFACE_CLEANUP: Duration = Duration::from_secs(10);

pub struct TransportConfig {
    name: String,
    identity: PrivateIdentity,
    broadcast: bool,
    retransmit: bool,
}

#[derive(Clone)]
pub struct AnnounceEvent {
    pub destination: Arc<Mutex<SingleOutputDestination>>,
    pub app_data: PacketDataBuffer,
}

struct TransportHandler {
    config: TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    announce_tx: broadcast::Sender<AnnounceEvent>,

    path_table: PathTable,
    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    single_out_destinations: HashMap<AddressHash, Arc<Mutex<SingleOutputDestination>>>,

    out_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,

    packet_cache: Mutex<PacketCache>,

    link_in_event_tx: broadcast::Sender<LinkEventData>,

    cancel: CancellationToken,
}

pub struct Transport {
    name: String,
    link_in_event_tx: broadcast::Sender<LinkEventData>,
    link_out_event_tx: broadcast::Sender<LinkEventData>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
}

impl TransportConfig {
    pub fn new<T: Into<String>>(name: T, identity: &PrivateIdentity, broadcast: bool) -> Self {
        Self {
            name: name.into(),
            identity: identity.clone(),
            broadcast,
            retransmit: false,
        }
    }

    pub fn set_retransmit(&mut self, retransmit: bool) {
        self.retransmit = retransmit;
    }
    pub fn set_broadcast(&mut self, broadcast: bool) {
        self.broadcast = broadcast;
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            name: "tp".into(),
            identity: PrivateIdentity::new_from_rand(OsRng),
            broadcast: false,
            retransmit: false,
        }
    }
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        let (announce_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_in_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (link_out_event_tx, _) = tokio::sync::broadcast::channel(16);
        let (iface_messages_tx, _) = tokio::sync::broadcast::channel(16);

        let iface_manager = InterfaceManager::new(16);

        let rx_receiver = iface_manager.receiver();

        let iface_manager = Arc::new(Mutex::new(iface_manager));

        let cancel = CancellationToken::new();
        let name = config.name.clone();
        let handler = Arc::new(Mutex::new(TransportHandler {
            config,
            iface_manager: iface_manager.clone(),
            path_table: PathTable::new(),
            single_in_destinations: HashMap::new(),
            single_out_destinations: HashMap::new(),
            out_links: HashMap::new(),
            in_links: HashMap::new(),
            packet_cache: Mutex::new(PacketCache::new()),
            announce_tx,
            link_in_event_tx: link_in_event_tx.clone(),
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
            link_in_event_tx,
            link_out_event_tx,
            iface_messages_tx,
            handler,
            cancel,
        }
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

    pub async fn send_to_out_links(&self, destination: &AddressHash, payload: &[u8]) {
        let mut count = 0usize;
        let handler = self.handler.lock().await;
        for link in handler.out_links.values() {
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
                "tp({}): no output links for {} destination",
                self.name,
                destination
            );
        }
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
        self.handler.lock().await.out_links.get(link_id).cloned()
    }

    pub async fn find_in_link(&self, link_id: &AddressHash) -> Option<Arc<Mutex<Link>>> {
        self.handler.lock().await.in_links.get(link_id).cloned()
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

        let mut link = Link::new(destination, self.link_out_event_tx.clone());

        let packet = link.request();

        log::debug!(
            "tp({}): create new link {} for destination {}",
            self.name,
            link.id(),
            destination
        );

        let link = Arc::new(Mutex::new(link));

        self.send_packet(packet).await;

        self.handler
            .lock()
            .await
            .out_links
            .insert(destination.address_hash, link.clone());

        link
    }

    pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_out_event_tx.subscribe()
    }

    pub fn in_link_events(&self) -> broadcast::Receiver<LinkEventData> {
        self.link_in_event_tx.subscribe()
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

    pub async fn has_destination(&self, address: &AddressHash) -> bool {
        self.handler
            .lock()
            .await
            .single_in_destinations
            .contains_key(address)
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl TransportHandler {
    async fn send_packet(&self, packet: Packet) {
        let message = TxMessage {
            tx_type: TxMessageType::Broadcast(None),
            packet,
        };

        self.send(message).await;
    }

    async fn send(&self, message: TxMessage) {
        self.packet_cache.lock().await.update(&message.packet);
        self.iface_manager.lock().await.send(message).await;
    }
}

async fn handle_proof<'a>(packet: &Packet, handler: MutexGuard<'a, TransportHandler>) {
    log::trace!(
        "tp({}): handle proof for {}",
        handler.config.name,
        packet.destination
    );

    for link in handler.out_links.values() {
        let mut link = link.lock().await;
        match link.handle_packet(packet) {
            LinkHandleResult::Activated => {
                let rtt_packet = link.create_rtt();
                handler.send_packet(rtt_packet).await;
            }
            _ => {}
        }
    }
}

async fn handle_data<'a>(packet: &Packet, handler: MutexGuard<'a, TransportHandler>) {
    let mut data_handled = false;

    if packet.header.destination_type == DestinationType::Link {
        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            let mut link = link.lock().await;
            let result = link.handle_packet(packet);
            match result {
                LinkHandleResult::KeepAlive => {
                    handler.send_packet(link.keep_alive_packet(0xFE)).await;
                }
                _ => {}
            }
        }

        for link in handler.out_links.values() {
            let mut link = link.lock().await;
            let _ = link.handle_packet(packet);
            data_handled = true;
        }
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(_destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {
            data_handled = true;

            // todo
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

async fn handle_announce<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    if let Ok(result) = DestinationAnnounce::validate(packet) {
        let destination = result.0;
        let app_data = result.1;
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

        let _ = handler.announce_tx.send(AnnounceEvent {
            destination,
            app_data: PacketDataBuffer::new_from_slice(&app_data),
        });
    }
}

async fn handle_link_request<'a>(packet: &Packet, mut handler: MutexGuard<'a, TransportHandler>) {
    log::trace!(
        "tp({}): handle link request for {}",
        handler.config.name,
        packet.destination
    );

    if let Some(destination) = handler
        .single_in_destinations
        .get(&packet.destination)
        .cloned()
    {
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
                        handler.link_in_event_tx.clone(),
                    );

                    if let Ok(mut link) = link {
                        handler.send_packet(link.prove()).await;

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
                }
            }
            DestinationHandleStatus::None => {}
        }
    }
}

async fn handle_check_links<'a>(mut handler: MutexGuard<'a, TransportHandler>) {
    let mut links_to_remove: Vec<AddressHash> = Vec::new();

    // Clean up input links
    for link_entry in &handler.in_links {
        let mut link = link_entry.1.lock().await;
        if link.elapsed() > INTERVAL_INPUT_LINK_CLEANUP {
            link.close();
            links_to_remove.push(*link_entry.0);
        }
    }

    for addr in &links_to_remove {
        handler.in_links.remove(&addr);
    }

    links_to_remove.clear();

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;
        if link.status() == LinkStatus::Closed {
            link.close();
            links_to_remove.push(*link_entry.0);
        }
    }

    for addr in &links_to_remove {
        handler.out_links.remove(&addr);
    }

    for link_entry in &handler.out_links {
        let mut link = link_entry.1.lock().await;

        if link.status() == LinkStatus::Active && link.elapsed() > INTERVAL_OUTPUT_LINK_RESTART {
            link.restart();
        }

        if link.status() == LinkStatus::Pending {
            if link.elapsed() > INTERVAL_OUTPUT_LINK_REPEAT {
                log::warn!(
                    "tp({}): repeat link request {}",
                    handler.config.name,
                    link.id()
                );
                handler.send_packet(link.request()).await;
            }
        }
    }
}

async fn handle_keep_links<'a>(handler: MutexGuard<'a, TransportHandler>) {
    for link in handler.out_links.values() {
        let link = link.lock().await;

        if link.status() == LinkStatus::Active {
            handler.send_packet(link.keep_alive_packet(0xFF)).await;
        }
    }
}

async fn handle_cleanup<'a>(handler: MutexGuard<'a, TransportHandler>) {
    handler.iface_manager.lock().await.cleanup();
}

fn create_retransmit_packet(packet: &Packet) -> Packet {
    Packet {
        header: Header {
            ifac_flag: packet.header.ifac_flag,
            header_type: packet.header.header_type,
            propagation_type: packet.header.propagation_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops + 1,
        },
        ifac: packet.ifac,
        destination: packet.destination,
        transport: packet.transport,
        context: packet.context,
        data: packet.data,
    }
}

async fn manage_transport(
    handler: Arc<Mutex<TransportHandler>>,
    rx_receiver: Arc<Mutex<InterfaceRxReceiver>>,
    iface_messages_tx: broadcast::Sender<RxMessage>,
) {
    let cancel = handler.lock().await.cancel.clone();

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

                        let handler = handler.lock().await;

                        if PACKET_TRACE {
                            log::trace!("tp: << rx({}) = {} {}", message.address, packet, packet.hash());
                        }

                        if handler.config.broadcast {
                            // Send broadcast message expect current iface address
                            handler.send(TxMessage { tx_type: TxMessageType::Broadcast(Some(message.address)), packet }).await;
                        }

                        match packet.header.packet_type {
                            PacketType::Announce => handle_announce(&packet, handler).await,
                            PacketType::LinkRequest => handle_link_request(&packet, handler).await,
                            PacketType::Proof => handle_proof(&packet, handler).await,
                            PacketType::Data => handle_data(&packet, handler).await,
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
                    _ = time::sleep(INTERVAL_LINKS_CHECK) => {
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
                    _ = time::sleep(Duration::from_secs(1)) => {
                        handler.lock().await.packet_cache.lock().await.release(Duration::from_secs(4));
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
                    _ = time::sleep(INTERVAL_OUTPUT_LINK_KEEP) => {
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
                    _ = time::sleep(INTERVAL_IFACE_CLEANUP) => {
                        handle_cleanup(handler.lock().await).await;
                    }
                }
            }
        });
    }
}
