//! Implementation of channels.
//!
//! A [Channel] in Reticulum is an abstraction on top of [Link], primarily for
//! reliable delivery of messages. Each message that is sent through a [Channel]
//! is answered with a receipt, so the sender knows it has been delivered.
//!
//! If the receipt does not arrive in time, the message is sent again.
//! If the receipt still does not arrive after a fixed number of tries, the
//! [Channel] is torn down and the underlying [Link] is closed.
//!
//! [Channel] also guarantees delivery of the messages in the order in which
//! they were sent.
//!
//! This crate defines the [Message] trait and the [Channel] struct.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::{Arc, Weak};
use core::ops::DerefMut;

use tokio::sync::{broadcast, Mutex, MutexGuard, mpsc, Notify};
use tokio::task::spawn;
use tokio::time::{Duration, Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;

use crate::destination::link::{
    LinkEvent, LinkEventData, LinkId, LinkPayload, LinkStatus
};
use crate::error::RnsError;
use crate::hash::Hash;
use crate::packet::{
    DestinationType, PacketContext, PacketDataBuffer, PACKET_MDU
};

#[cfg(not(test))]
use crate::{destination::link::Link, packet::Packet, transport::Transport};

#[cfg(test)]
use mock::{Link, Packet, Transport};

/// Message model for `Channel`.
///
/// Each `Channel` has a type system for its messages. The client opening the
/// channel defines it by implementing this trait. A typical implementation
/// will be an `enum` that has the message types as variants.
pub trait Message: Clone + Send + Sized + Sync + 'static {
    /// Reconstruct a message the channel has received.
    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError>;

    /// The payload of the message as it should be sent over the channel.
    fn pack(&self) -> Vec<u8>;

    /// The type information that channel will include in the message envelope.
    ///
    /// The reference implementation reserves the range `0xff00` to `0xffff` for
    /// "system messages". Although the range is not actually used, we recommend
    /// keeping the convention and not assigning numbers in that range to user-
    /// defined message types.
    fn message_type(&self) -> u16;
}

static SMT_STREAM_DATA: u16 = 0xff00;


async fn outlet_send(
    link: &Arc<Mutex<Link>>,
    raw: &[u8],
    transport: &Arc<Mutex<Transport>>
) -> (Packet, bool) {
    let mut packet;
    let active;

    {
        let link = link.lock().await;
        packet = link.data_packet(raw).unwrap();
        active = link.status() == LinkStatus::Active;
    }

    packet.context = PacketContext::Channel;

    if active {
        transport.lock().await.send_packet(packet).await;
    }

    (packet, active)
}

async fn outlet_resend(
    link: &Arc<Mutex<Link>>,
    packet: Packet,
    transport: Weak<Mutex<Transport>>,
) -> bool {
    if link.lock().await.status() == LinkStatus::Active {
        if let Some(transport) = transport.upgrade() {
            transport.lock().await.send_packet(packet).await;
            return true;
        }
    }

    false
}


async fn outlet_is_usable(link: &Arc<Mutex<Link>>) -> bool {
    link.lock().await.status() == LinkStatus::Active
    // This diverges from the reference implementation. The value is
    // hardcoded to true in the reference implementation, citing
    // "issues looking at Link.status".
}

async fn outlet_timed_out(link: &Arc<Mutex<Link>>) {
    link.lock().await.close();
}

/// Status of a message queried by `Channel::get_message_status`
#[derive(Debug, PartialEq)]
pub enum MessageStatus {
    /// No message of this hash is known
    Unknown,
    /// The message has been queued for sending but could not yet be sent
    Waiting,
    /// The message has been sent the specified number of times,
    /// but we have not received a delivery proof yet.
    Sent(u16),
    /// We have received proof that the message has been delivered.
    Delivered
}

struct Envelope<M: Message> {
    message: M,
    message_type: u16,
    sequence: u16,
}

impl<M: Message> Envelope<M> {
    fn new(message: M, message_type: u16, sequence: u16) -> Self {
        Self { message, message_type, sequence }
    }

    fn unpack(raw: &[u8], link_id: LinkId) -> Result<Self, RnsError> {
        let (message_type, sequence, size) = deenvelope_raw(raw)?;

        if raw.len() as u16 != size + 6 {
            log::trace!(
                "channel: ignoring length field in packed message which doesn't match actual message length."
            );
        }

        let message = M::unpack(&raw[6..], message_type)?;

        Ok(Self::new(message, message_type, sequence))
    }
}

fn envelope_raw(
    data: &[u8],
    message_type: u16,
    sequence: Option<u16>
) -> Vec<u8> {
    let raw_size = data.len();

    let mut enveloped = Vec::<u8>::with_capacity(raw_size + 6);

    enveloped.extend_from_slice(
        message_type.to_be_bytes().as_slice()
    );

    enveloped.extend_from_slice(
        sequence.unwrap_or(0u16).to_be_bytes().as_slice()
    );

    enveloped.extend_from_slice(
        (raw_size as u16).to_be_bytes().as_slice()
    );

    enveloped.extend_from_slice(data);

    enveloped
}


fn deenvelope_raw(data: &[u8]) -> Result<(u16, u16, u16), RnsError>
{
    if data.len() < 6 {
        return Err(RnsError::ChannelError);
    }

    let message_type = u16::from_be_bytes([data[0], data[1]]);
    let sequence = u16::from_be_bytes([data[2], data[3]]);
    let size = u16::from_be_bytes([data[4], data[5]]);

    Ok((message_type, sequence, size))
}

fn message_raw<M: Message>(message: &M, sequence: Option<u16>) -> Vec<u8> {
    let packed = message.pack();
    let message_type = message.message_type();

    envelope_raw(packed.as_ref(), message_type, sequence)
}

fn packet_timeout_time(
    rtt: Duration,
    ring_len: usize,
    tries: u16
) -> Duration {
    let rtt_f32 = rtt.as_secs_f32();
    let rtt_factor = if rtt_f32 >= 0.01 { 2.5 * rtt_f32 } else { 0.025 };

    let tries_factor = 1.5f32.powi(tries.saturating_sub(1) as i32);
    let total = tries_factor * rtt_factor * (ring_len as f32 + 1.5);

    Duration::from_secs_f32(total)
}


static WINDOW: u16 = 2;

static WINDOW_MIN: u16 = 2;
static WINDOW_MIN_LIMIT_SLOW: u16 = 2;
static WINDOW_MIN_LIMIT_MEDIUM: u16  = 5;
static WINDOW_MIN_LIMIT_FAST: u16 = 16;

static WINDOW_MAX_SLOW: u16 = 5;
static WINDOW_MAX_MEDIUM: u16 = 12;
static WINDOW_MAX_FAST: u16 = 48;
static WINDOW_MAX: u16 = WINDOW_MAX_FAST;

static FAST_RATE_THRESHOLD: u16 = 10;

static RTT_FAST: f32 = 0.18;
static RTT_MEDIUM: f32 = 0.75;
static RTT_SLOW: f32 = 1.45;

static WINDOW_FLEXIBILITY: u16 = 4;

static SEQ_MAX: u32 = 0xFFFF;


struct ChannelParams {
    pub max_tries: u16,
    pub fast_rate_rounds: u16,
    pub medium_rate_rounds: u16,
    pub window: u16, 
    pub window_max: u16,
    pub window_min: u16,
    pub window_flexibility: u16
}


impl ChannelParams {
    pub fn new(slow: bool) -> Self {
        Self {
            max_tries: 5,
            fast_rate_rounds: 0,
            medium_rate_rounds: 0,
            window: if slow { 1 } else { WINDOW },
            window_max: if slow { 1 } else { WINDOW_MAX_SLOW },
            window_min: if slow { 1 } else { WINDOW_MIN },
            window_flexibility: if slow { 1 } else { WINDOW_FLEXIBILITY }
        }
    }
}

fn adjust_params(params: &mut MutexGuard<ChannelParams>, rtt: Duration) {
    if params.window < params.window_max {
        params.window += 1
    }

    let rtt = rtt.as_secs_f32();
    if rtt != 0.0 {
        if rtt > RTT_FAST {
            params.fast_rate_rounds = 0;
            if rtt > RTT_MEDIUM {
                params.medium_rate_rounds = 0;
            } else {
                params.medium_rate_rounds += 1;
                if
                    params.window_max < WINDOW_MAX_MEDIUM 
                    && params.medium_rate_rounds == FAST_RATE_THRESHOLD 
                {
                    params.window_max = WINDOW_MAX_MEDIUM;
                    params.window_min = WINDOW_MIN_LIMIT_MEDIUM;
                }
            }
        } else {
            params.fast_rate_rounds += 1;
            if
                params.window_max < WINDOW_MAX_FAST
                && params.fast_rate_rounds == FAST_RATE_THRESHOLD
            {
                params.window_max = WINDOW_MAX_FAST;
                params.window_min = WINDOW_MIN_LIMIT_FAST;
            }
        }
    }
}


fn watch_message_try(
    timeouts: mpsc::Sender<Hash>,
    packet_hash: Hash,
    interval: Duration,
    mut delivery: broadcast::Receiver<bool>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let started = Instant::now();
        let timeout = started + interval;

        loop {
            tokio::select! {
                _ = sleep(timeout - Instant::now()) => {
                    let result = timeouts.send(packet_hash).await;

                    if let Err(e) = result {
                        log::error!(
                            "channel: internal error - could not communicate timeout ({})",
                            e
                        );
                    }

                    break;
                },
                delivered = delivery.recv() => {
                    if let Ok(delivered) = delivered {
                        if delivered {
                            break;
                        }
                    };
                },
                _ = cancel.cancelled() => {
                    break;
                }
            }
        }
    });
}

struct SentMessage {
    pub packet: Packet,
    pub delivered: broadcast::Sender<bool>,
    pub tries: u16,
}

struct Inbound<M: Message> {
    on_hold: BTreeMap<u16, M>,
    incoming: broadcast::Sender<M>,
    sequence: u16,
    link_id: LinkId,
}


impl<M: Message> Inbound<M> {
    fn new(link_id: LinkId) -> Self {
        Self {
            on_hold: BTreeMap::new(),
            incoming: broadcast::Sender::new(16),
            sequence: 0u16,
            link_id,
        }
    }

    fn get_incoming(&self) -> broadcast::Sender<M> {
        self.incoming.clone()
    }

    pub async fn receive(&mut self, raw: &[u8]) {
        log::trace!("channel({}) received {}B", self.link_id, raw.len());

        let envelope = match Envelope::<M>::unpack(raw, self.link_id) {
            Ok(env) => env,
            Err(e) => {
                log::error!("channel({}): error unpacking message", self.link_id);
                return;
            }
        };

        let sequence = envelope.sequence;

        if sequence < self.sequence {
            let overflow = sequence.saturating_add(WINDOW_MAX);

            if overflow >= self.sequence || sequence > overflow {
                log::trace!("channel({}): received packet out of sequence window", self.link_id);
                return;
            }
        }

        let replaced = self.on_hold.insert(sequence, envelope.message);

        if replaced.is_some() {
            log::trace!("channel({}): duplicate message received", self.link_id);
        }

        while let Some(message) = self.on_hold.remove(&self.sequence) {
            let result = self.incoming.send(message);

            if let Err(e) = result {
                log::error!(
                    "channel({}): could not propagate incoming message to client: {}",
                    self.link_id,
                    e
                );
            }

            self.sequence = self.sequence.wrapping_add(1);
        }
    }
}


struct Outbound {
    transport: Weak<Mutex<Transport>>,
    outlet: Arc<Mutex<Link>>,
    link_id: LinkId,
    sent_messages: BTreeMap<Hash, SentMessage>,
    delivered: BTreeSet<Hash>,
    next_sequence: u16,
    params: Arc<Mutex<ChannelParams>>,
    timeouts_tx: mpsc::Sender<Hash>,
    cancel: CancellationToken,
}


impl Outbound {
    async fn new(
        outlet: Arc<Mutex<Link>>,
        transport: Arc<Mutex<Transport>>,
        timeouts_tx: mpsc::Sender<Hash>,
    ) -> Self {
        let slow = outlet.lock().await.rtt().as_secs_f32() > RTT_SLOW;
        let params = Arc::new(Mutex::new(ChannelParams::new(slow)));
        let link_id = *outlet.lock().await.id();

        Self {
            transport: Arc::downgrade(&transport),
            outlet,
            link_id,
            sent_messages: BTreeMap::new(),
            delivered: BTreeSet::new(),
            next_sequence: 0,
            params,
            timeouts_tx,
            cancel: CancellationToken::new(),
        }
    }

    pub fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub (crate) fn link_id(&self) -> LinkId {
        self.link_id
    }

    pub fn params(&self) -> Weak<Mutex<ChannelParams>> {
        Arc::downgrade(&self.params)
    }

    pub fn outlet(&self) -> Weak<Mutex<Link>> {
        Arc::downgrade(&self.outlet)
    }

    async fn is_ready_to_send(&self) -> bool {
        if self.cancel.is_cancelled() {
            return false;
        }

        if !outlet_is_usable(&self.outlet).await {
            return false
        }

        let outstanding = self.sent_messages.len();
        let window = self.params.lock().await.window as usize;

        outstanding < window
    }

    async fn handle_proof(&mut self, packet_hash: Hash) {
        let sent_message = match self.sent_messages.remove(&packet_hash) {
            Some(m) => m,
            None => {
                log::trace!(
                    "channel({}): ignoring delivery proof for unknown message {}",
                    self.link_id,
                    packet_hash
                );
                return;
            }
        };

        let rtt = *self.outlet.lock().await.rtt();
        adjust_params(&mut self.params.lock().await, rtt);

        self.delivered.insert(packet_hash);

        let result = sent_message.delivered.send(true);

        if let Err(e) = result {
            log::error!(
                "channel({}): could not send delivery notice for message {} ({})",
                self.link_id,
                packet_hash,
                e
            );
        }
    }

    async fn handle_timeout(&mut self, packet_hash: Hash) {
        let packet;
        let mut tries;

        let max_tries = self.params.lock().await.max_tries;

        if let Some(entry) = self.sent_messages.get(&packet_hash) {
            tries = entry.tries;

            if tries >= max_tries {
                self.teardown().await;
                return;
            }

            packet = entry.packet.clone();
        } else {
            log::error!(
                "channel({}) internal error: timeout set for unknown message {}",
                self.link_id,
                packet_hash
            );
            return;
        }

        let sent = outlet_resend(
            &self.outlet,
            packet,
            self.transport.clone()
        ).await;

        if !sent {
            log::error!(
                "channel ({}): failed to resend message {}",
                self.link_id,
                packet_hash
            );
        }

        tries += 1;

        self.schedule_timeout(packet_hash, tries).await;

        self.sent_messages.get_mut(&packet_hash).unwrap().tries = tries;
    }

    async fn schedule_timeout(&self, packet_hash: Hash, tries: u16) {
        let sent_message = self.sent_messages.get(&packet_hash).unwrap();

        let rtt = *self.outlet.lock().await.rtt();
        let ring_len = self.sent_messages.len();

        let timeout = packet_timeout_time(rtt, ring_len, sent_message.tries);

        let delivery = sent_message.delivered.subscribe();

        watch_message_try(
            self.timeouts_tx.clone(),
            packet_hash,
            timeout,
            delivery,
            self.cancel.clone()
        );
    }

    async fn teardown(&mut self) {
        log::info!("channel({}): message timed out, tearing down channel", self.link_id);
        outlet_timed_out(&self.outlet).await;
    }

    pub async fn send<M: Message>(&mut self, message: &M) -> Result<Hash, RnsError> {
        let transport = match self.transport.upgrade() {
            Some(t) => t,
            None => {
                return Err(RnsError::ChannelLinkNotReady);
            }
        };

        if !self.is_ready_to_send().await {
            return Err(RnsError::ChannelLinkNotReady);
        }

        let sequence = self.next_sequence;

        self.next_sequence = self.next_sequence.wrapping_add(1);

        let packet_hash;
        {
            let raw = message_raw(message, Some(sequence));

            if raw.len() > PACKET_MDU as usize {
                return Err(RnsError::ChannelMessageTooBig);
            }

            let (packet, sent) = outlet_send(&self.outlet, &raw, &transport).await;
            packet_hash = packet.hash();

            let (delivery_tx, delivery_rx) = broadcast::channel(1);

            if sent {
                let sent_message = SentMessage {
                    packet: packet.clone(),
                    delivered: delivery_tx,
                    tries: 1,
                };

                self.sent_messages.insert(packet_hash, sent_message);
            }

            let tries = if sent { 1 } else { 0 };
            let rtt = *self.outlet.lock().await.rtt();

            let ring_len = self.sent_messages.len();
            let timeout = packet_timeout_time(rtt, ring_len, tries);

            watch_message_try(
                self.timeouts_tx.clone(),
                packet_hash,
                timeout,
                delivery_rx,
                self.cancel.clone(),
            );
        }

        Ok(packet_hash)
    }

    pub async fn watch_delivery(
        &mut self,
        packet_hash: Hash
    ) -> Option<broadcast::Receiver<bool>> {
        self.sent_messages.get(&packet_hash).map(|s| s.delivered.subscribe())
    }

    pub async fn mdu(&self) -> usize {
        PACKET_MDU - 6
    }

    pub async fn get_status(&self, packet_hash: &Hash) -> MessageStatus {
        match self.sent_messages.get(&packet_hash) {
            Some(sent_message) => {
                let tries = sent_message.tries;
                if tries == 0 {
                    MessageStatus::Waiting
                } else {
                    MessageStatus::Sent(tries)
                }
            },
            None => {
                if self.delivered.contains(&packet_hash) {
                    MessageStatus::Delivered
                } else {
                    MessageStatus::Unknown
                }
            }
        }
    }
}


async fn spawn_watch_outbound(
    outbound: Arc<Mutex<Outbound>>,
    mut out_link_events: broadcast::Receiver<LinkEventData>,
    mut timeouts_rx: mpsc::Receiver<Hash>,
) {
    let cancel = outbound.lock().await.cancel();
    let our_link_id = outbound.lock().await.link_id();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event_data = out_link_events.recv() => {
                    let event_data = match event_data {
                        Ok(ev) => ev,
                        Err(err) => {
                            log::warn!(
                                "channel({}): error {} watching outlink events, may miss delivery proofs",
                                our_link_id,
                                err
                            );
                            return;
                        }
                    };

                    if event_data.id == our_link_id {
                        if let LinkEvent::Proof(hash) = event_data.event {
                            outbound.lock().await.handle_proof(hash).await;
                        }
                    }
                },

                timed_out = timeouts_rx.recv() => {
                    if let Some(hash) = timed_out {
                        outbound.lock().await.handle_timeout(hash).await;
                    }
                },

                _ = cancel.cancelled() => {
                    break;
                }
            }
        }
    });
}


async fn spawn_receiver<M: Message>(
    mut rx: broadcast::Receiver<LinkPayload>,
    out_link_events: broadcast::Receiver<LinkEventData>,
    our_link_id: LinkId,
    cancel: CancellationToken,
) -> broadcast::Sender<M> {
    let mut inbound = Inbound::new(our_link_id);
    let incoming = inbound.get_incoming();

    tokio::spawn(async move {
        loop {
            tokio::select!{
                received = rx.recv() => {
                    match received {
                        Ok(payload) => inbound.receive(payload.as_slice()).await,
                        Err(err) => {
                            log::error!(
                                "channel({}): error {} getting inbound message from link",
                                our_link_id,
                                err
                            );
                            continue;
                        }
                    }
                },

                _ = cancel.cancelled() => {
                    break;
                },
            }
        }
    });

    incoming
}


/// The main object.
///
/// Notice that wrapping a [Link] into a [Channel] is a local action; it
/// happens in one node and is not communicated to the other side.
/// It is up to the client to know which links are supposed to be channels.
///
/// Channel messages have a specific packet context, however, so if only one
/// side opens a channel, the other side will reject all subsequent messages.
pub struct Channel<M: Message> {
    link: Arc<Mutex<Link>>,
    outbound: Arc<Mutex<Outbound>>,
    incoming: broadcast::Sender<M>,
}


impl<M: Message> Channel<M> {
    /// Consume `link` and wrap it in a new `Channel`.
    ///
    /// Fails if there is already a `Channel` wrapping `link`.
    pub async fn new(
        link: Arc<Mutex<Link>>,
        transport: &Arc<Mutex<Transport>>
    ) -> Result<Self, RnsError> {
        let out_link_events = transport.lock().await.out_link_events();

        let (me_tx, me_rx) = mpsc::channel(16);

        let outbound = Outbound::new(
            Arc::clone(&link),
            Arc::clone(transport),
            me_tx
        ).await;

        let link_id = outbound.link_id();
        let cancel = outbound.cancel();

        let outbound = Arc::new(Mutex::new(outbound));

        spawn_watch_outbound(
            Arc::clone(&outbound),
            out_link_events.resubscribe(),
            me_rx
        ).await;

        let rx = link.lock().await.bind_to_channel()?;

        let incoming = spawn_receiver(rx, out_link_events, link_id, cancel).await;

        Ok(Self { link, outbound, incoming })
    }

    /// Send a message over the channel.
    ///
    /// Fails if the channel is not ready to send. If successful, it returns
    /// the `Hash` with which the message can be identified.
    pub async fn send(&self, message: &M) -> Result<Hash, RnsError> {
        self.outbound.lock().await.send(message).await
    }

    /// Get notified when a specific message's delivery is confirmed.
    pub async fn watch_message_delivery(
        &self,
        packet_hash: Hash
    ) -> Option<broadcast::Receiver<bool>> {
        self.outbound.lock().await.watch_delivery(packet_hash).await
    }

    /// Query the status of a message.
    pub async fn message_status(&self, packet_hash: &Hash) -> MessageStatus {
        self.outbound.lock().await.get_status(&packet_hash).await
    }

    /// Returns `true` if the channel is currently ready to send another
    /// message.
    ///
    /// That is the case if the underlying link is active and the channel
    /// window is not full, i. e. not too many messages are awaiting
    /// delivery.
    pub async fn is_ready(&self) -> bool {
        self.outbound.lock().await.is_ready_to_send().await
    }

    /// Subscribe to the channel's incoming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<M> {
        self.incoming.subscribe()
    }

    pub fn get_link(&self) -> Arc<Mutex<Link>> {
        Arc::clone(&self.link)
    }
}

#[cfg(test)]
mod mock {
    use alloc::sync::Arc;

    use rand_core::OsRng;

    use tokio::sync::{broadcast, Mutex};
    use tokio::time::Duration;

    use crate::destination::{DestinationName, SingleInputDestination};
    use crate::destination::link::{
        LinkEvent, LinkEventData, LinkId, LinkPayload, LinkStatus
    };
    use crate::error::RnsError;
    use crate::hash::{AddressHash, Hash};
    use crate::packet::{PacketContext, PacketDataBuffer};

    #[derive(Clone, Copy)]
    pub struct Packet {
        pub data: PacketDataBuffer,
        pub id: LinkId,
        pub context: PacketContext,
    }

    impl Packet {
        pub fn new(raw: &[u8], id: LinkId) -> Self {
            Self {
                data: PacketDataBuffer::new_from_slice(raw),
                id,
                context: PacketContext::None
            }
        }

        pub fn hash(&self) -> Hash {
            Hash::new_from_slice(self.data.as_slice())
        }

        pub fn payload(&self) -> LinkPayload {
            LinkPayload::new_from_slice(self.data.as_slice())
        }

        pub fn prove(&self) -> LinkEventData {
            LinkEventData {
                id: self.id,
                address_hash: AddressHash::new_empty(),
                event: LinkEvent::Proof(self.hash())
            }
        }
    }

    #[derive(Clone)]
    pub struct Link {
        pub id: LinkId,
        pub rtt: Duration,
        pub status: LinkStatus,
        pub tx: broadcast::Sender<LinkPayload>,
        pub bound: bool
    }

    impl Link {
        pub fn new(status: LinkStatus) -> Self {
            let id = LinkId::new_from_rand(OsRng);
            let rtt = Duration::from_millis(20);
            let tx = broadcast::Sender::new(16);
            Self { id, rtt, status, tx, bound: false }
        }

        pub fn rtt(&self) -> &Duration {
            &self.rtt
        }

        pub fn id(&self) -> &LinkId {
            &self.id
        }

        pub fn status(&self) -> LinkStatus {
            self.status
        }

        pub fn data_packet(&self, raw: &[u8]) -> Result<Packet, RnsError> {
            Ok(Packet::new(raw, self.id))
        }

        pub fn close(&mut self) {
            self.status = LinkStatus::Closed;
        }

        pub fn bind_to_channel(
            &mut self
        ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
            if self.bound {
                return Err(RnsError::ChannelError);
            }

            self.bound = true;
            Ok(self.tx.subscribe())
        }
    }

    pub struct Transport {
        pub in_tx: broadcast::Sender<LinkEventData>,
        pub out_tx: broadcast::Sender<LinkEventData>,
        packets: Arc<Mutex<Vec<Packet>>>
        // the Arc<Mutex<...>> here is a hack so send_packet()
        // does not neet a mutable reference to self
    }

    impl Transport {
        pub fn new() -> Self {
            Self {
                in_tx: broadcast::Sender::new(16),
                out_tx: broadcast::Sender::new(16),
                packets: Arc::new(Mutex::new(Vec::new())),
            }
        }

        // mocked methods
        pub fn out_link_events(&self) -> broadcast::Receiver<LinkEventData> {
            self.out_tx.subscribe()
        }

        pub async fn send_packet(&self, packet: Packet) {
            self.packets.lock().await.push(packet);
        }

        // helper method
        pub async fn packets(&self) -> Vec<Packet> {
            self.packets.lock().await.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand_core::OsRng;

    #[test]
    fn test_envelope_raw() {
        let data = vec![ 0x43, 0x11, 0x00 ];
        let env = envelope_raw(data.as_slice(), 0x1000, Some(10));

        assert_eq!(
            env,
            vec![0x10, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x43, 0x11, 0x00]
        );
    }

    struct Fixture {
        pub link_a: Arc<Mutex<Link>>,
        pub link_b: Arc<Mutex<Link>>,
        pub transport_a: Arc<Mutex<Transport>>,
        pub transport_b: Arc<Mutex<Transport>>,
    }

    impl Fixture {
        pub fn new() -> Self {
            Self {
                link_a: Arc::new(Mutex::new(Link::new(LinkStatus::Active))),
                link_b: Arc::new(Mutex::new(Link::new(LinkStatus::Active))),
                transport_a: Arc::new(Mutex::new(Transport::new())),
                transport_b: Arc::new(Mutex::new(Transport::new())),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    enum TestMessage {
        Long(u64),
        Short(u32)
    }

    impl Message for TestMessage {
        fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError> {
            if message_type == 1 {
                if let Ok(a) = <[u8; 8]>::try_from(packed) {
                    return Ok(Self::Long(u64::from_le_bytes(a)));
                }
            } else if message_type == 2 {
                if let Ok(a) = <[u8; 4]>::try_from(packed) {
                    return Ok(Self::Short(u32::from_le_bytes(a)));
                }
            }

            Err(RnsError::ChannelUnknownMessageType)
        }

        fn pack(&self) -> Vec<u8> {
            match self {
                Self::Long(x) => x.to_le_bytes().to_vec(),
                Self::Short(x) => x.to_le_bytes().to_vec()
            }
        }

        fn message_type(&self) -> u16 {
            match self {
                Self::Long(_) => 1,
                Self::Short(_) => 2,
            }
        }
    }

    #[tokio::test]
    async fn test_message_delivery() {
        let fixture = Fixture::new();

        let channel_a = Channel::<TestMessage>::new(
            fixture.link_a.clone(),
            &fixture.transport_a
        ).await.unwrap();

        let channel_b = Channel::<TestMessage>::new(
            fixture.link_b.clone(),
            &fixture.transport_b
        ).await.unwrap();

        let packet_hash = channel_a.send(&TestMessage::Short(1377)).await.unwrap();

        let packets = fixture.transport_a.lock().await.packets().await;
        assert_eq!(packets.len(), 1);

        let packet = packets[0];

        assert_eq!(
            channel_a.message_status(&packet_hash).await,
            MessageStatus::Sent(1)
        );

        let mut delivered = channel_a
            .watch_message_delivery(packet_hash)
            .await
            .expect("message not found in channel a");

        let mut incoming_b = channel_b.subscribe();

        fixture.link_b.lock().await.tx.send(packet.payload()).unwrap();

        let incoming = incoming_b.recv().await.expect("expected incoming message");
        assert_eq!(incoming, TestMessage::Short(1377));

        assert!(delivered.is_empty());

        let proof = packet.prove();

        fixture.transport_a.lock().await.out_tx.send(proof).unwrap();

        assert!(delivered.recv().await.unwrap());

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            channel_a.message_status(&packet_hash).await,
            MessageStatus::Delivered
        );
    }

    #[tokio::test]
    async fn test_message_failure() {
        let fixture = Fixture::new();

        let channel_a = Channel::<TestMessage>::new(
            fixture.link_a.clone(),
            &fixture.transport_a
        ).await.unwrap();

        let packet_hash = channel_a.send(&TestMessage::Short(1)).await.unwrap();

        let mut delivered = channel_a
            .watch_message_delivery(packet_hash)
            .await
            .expect("message not found in channel a");

        tokio::time::sleep(Duration::from_secs(3)).await;

        let packets = fixture.transport_a.lock().await.packets().await;
        assert_eq!(packets.len(), 5);

        assert_eq!(
            fixture.link_a.lock().await.status(),
            LinkStatus::Closed
        );

        assert!(delivered.is_empty());

        assert!(!channel_a.is_ready().await);
    }

    #[tokio::test]
    async fn test_channel_not_ready() {
        let fixture = Fixture::new();
        fixture.link_a.lock().await.status = LinkStatus::Pending;

        let channel_a = Channel::<TestMessage>::new(
            fixture.link_a.clone(),
            &fixture.transport_a
        ).await.unwrap();

        assert!(!channel_a.is_ready().await);

        let result = channel_a.send(&TestMessage::Short(0)).await;
        assert_eq!(result, Err(RnsError::ChannelLinkNotReady));

        fixture.link_a.lock().await.status = LinkStatus::Active;

        assert!(channel_a.is_ready().await);

        channel_a.send(&TestMessage::Short(1)).await.unwrap();
        channel_a.send(&TestMessage::Short(2)).await.unwrap();

        let packets = fixture.transport_a.lock().await.packets().await;
        assert_eq!(packets.len(), 2);

        // now the channel should again not be ready as the window is full
        // (too many messages already awaiting delivery)
        assert!(!channel_a.is_ready().await);

        let result = channel_a.send(&TestMessage::Short(3)).await;
        assert_eq!(result, Err(RnsError::ChannelLinkNotReady));
    }

    #[tokio::test]
    async fn test_messages_ordering() {
        let fixture = Fixture::new();

        let channel_a = Channel::<TestMessage>::new(
            fixture.link_a.clone(),
            &fixture.transport_a
        ).await.unwrap();

        let channel_b = Channel::<TestMessage>::new(
            fixture.link_b.clone(),
            &fixture.transport_b
        ).await.unwrap();

        let mut incoming_b = channel_b.subscribe();

        channel_a.send(&TestMessage::Short(1)).await.unwrap();

        let packets = fixture.transport_a.lock().await.packets().await;
        fixture.link_b.lock().await.tx.send(packets[0].payload()).unwrap();

        let first = incoming_b.recv().await.unwrap();
        assert_eq!(first, TestMessage::Short(1));

        fixture.transport_a.lock().await.out_tx.send(packets[0].prove()).unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        channel_a.send(&TestMessage::Short(2)).await.unwrap();
        channel_a.send(&TestMessage::Short(3)).await.unwrap();

        let packets = fixture.transport_a.lock().await.packets().await;
        fixture.link_b.lock().await.tx.send(packets[2].payload()).unwrap();

        // packets have been sent in wrong order:
        // third packet will be on hold until the second one has been received.
        assert!(incoming_b.is_empty());

        fixture.link_b.lock().await.tx.send(packets[1].payload()).unwrap();

        let second = incoming_b.recv().await.unwrap();
        let third = incoming_b.recv().await.unwrap();

        assert_eq!(second, TestMessage::Short(2));
        assert_eq!(third, TestMessage::Short(3));

        fixture.transport_a.lock().await.out_tx.send(packets[1].prove()).unwrap();

        channel_a.send(&TestMessage::Short(4)).await.unwrap();

        let packets = fixture.transport_a.lock().await.packets().await;
        fixture.link_b.lock().await.tx.send(packets[3].payload()).unwrap();

        let fourth = incoming_b.recv().await.unwrap();
        assert_eq!(fourth, TestMessage::Short(4));
    }

    #[tokio::test]
    async fn test_missing_message() {
        let fixture = Fixture::new();

        let channel_a = Channel::<TestMessage>::new(
            fixture.link_a.clone(),
            &fixture.transport_a
        ).await.unwrap();

        let channel_b = Channel::<TestMessage>::new(
            fixture.link_b.clone(),
            &fixture.transport_b
        ).await.unwrap();

        let mut incoming_b = channel_b.subscribe();

        channel_a.send(&TestMessage::Long(50)).await.unwrap();
        channel_a.send(&TestMessage::Long(50)).await.unwrap();

        let packets = fixture.transport_a.lock().await.packets().await;

        fixture.link_b.lock().await.tx.send(packets[1].payload()).unwrap();

        tokio::time::sleep(Duration::from_secs(3)).await;

        assert!(incoming_b.is_empty());
    }
}
