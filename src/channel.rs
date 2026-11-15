//! Implementation of channels.
//!
//! A [Channel] in Reticulum is an abstraction on top of [Link], primarily for
//! reliable delivery of messages. Each message that is sent through a [Channel]
//! is answered with a receipt, so the sender knows it has been delivered.
//!
//! If the receipt does not arrive in time, the message is sent again and the
//! send window shrinks the way Python `Channel._packet_timeout` does.
//! If the receipt still does not arrive after a fixed number of tries, the
//! [Channel] is torn down and the underlying [Link] is closed.
//!
//! [Channel] also guarantees delivery of the messages in the order in which
//! they were sent.
//!
//! This module defines the [Message] trait and the [Channel] struct.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::{Arc, Weak};
use std::sync::Mutex as StdMutex;

use tokio::sync::{broadcast, mpsc, Mutex, MutexGuard};
use tokio::time::{sleep, Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::destination::link::{LinkEvent, LinkEventData, LinkId, LinkPayload, LinkStatus};
use crate::error::RnsError;
use crate::hash::Hash;
use crate::packet::PacketContext;

#[cfg(not(test))]
use crate::{
    destination::link::Link,
    packet::Packet,
    transport::{Transport, TransportHandler},
};

#[cfg(test)]
use mock::{Link, Packet, Transport, TransportHandler};

/// Default message payload budget at the protocol MTU.
///
/// Python `Channel.mdu` is `link.mdu - 6` (the envelope header). This
/// constant is that value when the link MTU is [`crate::packet::PROTOCOL_MTU`]
/// (425). A live link may negotiate a larger MTU; [`Channel::mdu`] also
/// refuses to advertise a payload whose envelope's Fernet token would not
/// fit in [`crate::packet::PACKET_MDU`].
pub const CHANNEL_MDU: usize = crate::packet::LINK_MDU - 6;

/// Largest link plaintext whose Fernet token fits in `PACKET_MDU`.
///
/// The token is IV + PKCS7(plaintext) + HMAC (`TOKEN_OVERHEAD` plus at
/// least one padding byte). A discovered MTU can be far larger than the
/// packet buffer; channel sends must not aim past what `encrypt` can write.
fn max_link_plaintext() -> usize {
    let room = crate::packet::PACKET_MDU.saturating_sub(crate::packet::TOKEN_OVERHEAD);
    let max_cipher = room / crate::packet::AES128_BLOCKSIZE * crate::packet::AES128_BLOCKSIZE;
    max_cipher.saturating_sub(1)
}

/// Message types at or above this value are reserved for system messages
/// (Python `MessageBase`: `MSGTYPE >= 0xf000`). `0xff00` is the buffer
/// stream type.
pub const MSGTYPE_SYSTEM_MIN: u16 = 0xf000;

/// Message model for `Channel`.
///
/// Each `Channel` has a primary type for its messages. The client opening the
/// channel defines it by implementing this trait. A typical implementation
/// will be an `enum` that has the message types as variants. Additional types,
/// including system type `0xff00`, can be registered on the same channel.
pub trait Message: Clone + Send + Sized + Sync + 'static {
    /// Reconstruct a message the channel has received.
    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError>;

    /// The payload of the message as it should be sent over the channel.
    fn pack(&self) -> Vec<u8>;

    /// The type information that channel will include in the message envelope.
    ///
    /// Types `>= `[`MSGTYPE_SYSTEM_MIN`] are reserved. They can be sent like
    /// any other message, but receiving them on a channel whose primary type
    /// does not unpack them requires
    /// [`Channel::register_message_type`] with `system` set.
    fn message_type(&self) -> u16;
}

async fn outlet_send(
    link: &Arc<Mutex<Link>>,
    raw: &[u8],
    transport: &Arc<Mutex<TransportHandler>>,
) -> Result<(Packet, bool), RnsError> {
    let (mut packet, active) = {
        let link = link.lock().await;
        let packet = link.data_packet(raw)?;
        (packet, link.status() == LinkStatus::Active)
    };

    packet.context = PacketContext::Channel;

    if active {
        transport.lock().await.send_packet(packet.clone()).await;
    }

    Ok((packet, active))
}

async fn outlet_resend(
    link: &Arc<Mutex<Link>>,
    packet: Packet,
    transport: Weak<Mutex<TransportHandler>>,
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
    Delivered,
}

fn envelope_raw(data: &[u8], message_type: u16, sequence: Option<u16>) -> Vec<u8> {
    let raw_size = data.len();

    let mut enveloped = Vec::<u8>::with_capacity(raw_size + 6);

    enveloped.extend_from_slice(message_type.to_be_bytes().as_slice());

    enveloped.extend_from_slice(sequence.unwrap_or(0u16).to_be_bytes().as_slice());

    enveloped.extend_from_slice((raw_size as u16).to_be_bytes().as_slice());

    enveloped.extend_from_slice(data);

    enveloped
}

fn deenvelope_raw(data: &[u8]) -> Result<(u16, u16, u16), RnsError> {
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

fn packet_timeout_time(rtt: Duration, ring_len: usize, tries: u16) -> Duration {
    let rtt_f32 = rtt.as_secs_f32();
    let rtt_factor = if rtt_f32 >= 0.01 {
        2.5 * rtt_f32
    } else {
        0.025
    };

    let tries_factor = 1.5f32.powi(tries.saturating_sub(1) as i32);
    let total = tries_factor * rtt_factor * (ring_len as f32 + 1.5);

    Duration::from_secs_f32(total)
}

const WINDOW: u16 = 2;

const WINDOW_MIN: u16 = 2;
const WINDOW_MIN_LIMIT_MEDIUM: u16 = 5;
const WINDOW_MIN_LIMIT_FAST: u16 = 16;

const WINDOW_MAX_SLOW: u16 = 5;
const WINDOW_MAX_MEDIUM: u16 = 12;
const WINDOW_MAX_FAST: u16 = 48;
const WINDOW_MAX: u16 = WINDOW_MAX_FAST;

const FAST_RATE_THRESHOLD: u16 = 10;

const RTT_FAST: f32 = 0.18;
const RTT_MEDIUM: f32 = 0.75;
const RTT_SLOW: f32 = 1.45;

/// Strict extra gap required before a timeout decrements `window_max`.
///
/// `window` itself shrinks by one whenever it is above `window_min`.
/// `window_max` shrinks by one only while
/// `window_max > window_min + WINDOW_FLEXIBILITY`. The initial window
/// (`window_max` 5, `window_min` 2) is already tighter than this gap, so
/// a timeout there does not move `window_max`. A link with RTT above
/// `RTT_SLOW` stores flexibility 1, not this constant.
const WINDOW_FLEXIBILITY: u16 = 4;

struct ChannelParams {
    pub max_tries: u16,
    pub fast_rate_rounds: u16,
    pub medium_rate_rounds: u16,
    pub window: u16,
    pub window_max: u16,
    pub window_min: u16,
    pub window_flexibility: u16,
}

impl ChannelParams {
    pub fn new(slow: bool) -> Self {
        if slow {
            // Python uses a fixed window of 1 when RTT is above `RTT_SLOW`.
            Self {
                max_tries: 5,
                fast_rate_rounds: 0,
                medium_rate_rounds: 0,
                window: 1,
                window_max: 1,
                window_min: 1,
                window_flexibility: 1,
            }
        } else {
            Self {
                max_tries: 5,
                fast_rate_rounds: 0,
                medium_rate_rounds: 0,
                window: WINDOW,
                window_max: WINDOW_MAX_SLOW,
                window_min: WINDOW_MIN,
                window_flexibility: WINDOW_FLEXIBILITY,
            }
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
                if params.window_max < WINDOW_MAX_MEDIUM
                    && params.medium_rate_rounds == FAST_RATE_THRESHOLD
                {
                    params.window_max = WINDOW_MAX_MEDIUM;
                    params.window_min = WINDOW_MIN_LIMIT_MEDIUM;
                }
            }
        } else {
            params.fast_rate_rounds += 1;
            if params.window_max < WINDOW_MAX_FAST && params.fast_rate_rounds == FAST_RATE_THRESHOLD
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

/// One ordered inbound envelope. Registered types share the sequence
/// space with the channel's primary message type.
enum Held<M: Message> {
    Primary(M),
    Registered {
        tx: broadcast::Sender<Vec<u8>>,
        payload: Vec<u8>,
    },
}

type TypeRegistry = BTreeMap<u16, broadcast::Sender<Vec<u8>>>;

struct Inbound<M: Message> {
    on_hold: BTreeMap<u16, Held<M>>,
    incoming: broadcast::Sender<M>,
    registry: Arc<StdMutex<TypeRegistry>>,
    sequence: u16,
    link_id: LinkId,
}

impl<M: Message> Inbound<M> {
    fn new(link_id: LinkId, registry: Arc<StdMutex<TypeRegistry>>) -> Self {
        Self {
            on_hold: BTreeMap::new(),
            incoming: broadcast::Sender::new(16),
            registry,
            sequence: 0u16,
            link_id,
        }
    }

    fn get_incoming(&self) -> broadcast::Sender<M> {
        self.incoming.clone()
    }

    pub async fn receive(&mut self, raw: &[u8]) {
        log::trace!("channel({}) received {}B", self.link_id, raw.len());

        let (message_type, sequence, size) = match deenvelope_raw(raw) {
            Ok(parts) => parts,
            Err(_) => {
                log::error!("channel({}): error unpacking message", self.link_id);
                return;
            }
        };

        if raw.len() as u16 != size + 6 {
            log::trace!(
                "channel: ignoring length field in packed message which doesn't match actual message length."
            );
        }

        let payload = raw[6..].to_vec();

        if sequence < self.sequence {
            let overflow = sequence.saturating_add(WINDOW_MAX);

            if overflow >= self.sequence || sequence > overflow {
                log::trace!(
                    "channel({}): received packet out of sequence window",
                    self.link_id
                );
                return;
            }
        }

        let registered_tx = self
            .registry
            .lock()
            .ok()
            .and_then(|registry| registry.get(&message_type).cloned());
        let held = if let Some(tx) = registered_tx {
            Held::Registered { tx, payload }
        } else {
            match M::unpack(&payload, message_type) {
                Ok(message) => Held::Primary(message),
                Err(_) => {
                    log::error!("channel({}): error unpacking message", self.link_id);
                    return;
                }
            }
        };

        let replaced = self.on_hold.insert(sequence, held);

        if replaced.is_some() {
            log::trace!("channel({}): duplicate message received", self.link_id);
        }

        while let Some(held) = self.on_hold.remove(&self.sequence) {
            match held {
                Held::Primary(message) => {
                    if self.incoming.send(message).is_err() {
                        log::warn!(
                            "channel({}): received a message that will not be processed (no subscribers)",
                            self.link_id,
                        );
                    }
                }
                Held::Registered { tx, payload } => {
                    if tx.send(payload).is_err() {
                        log::warn!(
                            "channel({}): received a registered message that will not be processed (no subscribers)",
                            self.link_id,
                        );
                    }
                }
            }

            self.sequence = self.sequence.wrapping_add(1);
        }
    }
}

struct Outbound {
    transport: Weak<Mutex<TransportHandler>>,
    outlet: Arc<Mutex<Link>>,
    link_id: LinkId,
    sent_messages: BTreeMap<Hash, SentMessage>,
    delivered: BTreeSet<Hash>,
    next_sequence: u16,
    params: Arc<Mutex<ChannelParams>>,
    timeouts_tx: mpsc::Sender<Hash>,
    cancel: CancellationToken,
    /// Hash of the most recently sent, not-yet-delivered message
    /// (for stream backpressure).
    last_pending: Option<Hash>,
}

impl Outbound {
    async fn new(
        outlet: Arc<Mutex<Link>>,
        transport: Arc<Mutex<TransportHandler>>,
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
            last_pending: None,
        }
    }

    /// Receiver for the delivery receipt of the most recently sent message
    /// (stream backpressure). Returns `None` when nothing is pending.
    async fn last_pending_receipt(&mut self) -> Option<broadcast::Receiver<bool>> {
        let hash = self.last_pending?;
        self.watch_delivery(hash).await
    }

    pub fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub(crate) fn link_id(&self) -> LinkId {
        self.link_id
    }

    async fn is_ready_to_send(&self) -> bool {
        if self.cancel.is_cancelled() {
            return false;
        }

        if !outlet_is_usable(&self.outlet).await {
            return false;
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
        if self.last_pending == Some(packet_hash) {
            self.last_pending = None;
        }

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

        // Python `Channel._packet_timeout`: shrink `window` whenever it is
        // above `window_min`. Shrink `window_max` only while it exceeds
        // `window_min + window_flexibility`.
        {
            let mut params = self.params.lock().await;
            if params.window > params.window_min {
                params.window -= 1;
                if params.window_max > params.window_min.saturating_add(params.window_flexibility) {
                    params.window_max -= 1;
                }
            }
        }

        let sent = outlet_resend(&self.outlet, packet, self.transport.clone()).await;

        if !sent {
            log::error!(
                "channel ({}): failed to resend message {}",
                self.link_id,
                packet_hash
            );
        }

        // Python increments `envelope.tries` before computing the next
        // timeout, so the backoff uses the post-increment count.
        tries += 1;
        self.sent_messages.get_mut(&packet_hash).unwrap().tries = tries;

        self.schedule_timeout(packet_hash).await;
    }

    async fn schedule_timeout(&self, packet_hash: Hash) {
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
            self.cancel.clone(),
        );
    }

    async fn teardown(&mut self) {
        log::info!(
            "channel({}): message timed out, tearing down channel",
            self.link_id
        );

        if let Some(transport) = self.transport.upgrade() {
            let result = transport.lock().await.link_close(self.link_id).await;

            if result.is_err() {
                log::debug!("channel({}): error closing underlying link", self.link_id);
            }
        }
    }

    pub async fn send<M: Message>(&mut self, message: &M) -> Result<Hash, RnsError> {
        let transport = match self.transport.upgrade() {
            Some(t) => t,
            None => {
                return Err(RnsError::LinkNotReady);
            }
        };

        if !self.is_ready_to_send().await {
            return Err(RnsError::LinkNotReady);
        }

        let sequence = self.next_sequence;

        let packet_hash;
        {
            let raw = message_raw(message, Some(sequence));
            let link_mdu = self.outlet.lock().await.mdu();
            let payload_len = raw.len().saturating_sub(6);
            // Python rejects `len(envelope.raw) > outlet.mdu`. The length
            // field is a u16, and the Fernet token must fit in PACKET_MDU
            // even when link MTU discovery reports a larger hardware MTU.
            let envelope_limit = link_mdu.min(max_link_plaintext()).min(0xFFFF + 6);
            if payload_len > 0xFFFF || raw.len() > envelope_limit {
                log::debug!(
                    "channel({}): message too big for link mdu ({} > {})",
                    self.link_id,
                    raw.len(),
                    envelope_limit
                );
                return Err(RnsError::ChannelMessageTooBig);
            }

            let (packet, sent) = match outlet_send(&self.outlet, &raw, &transport).await {
                Ok(sent) => sent,
                Err(_) => return Err(RnsError::ChannelMessageTooBig),
            };
            // Do not consume a sequence number unless the packet is tracked.
            // `data_packet` failing (token does not fit) and a link that
            // did not accept the packet both leave the sequence unchanged.
            if !sent {
                return Err(RnsError::LinkNotReady);
            }

            packet_hash = packet.hash();

            let (delivery_tx, delivery_rx) = broadcast::channel(1);

            let sent_message = SentMessage {
                packet,
                delivered: delivery_tx,
                tries: 1,
            };

            self.sent_messages.insert(packet_hash, sent_message);
            self.next_sequence = self.next_sequence.wrapping_add(1);

            let rtt = *self.outlet.lock().await.rtt();

            let ring_len = self.sent_messages.len();
            let timeout = packet_timeout_time(rtt, ring_len, 1);

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

    pub async fn watch_delivery(&mut self, packet_hash: Hash) -> Option<broadcast::Receiver<bool>> {
        self.sent_messages
            .get(&packet_hash)
            .map(|s| s.delivered.subscribe())
    }

    pub async fn get_status(&self, packet_hash: &Hash) -> MessageStatus {
        match self.sent_messages.get(packet_hash) {
            Some(sent_message) => {
                let tries = sent_message.tries;
                if tries == 0 {
                    MessageStatus::Waiting
                } else {
                    MessageStatus::Sent(tries)
                }
            }
            None => {
                if self.delivered.contains(packet_hash) {
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
    our_link_id: LinkId,
    cancel: CancellationToken,
    registry: Arc<StdMutex<TypeRegistry>>,
) -> broadcast::Sender<M> {
    let mut inbound = Inbound::new(our_link_id, registry);
    let incoming = inbound.get_incoming();

    tokio::spawn(async move {
        let mut last_error_logged: Option<Instant> = None;

        loop {
            tokio::select! {
                received = rx.recv() => {
                    match received {
                        Ok(payload) => inbound.receive(payload.as_slice()).await,
                        Err(err) => {
                            if let Some(then) = last_error_logged {
                                if then.elapsed() < Duration::from_secs(10) {
                                    continue;
                                }
                            }

                            log::error!(
                                "channel({}): error getting inbound message from link: {}",
                                our_link_id,
                                err
                            );

                            last_error_logged = Some(Instant::now());

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
    pub link: Arc<Mutex<Link>>,
    outbound: Arc<Mutex<Outbound>>,
    incoming: broadcast::Sender<M>,
    registry: Arc<StdMutex<TypeRegistry>>,
}

impl<M: Message> Clone for Channel<M> {
    fn clone(&self) -> Self {
        Self {
            link: Arc::clone(&self.link),
            outbound: Arc::clone(&self.outbound),
            incoming: self.incoming.clone(),
            registry: Arc::clone(&self.registry),
        }
    }
}

impl<M: Message> Channel<M> {
    /// Clone this channel handle (shares the same outbound queue and
    /// incoming broadcast sender).
    pub fn clone_for_stream(&self) -> Self {
        self.clone()
    }

    pub(crate) async fn new(
        transport: &Transport,
        link: Arc<Mutex<Link>>,
    ) -> Result<(Self, broadcast::Receiver<M>), RnsError> {
        let (me_tx, me_rx) = mpsc::channel(16);

        let outbound = Outbound::new(Arc::clone(&link), transport.get_handler(), me_tx).await;

        let link_id = outbound.link_id();
        let cancel = outbound.cancel();

        let link_events = transport.events_for_link(link_id).await;

        let outbound = Arc::new(Mutex::new(outbound));

        spawn_watch_outbound(Arc::clone(&outbound), link_events.resubscribe(), me_rx).await;

        let rx = transport.bind_link_to_channel(link_id).await?;

        let registry = Arc::new(StdMutex::new(TypeRegistry::new()));
        let incoming = spawn_receiver(rx, link_id, cancel, Arc::clone(&registry)).await;
        let incoming_rx = incoming.subscribe();

        let channel = Self {
            link,
            outbound,
            incoming,
            registry,
        };

        Ok((channel, incoming_rx))
    }

    /// Register an additional message type on this channel.
    ///
    /// Python `Channel.register_message_type` accepts several classes on one
    /// channel. Types `>= `[`MSGTYPE_SYSTEM_MIN`] (including buffer stream
    /// type `0xff00`) are rejected unless `system` is set, matching
    /// `_register_message_type(..., is_system_type=True)`.
    ///
    /// The receiver yields the packed message payload (the bytes after the
    /// 6-byte envelope header). A second registration of the same type
    /// subscribes to the existing stream. Registered types are delivered
    /// instead of the channel's primary [`Message`] when the type numbers
    /// match, and they share that primary type's sequence space.
    pub fn register_message_type(
        &self,
        message_type: u16,
        system: bool,
    ) -> Result<broadcast::Receiver<Vec<u8>>, RnsError> {
        if message_type >= MSGTYPE_SYSTEM_MIN && !system {
            return Err(RnsError::ChannelError);
        }

        let mut registry = self.registry.lock().map_err(|_| RnsError::ChannelError)?;
        if let Some(tx) = registry.get(&message_type) {
            return Ok(tx.subscribe());
        }

        let (tx, rx) = broadcast::channel(64);
        registry.insert(message_type, tx);
        Ok(rx)
    }

    /// Bytes available for one message payload (Python `Channel.mdu`).
    ///
    /// This is the link MDU minus the 6-byte envelope header, and at most
    /// the largest payload whose envelope's Fernet token fits in
    /// `PACKET_MDU`. At the protocol MTU that is still `link.mdu - 6`.
    pub async fn mdu(&self) -> usize {
        let link_mdu = self.link.lock().await.mdu();
        link_mdu
            .saturating_sub(6)
            .min(max_link_plaintext().saturating_sub(6))
    }

    /// Current send window (Python `Channel.window`).
    pub async fn window(&self) -> u16 {
        self.outbound.lock().await.params.lock().await.window
    }

    /// Current maximum send window (Python `Channel.window_max`).
    pub async fn window_max(&self) -> u16 {
        self.outbound.lock().await.params.lock().await.window_max
    }

    /// Current minimum send window (Python `Channel.window_min`).
    pub async fn window_min(&self) -> u16 {
        self.outbound.lock().await.params.lock().await.window_min
    }

    /// Send a message over the channel.
    ///
    /// `message` does not have to be the channel's primary type: any
    /// [`Message`] can be sent, including a system type such as `0xff00`.
    /// Fails if the channel is not ready to send, or if the packed envelope
    /// is larger than the link MDU. If successful, it returns the `Hash`
    /// with which the message can be identified.
    pub async fn send<T: Message>(&self, message: &T) -> Result<Hash, RnsError> {
        self.outbound.lock().await.send(message).await
    }

    /// Get notified when a specific message's delivery is confirmed.
    pub async fn watch_message_delivery(
        &self,
        packet_hash: Hash,
    ) -> Option<broadcast::Receiver<bool>> {
        self.outbound.lock().await.watch_delivery(packet_hash).await
    }

    /// Query the status of a message.
    pub async fn message_status(&self, packet_hash: &Hash) -> MessageStatus {
        self.outbound.lock().await.get_status(packet_hash).await
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

    /// Create an additional receiver for the channel's incoming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<M> {
        self.incoming.subscribe()
    }

    /// Receiver for the delivery receipt of the most recently sent message,
    /// if one is pending (used by stream pumps for backpressure).
    pub async fn last_receipt(&self) -> Option<tokio::sync::broadcast::Receiver<bool>> {
        self.outbound.lock().await.last_pending_receipt().await
    }
}

#[cfg(test)]
mod mock {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;

    use rand_core::OsRng;

    use tokio::sync::{broadcast, Mutex};
    use tokio::time::Duration;

    use crate::destination::link::{LinkEvent, LinkEventData, LinkId, LinkPayload, LinkStatus};
    use crate::error::RnsError;
    use crate::hash::{AddressHash, Hash};
    use crate::packet::{PacketContext, PacketDataBuffer};
    use crate::transport::BroadcastLinkPayloadSink;

    #[derive(Clone)]
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
                context: PacketContext::None,
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
                event: LinkEvent::Proof(self.hash()),
            }
        }
    }

    #[derive(Clone)]
    pub struct Link {
        pub id: LinkId,
        pub rtt: Duration,
        pub status: LinkStatus,
        pub mtu: usize,
        pub tx: broadcast::Sender<LinkPayload>,
    }

    impl Link {
        pub fn new(status: LinkStatus) -> Self {
            let id = LinkId::new_from_rand(OsRng);
            let rtt = Duration::from_millis(20);
            let tx = broadcast::Sender::new(16);
            Self {
                id,
                rtt,
                status,
                mtu: crate::packet::PROTOCOL_MTU,
                tx,
            }
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

        /// Same formula as `RNS.Link.mdu` / `Link::mdu`.
        pub fn mdu(&self) -> usize {
            let overhead = crate::packet::IFAC_MIN_SIZE
                + crate::packet::HEADER_MINSIZE
                + crate::packet::TOKEN_OVERHEAD;
            let mdu = self.mtu.saturating_sub(overhead);
            (mdu / crate::packet::AES128_BLOCKSIZE * crate::packet::AES128_BLOCKSIZE)
                .saturating_sub(1)
        }

        pub fn data_packet(&self, raw: &[u8]) -> Result<Packet, RnsError> {
            Ok(Packet::new(raw, self.id))
        }

        pub fn close(&mut self) {
            self.status = LinkStatus::Closed;
        }
    }

    pub struct Transport {
        #[expect(dead_code)]
        pub in_tx: broadcast::Sender<LinkEventData>,
        pub out_tx: broadcast::Sender<LinkEventData>,
        handler: Arc<Mutex<TransportHandler>>,
        channel_table: Arc<Mutex<BTreeMap<LinkId, BroadcastLinkPayloadSink>>>,
        // the Arc<Mutex<...>> here is a hack so the mocked methods
        // don't neet a mutable reference to self
    }

    pub struct TransportHandler {
        packets: Arc<Mutex<Vec<Packet>>>,
        links: Arc<Mutex<BTreeMap<LinkId, Arc<Mutex<Link>>>>>,
    }

    impl Transport {
        pub fn new() -> Self {
            Self {
                in_tx: broadcast::Sender::new(16),
                out_tx: broadcast::Sender::new(16),
                handler: Arc::new(Mutex::new(TransportHandler::new())),
                channel_table: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }

        // mocked methods
        pub fn get_handler(&self) -> Arc<Mutex<TransportHandler>> {
            self.handler.clone()
        }

        pub async fn events_for_link(&self, _: LinkId) -> broadcast::Receiver<LinkEventData> {
            self.out_tx.subscribe()
        }

        // helper method
        pub async fn packets(&self) -> Vec<Packet> {
            self.handler.lock().await.packets.lock().await.clone()
        }

        pub async fn create_link(&self, status: LinkStatus) -> Arc<Mutex<Link>> {
            let link = Link::new(status);
            let link_id = *link.id();
            let link = Arc::new(Mutex::new(link));

            self.handler
                .lock()
                .await
                .links
                .lock()
                .await
                .insert(link_id, link.clone());

            link
        }

        pub async fn bind_link_to_channel(
            &self,
            link_id: LinkId,
        ) -> Result<broadcast::Receiver<LinkPayload>, RnsError> {
            let mut channels = self.channel_table.lock().await;

            if channels.contains_key(&link_id) {
                return Err(RnsError::ChannelError);
            }

            match self.handler.lock().await.links.lock().await.get(&link_id) {
                Some(link) => {
                    let tx = link.lock().await.tx.clone();
                    let rx = tx.subscribe();

                    channels.insert(link_id, tx.into());

                    Ok(rx)
                }
                None => Err(RnsError::ChannelError),
            }
        }
    }

    impl TransportHandler {
        pub fn new() -> Self {
            TransportHandler {
                packets: Arc::new(Mutex::new(Vec::new())),
                links: Arc::new(Mutex::new(BTreeMap::new())),
            }
        }

        pub async fn send_packet(&self, packet: Packet) {
            self.packets.lock().await.push(packet);
        }

        pub async fn link_close(&self, link_id: LinkId) -> Result<(), RnsError> {
            if let Some(link) = self.links.lock().await.get(&link_id) {
                link.lock().await.close();
            }

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_raw() {
        let data = vec![0x43, 0x11, 0x00];
        let env = envelope_raw(data.as_slice(), 0x1000, Some(10));

        assert_eq!(
            env,
            vec![0x10, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x43, 0x11, 0x00]
        );
    }

    struct Fixture {
        pub link_a: Arc<Mutex<Link>>,
        pub link_b: Arc<Mutex<Link>>,
        pub transport_a: Transport,
        pub transport_b: Transport,
    }

    impl Fixture {
        pub async fn new() -> Self {
            let transport_a = Transport::new();
            let transport_b = Transport::new();

            let link_a = transport_a.create_link(LinkStatus::Active).await;
            let link_b = transport_b.create_link(LinkStatus::Active).await;

            let transport_a = transport_a;
            let transport_b = transport_b;

            Self {
                link_a,
                link_b,
                transport_a,
                transport_b,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    enum TestMessage {
        Long(u64),
        Short(u32),
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
                Self::Short(x) => x.to_le_bytes().to_vec(),
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
        let fixture = Fixture::new().await;

        let (channel_a, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        let (_channel_b, mut incoming_b) =
            Channel::<TestMessage>::new(&fixture.transport_b, fixture.link_b.clone())
                .await
                .unwrap();

        let packet_hash = channel_a.send(&TestMessage::Short(1377)).await.unwrap();

        let packets = fixture.transport_a.packets().await;
        assert_eq!(packets.len(), 1);

        let packet = packets[0].clone();

        assert_eq!(
            channel_a.message_status(&packet_hash).await,
            MessageStatus::Sent(1)
        );

        let mut delivered = channel_a
            .watch_message_delivery(packet_hash)
            .await
            .expect("message not found in channel a");

        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packet.payload())
            .unwrap();

        let incoming = incoming_b.recv().await.expect("expected incoming message");
        assert_eq!(incoming, TestMessage::Short(1377));

        assert!(delivered.is_empty());

        let proof = packet.prove();

        fixture.transport_a.out_tx.send(proof).unwrap();

        assert!(delivered.recv().await.unwrap());

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert_eq!(
            channel_a.message_status(&packet_hash).await,
            MessageStatus::Delivered
        );
    }

    #[tokio::test]
    async fn test_message_failure() {
        let fixture = Fixture::new().await;

        let (channel_a, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        let packet_hash = channel_a.send(&TestMessage::Short(1)).await.unwrap();

        let delivered = channel_a
            .watch_message_delivery(packet_hash)
            .await
            .expect("message not found in channel a");

        tokio::time::sleep(Duration::from_secs(3)).await;

        let packets = fixture.transport_a.packets().await;
        assert_eq!(packets.len(), 5);

        assert_eq!(fixture.link_a.lock().await.status(), LinkStatus::Closed);

        assert!(delivered.is_empty());

        assert!(!channel_a.is_ready().await);
    }

    #[tokio::test]
    async fn test_channel_not_ready() {
        let fixture = Fixture::new().await;
        fixture.link_a.lock().await.status = LinkStatus::Pending;

        let (channel_a, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        assert!(!channel_a.is_ready().await);

        let result = channel_a.send(&TestMessage::Short(0)).await;
        assert_eq!(result, Err(RnsError::LinkNotReady));

        fixture.link_a.lock().await.status = LinkStatus::Active;

        assert!(channel_a.is_ready().await);

        channel_a.send(&TestMessage::Short(1)).await.unwrap();
        channel_a.send(&TestMessage::Short(2)).await.unwrap();

        let packets = fixture.transport_a.packets().await;
        assert_eq!(packets.len(), 2);

        // now the channel should again not be ready as the window is full
        // (too many messages already awaiting delivery)
        assert!(!channel_a.is_ready().await);

        let result = channel_a.send(&TestMessage::Short(3)).await;
        assert_eq!(result, Err(RnsError::LinkNotReady));
    }

    #[tokio::test]
    async fn test_messages_ordering() {
        let fixture = Fixture::new().await;

        let (channel_a, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        let (_channel_b, mut incoming_b) =
            Channel::<TestMessage>::new(&fixture.transport_b, fixture.link_b.clone())
                .await
                .unwrap();

        channel_a.send(&TestMessage::Short(1)).await.unwrap();

        let packets = fixture.transport_a.packets().await;
        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[0].payload())
            .unwrap();

        let first = incoming_b.recv().await.unwrap();
        assert_eq!(first, TestMessage::Short(1));

        fixture.transport_a.out_tx.send(packets[0].prove()).unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        channel_a.send(&TestMessage::Short(2)).await.unwrap();
        channel_a.send(&TestMessage::Short(3)).await.unwrap();

        let packets = fixture.transport_a.packets().await;
        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[2].payload())
            .unwrap();

        // packets have been sent in wrong order:
        // third packet will be on hold until the second one has been received.
        assert!(incoming_b.is_empty());

        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[1].payload())
            .unwrap();

        let second = incoming_b.recv().await.unwrap();
        let third = incoming_b.recv().await.unwrap();

        assert_eq!(second, TestMessage::Short(2));
        assert_eq!(third, TestMessage::Short(3));

        fixture.transport_a.out_tx.send(packets[1].prove()).unwrap();

        channel_a.send(&TestMessage::Short(4)).await.unwrap();

        let packets = fixture.transport_a.packets().await;
        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[3].payload())
            .unwrap();

        let fourth = incoming_b.recv().await.unwrap();
        assert_eq!(fourth, TestMessage::Short(4));
    }

    #[tokio::test]
    async fn test_missing_message() {
        let fixture = Fixture::new().await;

        let (channel_a, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        let (_channel_b, incoming_b) =
            Channel::<TestMessage>::new(&fixture.transport_b, fixture.link_b.clone())
                .await
                .unwrap();

        channel_a.send(&TestMessage::Long(50)).await.unwrap();
        channel_a.send(&TestMessage::Long(50)).await.unwrap();

        let packets = fixture.transport_a.packets().await;

        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[1].payload())
            .unwrap(); //

        tokio::time::sleep(Duration::from_secs(3)).await;

        assert!(incoming_b.is_empty());
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Blob {
        message_type: u16,
        data: Vec<u8>,
    }

    impl Message for Blob {
        fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError> {
            Ok(Self {
                message_type,
                data: packed.to_vec(),
            })
        }

        fn pack(&self) -> Vec<u8> {
            self.data.clone()
        }

        fn message_type(&self) -> u16 {
            self.message_type
        }
    }

    async fn prove_one(fixture: &Fixture, channel: &Channel<TestMessage>) -> Hash {
        let before = fixture.transport_a.packets().await.len();
        let hash = channel.send(&TestMessage::Short(1)).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let packets = fixture.transport_a.packets().await;
            if packets.len() > before {
                fixture
                    .transport_a
                    .out_tx
                    .send(packets[before].prove())
                    .unwrap();
                break;
            }
            assert!(Instant::now() < deadline, "packet was not sent");
            sleep(Duration::from_millis(10)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if channel.message_status(&hash).await == MessageStatus::Delivered {
                return hash;
            }
            assert!(Instant::now() < deadline, "proof was not applied");
            sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn test_mdu_is_link_mdu_minus_header() {
        let fixture = Fixture::new().await;
        let (channel, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        let link_mdu = fixture.link_a.lock().await.mdu();
        assert_eq!(channel.mdu().await, link_mdu - 6);
        assert_eq!(channel.mdu().await, CHANNEL_MDU);
        const { assert!(CHANNEL_MDU < crate::packet::PACKET_MDU) };

        let too_big = Blob {
            message_type: 7,
            data: vec![0u8; channel.mdu().await + 1],
        };
        assert_eq!(
            channel.send(&too_big).await,
            Err(RnsError::ChannelMessageTooBig)
        );
        assert!(fixture.transport_a.packets().await.is_empty());

        let fits = Blob {
            message_type: 7,
            data: vec![0u8; channel.mdu().await],
        };
        channel.send(&fits).await.unwrap();
        let packets = fixture.transport_a.packets().await;
        assert_eq!(packets.len(), 1);
        // Sequence was not consumed by the rejected message.
        assert_eq!(&packets[0].data.as_slice()[2..4], &[0, 0]);
        assert_eq!(packets[0].data.as_slice().len(), link_mdu);
    }

    #[tokio::test]
    async fn test_packet_buffer_caps_envelope() {
        let fixture = Fixture::new().await;
        // TCP, local, and backbone report a hardware MTU far above the
        // packet buffer. Channel::mdu must not advertise 65535 there.
        fixture.link_a.lock().await.mtu = 1_048_576;
        let (channel, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        let link_mdu = fixture.link_a.lock().await.mdu();
        let cap = max_link_plaintext() - 6;
        assert!(link_mdu - 6 > 0xFFFF);
        assert_eq!(cap, 1993);
        assert_eq!(channel.mdu().await, cap);
        assert!(channel.mdu().await < link_mdu - 6);

        let too_big = Blob {
            message_type: 7,
            data: vec![0u8; cap + 1],
        };
        assert_eq!(
            channel.send(&too_big).await,
            Err(RnsError::ChannelMessageTooBig)
        );
        assert!(fixture.transport_a.packets().await.is_empty());

        channel.send(&TestMessage::Short(1)).await.unwrap();
        let packets = fixture.transport_a.packets().await;
        assert_eq!(packets.len(), 1);
        // The rejected envelope did not consume a sequence number.
        assert_eq!(&packets[0].data.as_slice()[2..4], &[0, 0]);
    }

    #[tokio::test]
    async fn test_multiple_registered_types_including_system() {
        let fixture = Fixture::new().await;
        let (channel_a, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();
        let (_channel_b, mut incoming_b) =
            Channel::<TestMessage>::new(&fixture.transport_b, fixture.link_b.clone())
                .await
                .unwrap();

        assert_eq!(
            _channel_b.register_message_type(0xff00, false).unwrap_err(),
            RnsError::ChannelError
        );
        let mut system_rx = _channel_b.register_message_type(0xff00, true).unwrap();
        let mut user_rx = _channel_b.register_message_type(0x0007, false).unwrap();

        let first = channel_a.send(&TestMessage::Short(9)).await.unwrap();
        channel_a
            .send(&Blob {
                message_type: 0xff00,
                data: b"stream".to_vec(),
            })
            .await
            .unwrap();
        // The initial window is 2. Prove the first message so the third
        // type can be sent without waiting out a timeout.
        {
            let packets = fixture.transport_a.packets().await;
            fixture.transport_a.out_tx.send(packets[0].prove()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if channel_a.message_status(&first).await == MessageStatus::Delivered {
                    break;
                }
                assert!(Instant::now() < deadline, "proof was not applied");
                sleep(Duration::from_millis(10)).await;
            }
        }
        channel_a
            .send(&Blob {
                message_type: 0x0007,
                data: b"extra".to_vec(),
            })
            .await
            .unwrap();

        let packets = fixture.transport_a.packets().await;
        assert_eq!(packets.len(), 3);

        // Deliver the system frame before the primary message. It shares the
        // sequence space, so it stays on hold until sequence 0 arrives.
        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[1].payload())
            .unwrap();
        sleep(Duration::from_millis(30)).await;
        assert!(system_rx.is_empty());
        assert!(incoming_b.is_empty());

        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[0].payload())
            .unwrap();
        fixture
            .link_b
            .lock()
            .await
            .tx
            .send(packets[2].payload())
            .unwrap();

        assert_eq!(incoming_b.recv().await.unwrap(), TestMessage::Short(9));
        assert_eq!(system_rx.recv().await.unwrap(), b"stream");
        assert_eq!(user_rx.recv().await.unwrap(), b"extra");
    }

    #[tokio::test]
    async fn test_timeout_does_not_shrink_window_at_minimum() {
        let fixture = Fixture::new().await;
        let (channel, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();
        assert_eq!(channel.window().await, WINDOW);
        assert_eq!(channel.window_min().await, WINDOW_MIN);

        channel.send(&TestMessage::Short(1)).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if fixture.transport_a.packets().await.len() >= 2 {
                break;
            }
            assert!(Instant::now() < deadline, "message was not resent");
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(channel.window().await, WINDOW);
        assert_eq!(channel.window_max().await, WINDOW_MAX_SLOW);
        assert_eq!(fixture.link_a.lock().await.status(), LinkStatus::Active);
    }

    #[tokio::test]
    async fn test_timeout_shrinks_window_but_not_max_inside_flexibility() {
        let fixture = Fixture::new().await;
        // Medium RTT: the window may grow to WINDOW_MAX_SLOW, but ten
        // medium rounds are required before window_max itself rises, so
        // one timeout can shrink `window` without touching `window_max`
        // (5 is not greater than window_min + WINDOW_FLEXIBILITY).
        fixture.link_a.lock().await.rtt = Duration::from_millis(200);
        let (channel, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        for _ in 0..3 {
            prove_one(&fixture, &channel).await;
        }
        assert_eq!(channel.window().await, WINDOW_MAX_SLOW);
        assert_eq!(channel.window_max().await, WINDOW_MAX_SLOW);

        channel.send(&TestMessage::Short(2)).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if channel.window().await == WINDOW_MAX_SLOW - 1 {
                break;
            }
            assert!(Instant::now() < deadline, "window did not shrink");
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(channel.window_max().await, WINDOW_MAX_SLOW);
        assert_eq!(fixture.transport_a.packets().await.len(), 5);
    }

    #[tokio::test]
    async fn test_timeout_shrinks_window_max_by_one_past_flexibility() {
        let fixture = Fixture::new().await;
        let (channel, _) =
            Channel::<TestMessage>::new(&fixture.transport_a, fixture.link_a.clone())
                .await
                .unwrap();

        // Fast RTT (the mock default). After FAST_RATE_THRESHOLD proofs,
        // window_max jumps to the fast limit and the window can grow past
        // window_min. The next timeout then decrements window_max by one
        // because it is more than WINDOW_FLEXIBILITY above window_min.
        for _ in 0..22 {
            prove_one(&fixture, &channel).await;
        }
        assert_eq!(channel.window().await, 17);
        assert_eq!(channel.window_max().await, WINDOW_MAX_FAST);
        assert_eq!(channel.window_min().await, WINDOW_MIN_LIMIT_FAST);

        channel.send(&TestMessage::Short(3)).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if channel.window_max().await == WINDOW_MAX_FAST - 1 {
                break;
            }
            assert!(Instant::now() < deadline, "window_max did not shrink");
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(channel.window().await, 16);
        assert_eq!(channel.window_max().await, WINDOW_MAX_FAST - 1);
        assert_ne!(
            channel.window_max().await,
            WINDOW_MAX_FAST - WINDOW_FLEXIBILITY
        );
    }
}
