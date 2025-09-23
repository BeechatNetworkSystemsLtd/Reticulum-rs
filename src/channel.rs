use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};

use tokio::sync::{broadcast, Mutex, MutexGuard, mpsc};
use tokio::task::spawn;
use tokio::time::{Duration, Instant, sleep};

use crate::destination::link::{Link, LinkId, LinkPayload, LinkStatus};
use crate::packet::{DestinationType, Packet, PacketContext, PacketDataBuffer, PACKET_MDU};
use crate::transport::Transport;


pub type MessageType = u16;

pub struct PackedMessage {
    payload: Vec<u8>,
    message_type: MessageType
}

impl PackedMessage {
    pub fn new(payload: Vec<u8>, message_type: MessageType) -> Self {
        Self { payload, message_type }
    }

    pub fn payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn message_type(&self) -> MessageType {
        self.message_type
    }
}

pub trait Message: Clone + Send + Sized + Sync + 'static {
    fn pack(&self) -> PackedMessage;

    fn unpack(packed: PackedMessage) -> Result<Self, ChannelError>;
}

static SMT_STREAM_DATA: MessageType = 0xff00;


#[derive(PartialEq)]
enum MessageState {
    New,
    Sent,
    Delivered,
    Failed
}


fn get_packet_state(packet: &Packet) -> MessageState {
    MessageState::Sent // TODO implement packet receipts
}


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
    _: &Arc<Mutex<Link>>,
    packet: Packet,
    transport: Weak<Mutex<Transport>>,
) {
    // TODO obtain new ciphertext for encrypted destinations?

    if let Some(transport) = transport.upgrade() {
        transport.lock().await.send_packet(packet).await;
    }
}


async fn outlet_is_usable(link: &Arc<Mutex<Link>>) -> bool {
    link.lock().await.status() == LinkStatus::Active
    // This diverges from the reference implementation. The value is
    // hardcoded to true in the reference implementation, citing
    // "issues looking at Link.status".
}

async fn outlet_timed_out(_: &Arc<Mutex<Link>>) -> bool {
    todo!();
}


fn schedule_packet_timeout_callback<M: Message>(
    callback: PacketTimeoutCallback<M>,
    mut timeout: Instant,
) -> mpsc::Sender<Option<Instant>> {
    let (tx, mut rx) = mpsc::channel(16);

    spawn(async move {
        loop {
            sleep(timeout - Instant::now()).await;

            if rx.is_empty() {
                callback.run().await;
                break;
            }

            if let Ok(Some(new_timeout)) = rx.try_recv() {
                timeout = new_timeout;
                continue;
            }

            break;
        }
    });

    tx
}

fn schedule_packet_delivered_callback<M: Message>(
    callback: PacketDeliveredCallback<M>
) -> mpsc::Sender<bool> {
    let (tx, mut rx) = mpsc::channel(1);

    spawn(async move {
        let delivered = rx.recv().await.unwrap_or(false);

        if delivered {
            callback.run().await;
        }
    });

    tx
}


struct PacketCallbacks {
    timeout: Instant,
    timeout_tx: mpsc::Sender<Option<Instant>>,
    delivery_tx: mpsc::Sender<bool>,
}


impl PacketCallbacks {
    fn new<M: Message>(
        timeout: Instant,
        timeout_callback: PacketTimeoutCallback<M>,
        delivered_callback: PacketDeliveredCallback<M>,
    ) -> Self {
        let timeout_tx = schedule_packet_timeout_callback(
            timeout_callback,
            timeout.clone(),
        );

        let delivery_tx = schedule_packet_delivered_callback(
            delivered_callback,
        );

        Self { timeout, timeout_tx, delivery_tx }
    }

    async fn update(&mut self, new_timeout: Instant) {
        if new_timeout > self.timeout {
            self.timeout_tx.send(Some(new_timeout)).await.ok();
            self.timeout = new_timeout;
        }
    }

    async fn cancel(&self) {
        self.timeout_tx.send(None).await.ok();
        self.delivery_tx.send(false).await.ok();
    }

    pub fn delivery_sender(&self) -> mpsc::Sender<bool> {
        self.delivery_tx.clone()
    }
}


#[derive(Debug)]
pub enum ChannelError {
    NoMessageType,
    InvalidMessageType,
    NotRegistered,
    LinkNotReady,
    AlreadySent,
    TooBig,
    Misc
}


pub struct Envelope<M: Message> {
    timestamp: Instant,
    message: Option<M>,
    raw: Option<Vec<u8>>,
    packet: Option<Packet>,
    sequence: Option<u16>,
    outlet_id: LinkId,
    tries: u64,
    unpacked: bool,
    packed: bool,
    tracked: bool,
    sent: bool,
    callbacks: Option<PacketCallbacks>,
}


fn envelope_raw(
    data: &[u8],
    message_type: MessageType,
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


fn deenvelope_raw(data: &[u8]) -> Result<(u16, u16, u16), ChannelError>
{
    if data.len() < 6 {
        return Err(ChannelError::Misc);
    }

    let message_type: MessageType = u16::from_be_bytes([data[0], data[1]]);
    let sequence = u16::from_be_bytes([data[2], data[3]]);
    let size = u16::from_be_bytes([data[4], data[5]]);

    Ok((message_type, sequence, size))
}


impl<M: Message> Envelope<M> {
    fn new(
        outlet_id: LinkId,
        message: Option<M>,
        raw: Option<Vec<u8>>,
        sequence: Option<u16>
    ) -> Self {
        Self {
            timestamp: Instant::now(),
            message,
            raw,
            packet: None,
            sequence,
            outlet_id,
            tries: 0,
            unpacked: false,
            packed: false,
            tracked: false,
            sent: false,
            callbacks: None,
        }
    }

    fn pack(&mut self) -> Result<(), ChannelError> {
        if let Some(ref message) = self.message {
            let packed = message.pack();
            let message_type = packed.message_type();
            let payload = packed.payload();

            self.raw = Some(
                envelope_raw(payload.as_ref(), message_type, self.sequence)
            );
            self.packed = true;

            Ok(())
        } else {
            Err(ChannelError::Misc)
        }
    }

    fn get_raw(&mut self) -> Result<&[u8], ChannelError> {
        if !self.packed {
            self.pack()?
        }
        Ok(self.raw.as_ref().unwrap())
    }

    fn unpack(
        &mut self,
    ) -> Result<(), ChannelError> {
        let raw = self.raw.as_ref().expect(
            "Reference implementation does not check if initialized here."
        );
        let (message_type, sequence, size) = deenvelope_raw(raw)?;

        if raw.len() as u16 != size + 6 {
            log::trace!(
                "Length field in envelope doesn't match actual message length. Ignoring."
            );
        }

        let packed = PackedMessage::new(raw[6..].to_vec(), message_type);

        self.message = Some(M::unpack(packed)?);
        self.sequence = Some(sequence);
        self.unpacked = true;

        Ok(())
    }

    fn get_sequence(&mut self) -> Result<u16, ChannelError> {
        if self.unpacked {
            Ok(self.sequence.unwrap())
        } else {
            if let Some(raw) = self.raw.as_ref() {
                let (_, s, _) = deenvelope_raw(raw)?;
                Ok(s)
            } else {
                Err(ChannelError::Misc)
            }
        }
    }

    fn get_message(
        &mut self,
    ) -> Result<&M, ChannelError> {
        if !self.unpacked {
            self.unpack()?;
        }

        Ok(self.message.as_ref().unwrap())
    }

    fn is_same_packet(&self, other: &Packet) -> bool {
        if let Some(ref our) = self.packet {
            our == other
        } else {
            false
        }
    }
}


fn packet_timeout_time(
    rtt: Duration,
    ring_len: usize,
    tries: u64
) -> Duration {
    let rtt_f32 = rtt.as_secs_f32();
    let rtt_factor = if rtt_f32 >= 0.01 { 2.5 * rtt_f32 } else { 0.025 };

    let tries_factor = 1.5f32.powi(tries.saturating_sub(1) as i32);
    let total = tries_factor * rtt_factor * (ring_len as f32 + 1.5);

    Duration::from_secs_f32(total)
}


async fn update_packet_timeouts<M: Message>(
    ring: &Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    rtt: Duration,
) {
    let ring = ring.lock().await;
    let ring_len = ring.len();

    for envelope in ring.iter() {
        let mut env = envelope.lock().await;
        let tries = env.tries;
        if let Some(ref mut cb) = env.callbacks {
            let until_timeout = packet_timeout_time(rtt, ring_len, tries);
            cb.update(Instant::now() + until_timeout).await;
        }
    }
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


async fn pop_tx_from_ring<'a, M: Message>(
    mut ring: MutexGuard<'a, VecDeque<Arc<Mutex<Envelope<M>>>>>,
    envelope: Arc<Mutex<Envelope<M>>>,
) {
    let mut i: Option<usize> = None;
    for (j, e) in ring.iter().enumerate() {
        if Arc::ptr_eq(e, &envelope) {
            i = Some(j)
        }
    }

    if i.is_none() {
        log::trace!("Envelope not found in tx ring");
        return;
    }

    ring.remove(i.unwrap());

}


fn adjust_params(
    outlet: &mut MutexGuard<Link>,
    params: &mut MutexGuard<ChannelParams>
) {     
    if params.window < params.window_max {
        params.window += 1
    }

    let rtt = outlet.rtt().as_secs_f32();
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


struct PacketDeliveredCallback<M: Message> {
    outlet: Arc<Mutex<Link>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    params: Arc<Mutex<ChannelParams>>,
    env: Weak<Mutex<Envelope<M>>>,
}


impl<M: Message> PacketDeliveredCallback<M> {
    fn new(
        outlet: &Arc<Mutex<Link>>,
        tx_ring: &Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
        params: &Arc<Mutex<ChannelParams>>,
        env: Weak<Mutex<Envelope<M>>>,
    ) -> Self {
        Self {
            outlet: Arc::clone(&outlet),
            tx_ring: Arc::clone(&tx_ring),
            params: Arc::clone(&params),
            env,
        }
    }

    async fn run(&self) {
        if let Some(envelope) = self.env.upgrade() {
            envelope.lock().await.tracked = false;
            pop_tx_from_ring(self.tx_ring.lock().await, envelope).await;
            
            adjust_params(
                &mut self.outlet.lock().await, 
                &mut self.params.lock().await
            );
        }
    }
}


#[derive(Clone)]
struct PacketTimeoutCallback<M: Message> {
    outlet: Arc<Mutex<Link>>,
    rx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    params: Arc<Mutex<ChannelParams>>,
    transport: Arc<Mutex<Transport>>,
    env: Weak<Mutex<Envelope<M>>>,
}


impl<M: Message> PacketTimeoutCallback<M> {
    fn new(
        outlet: &Arc<Mutex<Link>>,
        rx_ring: &Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
        tx_ring: &Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
        params: &Arc<Mutex<ChannelParams>>,
        transport: &Arc<Mutex<Transport>>,
        env: Weak<Mutex<Envelope<M>>>,
    ) -> Self {
        Self {
            outlet: Arc::clone(&outlet),
            rx_ring: Arc::clone(&rx_ring),
            tx_ring: Arc::clone(&tx_ring),
            params: Arc::clone(&params),
            transport: Arc::clone(&transport),
            env,
        }
    }

    async fn run_callback(&self, env: &Arc<Mutex<Envelope<M>>>) -> bool {
        let max_tries = self.params.lock().await.max_tries;

        let packet;
        {
            let mut envelope = env.lock().await;
        
            if !envelope.sent {
                log::error!("Timeout was set for a packet not yet sent.");
            }
            
            if envelope.tries as u16 > max_tries {
                log::error!("Retry count exceeded, tearing down link.");
                self.shutdown_channel().await;
                outlet_timed_out(&self.outlet).await;
                return true;
            }

            envelope.tries += 1;
            packet = envelope.packet.as_ref().unwrap().clone();
        }

        let transport = Arc::downgrade(&self.transport);
        outlet_resend(&self.outlet, packet, transport).await;

        let rtt = *self.outlet.lock().await.rtt();
        update_packet_timeouts(&self.tx_ring, rtt).await;

        let mut params = self.params.lock().await;
        if params.window > params.window_min {
            params.window -= 1;
            if params.window_max > params.window_min + params.window_flexibility {
                params.window_max -= 1;
            }
        }
        false
    }

    async fn shutdown_channel(&self) {
        // TODO close received messages channel (=drop Sender)

        let mut tx_ring = self.tx_ring.lock().await;

        for ref envelope in tx_ring.iter() {
            let env = envelope.lock().await;
            if let Some(ref cb) = env.callbacks {
                cb.cancel().await;
            }
        }

        tx_ring.clear();

        self.rx_ring.lock().await.clear();
    }

    async fn run(&self) {
        if let Some(env) = self.env.upgrade() {
            self.run_callback(&env).await;
        }
    }
}


pub type MessageCallbackId = usize;


async fn emplace_envelope<M: Message>(
    ring: &Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    envelope: Arc<Mutex<Envelope<M>>>,
) -> bool {
    let env_sequence = envelope.lock().await.sequence;
    let mut inserted = false;
    let mut ring = ring.lock().await;

    for (i, existing) in ring.iter().enumerate() {
        let ex_sequence = existing.lock().await.sequence;
        if env_sequence == ex_sequence {
            log::trace!("Envelope: Emplacement of duplicate envelope");
            return false;
        }

        if env_sequence < ex_sequence {
            // if !2*(self.next_rx_sequence - env_sequence.unwrap_or(0)) as u32 > SEQ_MAX {
            if true { // TODO
                ring.insert(i, envelope.clone());
                inserted = true;
                break;
            }
        }
    }

    if !inserted {
        ring.push_back(envelope.clone());
    }

    envelope.lock().await.tracked = true;
    true
}



pub struct ChannelReceiver<M: Message> {
    rx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    incoming: broadcast::Sender<M>,
    next_rx_sequence: u16,
    link_id: LinkId,
}


impl<M: Message> ChannelReceiver<M> {
    fn new(
        rx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
        link_id: LinkId,
    ) -> Self {
        Self {
            rx_ring,
            incoming: broadcast::Sender::new(16),
            next_rx_sequence: 0,
            link_id,
        }
    }

    fn get_incoming(&self) -> broadcast::Sender<M> {
        self.incoming.clone()
    }

    async fn receive_traverse_ring(
        &mut self,
        contiguous: &mut Vec<Arc<Mutex<Envelope<M>>>>
    ) -> bool {
        let mut rx_ring = self.rx_ring.lock().await;
        let mut retained = VecDeque::new();
        let mut start_over = false;

        while let Some(env) = rx_ring.pop_front() {
            let seq = match env.lock().await.get_sequence() {
                Ok(s) => s,
                Err(_) => {
                    log::trace!(
                        "Dropped malformed envelope from rx_ring (no sequence)"
                    );
                    continue;
                }
            };
            
            if seq == self.next_rx_sequence {
                contiguous.push(Arc::clone(&env));
                self.next_rx_sequence += 1;
                if self.next_rx_sequence == 0 {
                    start_over = true;
                    break;
                }
            } else {
                retained.push_back(env);
            }
        }

        rx_ring.append(&mut retained);

        start_over
    }

    pub async fn receive(&mut self, raw: &[u8]) {
        log::trace!("channel received {}B", raw.len());

        let mut envelope = Envelope::<M>::new(
            self.link_id,
            None,
            Some(raw.to_vec()),
            None
        );
        
        if envelope.unpack().is_err() {
            log::error!("Message could not be unpacked");
            return;
        }

        let sequence = envelope.sequence.expect(
            "Sequence is set on all unpacked messages."
        );

        if sequence < self.next_rx_sequence {
            let overflow = sequence.saturating_add(WINDOW_MAX);
            
            if overflow >= self.next_rx_sequence || sequence > overflow {
                log::trace!("Invalid packet sequence");
                return;
            }
        }

        let is_new = true;
        emplace_envelope(&self.rx_ring, Arc::new(Mutex::new(envelope))).await;

        if !is_new {
            log::trace!("Duplicate message received");
        }

        let mut contiguous = vec![];
        let start_over = self.receive_traverse_ring(&mut contiguous).await;
        if start_over {
            self.receive_traverse_ring(&mut contiguous).await;
        }

        for env in contiguous {
            let res = self.incoming.send(
                env.lock().await.message.as_ref().unwrap().clone()
            );
            if res.is_err() {
                log::trace!("Channel received message but no handler active.");
            }
        }
    }
}


pub struct Channel<M: Message> {
    outlet: Arc<Mutex<Link>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    rx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<M>>>>>>,
    next_sequence: u16,
    params: Arc<Mutex<ChannelParams>>
}


impl<M: Message> Channel<M> {
    async fn new(outlet: Arc<Mutex<Link>>) -> Self {
        let slow = outlet.lock().await.rtt().as_secs_f32() > RTT_SLOW;
        let params = Arc::new(Mutex::new(ChannelParams::new(slow)));

        Self {
            outlet,
            tx_ring: Default::default(),
            rx_ring: Default::default(),
            next_sequence: 0,
            params
        }
    }

    async fn receiver(&self) -> ChannelReceiver<M> {
        let link_id = *self.outlet.lock().await.id();
        
        ChannelReceiver::new(Arc::clone(&self.rx_ring), link_id)
    }

    async fn is_ready_to_send(&self) -> bool {
        let tx_ring = self.tx_ring.lock().await;

        if !outlet_is_usable(&self.outlet).await {
            return false
        }

        let mut outstanding = 0;
        for envelope in tx_ring.iter() {
            let env = envelope.lock().await;
            let our_id = *self.outlet.lock().await.id();
            if env.outlet_id != our_id {
                continue;
            }

            if let Some(ref packet) = env.packet {
                let state = get_packet_state(packet);
                if state == MessageState::Delivered {
                    continue;
                }
            }
            
            outstanding += 1;
        }

        outstanding < self.params.lock().await.window
    }

    fn new_delivered_callback(
        &self, 
        env: Weak<Mutex<Envelope<M>>>
    ) -> PacketDeliveredCallback<M> {
        PacketDeliveredCallback::new(
            &self.outlet,
            &self.tx_ring,
            &self.params,
            env,
        )
    }

    fn new_timeout_callback(
        &self,
        transport: &Arc<Mutex<Transport>>,
        env: Weak<Mutex<Envelope<M>>>,
    ) -> PacketTimeoutCallback<M> {
        PacketTimeoutCallback::new(
            &self.outlet,
            &self.rx_ring,
            &self.tx_ring,
            &self.params,
            transport,
            env,
        )
    }

    fn packet_callbacks(
        &self,
        timeout: Instant,
        transport: &Arc<Mutex<Transport>>,
        env: Weak<Mutex<Envelope<M>>>
    ) -> PacketCallbacks {
        let timeout_callback = self.new_timeout_callback(transport, env.clone());
        let delivered_callback = self.new_delivered_callback(env);

        PacketCallbacks::new(timeout, timeout_callback, delivered_callback)
    }

    pub async fn send(
        &mut self,
        message: &M,
        transport: &Arc<Mutex<Transport>>,
    ) -> Result<Arc<Mutex<Envelope<M>>>, ChannelError> {
        if !self.is_ready_to_send().await {
            return Err(ChannelError::LinkNotReady);
        }

        let envelope = Arc::new(Mutex::new(Envelope::new(
            *self.outlet.lock().await.id(),
            Some(message.clone()),
            None,
            Some(self.next_sequence)
        )));

        let env_weak = Arc::downgrade(&envelope);

        self.next_sequence += 1;

        emplace_envelope(&self.tx_ring, Arc::clone(&envelope)).await;

        let rtt;
        {
            let env = &mut envelope.lock().await;
            let raw = env.get_raw()?;

            if raw.len() > PACKET_MDU as usize {
                return Err(ChannelError::TooBig);
            }

            let (packet, sent) = outlet_send(&self.outlet, &raw, transport).await;

            env.tries += 1;
            env.packet = Some(packet);
            env.sent = sent;

            let outlet = self.outlet.lock().await;
            rtt = *outlet.rtt();
            let timeout = Instant::now() + packet_timeout_time(
                rtt,
                self.tx_ring.lock().await.len(),
                env.tries,
            );

            env.callbacks = Some(self.packet_callbacks(
                timeout,
                transport,
                env_weak
            ));
        }

        update_packet_timeouts(&self.tx_ring, rtt).await;

        Ok(envelope)
    }

    pub async fn mdu(&self) -> usize {
        PACKET_MDU - 6
    }
}


async fn spawn_receiver<M: Message>(
    channel: &Channel<M>,
    mut rx: broadcast::Receiver<LinkPayload>,
) -> broadcast::Sender<M> {
    let mut channel_receiver = channel.receiver().await;
    let incoming = channel_receiver.get_incoming();

    tokio::spawn(async move {
        while let Ok(payload) = rx.recv().await {
            channel_receiver.receive(payload.as_slice()).await;
        }
    });

    incoming
}


pub struct WrappedLink<M: Message> {
    link: Arc<Mutex<Link>>,
    channel: Channel<M>,
    incoming: broadcast::Sender<M>,
}


impl<M: Message> WrappedLink<M> {
    pub async fn new(link: Arc<Mutex<Link>>) -> Self {
        let channel = Channel::new(Arc::clone(&link)).await;
        let rx = link.lock().await.bind_to_channel().unwrap();
        let incoming = spawn_receiver(&channel, rx).await;

        Self { link, channel, incoming }
    }

    pub fn get_link(&self) -> Arc<Mutex<Link>> {
        Arc::clone(&self.link)
    }

    pub fn get_channel(&mut self) -> &mut Channel<M> {
        &mut self.channel
    }

    pub fn subscribe(&self) -> broadcast::Receiver<M> {
        self.incoming.subscribe()
    }
}


#[cfg(test)]
mod tests {
    fn test_envelope_raw() {
        let data = vec![ 0x43, 0x11, 0x00 ];
        let env = envelope_raw(data.as_slice(), 0x1000, Some(10));

        assert_eq!(
            env,
            vec![0x10, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x43, 0x11, 0x00]
        );
    }
}
