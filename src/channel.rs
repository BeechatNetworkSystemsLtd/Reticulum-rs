use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::{Mutex, MutexGuard};

use crate::destination::link::{Link, LinkStatus};
use crate::packet::{Packet, PacketContext, PacketDataBuffer, PACKET_MDU};
use crate::transport::Transport;


fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}


pub type MessageType = u16;
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


#[async_trait]
trait PacketCallback: Send + Sync {
    async fn run(&self, packet: &Packet);
}


trait ChannelOutlet: Send + Sync + 'static {
    async fn send(
        &self,
        raw: &[u8],
        transport: &Arc<Mutex<Transport>>
    ) -> Packet;

    fn resend(&self, packet: &mut Packet);

    fn mdu(&self) -> usize;

    fn outlet_rtt(&self) -> f32;

    fn is_usable(&self) -> bool;

    fn timed_out(&self) -> bool;

    fn set_packet_timeout_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn PacketCallback>>,
        timeout: f32,
    );

    fn set_packet_delivered_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn PacketCallback>>
    );
}


impl ChannelOutlet for Link {
    async fn send(
        &self,
        raw: &[u8],
        transport: &Arc<Mutex<Transport>>
    ) -> Packet {
        let mut packet: Packet = Default::default();
        packet.data = PacketDataBuffer::new_from_slice(raw);
        packet.context = PacketContext::Channel;
        // TODO link

        if self.status() == LinkStatus::Active {
            let transport = Arc::clone(transport);
            transport.lock().await.send_packet(packet).await;
        }

        packet
    }

    fn resend(&self, packet: &mut Packet) {
        let receipt: Option<bool> = todo!(); // Packet::resend, receipt type
        if receipt.is_none() {
            log::error!("Failed to resend packet.");
        }
    }

    fn mdu(&self) -> usize {
        PACKET_MDU
    }

    fn outlet_rtt(&self) -> f32 {
        5.0 // TODO implement rtt in link
    }

    fn is_usable(&self) -> bool {
        self.status() == LinkStatus::Active
        // This diverges from the reference implementation. The value is
        // hardcoded to true in the reference implementation, citing
        // "issues looking at Link.status".
    }

    fn timed_out(&self) -> bool {
        todo!();
    }

    fn set_packet_timeout_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn PacketCallback>>,
        timeout: f32
    ) {
        // TODO
    }

    fn set_packet_delivered_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn PacketCallback>>
    ) {
        // TODO
    }
}


pub trait Message: Send + Sync {
    fn message_type(&self) -> Option<MessageType>;

    fn pack(&self) -> Vec<u8>;

    fn unpack(&mut self, raw: &[u8]);
}


pub enum ChannelError {
    NoMessageType,
    InvalidMessageType,
    NotRegistered,
    LinkNotReady,
    AlreadySent,
    TooBig,
    Misc
}


#[derive(Default)]
struct MessageFactory(BTreeMap<MessageType, Box<fn() -> Arc<dyn Message>>>);


impl MessageFactory {
    fn register_type(
        &mut self,
        message_type: MessageType,
        factory: fn() -> Arc<dyn Message>,
    ) {
        // TODO reserve 0xf...
        self.0.insert(message_type, Box::new(factory));
    }

    fn create(
        &self,
        message_type: MessageType
    ) -> Result<Arc<dyn Message>, ChannelError> {
        match self.0.get(&message_type) {
            Some(factory) => Ok(factory()),
            None => Err(ChannelError::NotRegistered)
        }
    }
}


pub struct Envelope<O: ChannelOutlet> {
    timestamp: u64,
    message: Option<Arc<dyn Message>>,
    raw: Option<Vec<u8>>,
    packet: Option<Packet>,
    sequence: Option<u16>,
    outlet: Arc<Mutex<O>>,
    tries: u64,
    unpacked: bool,
    packed: bool,
    tracked: bool
}


fn envelope_raw(
    data: &[u8],
    message_type: MessageType,
    sequence: Option<u16>
) -> Vec<u8> {
    let raw_size = data.len();
    
    let mut enveloped = Vec::<u8>::with_capacity(raw_size + 6);
    
    enveloped.extend_from_slice(
        message_type.to_le_bytes().as_slice()
    );
    
    enveloped.extend_from_slice(
        sequence.unwrap_or(0u16).to_le_bytes().as_slice()
    );
    
    enveloped.extend_from_slice(
        (raw_size as u16).to_le_bytes().as_slice()
    );
    
    enveloped.extend_from_slice(data);

    enveloped
}


fn deenvelope_raw(data: &[u8]) -> Result<(u16, u16, u16), ChannelError>
{
    if data.len() < 6 {
        return Err(ChannelError::Misc);
    }

    let message_type: MessageType = u16::from_le_bytes([data[0], data[1]]);
    let sequence = u16::from_le_bytes([data[2], data[3]]);
    let size = u16::from_le_bytes([data[4], data[5]]);

    Ok((message_type, sequence, size))
}


impl<O: ChannelOutlet> Envelope<O> {
    fn new(
        outlet: Arc<Mutex<O>>,
        message: Option<Arc<dyn Message>>,
        raw: Option<Vec<u8>>,
        sequence: Option<u16>
    ) -> Self {
        Self {
            timestamp: now(),
            message,
            raw,
            packet: None,
            sequence,
            outlet,
            tries: 0,
            unpacked: false,
            packed: false,
            tracked: false
        }
    }

    fn pack(&mut self) -> Result<(), ChannelError> {
        let msg = match self.message.as_ref() {
            Some(m) => m,
            None => {
                return Err(ChannelError::Misc);
            }
        };

        let msg_type = match msg.message_type() {
            Some(m) => m,
            None => {
                return Err(ChannelError::NoMessageType);
            }
        };
        
        let data = msg.pack(); 
        self.raw = Some(envelope_raw(&data, msg_type, self.sequence));
        self.packed = true;

        Ok(())
    }

    fn get_raw(&mut self) -> Result<&[u8], ChannelError> {
        if !self.packed {
            self.pack()?
        }
        Ok(self.raw.as_ref().unwrap())
    }

    fn unpack(
        &mut self,
        message_factory: &MessageFactory,
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

        self.message = Some(message_factory.create(message_type)?);
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
        message_factory: &MessageFactory
    ) -> Result<Arc<dyn Message>, ChannelError> {
        if !self.unpacked {
            self.unpack(message_factory)?;
        }

        Ok(Arc::clone(self.message.as_ref().unwrap()))
    }

    fn is_same_packet(&self, other: &Packet) -> bool {
        if let Some(ref our) = self.packet {
            our == other
        } else {
            false
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


type MessageCallback = fn(&Arc<dyn Message>) -> Result<bool, ChannelError>;


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


async fn find_tx_envelope<O:ChannelOutlet>(
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    packet: &Packet
) -> Option<Arc<Mutex<Envelope<O>>>> 
{
    let outlet = outlet.lock().await;
    let tx_ring = tx_ring.lock().await;
 
    for ref env in tx_ring.iter() {
        if env.lock().await.is_same_packet(packet) {
            return Some(Arc::clone(env));
        }
    }

    log::trace!("Spurious message received");
    None
}


async fn pop_tx_from_ring<O: ChannelOutlet>(
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    envelope: Arc<Mutex<Envelope<O>>>,
) {
    let mut i: Option<usize> = None;
    for (j, e) in tx_ring.lock().await.iter().enumerate() {
        if Arc::ptr_eq(e, &envelope) {
            i = Some(j)
        }
    }

    if i.is_none() {
        log::trace!("Envelope not found in tx ring");
        return;
    }

    tx_ring.lock().await.remove(i.unwrap());

}


fn adjust_params<O: ChannelOutlet>(
    outlet: &mut MutexGuard<O>,
    params: &mut MutexGuard<ChannelParams>
) {     
    if params.window < params.window_max {
        params.window += 1
    }

    let rtt = outlet.outlet_rtt();
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


struct PacketDeliveredCallback<O: ChannelOutlet> {
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    params: Arc<Mutex<ChannelParams>>
}


impl<O: ChannelOutlet> PacketDeliveredCallback<O> {
    fn new(
        outlet: &Arc<Mutex<O>>,
        tx_ring: &Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
        params: &Arc<Mutex<ChannelParams>>
    ) -> Self {
        Self {
            outlet: Arc::clone(&outlet),
            tx_ring: Arc::clone(&tx_ring),
            params: Arc::clone(&params)
        }
    }
}


#[async_trait]
impl<O: ChannelOutlet> PacketCallback for PacketDeliveredCallback<O> {
    async fn run(&self, packet: &Packet) {
        let maybe_envelope = find_tx_envelope(
            Arc::clone(&self.outlet),
            Arc::clone(&self.tx_ring),
            packet
        ).await;

        if let Some(env) = maybe_envelope {
            env.lock().await.tracked = false;
            pop_tx_from_ring(Arc::clone(&self.tx_ring), env).await;
            
            adjust_params(
                &mut self.outlet.lock().await, 
                &mut self.params.lock().await
            );
        }
    }
}


#[derive(Clone)]
struct PacketTimeoutCallback<O: ChannelOutlet> {
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    params: Arc<Mutex<ChannelParams>>
}


impl<O: ChannelOutlet> PacketTimeoutCallback<O> {
    fn new(
        outlet: &Arc<Mutex<O>>,
        tx_ring: &Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
        params: &Arc<Mutex<ChannelParams>>
    ) -> Self {
        Self {
            outlet: Arc::clone(&outlet),
            tx_ring: Arc::clone(&tx_ring),
            params: Arc::clone(&params)
        }
    }

    fn new_delivered_callback(&self) -> Option<Box<dyn PacketCallback>> {
        Some(Box::new(PacketDeliveredCallback::new(
            &self.outlet,
            &self.tx_ring,
            &self.params
        )))
    }

    fn new_timeout_callback(&self) ->Option<Box<dyn PacketCallback>> {
        Some(Box::new(PacketTimeoutCallback::new(
            &self.outlet,
            &self.tx_ring,
            &self.params
        )))
    }

    async fn run_callback(&self, env: &Arc<Mutex<Envelope<O>>>) -> bool {
        let max_tries = self.params.lock().await.max_tries;

        if env.lock().await.tries as u16 > self.params.lock().await.max_tries {
            log::error!("Retry count exceeded, tearing down link.");
            // TODO shutdown();
            self.outlet.lock().await.timed_out();
            return true;
        }
            
        env.lock().await.tries += 1;
        self.outlet.lock().await.resend(env.lock().await.packet.as_mut().unwrap());
        
        self.outlet.lock().await.set_packet_delivered_callback(
            env.lock().await.packet.as_ref().unwrap(),
            self.new_delivered_callback()
        );

        self.outlet.lock().await.set_packet_timeout_callback(
            env.lock().await.packet.as_ref().unwrap(),
            self.new_timeout_callback(),
            1.0 // TODO proper value
        );

        // TODO update_packet_timeouts();

        let mut params = self.params.lock().await;
        if params.window > params.window_min {
            params.window -= 1;
            if params.window_max > params.window_min + params.window_flexibility {
                params.window_max -= 1;
            }
        }
        false
    }
}


#[async_trait]
impl<O: ChannelOutlet> PacketCallback for PacketTimeoutCallback<O> {
    async fn run(&self, packet: &Packet) {
        let maybe_envelope = find_tx_envelope(
            Arc::clone(&self.outlet),
            Arc::clone(&self.tx_ring),
            packet
        ).await;

        if let Some(env) = maybe_envelope {
            let flag = self.run_callback(&env).await;

            if flag {
                env.lock().await.tracked = false;
                pop_tx_from_ring(Arc::clone(&self.tx_ring), env).await;
                adjust_params(
                    &mut self.outlet.lock().await, 
                    &mut self.params.lock().await
                );
            }
        }
    }
}


pub type MessageCallbackId = usize;


pub struct Channel<O: ChannelOutlet> {
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    rx_ring: VecDeque<Arc<Mutex<Envelope<O>>>>,
    message_callbacks: Vec<Option<Box<MessageCallback>>>,
    next_sequence: u16,
    next_rx_sequence: u16,
    message_factory: MessageFactory,
    params: Arc<Mutex<ChannelParams>>
}


impl<O: ChannelOutlet + 'static> Channel<O> {
    async fn new(outlet: Arc<Mutex<O>>) -> Self {
        let slow = outlet.lock().await.outlet_rtt() > RTT_SLOW;
        let params = Arc::new(Mutex::new(ChannelParams::new(slow)));

        Self {
            outlet,
            tx_ring: Default::default(),
            rx_ring: Default::default(),
            message_callbacks: Default::default(),
            next_sequence: 0,
            next_rx_sequence: 0,
            message_factory: Default::default(),
            params
        }
    }

    fn register_message_type(
        &mut self,
        message_type: MessageType,
        factory: fn() -> Arc<dyn Message>,
        is_system_type: bool
    ) -> Result<(), ChannelError> {
        if message_type >= 0xf000 && !is_system_type {
            return Err(ChannelError::InvalidMessageType);
        }
        self.message_factory.register_type(message_type, factory);
        Ok(())
    }

    fn add_message_handler(
        &mut self,
        callback: MessageCallback
    ) -> MessageCallbackId {
        let id = self.message_callbacks.len();
        self.message_callbacks.push(Some(Box::new(callback)));
        return id;
    }

    fn remove_message_handler(&mut self, id: MessageCallbackId) -> bool {
        let found = self.message_callbacks.get(id).unwrap_or(&None).is_some();

        if found {
            self.message_callbacks[id] = None;
        }

        found
    }
    
    async fn clear_rings(&mut self) {
        let mut tx_ring = self.tx_ring.lock().await;
        let mut outlet = self.outlet.lock().await;

        for ref envelope in tx_ring.iter() {
            let env = envelope.lock().await;
            if let Some(ref packet) = env.packet {
                outlet.set_packet_timeout_callback(packet, None, 0.0);
                outlet.set_packet_delivered_callback(packet, None);
            }
        }
        tx_ring.clear();
        self.rx_ring.clear();
    }

    async fn shutdown(&mut self) {
        self.message_callbacks.clear();
        self.clear_rings().await;
    }

    async fn emplace_envelope(
        &mut self,
        envelope: Arc<Mutex<Envelope<O>>>,
        rx: bool
    ) -> bool {
        let env_sequence = envelope.lock().await.sequence;

        let ring = if rx {
            &mut self.rx_ring
        } else {
            &mut *self.tx_ring.lock().await
        };

        let mut inserted = false;

        for (i, existing) in ring.iter().enumerate() {
            let ex_sequence = existing.lock().await.sequence;
            if env_sequence == ex_sequence {
                log::trace!("Envelope: Emplacement of duplicate envelope");
                return false;
            }

            if env_sequence < ex_sequence {
                if !2*(self.next_rx_sequence - env_sequence.unwrap_or(0)) as u32 > SEQ_MAX {
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

    fn run_callbacks(&self, message: &Arc<dyn Message>) {
        for maybe_callback in self.message_callbacks.iter() {
            if let Some(callback) = maybe_callback {
                match (* callback)(message) {
                    Ok(is_done) => {
                        if is_done {
                            return;
                        }
                    },
                    Err(_) => {
                        log::error!("Error running message callback");
                    }
                }
            }
        }
    }

    async fn receive_traverse_ring(
        &mut self,
        contiguous: &mut Vec<Arc<Mutex<Envelope<O>>>>
    ) -> bool {
        let mut retained = VecDeque::new();
        let mut start_over = false;

        while let Some(env) = self.rx_ring.pop_front() {
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

        if start_over {
            retained.append(&mut self.rx_ring);
        }

        self.rx_ring = retained;

        start_over
    }

    async fn receive(&mut self, raw: &[u8]) {
        let mut envelope = Envelope::new(
            self.outlet.clone(),
            None,
            Some(raw.to_vec()),
            None
        );
        
        if envelope.unpack(&self.message_factory).is_err() {
            log::error!("Message could not be unpacked");
            return;
        }

        let sequence = envelope.sequence.expect(
            "Sequence is set on all unpacked messages."
        );

        if sequence < self.next_rx_sequence {
            let overflow = sequence.saturating_add(WINDOW_MAX);
            
            if overflow >= self.next_rx_sequence || sequence > overflow {
                log::trace!("Incalid packet sequence");
                return;
            }
        }

        let envelope = Arc::new(Mutex::new(envelope));
        let is_new = self.emplace_envelope(envelope, true).await;

        if !is_new {
            log::trace!("Duplicate message received");
        }

        let mut contiguous = vec![];
        let start_over = self.receive_traverse_ring(&mut contiguous).await;
        if start_over {
            self.receive_traverse_ring(&mut contiguous).await;
        }

        for env in contiguous {
            match env.lock().await.get_message(&self.message_factory) {
                Ok(ref message) => {
                    self.run_callbacks(message);
                },
                Err(_) => {
                    log::trace!("Message could not be unpacked");
                }
            }
        }
    }

    async fn is_ready_to_send(&self) -> bool {
        let tx_ring = self.tx_ring.lock().await;

        if !self.outlet.lock().await.is_usable() {
            return false
        }

        let mut outstanding = 0;
        for envelope in tx_ring.iter() {
            let env = envelope.lock().await;
            if !Arc::ptr_eq(&env.outlet, &self.outlet) {
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

    fn update_packet_timeouts(&mut self) {
        //TODO
    }

    async fn get_packet_timeout_time(&self, rtt: f32, tries: u64) -> f32 {
        let ring_len = self.tx_ring.lock().await.len();

        let rtt_factor = if rtt > 0.01 { rtt * 2.5 } else { 0.025 };
        let tries_factor = 1.5f32.powi(tries.saturating_sub(1) as i32);

        tries_factor * rtt_factor * (ring_len as f32 + 1.5)
    }

    fn new_delivered_callback(&self) -> Option<Box<dyn PacketCallback>> {
        Some(Box::new(PacketDeliveredCallback::new(
            &self.outlet,
            &self.tx_ring,
            &self.params
        )))
    }

    fn new_timeout_callback(&self) -> Option<Box<dyn PacketCallback>> {
        Some(Box::new(PacketTimeoutCallback::new(
            &self.outlet,
            &self.tx_ring,
            &self.params
        )))
    }
    
    pub async fn send(
        &mut self,
        message: &Arc<dyn Message>,
        transport: &Arc<Mutex<Transport>>,
    ) -> Result<Arc<Mutex<Envelope<O>>>, ChannelError> {
        if !self.is_ready_to_send().await {
            return Err(ChannelError::LinkNotReady);
        }

        let mut envelope = Arc::new(Mutex::new(Envelope::new(
            Arc::clone(&self.outlet),
            Some(Arc::clone(message)), 
            None,
            Some(self.next_sequence)
        )));

        self.next_sequence += 1;

        self.emplace_envelope(Arc::clone(&envelope), false).await;

        {
            let env = &mut envelope.lock().await;
            let mut outlet = self.outlet.lock().await;

            let raw = env.get_raw()?;

            if raw.len() > outlet.mdu() as usize {
                return Err(ChannelError::TooBig);
            }

            let packet = outlet.send(&raw, transport).await;

            env.tries += 1;
            let rtt = outlet.outlet_rtt();
           
            outlet.set_packet_delivered_callback(
                &packet,
                self.new_delivered_callback()
            );
            outlet.set_packet_timeout_callback(
                &packet,
                self.new_timeout_callback(),
                self.get_packet_timeout_time(rtt, env.tries).await
            );

            env.packet = Some(packet);
        }

        self.update_packet_timeouts();

        Ok(envelope)
    }

    async fn mdu(&self) -> usize {
        self.outlet.lock().await.mdu() - 6
    }
}


pub struct WrappedLink {
    link: Arc<Mutex<Link>>,
    channel: Channel<Link>
}


impl WrappedLink {
    pub async fn new(link: Arc<Mutex<Link>>) -> Self {
        let channel = Channel::new(Arc::clone(&link)).await;
        Self { link, channel }
    }

    fn get_link(&self) -> Arc<Mutex<Link>> {
        Arc::clone(&self.link)
    }

    pub fn get_channel(&mut self) -> &mut Channel<Link> {
        &mut self.channel
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
