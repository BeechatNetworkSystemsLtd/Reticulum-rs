use alloc::collections::{BTreeMap, VecDeque};
use std::{
    boxed::Box,
    sync::{Arc, Mutex},
};
use crate::{
    destination::link::{Link, LinkStatus},
    packet::{Packet, PacketContext, PacketDataBuffer, PACKET_MDU},
};


type MessageType = u16;
static SMT_STREAM_DATA: MessageType = 0xff00;


#[derive(PartialEq)]
enum MessageState {
    New,
    Sent,
    Delivered,
    Failed
}


trait ChannelOutlet {
    fn send(&self, raw: &[u8]) -> Packet;

    fn resend(&self, packet: &mut Packet);

    fn mdu(&self) -> usize;

    fn rtt(&self) -> f32;

    fn is_usable(&self) -> bool;

    fn get_packet_state(&self, packet: &Packet) -> MessageState;

    fn timed_out(&self) -> bool; // TODO return type?

    fn set_packet_timeout_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn FnOnce(&Packet)>>,
        timeout: f32,
    );

    fn set_packet_delivered_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn FnOnce(&Packet)>>
    );

    fn get_packet_id(&self, packet: &Packet) -> u32;
}


struct LinkOutlet(Link);


impl ChannelOutlet for LinkOutlet {
    fn send(&self, raw: &[u8]) -> Packet {
        let mut packet: Packet = Default::default();
        packet.data = PacketDataBuffer::new_from_slice(raw);
        packet.context = PacketContext::Channel;
        // TODO link

        if self.0.status() == LinkStatus::Active {
            todo!() // Packet::send implemented?
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

    fn rtt(&self) -> f32 {
        todo!() // implement rtt in link
    }

    fn is_usable(&self) -> bool {
        self.0.status() == LinkStatus::Active
        // TODO always true in ref impl, "issues looking at Link.status"
    }

    fn get_packet_state(&self, packet: &Packet) -> MessageState {
        todo!();
    }

    fn timed_out(&self) -> bool {
        todo!();
    }

    fn set_packet_timeout_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn FnOnce(&Packet)>>,
        timeout: f32
    ) {
        todo!();
    }

    fn set_packet_delivered_callback(
        &mut self,
        packet: &Packet,
        callback: Option<Box<dyn FnOnce(&Packet)>>
    ) {
        todo!();
    }

    fn get_packet_id(&self, packet: &Packet) -> u32 {
        todo!();
    }
}


trait Message {
    fn message_type(&self) -> Option<MessageType>;

    fn pack(&self) -> Vec<u8>;

    fn unpack(&mut self, raw: &[u8]);
}


enum ChannelError {
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


struct Envelope<O: ChannelOutlet> {
    timestamp: u64,
    id: u64,
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


fn deenvelope_raw(data: &[u8]) -> (u16, u16, u16)
{
    assert!(data.len() >= 6); // TODO proper runtime error

    let message_type: MessageType = u16::from_le_bytes([data[0], data[1]]);
    let sequence = u16::from_le_bytes([data[2], data[3]]);
    let size = u16::from_le_bytes([data[4], data[5]]);

    (message_type, sequence, size)
}


impl<O: ChannelOutlet> Envelope<O> {
    fn new(
        outlet: Arc<Mutex<O>>,
        message: Option<Arc<dyn Message>>,
        raw: Option<Vec<u8>>,
        sequence: Option<u16>
    ) -> Self {
        Self {
            timestamp: 0, // TODO
            id: 0, // TODO
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
        let msg = self.message.as_ref().expect(
            "Ref impl assumes message to be initialized at this point"
        );

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
        let (message_type, _, size) = deenvelope_raw(raw);

        if raw.len() as u16 != size + 6 {
            log::trace!(
                "Length field in envelope doesn't match actual message length. Ignoring."
            );
        }

        self.message = Some(message_factory.create(message_type)?);
        self.unpacked = true;

        Ok(())
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
static SEQ_MODULUS: u32 = SEQ_MAX+1;


type MessageCallback = fn(&Box<dyn Message>) -> Result<bool, ChannelError>;


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


fn _tx_packet_op<O: ChannelOutlet>(
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    params: Arc<Mutex<ChannelParams>>,
    packet: &Packet,
    op: Box<dyn FnOnce(&mut Envelope<O>) -> bool>
) {
    let mut outlet = outlet.lock().unwrap();
    let mut tx_ring = tx_ring.lock().unwrap();
 
    let mut envelope: Option<Arc<Mutex<Envelope<O>>>> = None;

    let packet_id = outlet.get_packet_id(packet);
    for ref env in tx_ring.iter() {
        if let Some(ref env_packet) = env.lock().unwrap().packet {
            if outlet.get_packet_id(env_packet) == packet_id {
                envelope = Some(Arc::clone(env));
                break;
            }
        }
    }

    if envelope.is_none() {
        log::trace!("Spurious message received");
        return;
    }

    let mut envelope = envelope.unwrap();
    if !op (&mut envelope.lock().unwrap()) {
        return;
    }

    envelope.lock().unwrap().tracked = false;
        
    let mut i: Option<usize> = None;
    for (j, e) in tx_ring.iter().enumerate() {
        if Arc::ptr_eq(e, &envelope) {
            i = Some(j)
        }
    }

    if i.is_none() {
        log::trace!("Envelope not found in tx ring");
        return;
    }

    tx_ring.remove(i.unwrap());

    let mut params = params.lock().unwrap();
        
    if params.window < params.window_max {
        params.window += 1
    }

    let rtt = outlet.rtt();
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


fn packet_delivered_callback<O: ChannelOutlet>(
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    params: Arc<Mutex<ChannelParams>>,
    packet: &Packet
) {
    _tx_packet_op(
        outlet,
        tx_ring,
        params,
        packet,
        Box::new(|_| { true })
    );
}


fn packet_timeout_callback<O: ChannelOutlet + 'static>(
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    params: Arc<Mutex<ChannelParams>>,
    packet: &Packet
) {
    let state = outlet.lock().unwrap().get_packet_state(packet);

    if state == MessageState::Delivered {
        return;
    }

    let outlet1 = Arc::clone(&outlet);
    let params1 = Arc::clone(&params);
    let tx_ring1 = Arc::clone(&tx_ring);

    _tx_packet_op(
        outlet,
        tx_ring,
        params,
        packet,
        Box::new(move |env| -> bool {
            
            if env.tries as u16 > params1.lock().unwrap().max_tries {
                log::error!("Retry count exceeded, tearing down link.");
                // TODO self.shutdown();
                outlet1.lock().unwrap().timed_out();
                return true;
            }
            
            let outlet2 = Arc::clone(&outlet1);
            let params2 = Arc::clone(&params1);
            let tx_ring2 = Arc::clone(&tx_ring1);

            env.tries += 1;
            outlet1.lock().unwrap().resend(env.packet.as_mut().unwrap());
            outlet1.lock().unwrap().set_packet_delivered_callback(
                env.packet.as_ref().unwrap(),
                Some(Box::new(move |p: &Packet| {
                    packet_delivered_callback(
                        outlet2, 
                        tx_ring2, 
                        params2, 
                        p
                    );
                }))
            );

            let outlet3 = Arc::clone(&outlet1);
            let params3 = Arc::clone(&params1);
            let tx_ring3 = Arc::clone(&tx_ring1);

            outlet1.lock().unwrap().set_packet_timeout_callback(
                env.packet.as_ref().unwrap(),
                Some(Box::new(|p: &Packet| {
                    packet_timeout_callback(outlet3, tx_ring3, params3, p);
                })),
                1.0 // TODO proper value
            );
            // TODO update_packet_timeouts();

            let mut params = params1.lock().unwrap();
            if params.window > params.window_min {
                params.window -= 1;
                if params.window_max > params.window_min + params.window_flexibility {
                    params.window_max -= 1;
                }
            }
            false
        })
    );
}



struct Channel<O: ChannelOutlet> {
    outlet: Arc<Mutex<O>>,
    tx_ring: Arc<Mutex<VecDeque<Arc<Mutex<Envelope<O>>>>>>,
    rx_ring: VecDeque<Arc<Mutex<Envelope<O>>>>,
    message_callbacks: Vec<Box<MessageCallback>>,
    next_sequence: u16,
    next_rx_sequence: u16,
    message_factory: MessageFactory,
    params: Arc<Mutex<ChannelParams>>
}


impl<O: ChannelOutlet + 'static> Channel<O> {
    fn new(outlet: Arc<Mutex<O>>) -> Self {
        let slow = outlet.lock().unwrap().rtt() > RTT_SLOW;
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
    ) {
        self.message_callbacks.push(Box::new(callback));
        // TODO check for duplicates
    }

    // TODO remove_message_handler
    
    fn clear_rings(&mut self) {
        let mut tx_ring = self.tx_ring.lock().unwrap();

        let mut outlet = self.outlet.lock().unwrap();
        for ref envelope in tx_ring.iter() {
            let env = envelope.lock().unwrap();
            if let Some(ref packet) = env.packet {
                outlet.set_packet_timeout_callback(packet, None, 0.0);
                outlet.set_packet_delivered_callback(packet, None);
            }
        }
        tx_ring.clear();
        self.rx_ring.clear();
    }

    fn shutdown(&mut self) {
        self.message_callbacks.clear();
        self.clear_rings();
    }

    fn emplace_envelope(
        &mut self,
        envelope: Arc<Mutex<Envelope<O>>>,
    ) -> bool {
        let env_sequence = envelope.lock().unwrap().sequence;

        let mut ring = self.tx_ring.lock().unwrap();

        for (i, existing) in ring.iter().enumerate() {
            let ex_sequence = existing.lock().unwrap().sequence;
            if env_sequence == ex_sequence {
                log::trace!("Envelope: Emplacement of duplicate envelope");
                return false;
            }

            if env_sequence < ex_sequence {
                if ! 2*(self.next_rx_sequence - env_sequence.unwrap_or(0)) as u32 > SEQ_MAX {
                    ring.insert(i, envelope.clone());
                    envelope.lock().unwrap().tracked = true;
                    return true;
                }
            }
        }

        ring.push_back(envelope.clone());

        envelope.lock().unwrap().tracked = true;
        true
    }

    fn run_callbacks(self, message: &Box<dyn Message>) {
        for callback in self.message_callbacks {
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

    fn receive(&mut self, raw: &[u8]) {
        let mut envelope = Envelope::new(self.outlet.clone(), None, Some(raw.to_vec()), None);
        
        if envelope.unpack(&self.message_factory).is_err() {
            log::error!("Message could not be unpacked");
            return;
        }

        todo!();
    }

    fn is_ready_to_send(&self) -> bool {
        let tx_ring = self.tx_ring.lock().unwrap();

        if !self.outlet.lock().unwrap().is_usable() {
            return false
        }

        let mut outstanding = 0;
        for envelope in tx_ring.iter() {
            let env = envelope.lock().unwrap();
            if !Arc::ptr_eq(&env.outlet, &self.outlet) {
                continue;
            }

            if let Some(ref packet) = env.packet {
                let state = self.outlet.lock().unwrap().get_packet_state(packet);
                if state == MessageState::Delivered {
                    continue;
                }
            }
            
            outstanding += 1;
        }

        outstanding < self.params.lock().unwrap().window
    }

    fn packet_tx_op(
        &self,
        packet: &Packet,
        op: Box<dyn Fn(&mut Envelope<O>) -> bool>
    ) {
        _tx_packet_op(
            Arc::clone(&self.outlet),
            Arc::clone(&self.tx_ring),
            Arc::clone(&self.params),
            packet,
            op
        );
    }

    fn update_packet_timeouts(&mut self) {
        todo!();
    }

    fn get_packet_timeout_time(&self, tries: u64) -> f32 {
        todo!();
    }

    fn send(
        &mut self,
        message: &Arc<dyn Message>
    ) -> Result<Arc<Mutex<Envelope<O>>>, ChannelError> {
        if !self.is_ready_to_send() {
            return Err(ChannelError::LinkNotReady);
        }

        let mut envelope = Arc::new(Mutex::new(Envelope::new(
            Arc::clone(&self.outlet),
            Some(Arc::clone(message)), 
            None,
            Some(self.next_sequence)
        )));

        self.next_sequence += 1;
        self.next_sequence %= SEQ_MODULUS as u16;

        self.emplace_envelope(Arc::clone(&envelope));

        {
            let outlet1 = Arc::clone(&self.outlet);
            let params1 = Arc::clone(&self.params);
            let tx_ring1 = Arc::clone(&self.tx_ring);

            let outlet2 = Arc::clone(&self.outlet);
            let params2 = Arc::clone(&self.params);
            let tx_ring2 = Arc::clone(&self.tx_ring);

            let env = &mut envelope.lock().unwrap();
            let mut outlet = self.outlet.lock().unwrap();

            let raw = env.raw.as_ref().unwrap().clone();
            if raw.len() > outlet.mdu() as usize {
                return Err(ChannelError::TooBig);
            }

            let packet = outlet.send(&raw);

            env.tries += 1;
            
            outlet.set_packet_delivered_callback(
                &packet, 
                Some(Box::new(move |p: &Packet| {
                    packet_delivered_callback(outlet1, tx_ring1, params1, p);
                }))
            ); 
            outlet.set_packet_timeout_callback(
                &packet,
                Some(Box::new(move |p: &Packet| { 
                    packet_timeout_callback(outlet2, tx_ring2, params2, p); 
                })),
                self.get_packet_timeout_time(env.tries)
            );

            env.packet = Some(packet);
        }

        self.update_packet_timeouts();

        Ok(envelope)
    }

    fn mdu(&self) -> usize {
        self.outlet.lock().unwrap().mdu() - 6
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
