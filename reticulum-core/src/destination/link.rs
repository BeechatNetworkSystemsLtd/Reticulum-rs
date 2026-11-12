use alloc::{boxed::Box, vec::Vec};

use core::{cmp::min, time::Duration};

use ed25519_dalek::{Signature, SigningKey, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use rand_core::OsRng;
use sha2::Digest;
use x25519_dalek::StaticSecret;

use crate::{
    buffer::OutputBuffer,
    error::RnsError,
    hash::{AddressHash, Hash, ADDRESS_HASH_SIZE, HASH_SIZE},
    identity::{DecryptIdentity, DerivedKey, EncryptIdentity, Identity, PrivateIdentity},
    packet::{
        DestinationType, Header, Packet, PacketContext, PacketDataBuffer, PacketType, PACKET_MDU,
    },
    time::now,
};

use super::DestinationDesc;

const LINK_MTU_SIZE: usize = 3;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum LinkStatus {
    Pending = 0x00,
    Handshake = 0x01,
    Active = 0x02,
    Stale = 0x03,
    Closed = 0x04,
}

impl LinkStatus {
    pub fn not_yet_active(&self) -> bool {
        *self == LinkStatus::Pending || *self == LinkStatus::Handshake
    }
}

pub type LinkId = AddressHash;

#[derive(Clone, Debug)]
pub struct LinkPayload {
    buffer: [u8; PACKET_MDU],
    len: usize,
}

impl LinkPayload {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; PACKET_MDU],
            len: 0,
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut buffer = [0u8; PACKET_MDU];

        let len = min(data.len(), buffer.len());

        buffer[..len].copy_from_slice(&data[..len]);

        Self { buffer, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.len]
    }
}

impl Default for LinkPayload {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&Packet> for LinkId {
    fn from(packet: &Packet) -> Self {
        let data = packet.data.as_slice();
        let data_diff = if data.len() > PUBLIC_KEY_LENGTH * 2 {
            data.len() - PUBLIC_KEY_LENGTH * 2
        } else {
            0
        };

        let hashable_data = &data[..data.len() - data_diff];

        AddressHash::new_from_hash(&Hash::new(
            Hash::generator()
                .chain_update([packet.header.to_meta() & 0b00001111])
                .chain_update(packet.destination.as_slice())
                .chain_update([packet.context as u8])
                .chain_update(hashable_data)
                .finalize()
                .into(),
        ))
    }
}

// TODO: consider boxing MessageReceived because Packet is >2000 bytes
#[expect(clippy::large_enum_variant)]
pub enum LinkHandleResult {
    None,
    Activated,
    KeepAlive,
    MessageReceived(Option<Packet>),
}

#[derive(Clone, Debug)]
pub enum LinkEvent {
    Activated,
    // LinkPayload >2000 bytes so we box it
    Data(Box<LinkPayload>),
    Proof(Hash),
    // Identity 240 bytes
    RemoteIdentified(Box<Identity>),
    Closed,
}

#[derive(Clone, Debug)]
pub struct LinkEventData {
    pub id: LinkId,
    pub address_hash: AddressHash,
    pub event: LinkEvent,
}

pub trait LinkEventSink: Clone + Send + Sync + 'static {
    fn send(&self, event: LinkEventData);
}

pub trait LinkPayloadSink: Clone + Send + Sync + 'static {
    fn send(&self, payload: LinkPayload);
}

pub struct Link {
    id: LinkId,
    destination: DestinationDesc,
    priv_identity: PrivateIdentity,
    peer_identity: Identity,
    /// For out-links (initiators), this will be set to the identity of the owner of the Link
    /// destination after the handshake. For in-links, this will remain None unless the remote peer
    /// identifies with `link.identify(identity)`
    remote_identity: Option<Identity>,
    derived_key: DerivedKey,
    status: LinkStatus,
    request_time: Duration,
    rtt: Duration,
    proves_messages: bool,
}

impl Link {
    pub fn new(destination: DestinationDesc) -> Self {
        Self {
            id: AddressHash::new_empty(),
            destination,
            priv_identity: PrivateIdentity::new_from_rand(OsRng),
            peer_identity: Identity::default(),
            remote_identity: None,
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            request_time: now(),
            rtt: Duration::from_secs(0),
            proves_messages: false,
        }
    }

    pub fn prove_messages(&mut self, setting: bool) {
        self.proves_messages = setting;
    }

    pub fn new_from_request(
        packet: &Packet,
        signing_key: SigningKey,
        destination: DestinationDesc
    ) -> Result<Self, RnsError> {
        if packet.data.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::InvalidArgument);
        }

        let peer_identity = Identity::new_from_slices(
            &packet.data.as_slice()[..PUBLIC_KEY_LENGTH],
            &packet.data.as_slice()[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        );

        let link_id = LinkId::from(packet);
        log::debug!("link: create from request {}", link_id);

        let mut link = Self {
            id: link_id,
            destination,
            priv_identity: PrivateIdentity::new(StaticSecret::random_from_rng(OsRng), signing_key),
            peer_identity,
            remote_identity: None,
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            request_time: now(),
            rtt: Duration::from_secs(0),
            proves_messages: false,
        };

        link.handshake(peer_identity);

        Ok(link)
    }

    pub fn request(&mut self) -> Packet {
        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());

        let packet = Packet {
            header: Header {
                packet_type: PacketType::LinkRequest,
                ..Default::default()
            },
            ifac: None,
            destination: self.destination.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        };

        self.status = LinkStatus::Pending;
        self.id = LinkId::from(&packet);
        self.touch();

        packet
    }

    pub fn touch(&mut self) {
        self.request_time = now();
        if self.status == LinkStatus::Stale {
            log::info!("link({}): active again", self.id);
            self.status = LinkStatus::Active;
        }
    }

    pub fn data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        match self.status {
            LinkStatus::Pending | LinkStatus::Handshake => {
                log::warn!("link: can't create data packet for pending link");
                return Err(RnsError::LinkNotReady)
            }
            LinkStatus::Closed => {
                log::warn!("link: can't create data packet for closed link");
                return Err(RnsError::LinkClosed)
            }
            LinkStatus::Active | LinkStatus::Stale => {}
        }

        let mut packet_data = PacketDataBuffer::new();

        let cipher_text_len = {
            let cipher_text = self.encrypt(data, packet_data.accuire_buf_max())?;
            cipher_text.len()
        };

        packet_data.resize(cipher_text_len);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    /// Identifies the initiator of the link to the remote peer
    pub fn identify(&self, identity: &PrivateIdentity) -> Result<Packet, RnsError> {
        match self.status {
            LinkStatus::Pending | LinkStatus::Handshake => {
                log::warn!("link: can't create identify packet for pending link");
                return Err(RnsError::LinkNotReady)
            }
            LinkStatus::Closed => {
                log::warn!("link: can't create identify packet for closed link");
                return Err(RnsError::LinkClosed)
            }
            LinkStatus::Active | LinkStatus::Stale => {}
        }
        let pub_identity = identity.as_identity();
        let signed_data = [
            self.id.as_slice(), pub_identity.public_key_bytes(), pub_identity.verifying_key_bytes()
        ].concat();
        let signature = identity.sign(&signed_data);
        let proof_data = [
            pub_identity.public_key_bytes(),
            pub_identity.verifying_key_bytes(),
            &signature.to_bytes()[..]
        ].concat();
        let mut data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt(&proof_data, data.accuire_buf_max())?;
            cipher_text.len()
        };
        data.resize(cipher_text_len);
        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkIdentify,
            data
        })
    }

    pub fn keep_alive_packet(&self, data: u8) -> Packet {
        log::trace!("link({}): create keep alive {}", self.id, data);

        let mut packet_data = PacketDataBuffer::new();
        packet_data.safe_write(&[data]);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::KeepAlive,
            data: packet_data,
        }
    }

    pub fn message_proof(&self, hash: Hash) -> Packet {
        log::trace!("link({}): creating proof for message hash {}", self.id, hash);

        let signature = self.priv_identity.sign(hash.as_slice());

        let mut packet_data = PacketDataBuffer::new();
        packet_data.safe_write(hash.as_slice());
        packet_data.safe_write(&signature.to_bytes()[..]);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        }
    }

    pub fn encrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.priv_identity
            .encrypt(OsRng, text, &self.derived_key, out_buf)
    }

    pub fn decrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.priv_identity
            .decrypt(OsRng, text, &self.derived_key, out_buf)
    }

    pub fn destination(&self) -> &DestinationDesc {
        &self.destination
    }

    /// For out-links (initiators), this is the identity of the 'Link' destination owner after it
    /// has been verified and the 'Link' is 'Active'. For in-links, the remote identity is unknown
    /// until the link initiator has identified using `link.identify(identity)`.
    pub fn remote_identity(&self) -> Option<Identity> {
        self.remote_identity
    }

    pub fn create_rtt(&self) -> Packet {
        let rtt = self.rtt.as_secs_f64();
        let mut buf = Vec::with_capacity(9);
        rmp::encode::write_f64(&mut buf, rtt).unwrap();

        let mut packet_data = PacketDataBuffer::new();

        let token_len = {
            let token = self
                .encrypt(buf.as_slice(), packet_data.accuire_buf_max())
                .expect("encrypted data");
            token.len()
        };

        packet_data.resize(token_len);

        log::trace!("link: {} create rtt packet = {} sec", self.id, rtt);

        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRTT,
            data: packet_data,
        }
    }

    fn handshake(&mut self, peer_identity: Identity) {
        log::debug!("link({}): handshake", self.id);

        self.status = LinkStatus::Handshake;
        self.peer_identity = peer_identity;

        self.derived_key = self
            .priv_identity
            .derive_key(&self.peer_identity.public_key, Some(self.id.as_slice()));
    }

    fn post_event<E: LinkEventSink>(&self, event_tx: &E, event: LinkEvent) {
        event_tx.send(LinkEventData {
            id: self.id,
            address_hash: self.destination.address_hash,
            event,
        });
    }

    pub fn stale(&mut self) {
        self.status = LinkStatus::Stale;

        log::warn!("link: stale {}", self.id);
    }

    pub fn restart(&mut self) {
        log::warn!(
            "link({}): restart after {}s",
            self.id,
            self.elapsed().as_secs()
        );

        self.status = LinkStatus::Pending;
    }

    pub fn elapsed(&self) -> Duration {
        now() - self.request_time
    }

    pub fn status(&self) -> LinkStatus {
        self.status
    }

    pub fn set_status(&mut self, status: LinkStatus) {
        self.status = status
    }

    pub fn id(&self) -> &LinkId {
        &self.id
    }

    pub fn priv_identity(&self) -> &PrivateIdentity {
        &self.priv_identity
    }

    pub fn rtt(&self) -> &Duration {
        &self.rtt
    }

    fn handle_data_packet<E: LinkEventSink, P: LinkPayloadSink>(
        &mut self,
        event_tx: &E,
        channel_tx: Option<&P>,
        packet: &Packet,
        out_link: bool
    ) -> LinkHandleResult {
        if self.status != LinkStatus::Active {
            log::warn!("link({}): handling data packet in inactive state", self.id);
        }

        match packet.context {
            PacketContext::None => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): data {}B", self.id, plain_text.len());
                    self.touch();
                    self.post_event(event_tx,
                        LinkEvent::Data(Box::new(LinkPayload::new_from_slice(plain_text))));

                    let proof = if self.proves_messages {
                        Some(self.message_proof(packet.hash()))
                    } else {
                        None
                    };

                    return LinkHandleResult::MessageReceived(proof);
                } else {
                    log::error!("link({}): can't decrypt packet", self.id);
                }
            }
            PacketContext::LinkIdentify => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): link identify data {}B", self.id, plain_text.len());
                    self.touch();
                    if !out_link && plain_text.len() == PUBLIC_KEY_LENGTH * 2 + SIGNATURE_LENGTH {
                        let public_key = &plain_text[..PUBLIC_KEY_LENGTH];
                        let verifying_key = &plain_text[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2];
                        let signed_data = [self.id().as_slice(), public_key, verifying_key].concat();
                        let signature = match Signature::from_slice(
                            &plain_text[PUBLIC_KEY_LENGTH * 2..]
                        ) {
                            Ok(signature) => signature,
                            Err(err) => {
                                log::warn!(
                                    "link({}): link identify packet invalid signature bytes: {err}",
                                    self.id());
                                return LinkHandleResult::None
                            }
                        };
                        let identity = Identity::new_from_slices(public_key, verifying_key);
                        match identity.verify(&signed_data, &signature) {
                            Ok(()) => {
                                if let Some(remote_id) = self.remote_identity.as_ref() {
                                    log::debug!("link({}): link identity {} is valid but link is already identified as {}",
                                        self.id(), identity.address_hash, remote_id.address_hash);
                                } else {
                                    log::debug!("link({}): link identified: {}",
                                        self.id(), identity.address_hash);
                                    self.remote_identity = Some(identity);
                                    self.post_event(event_tx, LinkEvent::RemoteIdentified(Box::new(identity)));
                                }
                            }
                            Err(err) => log::warn!(
                                "link({}): identity verification failed: {err:?}", self.id())
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt link identify packet", self.id);
                }
            }
            PacketContext::KeepAlive => {
                if !packet.data.is_empty() && packet.data.as_slice()[0] == 0xFF {
                    if out_link {
                        log::trace!("link({}): own keep-alive request heard back", self.id);
                        return LinkHandleResult::None;
                    }
                    self.touch();
                    log::trace!("link({}): keep-alive request", self.id);
                    return LinkHandleResult::KeepAlive;
                }
                if !packet.data.is_empty() && packet.data.as_slice()[0] == 0xFE {
                    if !out_link {
                        log::trace!("link({}): own keep-alive response heard back", self.id);
                        return LinkHandleResult::None;
                    }
                    log::trace!("link({}): keep-alive response", self.id);
                    self.touch();
                    return LinkHandleResult::None;
                }
            }
            PacketContext::LinkRTT if !out_link => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    if let Ok(rtt) = rmp::decode::read_f64(&mut &plain_text[..]) {
                        self.rtt = Duration::from_secs_f64(rtt);
                    } else {
                        log::error!("link({}): failed to decode rtt", self.id);
                    }
                } else {
                    log::error!("link({}): can't decrypt rtt packet", self.id);
                }
            }
            PacketContext::LinkClose => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    match plain_text[..].try_into() {
                        Err(err) => {
                            log::error!("link({}): invalid decode link close payload: {err}",
                                self.id)
                        }
                        Ok(dest_bytes) => {
                            let link_id = LinkId::new(dest_bytes);
                            if self.id == link_id {
                                self.close(event_tx);
                            }
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt link close packet", self.id);
                }
            }
            PacketContext::Channel => {
                if let Some(channel_tx) = channel_tx {
                    let mut buffer = [0u8; PACKET_MDU];
                    if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer) {
                        log::trace!("link({}): data over channel {}B", self.id, plain_text.len());
                        self.request_time = now();

                        channel_tx.send(LinkPayload::new_from_slice(plain_text));

                        let payload = LinkPayload::new_from_slice(plain_text);
                        self.post_event(event_tx, LinkEvent::Data(Box::new(payload)));

                        let proof = Some(self.message_proof(packet.hash()));

                        return LinkHandleResult::MessageReceived(proof);
                    } else {
                        log::error!("link({}): can't decrypt channel packet", self.id);
                    }
                } else {
                    log::error!("link({}): received channel packet but have no channel", self.id);
                }
            }
            _ => {}
        }

        LinkHandleResult::None
    }

    fn handle_proof_packet<E: LinkEventSink>(
        &mut self,
        event_tx: &E,
        packet: &Packet
    ) -> LinkHandleResult {
        if self.status == LinkStatus::Pending
            && packet.context == PacketContext::LinkRequestProof
        {
            if let Ok(identity) = validate_proof_packet(&self.destination, &self.id, packet) {
                log::debug!("link({}): has been proved", self.id);

                self.handshake(identity);
                self.remote_identity = Some(self.destination.identity);

                self.status = LinkStatus::Active;
                self.rtt = self.elapsed();

                log::debug!("link({}): activated", self.id);

                self.post_event(event_tx, LinkEvent::Activated);

                return LinkHandleResult::Activated;
            } else {
                log::warn!("link({}): proof is not valid", self.id);
            }
        }

        if matches!(self.status, LinkStatus::Active | LinkStatus::Stale)
            && packet.context == PacketContext::None
            && let Ok(hash) = validate_message_proof(&self.peer_identity, packet.data.as_slice())
        {
            self.touch();
            self.post_event(event_tx, LinkEvent::Proof(hash));
        }

        LinkHandleResult::None
    }
}

/// These methods are intended for use by Transport implementations
pub trait LinkExt<E: LinkEventSink> {
    fn prove(&mut self, event_tx: &E) -> Packet;
    fn teardown(&mut self, event_tx: &E) -> Result<Option<Packet>, RnsError>;
    fn close(&mut self, event_tx: &E);
}

pub trait LinkExtHandlePacket<E: LinkEventSink, P: LinkPayloadSink> {
    fn handle_packet(
        &mut self,
        event_tx: &E,
        channel_tx: Option<&P>,
        packet: &Packet,
        out_link: bool
    ) -> LinkHandleResult;
}

impl <E: LinkEventSink> LinkExt<E> for Link {
    fn prove(&mut self, event_tx: &E) -> Packet {
        log::debug!("link({}): prove", self.id);

        if matches!(self.status, LinkStatus::Pending | LinkStatus::Handshake) {
            self.set_status(LinkStatus::Active);
            self.post_event(event_tx, LinkEvent::Activated);
        }

        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.id.as_slice());
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());

        let signature = self.priv_identity.sign(packet_data.as_slice());

        packet_data.reset();
        packet_data.safe_write(&signature.to_bytes()[..]);
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());

        Packet {
            header: Header {
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRequestProof,
            data: packet_data,
        }
    }

    fn teardown(&mut self, event_tx: &E) -> Result<Option<Packet>, RnsError> {
        let packet = if self.status != LinkStatus::Pending && self.status != LinkStatus::Closed {
            let mut packet = self.data_packet(self.id.as_slice())?;
            packet.context = PacketContext::LinkClose;
            Some(packet)
        } else {
            None
        };
        self.close(event_tx);
        Ok(packet)
    }

    fn close(&mut self, event_tx: &E) {
        self.status = LinkStatus::Closed;
        self.post_event(event_tx, LinkEvent::Closed);
        log::warn!("link: close {}", self.id);
    }
}

impl <E: LinkEventSink, P: LinkPayloadSink> LinkExtHandlePacket<E, P> for Link {
    fn handle_packet(
        &mut self,
        event_tx: &E,
        channel_tx: Option<&P>,
        packet: &Packet,
        out_link: bool
    ) -> LinkHandleResult {
        if packet.destination != self.id {
            return LinkHandleResult::None;
        }

        match packet.header.packet_type {
            PacketType::Data => self.handle_data_packet(event_tx, channel_tx, packet, out_link),
            PacketType::Proof => self.handle_proof_packet(event_tx, packet),
            _ => LinkHandleResult::None,
        }
    }
}

pub fn validate_proof_packet(
    destination: &DestinationDesc,
    id: &LinkId,
    packet: &Packet,
) -> Result<Identity, RnsError> {
    const MIN_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;
    const MTU_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + LINK_MTU_SIZE;
    const SIGN_DATA_LEN: usize = ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE;

    if packet.data.len() < MIN_PROOF_LEN {
        return Err(RnsError::PacketError);
    }

    let mut proof_data = [0u8; SIGN_DATA_LEN];

    let verifying_key = destination.identity.verifying_key.as_bytes();
    let sign_data_len = {
        let mut output = OutputBuffer::new(&mut proof_data[..]);

        output.write(id.as_slice())?;
        output.write(
            &packet.data.as_slice()[SIGNATURE_LENGTH..SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH],
        )?;
        output.write(verifying_key)?;

        if packet.data.len() >= MTU_PROOF_LEN {
            let mtu_bytes = &packet.data.as_slice()[SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH..];
            output.write(mtu_bytes)?;
        }

        output.offset()
    };

    let identity = Identity::new_from_slices(
        &proof_data[ADDRESS_HASH_SIZE..ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH],
        verifying_key,
    );

    let signature = Signature::from_slice(&packet.data.as_slice()[..SIGNATURE_LENGTH])
        .map_err(|_| RnsError::CryptoError)?;

    identity
        .verify(&proof_data[..sign_data_len], &signature)
        .map_err(|_| RnsError::IncorrectSignature)?;

    Ok(identity)
}

fn validate_message_proof(
    identity: &Identity,
    data: &[u8]
) -> Result<Hash, RnsError> {
    if data.len() <= HASH_SIZE {
        return Err(RnsError::PacketError);
    }

    let maybe_signature = Signature::from_slice(&data[HASH_SIZE..]);
    let signature = match maybe_signature {
        Ok(s) => s,
        Err(_) => return Err(RnsError::PacketError),
    };

    let hash_slice = &data[..HASH_SIZE];

    if identity.verifying_key.verify(hash_slice, &signature).is_ok() {
        Ok(Hash::new(hash_slice.try_into().unwrap()))
    } else {
        Err(RnsError::IncorrectSignature)
    }
}
