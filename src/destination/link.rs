use std::{
    cmp::min,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signature, SigningKey, Verifier, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use oqs;
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
    pqc
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

#[derive(Clone)]
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

    pub fn new_from_vec(data: &Vec<u8>) -> Self {
        let mut buffer = [0u8; PACKET_MDU];

        for i in 0..min(buffer.len(), data.len()) {
            buffer[i] = data[i];
        }

        Self {
            buffer,
            len: data.len(),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.len]
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
                .chain_update(&[packet.header.to_meta() & 0b00001111])
                .chain_update(packet.destination.as_slice())
                .chain_update(&[packet.context as u8])
                .chain_update(hashable_data)
                .finalize()
                .into(),
        ))
    }
}

pub enum LinkHandleResult {
    None,
    Activated,
    KeepAlive,
    MessageReceived(Option<Packet>),
}

#[derive(Clone)]
pub enum LinkEvent {
    Activated,
    Data(LinkPayload),
    Proof(Hash),
    Closed,
}

#[derive(Clone)]
pub struct LinkEventData {
    pub id: LinkId,
    pub address_hash: AddressHash,
    pub event: LinkEvent,
}

pub struct Link {
    id: LinkId,
    destination: DestinationDesc,
    priv_identity: PrivateIdentity,
    peer_identity: Identity,
    derived_key: DerivedKey,
    pqc_derived_key: Option<DerivedKey>,
    status: LinkStatus,
    request_time: Instant,
    rtt: Duration,
    event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    proves_messages: bool,
}

impl Link {
    pub(crate) fn new(
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Self {
        Self {
            id: AddressHash::new_empty(),
            destination,
            priv_identity: PrivateIdentity::new_from_rand(OsRng),
            peer_identity: Identity::default(),
            derived_key: DerivedKey::new_empty(),
            pqc_derived_key: None,
            status: LinkStatus::Pending,
            request_time: Instant::now(),
            rtt: Duration::from_secs(0),
            event_tx,
            proves_messages: false,
        }
    }

    /// New link using post-quantum cryptographic primitives
    pub(crate) fn new_pqc(
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> oqs::Result<Self> {
        Ok(Self {
            id: AddressHash::new_empty(),
            destination,
            priv_identity: PrivateIdentity::new_from_rand_with_pqc(OsRng)?,
            peer_identity: Identity::default(),
            derived_key: DerivedKey::new_empty(),
            pqc_derived_key: None,
            status: LinkStatus::Pending,
            request_time: Instant::now(),
            rtt: Duration::from_secs(0),
            event_tx,
            proves_messages: false,
        })
    }

    pub fn prove_messages(&mut self, setting: bool) {
        self.proves_messages = setting;
    }

    pub fn new_from_request(
        packet: &Packet,
        signing_key: SigningKey,
        pqc_signkey: Option<(oqs::sig::PublicKey, oqs::sig::SecretKey)>,
        destination: DestinationDesc,
        event_tx: tokio::sync::broadcast::Sender<LinkEventData>,
    ) -> Result<Self, RnsError> {
        if packet.data.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::InvalidArgument);
        }

        let mut peer_identity = Identity::new_from_slices(
            &packet.data.as_slice()[..PUBLIC_KEY_LENGTH],
            &packet.data.as_slice()[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        );

        let link_id = LinkId::from(packet);
        log::debug!("link: create from request {}", link_id);

        let (pqc_keys, pqc_only) = if packet.data.len() > PUBLIC_KEY_LENGTH * 2 + 3 {
            let pqc_pubkey_len = pqc::ALGORITHM_MLKEM768.length_public_key();
            // extract initiator pubkey
            let peer_pubkey_bytes = &packet.data.as_slice()[
                PUBLIC_KEY_LENGTH * 2..PUBLIC_KEY_LENGTH * 2 + pqc_pubkey_len];
            let pubkey = pqc::ALGORITHM_MLKEM768.public_key_from_bytes(&peer_pubkey_bytes)
                .map(|k| k.to_owned())
                .ok_or_else(||{
                    log::error!("error loading initiator PQC pubkey from link request packet");
                    RnsError::PacketError
                })?;
            peer_identity.pqc_pubkey = Some(pubkey);
            // generate ephemeral pubkey
            let (pubkey, privkey) = pqc::ALGORITHM_MLKEM768.keypair().map_err(RnsError::OqsError)?;
            let (verifykey, signkey) = pqc_signkey.ok_or_else(||{
                log::error!("could not create link: input destination {} does not have pqc keys",
                    destination.address_hash);
                RnsError::InvalidArgument
            })?;
            let pqc_keys = pqc::PostQuantumKeys::new(pubkey, privkey, verifykey, signkey);
            (Some(pqc_keys), true)
        } else {
            (None, false)
        };

        let mut link = Self {
            id: link_id,
            destination,
            priv_identity: PrivateIdentity::new(StaticSecret::random_from_rng(OsRng), signing_key, pqc_keys, pqc_only),
            peer_identity: peer_identity.clone(),
            derived_key: DerivedKey::new_empty(),
            pqc_derived_key: None,
            status: LinkStatus::Pending,
            request_time: Instant::now(),
            rtt: Duration::from_secs(0),
            event_tx,
            proves_messages: false,
        };

        link.handshake(peer_identity);

        Ok(link)
    }

    pub(crate) fn request(&mut self) -> Packet {
        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());

        if let Some(pqc_keys) = self.priv_identity.pqc_keys() {
            packet_data.safe_write(pqc_keys.pubkey().as_ref());
        }

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
        self.request_time = Instant::now();

        packet
    }

    pub fn prove(&mut self) -> Result<Packet, RnsError> {
        log::debug!("link({}): prove", self.id);

        if self.status != LinkStatus::Active {
            self.status = LinkStatus::Active;
            self.post_event(LinkEvent::Activated);
        }

        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.id.as_slice());
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());

        let signature = self.priv_identity.sign(packet_data.as_slice());

        // PQC signature additionally over PQC keys and shared secret
        let (pqc_signature, ciphertexts) = if let Some(pqc_keys) = self.priv_identity.pqc_keys() {
            // shared secret
            let peer_pubkey = self.peer_identity.pqc_pubkey.as_ref().ok_or_else(||{
                log::error!("peer PQC pubkey required to encpasulate shared secret");
                RnsError::InvalidArgument
            })?;
            let (sign_ciphertext, sign_secret) = pqc::ALGORITHM_MLKEM768.encapsulate(peer_pubkey)
                .map_err(|err| {
                    log::error!("error encapsulating signature shared secret: {err:?}");
                    RnsError::CryptoError
                })?;
            let (enc_ciphertext, enc_secret) = pqc::ALGORITHM_MLKEM768.encapsulate(peer_pubkey)
                .map_err(|err| {
                    log::error!("error encapsulating encryption shared secret: {err:?}");
                    RnsError::CryptoError
                })?;
            let derived_key = DerivedKey::from_slices(sign_secret.as_ref(), enc_secret.as_ref())
                .ok_or_else(||{
                    log::error!("error loading secret key bytes");
                    RnsError::CryptoError
                })?;
            self.pqc_derived_key = Some(derived_key);
            packet_data.safe_write(pqc_keys.pubkey().as_ref());
            packet_data.safe_write(pqc_keys.verifykey().as_ref());
            (Some(pqc_keys.sign(packet_data.as_slice())), Some((sign_ciphertext, enc_ciphertext)))
        } else {
            (None, None)
        };

        packet_data.reset();

        packet_data.safe_write(&signature.to_bytes()[..]);
        if let Some(pq_sig) = pqc_signature {
            packet_data.safe_write(pq_sig.as_ref());
        }
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        if let Some(pqc_keys) = self.priv_identity.pqc_keys() {
            packet_data.safe_write(pqc_keys.pubkey().as_ref());
            packet_data.safe_write(pqc_keys.verifykey().as_ref());
            if let Some((sign_ciphertext, enc_ciphertext)) = ciphertexts {
                packet_data.safe_write(sign_ciphertext.as_ref());
                packet_data.safe_write(enc_ciphertext.as_ref());
            }
        }

        let packet = Packet {
            header: Header {
                packet_type: PacketType::Proof,
                destination_type: DestinationType::Link,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context: PacketContext::LinkRequestProof,
            data: packet_data,
        };

        Ok(packet)
    }

    fn handle_data_packet(&mut self, packet: &Packet, out_link: bool) -> LinkHandleResult {
        if self.status != LinkStatus::Active {
            log::warn!("link({}): handling data packet in inactive state", self.id);
        }

        match packet.context {
            PacketContext::None => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    log::trace!("link({}): data {}B", self.id, plain_text.len());
                    self.request_time = Instant::now();
                    self.post_event(LinkEvent::Data(LinkPayload::new_from_slice(plain_text)));

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
            PacketContext::KeepAlive => {
                if packet.data.len() >= 1 && packet.data.as_slice()[0] == 0xFF {
                    self.request_time = Instant::now();
                    log::trace!("link({}): keep-alive request", self.id);
                    return LinkHandleResult::KeepAlive;
                }
                if packet.data.len() >= 1 && packet.data.as_slice()[0] == 0xFE {
                    log::trace!("link({}): keep-alive response", self.id);
                    self.request_time = Instant::now();
                    return LinkHandleResult::None;
                }
            }
            PacketContext::LinkRTT => if !out_link {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt(packet.data.as_slice(), &mut buffer[..]) {
                    if let Ok(rtt) = rmp::decode::read_f32(&mut &plain_text[..]) {
                        self.rtt = Duration::from_secs_f32(rtt);
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
                                let _ = self.close();
                            }
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt link close packet", self.id);
                }
            }
            _ => {}
        }

        LinkHandleResult::None
    }

    pub fn handle_packet(&mut self, packet: &Packet, out_link: bool) -> LinkHandleResult {
        if packet.destination != self.id {
            return LinkHandleResult::None;
        }

        match packet.header.packet_type {
            PacketType::Data => return self.handle_data_packet(packet, out_link),
            PacketType::Proof => return self.handle_proof_packet(packet),
            _ => return LinkHandleResult::None,
        }
    }

    fn handle_proof_packet(&mut self, packet: &Packet) -> LinkHandleResult {
        if self.status == LinkStatus::Pending
            && packet.context == PacketContext::LinkRequestProof
        {
            if let Ok(identity) = validate_proof_packet(self, packet) {
                log::debug!("link({}): has been proved", self.id);

                self.handshake(identity);

                self.status = LinkStatus::Active;
                self.rtt = self.request_time.elapsed();

                log::debug!("link({}): activated", self.id);

                self.post_event(LinkEvent::Activated);

                return LinkHandleResult::Activated;
            } else {
                log::warn!("link({}): proof is not valid", self.id);
            }
        }

        if self.status == LinkStatus::Active && packet.context == PacketContext::None {
            if let Ok(hash) = validate_message_proof(
                &self.destination,
                packet.data.as_slice()
            ) {
                self.post_event(LinkEvent::Proof(hash));
            }
        }

        return LinkHandleResult::None;
    }

    pub fn data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        if self.status != LinkStatus::Active && self.status != LinkStatus::Stale {
            log::warn!("link: can't create data packet for closed link");
            return Err(RnsError::LinkClosed)
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
        if let Some(derived_key) = self.pqc_derived_key.as_ref() {
            self.priv_identity
                .encrypt(OsRng, text, derived_key, out_buf)
        } else {
            self.priv_identity
                .encrypt(OsRng, text, &self.derived_key, out_buf)
        }
    }

    pub fn decrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        if let Some(derived_key) = self.pqc_derived_key.as_ref() {
            self.priv_identity
                .decrypt(OsRng, text, derived_key, out_buf)
        } else {
            self.priv_identity
                .decrypt(OsRng, text, &self.derived_key, out_buf)
        }
    }

    pub fn destination(&self) -> &DestinationDesc {
        &self.destination
    }

    pub fn create_rtt(&self) -> Packet {
        let rtt = self.rtt.as_secs_f32();
        let mut buf = Vec::new();
        {
            buf.reserve(4);
            rmp::encode::write_f32(&mut buf, rtt).unwrap();
        }

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
            .derive_key(&self.peer_identity.public_key, Some(&self.id.as_slice()));
    }

    fn post_event(&self, event: LinkEvent) {
        let _ = self.event_tx.send(LinkEventData {
            id: self.id,
            address_hash: self.destination.address_hash,
            event,
        });
    }

    pub(crate) fn teardown(&mut self) -> Result<Option<Packet>, RnsError> {
        let packet = if self.status != LinkStatus::Pending && self.status != LinkStatus::Closed {
            let mut packet = self.data_packet(self.id.as_slice())?;
            packet.context = PacketContext::LinkClose;
            Some(packet)
        } else {
            None
        };
        self.close();
        Ok(packet)
    }

    pub(crate) fn close(&mut self) {
        self.status = LinkStatus::Closed;
        self.post_event(LinkEvent::Closed);
        log::warn!("link: close {}", self.id);
    }

    pub fn stale(&mut self) {
        self.status = LinkStatus::Stale;

        log::warn!("link: stale {}", self.id);
    }

    pub fn restart(&mut self) {
        log::warn!(
            "link({}): restart after {}s",
            self.id,
            self.request_time.elapsed().as_secs()
        );

        self.status = LinkStatus::Pending;
    }

    pub fn elapsed(&self) -> Duration {
        self.request_time.elapsed()
    }

    pub fn status(&self) -> LinkStatus {
        self.status
    }

    pub fn id(&self) -> &LinkId {
        &self.id
    }

    pub fn rtt(&self) -> &Duration {
        &self.rtt
    }

    pub fn is_pqc(&self) -> bool {
        self.priv_identity.pqc_keys().is_some()
    }
}

fn validate_proof_packet(
    link: &mut Link,
    packet: &Packet,
) -> Result<Identity, RnsError> {
    const MIN_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;
    let min_pqc_proof_len = SIGNATURE_LENGTH + pqc::ALGORITHM_MLDSA65.length_signature() +
        PUBLIC_KEY_LENGTH + pqc::ALGORITHM_MLKEM768.length_public_key() +
        pqc::ALGORITHM_MLDSA65.length_public_key() +
        pqc::ALGORITHM_MLKEM768.length_ciphertext() * 2;
    const MTU_PROOF_LEN: usize = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH + LINK_MTU_SIZE;
    const SIGN_DATA_LEN: usize = ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE;

    if packet.data.len() < MIN_PROOF_LEN {
        return Err(RnsError::PacketError);
    }

    if packet.data.len() >= min_pqc_proof_len {
        return validate_pqc_proof_packet(link, packet)
    }

    let mut proof_data = [0u8; SIGN_DATA_LEN];

    let verifying_key = link.destination.identity.verifying_key.as_bytes();
    let sign_data_len = {
        let mut output = OutputBuffer::new(&mut proof_data[..]);

        output.write(link.id.as_slice())?;
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

    identity.verify(&proof_data[..sign_data_len], &signature)?;

    Ok(identity)
}

fn validate_pqc_proof_packet(
    link: &mut Link,
    packet: &Packet,
) -> Result<Identity, RnsError> {
    const SIGN_DATA_LEN: usize = ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE;
    let pqc_pubkey_len = pqc::ALGORITHM_MLKEM768.length_public_key();
    let pqc_verifykey_len = pqc::ALGORITHM_MLDSA65.length_public_key();
    let pqc_sign_data_len = SIGN_DATA_LEN + pqc_pubkey_len + pqc_verifykey_len;
    let pqc_signature_len = pqc::ALGORITHM_MLDSA65.length_signature();
    let pqc_ciphertext_len = pqc::ALGORITHM_MLKEM768.length_ciphertext();
    // length of packet without MTU
    let pqc_min_proof_len = SIGNATURE_LENGTH + pqc_signature_len + PUBLIC_KEY_LENGTH
        + pqc_pubkey_len + pqc_verifykey_len + pqc_ciphertext_len * 2;

    let mut proof_data = vec![0u8; pqc_sign_data_len];
    // validate ECC signature
    let verifying_key = link.destination.identity.verifying_key.as_bytes();

    let mut output = OutputBuffer::new(&mut proof_data[..]);
    output.write(link.id.as_slice())?;
    // X25519 pubkey offset
    let offset = SIGNATURE_LENGTH + pqc_signature_len;
    output.write(&packet.data.as_slice()[offset..offset + PUBLIC_KEY_LENGTH])?;
    output.write(verifying_key)?;

    if packet.data.len() > pqc_min_proof_len {
        // append MTU bytes
        output.write(&packet.data.as_slice()[pqc_min_proof_len..pqc_min_proof_len + LINK_MTU_SIZE])?;
    }
    let sign_data_len = output.offset();

    // construct the validated peer identity
    let mut identity = Identity::new_from_slices(
        &output.as_slice()[ADDRESS_HASH_SIZE..ADDRESS_HASH_SIZE + PUBLIC_KEY_LENGTH],
        verifying_key,
    );

    let signature = Signature::from_slice(&packet.data.as_slice()[..SIGNATURE_LENGTH])
        .map_err(|_| RnsError::CryptoError)?;

    identity.verify(&output.as_slice()[..sign_data_len], &signature)?;

    // get PQC keys + ciphertexts
    let mut offset = SIGNATURE_LENGTH + pqc_signature_len + PUBLIC_KEY_LENGTH;
    let pubkey = pqc::ALGORITHM_MLKEM768.public_key_from_bytes(
        &packet.data.as_slice()[offset..offset + pqc_pubkey_len])
    .map(|k| k.to_owned())
    .ok_or_else(||{
        log::error!("error loading PQC pubkey from proof packet");
        RnsError::PacketError
    })?;
    offset += pqc_pubkey_len;
    output.write(pubkey.as_ref())?;
    identity.pqc_pubkey = Some(pubkey);
    let verifykey = pqc::ALGORITHM_MLDSA65.public_key_from_bytes(
        &packet.data.as_slice()[offset..offset + pqc_verifykey_len])
    .map(|k| k.to_owned())
    .ok_or_else(||{
        log::error!("error loading PQC verifying key from proof packet");
        RnsError::PacketError
    })?;
    offset += pqc_verifykey_len;

    // check against the announced verifykey hash
    let verifykey_hash = Hash::new_from_slice(verifykey.as_ref());
    if Some(verifykey_hash) != link.destination.identity.pqc_verifykey_hash {
        log::warn!("PQC verifykey hash comparison failed");
        return Err(RnsError::CryptoError)
    }

    if packet.data.len() > pqc_min_proof_len {
        // rewind MTU bytes first then append after verifykey
        output.rewind(LINK_MTU_SIZE);
        output.write(verifykey.as_ref())?;
        output.write(&packet.data.as_slice()[pqc_min_proof_len..pqc_min_proof_len + LINK_MTU_SIZE])?;
    } else {
        output.write(verifykey.as_ref())?;
    }
    identity.pqc_verifykey = Some(verifykey.clone());
    link.destination.identity.pqc_verifykey = Some(verifykey);
    let sign_ciphertext = pqc::ALGORITHM_MLKEM768.ciphertext_from_bytes(
        &packet.data.as_slice()[offset..offset + pqc_ciphertext_len]
    )   .map(|k| k.to_owned())
        .ok_or_else(||{
            log::error!("error loading PQC signature ciphertext from proof packet");
            RnsError::PacketError
        })?;
    offset += pqc_ciphertext_len;
    let enc_ciphertext = pqc::ALGORITHM_MLKEM768.ciphertext_from_bytes(
        &packet.data.as_slice()[offset..offset + pqc_ciphertext_len]
    )   .map(|k| k.to_owned())
        .ok_or_else(||{
            log::error!("error loading PQC encryption ciphertext from proof packet");
            RnsError::PacketError
        })?;
    if let Some(pqc_keys) = link.priv_identity.pqc_keys() {
        let sign_secret = pqc::ALGORITHM_MLKEM768.decapsulate(pqc_keys.privkey(), &sign_ciphertext)
            .map_err(|err|{
                log::error!("error decapsulating PQC signature shared secret from proof packet: {err:?}");
                RnsError::PacketError
            })?;
        let enc_secret = pqc::ALGORITHM_MLKEM768.decapsulate(pqc_keys.privkey(), &enc_ciphertext)
            .map_err(|err|{
                log::error!("error decapsulating PQC encryption shared secret from proof packet: {err:?}");
                RnsError::PacketError
            })?;
        let derived_key = DerivedKey::from_slices(sign_secret.as_ref(), enc_secret.as_ref())
            .ok_or_else(||{
                log::error!("error loading secret key bytes");
                RnsError::CryptoError
            })?;
        link.pqc_derived_key = Some(derived_key);
    } else {
        log::error!("link missing private PQC key to decapsulate shared secret");
        return Err(RnsError::InvalidArgument)
    }

    // validate PQC signature
    let pqc_signature = pqc::ALGORITHM_MLDSA65.signature_from_bytes(
        &packet.data.as_slice()[SIGNATURE_LENGTH..SIGNATURE_LENGTH + pqc_signature_len]
    ) .map(|k| k.to_owned())
      .ok_or_else(|| RnsError::CryptoError)?;
    identity.verify_pqc(&output.as_slice()[..output.offset()], &pqc_signature)
        .map_err(|_| RnsError::IncorrectSignature)?;

    Ok(identity)
}

fn validate_message_proof(
    destination: &DestinationDesc,
    data: &[u8],
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

    if destination.identity.verifying_key.verify(hash_slice, &signature).is_ok() {
        Ok(Hash::new(hash_slice.try_into().unwrap()))
    } else {
        Err(RnsError::IncorrectSignature)
    }
}
