use alloc::boxed::Box;

use core::{cmp::min, time::Duration};

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH, Signature, SigningKey, Verifier};
#[cfg(feature = "std")]
use rand_core::OsRng;
use sha2::Digest;
use x25519_dalek::StaticSecret;

use crate::{
    buffer::OutputBuffer,
    error::RnsError,
    hash::{ADDRESS_HASH_SIZE, AddressHash, HASH_SIZE, Hash},
    identity::{DecryptIdentity, DerivedKey, EncryptIdentity, Identity, PrivateIdentity},
    packet::{
        DestinationType, Header, PACKET_MDU, Packet, PacketContext, PacketDataBuffer, PacketType,
    },
    time::now,
};

use super::DestinationDesc;

pub const LINK_MTU_SIZE: usize = 3;

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
    /// Establishment clock. Inbound traffic must not move it: the
    /// responder's RTT is `max(now - request_time, advertised)`, and an
    /// early `touch` of the LRRTT packet would otherwise zero the sample.
    request_time: Duration,
    /// Last packet that counts as inbound activity (Python `last_inbound`).
    last_inbound: Duration,
    /// Last packet sent on this link (Python `last_outbound`).
    last_outbound: Duration,
    rtt: Duration,
    /// `false` until a link proof or an LRRTT packet supplies an RTT
    /// (Python `Link.rtt is None`).
    rtt_known: bool,
    keepalive: Duration,
    /// Last initiator keepalive (0xFF) or responder reply (0xFE).
    /// Not updated by other outbound traffic.
    last_keepalive: Duration,
    proves_messages: bool,
    /// Maximum transfer unit negotiated (or defaulted) for this link.
    mtu: usize,
    /// Bytes spent on link establishment (request + proof), used for rate estimation.
    establishment_cost: usize,
    /// Current expected in-flight rate estimate in bytes per second.
    expected_rate: Option<f64>,
    /// Window size remembered from the last completed incoming resource.
    last_resource_window: Option<usize>,
    /// EIFR remembered from the last completed incoming resource.
    last_resource_eifr: Option<f64>,
}

/// Enabled link cipher mode (Python only enables `MODE_AES256_CBC` today).
pub const LINK_MODE_AES256_CBC: u8 = 0x01;

/// Top bits of the first MTU signalling byte (Python `Link.MODE_BYTEMASK`).
const LINK_MODE_BYTEMASK: u8 = 0xE0;

/// RTT at which the keepalive interval reaches `KEEPALIVE_MAX`
/// (Python `Link.KEEPALIVE_MAX_RTT`).
pub const KEEPALIVE_MAX_RTT: f64 = 1.75;
/// Multiplier in the post-stale grace sleep (Python `Link.KEEPALIVE_TIMEOUT_FACTOR`).
pub const KEEPALIVE_TIMEOUT_FACTOR: u32 = 4;
/// Seconds added to the post-stale sleep, and the effective close delay
/// once `WATCHDOG_MAX_SLEEP` caps that sleep (Python `Link.STALE_GRACE`).
pub const STALE_GRACE: Duration = Duration::from_secs(5);
/// Upper bound on the keepalive interval (Python `Link.KEEPALIVE_MAX`).
pub const KEEPALIVE_MAX: Duration = Duration::from_secs(360);
/// Lower bound on the keepalive interval (Python `Link.KEEPALIVE_MIN`).
pub const KEEPALIVE_MIN: Duration = Duration::from_secs(5);
/// Keepalive interval before RTT is known (Python `Link.KEEPALIVE`).
pub const KEEPALIVE: Duration = KEEPALIVE_MAX;
/// `stale_time = keepalive * STALE_FACTOR` (Python `Link.STALE_FACTOR`).
pub const STALE_FACTOR: u32 = 2;
/// Inbound-silence limit before RTT is known (Python `Link.STALE_TIME`).
pub const STALE_TIME: Duration = Duration::from_secs(KEEPALIVE_MAX.as_secs() * STALE_FACTOR as u64);
/// Cap on a single watchdog sleep. The post-stale grace is
/// `min(rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE, WATCHDOG_MAX_SLEEP)`.
pub const WATCHDOG_MAX_SLEEP: Duration = Duration::from_secs(5);

impl Link {
    /// Three bytes of MTU/mode signalling appended to link requests and
    /// link request proofs: `(mtu & 0x1FFFFF) + ((mode << 5 & 0xE0) << 16)`
    /// packed as the low three bytes of a big-endian u32
    /// (Python `Link.signalling_bytes`).
    pub fn signalling_bytes(mtu: usize) -> [u8; LINK_MTU_SIZE] {
        let mode = LINK_MODE_AES256_CBC;
        let value = (mtu & 0x1F_FFFF) + ((((mode << 5) & 0xE0) as usize) << 16);
        let packed = (value as u32).to_be_bytes();
        [packed[1], packed[2], packed[3]]
    }

    #[cfg(feature = "std")]
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
            last_inbound: now(),
            last_outbound: now(),
            rtt: Duration::from_secs(0),
            rtt_known: false,
            keepalive: KEEPALIVE,
            last_keepalive: now(),
            proves_messages: false,
            mtu: crate::packet::PROTOCOL_MTU,
            establishment_cost: 0,
            expected_rate: None,
            last_resource_window: None,
            last_resource_eifr: None,
        }
    }

    pub fn prove_messages(&mut self, setting: bool) {
        self.proves_messages = setting;
    }

    #[cfg(feature = "std")]
    pub fn new_from_request(
        packet: &Packet,
        signing_key: SigningKey,
        destination: DestinationDesc,
    ) -> Result<Self, RnsError> {
        Self::new_from_request_with_rng(packet, signing_key, destination, OsRng)
    }

    pub fn new_from_request_with_rng<R: rand_core::CryptoRngCore + Copy>(
        packet: &Packet,
        signing_key: SigningKey,
        destination: DestinationDesc,
        rng: R,
    ) -> Result<Self, RnsError> {
        if packet.data.len() < PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::InvalidArgument);
        }
        // Python `ENABLED_MODES` is only AES-256-CBC. `handshake` raises
        // for anything else and `validate_request` drops the link.
        reject_disabled_link_mode(packet)?;

        let peer_identity = Identity::new_from_slices(
            &packet.data.as_slice()[..PUBLIC_KEY_LENGTH],
            &packet.data.as_slice()[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2],
        );

        let link_id = LinkId::from(packet);
        log::debug!("link: create from request {}", link_id);

        // A link request may carry 3 bytes of MTU/mode signalling appended
        // after the ephemeral keys (Python `Link.mtu_from_lr_packet`).
        let mtu = if packet.data.len() >= PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE {
            let sig = &packet.data.as_slice()
                [PUBLIC_KEY_LENGTH * 2..PUBLIC_KEY_LENGTH * 2 + LINK_MTU_SIZE];
            let value = ((sig[0] as usize) << 16) | ((sig[1] as usize) << 8) | (sig[2] as usize);
            let mtu = value & 0x1F_FFFF;
            if mtu != 0 && mtu < crate::packet::LINK_MTU_MIN {
                return Err(RnsError::InvalidArgument);
            }
            if mtu == 0 {
                crate::packet::PROTOCOL_MTU
            } else {
                mtu
            }
        } else {
            crate::packet::PROTOCOL_MTU
        };

        let mut link = Self {
            id: link_id,
            destination,
            priv_identity: PrivateIdentity::new(StaticSecret::random_from_rng(rng), signing_key),
            peer_identity,
            remote_identity: None,
            derived_key: DerivedKey::new_empty(),
            status: LinkStatus::Pending,
            request_time: now(),
            last_inbound: now(),
            last_outbound: now(),
            rtt: Duration::from_secs(0),
            rtt_known: false,
            keepalive: KEEPALIVE,
            last_keepalive: now(),
            proves_messages: false,
            mtu,
            establishment_cost: 0,
            expected_rate: None,
            last_resource_window: None,
            last_resource_eifr: None,
        };

        link.handshake(peer_identity);

        Ok(link)
    }

    pub fn request(&mut self) -> Packet {
        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());
        // MTU/mode signalling, mirroring `Link.signalling_bytes(mtu, mode)`.
        let _ = packet_data.safe_write(&Self::signalling_bytes(self.mtu));

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
        // Retry pacing and the RTT sample share the establishment clock.
        // `touch` only moves inbound silence.
        self.request_time = now();
        self.touch();

        packet
    }

    /// Record inbound activity and revive a stale link.
    /// Outbound sends, including our own keepalive, must not call this:
    /// Python only moves `last_inbound` when a packet arrives.
    pub fn touch(&mut self) {
        self.last_inbound = now();
        if self.status == LinkStatus::Stale {
            self.status = LinkStatus::Active;
        }
    }

    #[cfg(feature = "std")]
    pub fn data_packet(&self, data: &[u8]) -> Result<Packet, RnsError> {
        self.data_packet_with_rng(data, OsRng)
    }

    pub fn data_packet_with_rng<R: rand_core::CryptoRngCore + Copy>(
        &self,
        data: &[u8],
        rng: R,
    ) -> Result<Packet, RnsError> {
        match self.status {
            LinkStatus::Pending | LinkStatus::Handshake => {
                log::warn!("link: can't create data packet for pending link");
                return Err(RnsError::LinkNotReady);
            }
            LinkStatus::Closed => {
                log::warn!("link: can't create data packet for closed link");
                return Err(RnsError::LinkClosed);
            }
            LinkStatus::Active | LinkStatus::Stale => {}
        }

        let mut packet_data = PacketDataBuffer::new();

        let cipher_text_len = {
            let cipher_text = self.encrypt_with_rng(rng, data, packet_data.accuire_buf_max())?;
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
    #[cfg(feature = "std")]
    pub fn identify(&self, identity: &PrivateIdentity) -> Result<Packet, RnsError> {
        self.identify_with_rng(identity, OsRng)
    }

    pub fn identify_with_rng<R: rand_core::CryptoRngCore + Copy>(
        &self,
        identity: &PrivateIdentity,
        rng: R,
    ) -> Result<Packet, RnsError> {
        match self.status {
            LinkStatus::Pending | LinkStatus::Handshake => {
                log::warn!("link: can't create identify packet for pending link");
                return Err(RnsError::LinkNotReady);
            }
            LinkStatus::Closed => {
                log::warn!("link: can't create identify packet for closed link");
                return Err(RnsError::LinkClosed);
            }
            LinkStatus::Active | LinkStatus::Stale => {}
        }
        let pub_identity = identity.as_identity();
        let signed_data = [
            self.id.as_slice(),
            pub_identity.public_key_bytes(),
            pub_identity.verifying_key_bytes(),
        ]
        .concat();
        let signature = identity.sign(&signed_data);
        let proof_data = [
            pub_identity.public_key_bytes(),
            pub_identity.verifying_key_bytes(),
            &signature.to_bytes()[..],
        ]
        .concat();
        let mut data = PacketDataBuffer::new();
        let cipher_text_len = {
            let cipher_text = self.encrypt_with_rng(rng, &proof_data, data.accuire_buf_max())?;
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
            data,
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

    /// Create a link-encrypted data packet with a custom context, matching
    /// Python `RNS.Packet(link, data, context=...)` for payloads that are
    /// encrypted with the link token (resource advertisements, requests,
    /// hashmap updates and cancel messages).
    #[cfg(feature = "std")]
    pub fn context_packet(&self, data: &[u8], context: PacketContext) -> Result<Packet, RnsError> {
        self.context_packet_with_rng(data, context, OsRng)
    }

    pub fn context_packet_with_rng<R: rand_core::CryptoRngCore + Copy>(
        &self,
        data: &[u8],
        context: PacketContext,
        rng: R,
    ) -> Result<Packet, RnsError> {
        match self.status {
            LinkStatus::Pending | LinkStatus::Handshake => {
                log::warn!("link: can't create data packet for pending link");
                return Err(RnsError::LinkNotReady);
            }
            LinkStatus::Closed => {
                log::warn!("link: can't create data packet for closed link");
                return Err(RnsError::LinkClosed);
            }
            LinkStatus::Active | LinkStatus::Stale => {}
        }

        let mut packet_data = PacketDataBuffer::new();

        let cipher_text_len = {
            let cipher_text = self.encrypt_with_rng(rng, data, packet_data.accuire_buf_max())?;
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
            context,
            data: packet_data,
        })
    }

    /// Create an unencrypted link-addressed packet. Resource part packets
    /// carry pre-encrypted chunks of the whole-resource token and resource
    /// proofs are never encrypted (Python `Packet.pack` rules).
    pub fn raw_packet(
        &self,
        data: &[u8],
        packet_type: PacketType,
        context: PacketContext,
    ) -> Result<Packet, RnsError> {
        match self.status {
            LinkStatus::Pending | LinkStatus::Handshake => {
                log::warn!("link: can't create data packet for pending link");
                return Err(RnsError::LinkNotReady);
            }
            LinkStatus::Closed => {
                log::warn!("link: can't create data packet for closed link");
                return Err(RnsError::LinkClosed);
            }
            LinkStatus::Active | LinkStatus::Stale => {}
        }

        let mut packet_data = PacketDataBuffer::new();
        let _ = packet_data.safe_write(data);

        Ok(Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type,
                ..Default::default()
            },
            ifac: None,
            destination: self.id,
            transport: None,
            context,
            data: packet_data,
        })
    }

    /// Encrypt an arbitrary-length plaintext with the link token. Used by
    /// the resource engine which encrypts the whole resource stream once
    /// (Python `link.encrypt`). The Fernet token grows the data by
    /// `TOKEN_OVERHEAD` bytes plus block padding.
    #[cfg(feature = "std")]
    pub fn encrypt_alloc(
        &self,
        text: &[u8],
        out_buf: &mut alloc::vec::Vec<u8>,
    ) -> Result<usize, RnsError> {
        let start = out_buf.len();
        out_buf.resize(start + text.len() + crate::packet::TOKEN_OVERHEAD + 64, 0);
        let chunk = self.encrypt_with_rng(OsRng, text, &mut out_buf[start..])?;
        let written = chunk.len();
        out_buf.truncate(start + written);
        Ok(out_buf.len())
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Set the negotiated link MTU (bounded by the protocol MTU floor rules).
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = if mtu == 0 {
            crate::packet::PROTOCOL_MTU
        } else {
            mtu.max(crate::packet::LINK_MTU_MIN)
        };
    }

    /// Maximum link-encrypted plaintext size (`RNS.Link.MDU`).
    pub fn mdu(&self) -> usize {
        let mdu = self.mtu.saturating_sub(
            crate::packet::IFAC_MIN_SIZE
                + crate::packet::HEADER_MINSIZE
                + crate::packet::TOKEN_OVERHEAD,
        );
        (mdu / crate::packet::AES128_BLOCKSIZE * crate::packet::AES128_BLOCKSIZE).saturating_sub(1)
    }

    /// Maximum size of an unencrypted resource part chunk
    /// (`link.mtu - HEADER_MAXSIZE - IFAC_MIN_SIZE`, Python `Resource.sdu`).
    pub fn sdu(&self) -> usize {
        self.mtu
            .saturating_sub(crate::packet::HEADER_MAXSIZE + crate::packet::IFAC_MIN_SIZE)
    }

    pub fn establishment_cost(&self) -> usize {
        self.establishment_cost
    }

    pub fn add_establishment_cost(&mut self, cost: usize) {
        self.establishment_cost += cost;
    }

    pub fn expected_rate(&self) -> Option<f64> {
        self.expected_rate
    }

    pub fn set_expected_rate(&mut self, rate: Option<f64>) {
        self.expected_rate = rate;
    }

    pub fn last_resource_window(&self) -> Option<usize> {
        self.last_resource_window
    }

    pub fn set_last_resource_window(&mut self, window: Option<usize>) {
        self.last_resource_window = window;
    }

    pub fn last_resource_eifr(&self) -> Option<f64> {
        self.last_resource_eifr
    }

    pub fn set_last_resource_eifr(&mut self, eifr: Option<f64>) {
        self.last_resource_eifr = eifr;
    }

    pub fn message_proof(&self, hash: Hash) -> Packet {
        log::trace!(
            "link({}): creating proof for message hash {}",
            self.id,
            hash
        );

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

    pub fn encrypt_with_rng<'a, R: rand_core::CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        self.priv_identity
            .encrypt(rng, text, &self.derived_key, out_buf)
    }

    #[cfg(feature = "std")]
    pub fn encrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.encrypt_with_rng(OsRng, text, out_buf)
    }

    pub fn decrypt_with_rng<'a, R: rand_core::CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        <PrivateIdentity as DecryptIdentity>::decrypt(
            &self.priv_identity,
            rng,
            text,
            &self.derived_key,
            out_buf,
        )
    }

    #[cfg(feature = "std")]
    pub fn decrypt<'a>(&self, text: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.decrypt_with_rng(OsRng, text, out_buf)
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

    #[cfg(feature = "std")]
    pub fn create_rtt(&self) -> Packet {
        let rtt = self.rtt.as_secs_f64();
        let mut buf = alloc::vec::Vec::with_capacity(9);
        rmp::encode::write_f64(&mut buf, rtt).unwrap();

        let mut packet_data = PacketDataBuffer::new();

        let token_len = {
            let token = self
                .encrypt_with_rng(OsRng, buf.as_slice(), packet_data.accuire_buf_max())
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

    /// Time since the last inbound packet. Pending establishment uses the
    /// same clock because [`Link::request`] stamps both.
    pub fn elapsed(&self) -> Duration {
        now().saturating_sub(self.last_inbound)
    }

    fn since_request(&self) -> Duration {
        now().saturating_sub(self.request_time)
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

    pub fn rtt_known(&self) -> bool {
        self.rtt_known
    }

    /// Keepalive interval. `KEEPALIVE_MAX` until RTT is known, otherwise
    /// `clamp(rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MIN, KEEPALIVE_MAX)`.
    pub fn keepalive(&self) -> Duration {
        self.keepalive
    }

    /// Inbound silence before the link is marked stale (`2 * keepalive`).
    pub fn stale_time(&self) -> Duration {
        self.keepalive.saturating_mul(STALE_FACTOR)
    }

    /// Stale threshold, using `unknown_rtt` until an RTT has been measured.
    pub fn effective_stale(&self, unknown_rtt: Duration) -> Duration {
        if self.rtt_known {
            self.stale_time()
        } else {
            unknown_rtt
        }
    }

    /// Delay from the stale mark to teardown. Python sleeps
    /// `rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE` and then caps that
    /// sleep at `WATCHDOG_MAX_SLEEP`, so the effective delay is 5s.
    pub fn close_grace(&self) -> Duration {
        let scaled = if self.rtt_known {
            self.rtt
                .saturating_mul(KEEPALIVE_TIMEOUT_FACTOR)
                .saturating_add(STALE_GRACE)
        } else {
            STALE_GRACE
        };
        scaled.min(WATCHDOG_MAX_SLEEP)
    }

    fn keepalive_interval(&self, unknown_rtt: Duration) -> Duration {
        if self.rtt_known {
            self.keepalive
        } else {
            unknown_rtt
        }
    }

    /// Whether the initiator should emit keepalive `0xFF`.
    /// Python sends only when inbound or outbound has been idle for one
    /// interval, and at most once per interval. `unknown_rtt` is that
    /// interval before an RTT has been measured.
    pub fn keepalive_due(&self, unknown_rtt: Duration) -> bool {
        if self.status != LinkStatus::Active {
            return false;
        }
        let interval = self.keepalive_interval(unknown_rtt);
        let now = now();
        let inbound_idle = now.saturating_sub(self.last_inbound) >= interval;
        let outbound_idle = now.saturating_sub(self.last_outbound) >= interval;
        let keepalive_idle = now.saturating_sub(self.last_keepalive) >= interval;
        (inbound_idle || outbound_idle) && keepalive_idle
    }

    /// Whether the responder should answer `0xFF` with `0xFE`.
    /// Python replies only when `now >= last_outbound + keepalive`.
    pub fn keepalive_reply_due(&self, unknown_rtt: Duration) -> bool {
        if !matches!(self.status, LinkStatus::Active | LinkStatus::Stale) {
            return false;
        }
        let interval = self.keepalive_interval(unknown_rtt);
        now().saturating_sub(self.last_outbound) >= interval
    }

    /// Record an outbound send. Keepalive packets also stamp `last_keepalive`
    /// (Python `Link.had_outbound`). Does not move the inbound clock.
    pub fn mark_outbound(&mut self, is_keepalive: bool) {
        let now = now();
        self.last_outbound = now;
        if is_keepalive {
            self.last_keepalive = now;
        }
    }

    /// Record an outbound keepalive without touching the inbound clock.
    pub fn mark_keepalive_sent(&mut self) {
        self.mark_outbound(true);
    }

    fn note_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
        self.rtt_known = true;
        let scaled = rtt.as_secs_f64() * (KEEPALIVE_MAX.as_secs_f64() / KEEPALIVE_MAX_RTT);
        let secs = scaled.clamp(KEEPALIVE_MIN.as_secs_f64(), KEEPALIVE_MAX.as_secs_f64());
        self.keepalive = Duration::from_secs_f64(secs);
    }

    /// Python `Link.rtt_packet`: `rtt = max(time.time() - request_time, unpacked)`.
    fn note_responder_rtt(&mut self, advertised: Duration) {
        self.note_rtt(self.since_request().max(advertised));
    }

    fn handle_data_packet<E: LinkEventSink, P: LinkPayloadSink>(
        &mut self,
        event_tx: &E,
        channel_tx: Option<&P>,
        packet: &Packet,
        out_link: bool,
    ) -> LinkHandleResult {
        if self.status != LinkStatus::Active {
            // Pending/handshaking links have an all-zero derived key until
            // the handshake proof validates: anyone observing the public
            // link request could encrypt with that known key and inject
            // data or close the link. Reject data until Active
            // (Python ignores packets on un-activated links).
            if matches!(self.status, LinkStatus::Pending | LinkStatus::Handshake) {
                log::warn!(
                    "link({}): dropping data packet on un-activated link",
                    self.id
                );
                return LinkHandleResult::None;
            }
            log::warn!("link({}): handling data packet in inactive state", self.id);
        }

        match packet.context {
            PacketContext::None => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt_with_rng(
                    crate::crypt::fernet::ZeroRng,
                    packet.data.as_slice(),
                    &mut buffer[..],
                ) {
                    log::trace!("link({}): data {}B", self.id, plain_text.len());
                    self.touch();
                    self.post_event(
                        event_tx,
                        LinkEvent::Data(Box::new(LinkPayload::new_from_slice(plain_text))),
                    );

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
                if let Ok(plain_text) = self.decrypt_with_rng(
                    crate::crypt::fernet::ZeroRng,
                    packet.data.as_slice(),
                    &mut buffer[..],
                ) {
                    log::trace!(
                        "link({}): link identify data {}B",
                        self.id,
                        plain_text.len()
                    );
                    self.touch();
                    if !out_link && plain_text.len() == PUBLIC_KEY_LENGTH * 2 + SIGNATURE_LENGTH {
                        let public_key = &plain_text[..PUBLIC_KEY_LENGTH];
                        let verifying_key = &plain_text[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2];
                        let signed_data =
                            [self.id().as_slice(), public_key, verifying_key].concat();
                        let signature = match Signature::from_slice(
                            &plain_text[PUBLIC_KEY_LENGTH * 2..],
                        ) {
                            Ok(signature) => signature,
                            Err(err) => {
                                log::warn!(
                                    "link({}): link identify packet invalid signature bytes: {err}",
                                    self.id()
                                );
                                return LinkHandleResult::None;
                            }
                        };
                        let identity = Identity::new_from_slices(public_key, verifying_key);
                        match identity.verify(&signed_data, &signature) {
                            Ok(()) => {
                                if let Some(remote_id) = self.remote_identity.as_ref() {
                                    log::debug!(
                                        "link({}): link identity {} is valid but link is already identified as {}",
                                        self.id(),
                                        identity.address_hash,
                                        remote_id.address_hash
                                    );
                                } else {
                                    log::debug!(
                                        "link({}): link identified: {}",
                                        self.id(),
                                        identity.address_hash
                                    );
                                    self.remote_identity = Some(identity);
                                    self.post_event(
                                        event_tx,
                                        LinkEvent::RemoteIdentified(Box::new(identity)),
                                    );
                                }
                            }
                            Err(err) => log::warn!(
                                "link({}): identity verification failed: {err:?}",
                                self.id()
                            ),
                        }
                    }
                } else {
                    log::error!("link({}): can't decrypt link identify packet", self.id);
                }
            }
            PacketContext::KeepAlive => {
                if !packet.data.is_empty() && packet.data.as_slice()[0] == 0xFF {
                    // Initiator's own or reflected 0xFF is not inbound traffic
                    // and must not be echoed as 0xFE (Python `Link.__receive`).
                    if out_link {
                        log::trace!("link({}): ignoring initiator keepalive", self.id);
                        return LinkHandleResult::None;
                    }
                    self.touch();
                    log::trace!("link({}): keep-alive request", self.id);
                    return LinkHandleResult::KeepAlive;
                }
                if !packet.data.is_empty() && packet.data.as_slice()[0] == 0xFE {
                    log::trace!("link({}): keep-alive response", self.id);
                    self.touch();
                    return LinkHandleResult::None;
                }
            }
            PacketContext::LinkRTT if !out_link => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt_with_rng(
                    crate::crypt::fernet::ZeroRng,
                    packet.data.as_slice(),
                    &mut buffer[..],
                ) {
                    if let Ok(rtt) = rmp::decode::read_f64(&mut &plain_text[..]) {
                        // A hostile peer can encode NaN/infinite or
                        // enormous RTT values; clamp to a sane range
                        // instead of panicking in Duration construction.
                        if rtt.is_finite() && (0.0..86_400.0).contains(&rtt) {
                            // Measure before touch(). `request_time` is the
                            // establishment clock, so an earlier inbound
                            // refresh of this same packet does not zero it.
                            self.note_responder_rtt(Duration::from_secs_f64(rtt));
                            self.touch();
                        } else {
                            log::debug!("link: ignoring invalid rtt packet ({rtt})");
                        }
                    } else {
                        log::error!("link({}): failed to decode rtt", self.id);
                    }
                } else {
                    log::error!("link({}): can't decrypt rtt packet", self.id);
                }
            }
            PacketContext::LinkClose => {
                let mut buffer = [0u8; PACKET_MDU];
                if let Ok(plain_text) = self.decrypt_with_rng(
                    crate::crypt::fernet::ZeroRng,
                    packet.data.as_slice(),
                    &mut buffer[..],
                ) {
                    match plain_text[..].try_into() {
                        Err(err) => {
                            log::error!(
                                "link({}): invalid decode link close payload: {err}",
                                self.id
                            )
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
                    if let Ok(plain_text) = self.decrypt_with_rng(
                        crate::crypt::fernet::ZeroRng,
                        packet.data.as_slice(),
                        &mut buffer,
                    ) {
                        log::trace!("link({}): data over channel {}B", self.id, plain_text.len());
                        self.touch();

                        channel_tx.send(LinkPayload::new_from_slice(plain_text));

                        let payload = LinkPayload::new_from_slice(plain_text);
                        self.post_event(event_tx, LinkEvent::Data(Box::new(payload)));

                        let proof = Some(self.message_proof(packet.hash()));

                        return LinkHandleResult::MessageReceived(proof);
                    } else {
                        log::error!("link({}): can't decrypt channel packet", self.id);
                    }
                } else {
                    log::error!(
                        "link({}): received channel packet but have no channel",
                        self.id
                    );
                }
            }
            _ => {}
        }

        LinkHandleResult::None
    }

    fn handle_proof_packet<E: LinkEventSink>(
        &mut self,
        event_tx: &E,
        packet: &Packet,
    ) -> LinkHandleResult {
        if self.status == LinkStatus::Pending && packet.context == PacketContext::LinkRequestProof {
            // Python `validate_proof` closes the link when the proof mode
            // is not the enabled mode. Absent signalling stays AES-256-CBC.
            let mode = mode_from_lp_packet(packet.data.as_slice());
            if mode != LINK_MODE_AES256_CBC {
                log::debug!("link({}): rejecting link proof mode {mode:#04x}", self.id);
                self.close(event_tx);
                return LinkHandleResult::None;
            }
            if let Ok(identity) = validate_proof_packet(&self.destination, &self.id, packet) {
                log::debug!("link({}): has been proved", self.id);

                self.handshake(identity);
                self.remote_identity = Some(self.destination.identity);

                self.status = LinkStatus::Active;
                // Establishment clock, not inbound silence.
                self.note_rtt(self.since_request());
                self.last_keepalive = now();
                self.touch();

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
        out_link: bool,
    ) -> LinkHandleResult;
}

impl<E: LinkEventSink> LinkExt<E> for Link {
    fn prove(&mut self, event_tx: &E) -> Packet {
        log::debug!("link({}): prove", self.id);

        if self.status != LinkStatus::Active {
            self.set_status(LinkStatus::Active);
            self.post_event(event_tx, LinkEvent::Activated);
        }

        let mut packet_data = PacketDataBuffer::new();

        packet_data.safe_write(self.id.as_slice());
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        packet_data.safe_write(self.priv_identity.as_identity().verifying_key.as_bytes());
        let _ = packet_data.safe_write(&Self::signalling_bytes(self.mtu));

        let signature = self.priv_identity.sign(packet_data.as_slice());

        packet_data.reset();
        packet_data.safe_write(&signature.to_bytes()[..]);
        packet_data.safe_write(self.priv_identity.as_identity().public_key.as_bytes());
        let _ = packet_data.safe_write(&Self::signalling_bytes(self.mtu));

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
            let mut packet =
                self.data_packet_with_rng(self.id.as_slice(), crate::crypt::fernet::ZeroRng)?;
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

impl<E: LinkEventSink, P: LinkPayloadSink> LinkExtHandlePacket<E, P> for Link {
    fn handle_packet(
        &mut self,
        event_tx: &E,
        channel_tx: Option<&P>,
        packet: &Packet,
        out_link: bool,
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

/// Python `Link.mode_from_lr_packet`: absent signalling defaults to
/// AES-256-CBC. Any other mode is not in `ENABLED_MODES`.
fn reject_disabled_link_mode(packet: &Packet) -> Result<(), RnsError> {
    let keys = PUBLIC_KEY_LENGTH * 2;
    if packet.data.len() <= keys {
        return Ok(());
    }
    let mode = (packet.data.as_slice()[keys] & LINK_MODE_BYTEMASK) >> 5;
    if mode == LINK_MODE_AES256_CBC {
        Ok(())
    } else {
        log::debug!("link: rejecting link request mode {mode:#04x}");
        Err(RnsError::InvalidArgument)
    }
}

/// Python `Link.mode_from_lp_packet`. Signalling starts after the
/// signature and the ephemeral public key. Absent bytes default to
/// AES-256-CBC.
fn mode_from_lp_packet(data: &[u8]) -> u8 {
    let offset = SIGNATURE_LENGTH + PUBLIC_KEY_LENGTH;
    if data.len() > offset {
        data[offset] >> 5
    } else {
        LINK_MODE_AES256_CBC
    }
}

fn validate_proof_packet(
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

fn validate_message_proof(identity: &Identity, data: &[u8]) -> Result<Hash, RnsError> {
    if data.len() <= HASH_SIZE {
        return Err(RnsError::PacketError);
    }

    let maybe_signature = Signature::from_slice(&data[HASH_SIZE..]);
    let signature = match maybe_signature {
        Ok(s) => s,
        Err(_) => return Err(RnsError::PacketError),
    };

    let hash_slice = &data[..HASH_SIZE];

    if identity
        .verifying_key
        .verify(hash_slice, &signature)
        .is_ok()
    {
        Ok(Hash::new(hash_slice.try_into().unwrap()))
    } else {
        Err(RnsError::IncorrectSignature)
    }
}

#[cfg(all(test, feature = "std"))]
mod mtu_tests {
    use super::*;
    use crate::destination::{DestinationName, SingleInputDestination};
    use crate::packet::{LINK_MTU_MIN, PROTOCOL_MTU};

    fn request_with_mtu(mtu: usize) -> (Packet, PrivateIdentity, DestinationDesc) {
        let peer = PrivateIdentity::new_from_rand(OsRng);
        let local = PrivateIdentity::new_from_rand(OsRng);
        let destination =
            SingleInputDestination::new(local.clone(), DestinationName::new("test", "link.mtu"));
        let mut data = PacketDataBuffer::new();
        data.safe_write(peer.as_identity().public_key.as_bytes());
        data.safe_write(peer.as_identity().verifying_key.as_bytes());
        data.safe_write(&Link::signalling_bytes(mtu));
        (
            Packet {
                destination: destination.desc.address_hash,
                data,
                ..Default::default()
            },
            local,
            destination.desc,
        )
    }

    #[test]
    fn negotiated_mtu_rejects_unsafe_nonzero_values() {
        let (packet, local, desc) = request_with_mtu(LINK_MTU_MIN - 1);
        assert!(matches!(
            Link::new_from_request(&packet, local.sign_key().clone(), desc),
            Err(RnsError::InvalidArgument)
        ));

        let (packet, local, desc) = request_with_mtu(LINK_MTU_MIN);
        assert_eq!(
            Link::new_from_request(&packet, local.sign_key().clone(), desc)
                .expect("minimum MTU")
                .mtu(),
            LINK_MTU_MIN
        );

        let (packet, local, desc) = request_with_mtu(0);
        assert_eq!(
            Link::new_from_request(&packet, local.sign_key().clone(), desc)
                .expect("default MTU signalling")
                .mtu(),
            PROTOCOL_MTU
        );
    }

    #[test]
    fn local_mtu_and_size_accessors_are_defensive() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "link.local-mtu"));
        let mut link = Link::new(destination.desc);

        link.set_mtu(0);
        assert_eq!(link.mtu(), PROTOCOL_MTU);
        link.set_mtu(LINK_MTU_MIN - 1);
        assert_eq!(link.mtu(), LINK_MTU_MIN);
        assert!(link.mdu() < link.mtu());
        assert!(link.sdu() <= link.mtu());
    }
}

#[cfg(all(test, feature = "std"))]
mod keepalive_tests {
    use super::*;
    use crate::destination::{DestinationName, SingleInputDestination};
    use crate::packet::PROTOCOL_MTU;

    fn fresh_link() -> Link {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "link.keepalive"));
        Link::new(destination.desc)
    }

    fn assert_close(actual: Duration, expected: f64) {
        let delta = (actual.as_secs_f64() - expected).abs();
        assert!(
            delta < 1e-6,
            "got {}s, expected {expected}s",
            actual.as_secs_f64()
        );
    }

    #[test]
    fn unknown_rtt_uses_keepalive_max() {
        let link = fresh_link();
        assert!(!link.rtt_known());
        assert_eq!(link.keepalive(), Duration::from_secs(360));
        assert_eq!(link.stale_time(), Duration::from_secs(720));
        assert_eq!(link.close_grace(), STALE_GRACE);
    }

    #[test]
    fn small_rtt_clamps_to_keepalive_min() {
        let mut link = fresh_link();
        link.note_rtt(Duration::from_secs_f64(0.01));
        assert_eq!(link.keepalive(), Duration::from_secs(5));
        assert_eq!(link.stale_time(), Duration::from_secs(10));
    }

    #[test]
    fn rtt_scales_keepalive_and_doubles_stale_time() {
        let mut link = fresh_link();
        link.note_rtt(Duration::from_secs_f64(0.1));
        let expected = 0.1 * 360.0 / 1.75;
        assert_close(link.keepalive(), expected);
        assert_close(link.stale_time(), expected * 2.0);
    }

    #[test]
    fn large_rtt_clamps_to_keepalive_max() {
        let mut link = fresh_link();
        link.note_rtt(Duration::from_secs(10));
        assert_eq!(link.keepalive(), Duration::from_secs(360));
        assert_eq!(link.stale_time(), Duration::from_secs(720));
        // Uncapped grace would be `10 * 4 + 5`. The watchdog cap makes it 5s.
        assert_eq!(link.close_grace(), Duration::from_secs(5));
    }

    #[test]
    fn link_request_rejects_mode_other_than_aes256_cbc() {
        let peer = PrivateIdentity::new_from_rand(OsRng);
        let local = PrivateIdentity::new_from_rand(OsRng);
        let destination =
            SingleInputDestination::new(local.clone(), DestinationName::new("test", "link.mode"));
        let mode: u8 = 0x02;
        let value = (PROTOCOL_MTU & 0x1F_FFFF) + ((((mode << 5) & 0xE0) as usize) << 16);
        let packed = (value as u32).to_be_bytes();
        let mut data = PacketDataBuffer::new();
        data.safe_write(peer.as_identity().public_key.as_bytes());
        data.safe_write(peer.as_identity().verifying_key.as_bytes());
        data.safe_write(&[packed[1], packed[2], packed[3]]);
        let packet = Packet {
            destination: destination.desc.address_hash,
            data,
            ..Default::default()
        };

        assert!(matches!(
            Link::new_from_request(&packet, local.sign_key().clone(), destination.desc),
            Err(RnsError::InvalidArgument)
        ));
    }

    #[derive(Clone)]
    struct Nop;

    impl LinkEventSink for Nop {
        fn send(&self, _event: LinkEventData) {}
    }

    impl LinkPayloadSink for Nop {
        fn send(&self, _payload: LinkPayload) {}
    }

    fn keepalive_packet(byte: u8) -> Packet {
        let mut data = PacketDataBuffer::new();
        data.safe_write(&[byte]);
        Packet {
            header: Header {
                destination_type: DestinationType::Link,
                packet_type: PacketType::Data,
                ..Default::default()
            },
            context: PacketContext::KeepAlive,
            data,
            ..Default::default()
        }
    }

    #[test]
    fn inbound_touch_leaves_establishment_clock() {
        let mut link = fresh_link();
        let stamped = now().saturating_sub(Duration::from_secs(4));
        link.request_time = stamped;
        link.touch();
        assert_eq!(link.request_time, stamped);
        assert!(link.last_inbound > stamped);
    }

    #[test]
    fn responder_rtt_is_max_of_measured_and_advertised() {
        let mut link = fresh_link();
        // Establishment is the monotonic origin. `touch` must not collapse
        // the sample onto the advertised RTT (the clock starts at process
        // launch, so the measured side is small but strictly larger).
        link.request_time = Duration::ZERO;
        link.touch();
        assert_eq!(link.request_time, Duration::ZERO);
        let advertised = Duration::from_nanos(1);
        link.note_responder_rtt(advertised);
        assert!(*link.rtt() > advertised);

        let mut link = fresh_link();
        link.request_time = now();
        link.note_responder_rtt(Duration::from_secs(2));
        assert!(link.rtt().as_secs_f64() >= 2.0);
        assert!(link.rtt().as_secs_f64() < 2.5);
    }

    #[test]
    fn initiator_keepalive_does_not_refresh_silence() {
        let mut link = fresh_link();
        link.set_status(LinkStatus::Active);
        link.last_inbound = Duration::ZERO;
        let result = link.handle_data_packet(&Nop, None::<&Nop>, &keepalive_packet(0xFF), true);
        assert!(matches!(result, LinkHandleResult::None));
        assert_eq!(link.last_inbound, Duration::ZERO);
    }

    #[test]
    fn responder_keepalive_refreshes_silence() {
        let mut link = fresh_link();
        link.set_status(LinkStatus::Active);
        link.last_inbound = Duration::ZERO;
        let result = link.handle_data_packet(&Nop, None::<&Nop>, &keepalive_packet(0xFF), false);
        assert!(matches!(result, LinkHandleResult::KeepAlive));
        assert!(link.last_inbound > Duration::ZERO);
    }

    #[test]
    fn keepalive_response_refreshes_inbound() {
        let mut link = fresh_link();
        link.set_status(LinkStatus::Active);
        link.last_inbound = Duration::ZERO;
        let result = link.handle_data_packet(&Nop, None::<&Nop>, &keepalive_packet(0xFE), true);
        assert!(matches!(result, LinkHandleResult::None));
        assert!(link.last_inbound > Duration::ZERO);
    }

    #[test]
    fn keepalive_waits_for_an_idle_direction() {
        let mut link = fresh_link();
        link.set_status(LinkStatus::Active);
        // `Duration::MAX` saturates elapsed time to zero (fresh). `ZERO` is
        // the monotonic origin, so a 1ns interval counts as idle without
        // sleeping. The real interval is `KEEPALIVE` once a link is running.
        let fresh = Duration::MAX;
        let interval = Duration::from_nanos(1);
        link.last_inbound = fresh;
        link.last_outbound = fresh;
        link.last_keepalive = Duration::ZERO;
        assert!(!link.keepalive_due(interval));

        link.last_inbound = Duration::ZERO;
        assert!(link.keepalive_due(interval));

        link.last_inbound = fresh;
        link.last_outbound = Duration::ZERO;
        assert!(link.keepalive_due(interval));

        link.last_outbound = fresh;
        link.last_keepalive = fresh;
        link.last_inbound = Duration::ZERO;
        assert!(!link.keepalive_due(interval));
    }

    #[test]
    fn keepalive_reply_follows_outbound_idle() {
        let mut link = fresh_link();
        link.set_status(LinkStatus::Active);
        let interval = Duration::from_nanos(1);
        link.last_outbound = Duration::MAX;
        assert!(!link.keepalive_reply_due(interval));
        link.last_outbound = Duration::ZERO;
        assert!(link.keepalive_reply_due(interval));
        link.mark_outbound(true);
        assert!(!link.keepalive_reply_due(KEEPALIVE));
        assert!(link.last_keepalive > Duration::ZERO);
    }

    fn proof_with_mode(mode: Option<u8>) -> Packet {
        let mut raw = vec![0u8; 96];
        if let Some(mode) = mode {
            raw.push(mode << 5);
        }
        let mut data = PacketDataBuffer::new();
        data.safe_write(&raw);
        Packet {
            header: Header {
                packet_type: PacketType::Proof,
                ..Default::default()
            },
            context: PacketContext::LinkRequestProof,
            data,
            ..Default::default()
        }
    }

    #[test]
    fn link_proof_rejects_mode_other_than_aes256_cbc() {
        let mut link = fresh_link();
        link.set_status(LinkStatus::Pending);
        let result = link.handle_proof_packet(&Nop, &proof_with_mode(Some(0x02)));
        assert!(matches!(result, LinkHandleResult::None));
        assert_eq!(link.status(), LinkStatus::Closed);

        let mut link = fresh_link();
        link.set_status(LinkStatus::Pending);
        let _ = link.handle_proof_packet(&Nop, &proof_with_mode(None));
        assert_eq!(link.status(), LinkStatus::Pending);

        let mut link = fresh_link();
        link.set_status(LinkStatus::Pending);
        let _ = link.handle_proof_packet(&Nop, &proof_with_mode(Some(0x01)));
        assert_eq!(link.status(), LinkStatus::Pending);
    }
}
