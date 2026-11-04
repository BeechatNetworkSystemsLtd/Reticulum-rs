pub mod link;
pub mod link_map;

use ed25519_dalek::{SIGNATURE_LENGTH, Signature, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use x25519_dalek::PublicKey;

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use crate::{
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::{
        EmptyIdentity, HashIdentity, Identity, PUBLIC_KEY_LENGTH, PrivateIdentity,
        RATCHET_ID_LENGTH, RATCHET_KEY_LENGTH, generate_ratchet, ratchet_public_from_private,
    },
    packet::{
        self, DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext,
        PacketDataBuffer, PacketType, PropagationType,
    },
    time::unix_time_as_secs,
};
use sha2::Digest;

//***************************************************************************//

pub trait Direction {}

pub struct Input;
pub struct Output;

impl Direction for Input {}
impl Direction for Output {}

//***************************************************************************//

pub trait Type {
    fn destination_type() -> DestinationType;
}

pub struct Single;
pub struct Plain;
pub struct Group;

impl Type for Single {
    fn destination_type() -> DestinationType {
        DestinationType::Single
    }
}

impl Type for Plain {
    fn destination_type() -> DestinationType {
        DestinationType::Plain
    }
}

impl Type for Group {
    fn destination_type() -> DestinationType {
        DestinationType::Group
    }
}

pub const NAME_HASH_LENGTH: usize = 10;
pub const RAND_HASH_LENGTH: usize = 10;
pub const MIN_ANNOUNCE_DATA_LENGTH: usize =
    PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH + RAND_HASH_LENGTH + SIGNATURE_LENGTH;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct DestinationName {
    pub hash: Hash,
}

impl DestinationName {
    pub fn new(app_name: &str, aspects: &str) -> Self {
        let hash = Hash::new(
            Hash::generator()
                .chain_update(app_name.as_bytes())
                .chain_update(".".as_bytes())
                .chain_update(aspects.as_bytes())
                .finalize()
                .into(),
        );

        Self { hash }
    }

    pub fn new_from_hash_slice(hash_slice: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        hash[..hash_slice.len()].copy_from_slice(hash_slice);

        Self {
            hash: Hash::new(hash),
        }
    }

    /// The destination address hash for this name and an announcing
    /// identity (Python `Destination.hash_from_name_and_identity`).
    pub fn address_hash_for<I: crate::identity::HashIdentity>(&self, identity: &I) -> AddressHash {
        create_address_hash(identity, self)
    }

    pub fn as_name_hash_slice(&self) -> &[u8] {
        &self.hash.as_slice()[..NAME_HASH_LENGTH]
    }

    /// Whether this name and `other` denote the same destination name,
    /// ignoring the address hash (compares the name hash).
    pub fn desc_hash_matches(&self, other: &DestinationName) -> bool {
        self.as_name_hash_slice() == other.as_name_hash_slice()
    }
}

#[derive(Copy, Clone)]
pub struct DestinationDesc {
    pub identity: Identity,
    pub address_hash: AddressHash,
    pub name: DestinationName,
}

impl fmt::Display for DestinationDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address_hash)?;

        Ok(())
    }
}

/// Parsed contents of a validated announce packet.
#[derive(Clone, Debug)]
pub struct AnnounceData<'a> {
    /// Announce app data. Mirrors the Python `Identity.validate_announce`
    /// quirk: `None` when a ratchet-less announce carries no app data, and
    /// an empty slice for ratchet announces without app data.
    pub app_data: Option<&'a [u8]>,
    /// Public ratchet key carried by the announce (`None` when the announce
    /// does not include one, Python `Identity.RATCHETSIZE // 8` bytes when
    /// it does).
    pub ratchet: Option<[u8; RATCHET_KEY_LENGTH]>,
}

pub type DestinationAnnounce = Packet;

impl DestinationAnnounce {
    /// Validate an announce packet (Python `Identity.validate_announce`).
    ///
    /// Verifies the signature over
    /// `destination_hash || public_key || name_hash || random_hash || ratchet || app_data`,
    /// and that the announced destination hash actually belongs to the
    /// announced name hash and identity.
    pub fn validate(
        packet: &Packet,
    ) -> Result<(SingleOutputDestination, AnnounceData<'_>), RnsError> {
        if packet.header.packet_type != PacketType::Announce {
            return Err(RnsError::PacketError);
        }

        let announce_data = packet.data.as_slice();

        let minimum = if packet.header.context_flag {
            MIN_ANNOUNCE_DATA_LENGTH + RATCHET_KEY_LENGTH
        } else {
            MIN_ANNOUNCE_DATA_LENGTH
        };

        if announce_data.len() < minimum {
            return Err(RnsError::OutOfMemory);
        }

        let mut offset = 0usize;

        let public_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;
            PublicKey::from(key_data)
        };

        let verifying_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&announce_data[offset..(offset + PUBLIC_KEY_LENGTH)]);
            offset += PUBLIC_KEY_LENGTH;

            VerifyingKey::from_bytes(&key_data).map_err(|_| RnsError::CryptoError)?
        };

        let identity = Identity::new(public_key, verifying_key);

        let name_hash = &announce_data[offset..(offset + NAME_HASH_LENGTH)];
        offset += NAME_HASH_LENGTH;
        let rand_hash = &announce_data[offset..(offset + RAND_HASH_LENGTH)];
        offset += RAND_HASH_LENGTH;

        // If the packet context flag is set, this announce contains a
        // ratchet key between the random hash and the signature.
        let ratchet = if packet.header.context_flag {
            let mut ratchet = [0u8; RATCHET_KEY_LENGTH];
            ratchet.copy_from_slice(&announce_data[offset..(offset + RATCHET_KEY_LENGTH)]);
            offset += RATCHET_KEY_LENGTH;
            Some(ratchet)
        } else {
            None
        };

        let signature = &announce_data[offset..(offset + SIGNATURE_LENGTH)];
        offset += SIGNATURE_LENGTH;

        // Python `Identity.validate_announce`: app data is present when the
        // announce is longer than `keysize+name_hash_len+10+sig_len`.
        let app_data = if announce_data.len() > MIN_ANNOUNCE_DATA_LENGTH {
            Some(&announce_data[offset..])
        } else {
            None
        };

        let destination = &packet.destination;

        // Verification function doesn't support prehashed message, so the
        // signed fields are concatenated into an exact-size buffer:
        // everything in `announce_data` except the signature, plus the
        // destination hash. `announce_data.len() >= minimum >=
        // SIGNATURE_LENGTH`, so the capacity never underflows and the
        // extends below never reallocate.
        let mut signed_data =
            Vec::with_capacity(destination.as_slice().len() + announce_data.len() - SIGNATURE_LENGTH);
        signed_data.extend_from_slice(destination.as_slice());
        signed_data.extend_from_slice(public_key.as_bytes());
        signed_data.extend_from_slice(verifying_key.as_bytes());
        signed_data.extend_from_slice(name_hash);
        signed_data.extend_from_slice(rand_hash);

        if let Some(ratchet) = &ratchet {
            signed_data.extend_from_slice(ratchet);
        }

        if let Some(app_data) = app_data {
            signed_data.extend_from_slice(app_data);
        }

        let signature = Signature::from_slice(signature).map_err(|_| RnsError::CryptoError)?;

        identity.verify(&signed_data, &signature)?;

        // The announced destination hash must belong to the announced name
        // hash and identity (Python rejects hash collisions here).
        let expected_hash = Hash::new(
            Hash::generator()
                .chain_update(name_hash)
                .chain_update(identity.address_hash.as_slice())
                .finalize()
                .into(),
        );

        if AddressHash::new_from_hash(&expected_hash) != *destination {
            return Err(RnsError::IncorrectHash);
        }

        Ok((
            SingleOutputDestination::new(identity, DestinationName::new_from_hash_slice(name_hash)),
            AnnounceData { app_data, ratchet },
        ))
    }
}

pub struct Destination<I: HashIdentity, D: Direction, T: Type> {
    pub direction: PhantomData<D>,
    pub r#type: PhantomData<T>,
    pub identity: I,
    /// Packet proof strategy for link data addressed to this destination
    /// (only meaningful for SINGLE IN destinations).
    pub proof_strategy: ProofStrategy,
    /// Whether this destination accepts incoming link requests
    /// (Python `Destination.accepts_links`).
    pub accepts_links: bool,
    /// Retained *private* ratchet keys, newest first. `None` while ratchets
    /// are disabled (Python `Destination.ratchets`).
    pub ratchets: Option<Vec<[u8; RATCHET_KEY_LENGTH]>>,

    /// Symmetric group key for GROUP destinations
    /// (Python `Destination.prv`).
    pub group_key: Option<GroupKey>,
    /// Unix timestamp of the last ratchet rotation
    /// (Python `Destination.latest_ratchet_time`).
    pub latest_ratchet_time: u64,
    /// Minimum interval between ratchet rotations in seconds
    /// (Python `Destination.ratchet_interval`).
    pub ratchet_interval: u64,
    /// Number of ratchet keys to retain
    /// (Python `Destination.retained_ratchets`).
    pub retained_ratchets: usize,
    /// Called for [`ProofStrategy::App`] instead of sending a proof
    /// automatically (Python `callbacks.proof_requested`).
    proof_requested: Option<fn(&Packet) -> bool>,
    /// Bytes included in announces when the caller does not pass app data
    /// (Python `Destination.default_app_data`).
    default_app_data: Option<Vec<u8>>,
    /// Reject packets encrypted to the static identity key
    /// (Python `Destination.__enforce_ratchets`).
    ratchets_enforced: bool,
    pub desc: DestinationDesc,
}

impl<I: HashIdentity, D: Direction, T: Type> Destination<I, D, T> {
    pub fn destination_type(&self) -> packet::DestinationType {
        <T as Type>::destination_type()
    }
}

/// Encrypt `text` for a SINGLE destination (Python `Destination.encrypt`).
///
/// When the destination's identity has a known ratchet for this destination
/// (supplied by the caller, Python `RNS.Identity.get_ratchet(self.hash)`),
/// the ephemeral key exchange is performed against the ratchet key.
pub fn encrypt_single<'a, R: CryptoRngCore + Copy>(
    identity: &Identity,
    text: &[u8],
    ratchet: Option<&PublicKey>,
    rng: R,
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], RnsError> {
    identity.encrypt(rng, text, ratchet, out_buf)
}

pub enum DestinationHandleStatus {
    None,
    LinkProof,
}

/// Proof strategies for link data packets
/// (Python `Destination.PROVE_NONE/PROVE_APP/PROVE_ALL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProofStrategy {
    /// Never prove packets.
    #[default]
    None,
    /// Ask [`Destination::set_proof_requested_callback`]. Does not prove
    /// unless that callback returns true.
    App,
    /// Prove all packets.
    All,
}

/// Number of ratchet keys a destination retains by default
/// (Python `Destination.RATCHET_COUNT`).
pub const RATCHET_COUNT: usize = 512;

/// Minimum interval between ratchet rotations in seconds
/// (Python `Destination.RATCHET_INTERVAL`).
pub const RATCHET_INTERVAL_SECS: u64 = 30 * 60;

impl Destination<PrivateIdentity, Input, Single> {
    /// Set the packet proof strategy
    /// (Python `Destination.set_proof_strategy`).
    pub fn set_proof_strategy(&mut self, strategy: ProofStrategy) {
        self.proof_strategy = strategy;
    }

    pub fn proof_strategy(&self) -> ProofStrategy {
        self.proof_strategy
    }

    /// Register the callback consulted by [`ProofStrategy::App`]
    /// (Python `Destination.set_proof_requested_callback`).
    ///
    /// The callback receives the packet and returns whether a proof should
    /// be sent. [`ProofStrategy::All`] does not call it.
    pub fn set_proof_requested_callback(&mut self, callback: fn(&Packet) -> bool) {
        self.proof_requested = Some(callback);
    }

    /// Whether a proof should be sent for `packet`.
    ///
    /// [`ProofStrategy::All`] proves on its own. [`ProofStrategy::App`] does
    /// not: it raises the proof-requested callback and proves only when that
    /// returns true. [`ProofStrategy::None`] never proves.
    pub fn should_prove(&self, packet: &Packet) -> bool {
        match self.proof_strategy {
            ProofStrategy::All => true,
            ProofStrategy::None => false,
            ProofStrategy::App => self
                .proof_requested
                .map(|callback| callback(packet))
                .unwrap_or(false),
        }
    }

    /// Enable ratchets on this destination (Python `Destination.enable_ratchets`).
    ///
    /// `ratchets` are the retained *private* ratchet keys (newest first,
    /// typically loaded from the destination's ratchet file by the
    /// `reticulum` storage module). Passing an empty list starts a fresh
    /// ratchet chain, exactly like a missing ratchet file in Python.
    pub fn enable_ratchets(&mut self, ratchets: Vec<[u8; RATCHET_KEY_LENGTH]>) {
        self.ratchets = Some(ratchets);
        self.latest_ratchet_time = 0;
    }

    /// Disable ratchets on this destination again.
    pub fn disable_ratchets(&mut self) {
        self.ratchets = None;
        self.ratchets_enforced = false;
    }

    /// Reject packets that use the base identity key
    /// (Python `Destination.enforce_ratchets`).
    ///
    /// Returns false when ratchets are not enabled.
    pub fn enforce_ratchets(&mut self) -> bool {
        if self.ratchets.is_some() {
            self.ratchets_enforced = true;
            true
        } else {
            false
        }
    }

    /// Default app data included in announces that do not pass their own
    /// (Python `Destination.set_default_app_data`). `None` clears it.
    pub fn set_default_app_data(&mut self, app_data: Option<&[u8]>) {
        self.default_app_data = app_data.map(|data| data.to_vec());
    }

    /// Clear default app data (Python `Destination.clear_default_app_data`).
    pub fn clear_default_app_data(&mut self) {
        self.set_default_app_data(None);
    }

    pub fn ratchets_enabled(&self) -> bool {
        self.ratchets.is_some()
    }

    /// The retained private ratchet keys, newest first.
    pub fn ratchets(&self) -> Option<&[[u8; RATCHET_KEY_LENGTH]]> {
        self.ratchets.as_deref()
    }

    /// Private ratchet keys as a mutable slice (storage (re)load).
    pub fn ratchets_mut(&mut self) -> Option<&mut Vec<[u8; RATCHET_KEY_LENGTH]>> {
        self.ratchets.as_mut()
    }

    /// Set the minimum interval in seconds between ratchet key rotations
    /// (Python `Destination.set_ratchet_interval`).
    pub fn set_ratchet_interval(&mut self, interval: u64) {
        if interval > 0 {
            self.ratchet_interval = interval;
        }
    }

    /// Set the number of retained ratchet keys
    /// (Python `Destination.set_retained_ratchets`).
    pub fn set_retained_ratchets(&mut self, count: usize) {
        if count > 0 {
            self.retained_ratchets = count;
            self.clean_ratchets();
        }
    }

    /// Drop all but the newest `retained_ratchets` keys
    /// (Python `Destination._clean_ratchets`).
    pub fn clean_ratchets(&mut self) {
        if let Some(ratchets) = &mut self.ratchets
            && ratchets.len() > self.retained_ratchets
        {
            ratchets.truncate(RATCHET_COUNT.min(self.retained_ratchets));
        }
    }

    /// Generate a fresh ratchet key at the front of the list if the
    /// rotation interval has elapsed (Python `Destination.rotate_ratchets`).
    /// Returns the new ratchet key when one was generated.
    pub fn rotate_ratchets<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        now_secs: u64,
    ) -> Option<[u8; RATCHET_KEY_LENGTH]> {
        let ratchets = self.ratchets.as_mut()?;
        if now_secs > self.latest_ratchet_time + self.ratchet_interval {
            let new_ratchet = generate_ratchet(rng);
            ratchets.insert(0, new_ratchet);
            self.latest_ratchet_time = now_secs;
            self.clean_ratchets();
            Some(new_ratchet)
        } else {
            None
        }
    }

    /// Decrypt a SINGLE-destination data packet (Python `Destination.decrypt`).
    ///
    /// Retained ratchet keys are tried first. The static identity key is
    /// used only when ratchet enforcement is off.
    pub fn decrypt<'a>(&self, data: &[u8], out_buf: &'a mut [u8]) -> Result<&'a [u8], RnsError> {
        self.decrypt_ratchet(data, out_buf)
            .map(|(plaintext, _ratchet_id)| plaintext)
    }

    /// Decrypt and report the ratchet id that opened the packet.
    ///
    /// The id is `None` when the static identity key was used. Enforcement
    /// rejects that fallback (Python `enforce_ratchets`).
    pub fn decrypt_ratchet<'a>(
        &self,
        data: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<(&'a [u8], Option<[u8; RATCHET_ID_LENGTH]>), RnsError> {
        let ratchets = self.ratchets.as_deref().unwrap_or(&[]);
        self.identity
            .decrypt_ratchet(data, ratchets, self.ratchets_enforced, out_buf)
    }

    /// Control whether this destination accepts incoming link requests
    /// (Python `Destination.set_accepts_links` / `accepts_links`).
    pub fn set_accepts_links(&mut self, accepts: bool) {
        self.accepts_links = accepts;
    }

    pub fn accepts_links(&self) -> bool {
        self.accepts_links
    }

    pub fn new(identity: PrivateIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        let pub_identity = *identity.as_identity();

        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            group_key: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            proof_requested: None,
            default_app_data: None,
            ratchets_enforced: false,
            desc: DestinationDesc {
                identity: pub_identity,
                name,
                address_hash,
            },
        }
    }

    /// Build an announce packet (Python `Destination.announce`).
    ///
    /// When ratchets are enabled the newest ratchet public key is included
    /// between the random hash and the signature, and the packet context
    /// flag is set to signal its presence.
    pub fn announce<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        self.announce_at(rng, app_data, unix_time_as_secs())
    }

    /// Deterministic-time variant of [`Destination::announce`].
    pub fn announce_at<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        app_data: Option<&[u8]>,
        now_secs: u64,
    ) -> Result<Packet, RnsError> {
        // Python `Destination.announce`: an omitted app_data falls back to
        // the destination default, which may itself be absent.
        let default_app_data = self.default_app_data.clone();
        let app_data = match app_data {
            Some(data) => Some(data),
            None => default_app_data.as_deref(),
        };

        // Python `Destination.announce`: rotate ratchets (respecting the
        // rotation interval) and announce the newest public key.
        let ratchet = self
            .rotate_ratchets_if_due(rng, now_secs)
            .map(|(public, _private)| public);

        let mut packet_data = PacketDataBuffer::new();

        let rand_hash = Hash::new_from_rand(rng);
        let timestamp = now_secs.to_be_bytes();
        let rand_hash = [
            &rand_hash.as_slice()[..RAND_HASH_LENGTH / 2],
            &timestamp[3..],
        ]
        .concat();

        let pub_key = self.identity.as_identity().public_key_bytes();
        let verifying_key = self.identity.as_identity().verifying_key_bytes();

        packet_data
            .chain_safe_write(self.desc.address_hash.as_slice())
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(&rand_hash);

        if let Some(ratchet) = &ratchet {
            packet_data.chain_safe_write(ratchet);
        }

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        let signature = self.identity.sign(packet_data.as_slice());

        packet_data.reset();

        packet_data
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(&rand_hash);

        if let Some(ratchet) = &ratchet {
            packet_data.chain_safe_write(ratchet);
        }

        packet_data.chain_safe_write(&signature.to_bytes());

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        // Python `Destination.announce`: `context_flag = FLAG_SET` when the
        // announce carries a ratchet.
        let header = Header {
            ifac_flag: IfacFlag::Open,
            context_flag: ratchet.is_some(),
            header_type: HeaderType::Type1,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops: 0,
        };

        Ok(Packet {
            header,
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    /// Rotate ratchets when the rotation interval has elapsed, returning the
    /// public (and private) key of the ratchet that an announce should
    /// carry. Mirrors Python `Destination.announce` calling
    /// `rotate_ratchets` then using `self.ratchets[0]`.
    fn rotate_ratchets_if_due<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        now_secs: u64,
    ) -> Option<([u8; RATCHET_KEY_LENGTH], [u8; RATCHET_KEY_LENGTH])> {
        let ratchets = self.ratchets.as_ref()?;

        let rotate =
            ratchets.is_empty() || now_secs > self.latest_ratchet_time + self.ratchet_interval;

        if rotate {
            let new_ratchet = generate_ratchet(rng);
            if let Some(ratchets) = self.ratchets.as_mut() {
                ratchets.insert(0, new_ratchet);
            }
            self.latest_ratchet_time = now_secs;
            self.clean_ratchets();
        }

        let private = *self.ratchets.as_ref()?.first()?;
        let public = ratchet_public_from_private(&private);
        Some((public, private))
    }

    pub fn path_response<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let mut announce = self.announce(rng, app_data)?;
        announce.context = PacketContext::PathResponse;

        Ok(announce)
    }

    pub fn handle_packet(&mut self, packet: &Packet) -> DestinationHandleStatus {
        if self.desc.address_hash != packet.destination {
            return DestinationHandleStatus::None;
        }

        if packet.header.packet_type == PacketType::LinkRequest {
            // Link-request proofs are not gated by the proof strategy
            // (Python `Destination.incoming_link_request`).
            return DestinationHandleStatus::LinkProof;
        }

        DestinationHandleStatus::None
    }

    pub fn sign_key(&self) -> &SigningKey {
        self.identity.sign_key()
    }
}

impl Destination<Identity, Output, Single> {
    pub fn new(identity: Identity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            group_key: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            proof_requested: None,
            default_app_data: None,
            ratchets_enforced: false,
            desc: DestinationDesc {
                identity,
                name,
                address_hash,
            },
        }
    }
}

impl<D: Direction> Destination<EmptyIdentity, D, Plain> {
    pub fn new(identity: EmptyIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            group_key: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            proof_requested: None,
            default_app_data: None,
            ratchets_enforced: false,
            desc: DestinationDesc {
                identity: Default::default(),
                name,
                address_hash,
            },
        }
    }
}

/// Symmetric group key (Python `RNS.Cryptography.Token`): the raw key is
/// split into an HMAC signing key and an AES-CBC encryption key. A 64-byte
/// key is AES-256 (Python `Token.generate_key()` default) and a 32-byte
/// key is AES-128. The `fernet-aes128` feature still selects the size of
/// keys this type generates. Token format `iv || ciphertext || hmac` is
/// byte-compatible with the reference `Destination.prv`.
pub struct GroupKey {
    /// Decrypt/verify view of the token keys (no entropy consumed).
    fernet: crate::crypt::fernet::Fernet<crate::crypt::fernet::ZeroRng>,
    /// Encryption view with real entropy: every encryption generates a
    /// fresh cryptographically secure IV. `ZeroRng` here would fix the IV
    /// at zero, breaking CBC confidentiality across repeated plaintexts.
    #[cfg(feature = "std")]
    fernet_enc: crate::crypt::fernet::Fernet<rand_core::OsRng>,
    raw: [u8; GROUP_KEY_SIZE],
}

/// Group key size for the compiled AES mode.
#[cfg(feature = "fernet-aes128")]
pub const GROUP_KEY_SIZE: usize = 32;
#[cfg(not(feature = "fernet-aes128"))]
pub const GROUP_KEY_SIZE: usize = 64;

impl GroupKey {
    /// Generate a new random group key
    /// (Python `Destination.create_keys` -> `Token.generate_key`).
    pub fn generate<R: CryptoRngCore>(mut rng: R) -> Self {
        let mut raw = [0u8; GROUP_KEY_SIZE];
        rng.fill_bytes(&mut raw);
        Self::from_bytes(raw)
    }

    /// Wrap an existing group key
    /// (Python `Destination.load_private_key`).
    pub fn from_bytes(raw: [u8; GROUP_KEY_SIZE]) -> Self {
        let half = GROUP_KEY_SIZE / 2;
        Self {
            fernet: crate::crypt::fernet::Fernet::<crate::crypt::fernet::ZeroRng>::new_from_slices(
                &raw[..half],
                &raw[half..],
                crate::crypt::fernet::ZeroRng,
            ),
            #[cfg(feature = "std")]
            fernet_enc: crate::crypt::fernet::Fernet::<rand_core::OsRng>::new_from_slices(
                &raw[..half],
                &raw[half..],
                rand_core::OsRng,
            ),
            raw,
        }
    }

    /// The raw private key bytes (Python `Destination.get_private_key`).
    pub fn as_bytes(&self) -> &[u8; GROUP_KEY_SIZE] {
        &self.raw
    }

    /// Encrypt a payload into `out_buf`, returning the token bytes
    /// (Python `Token.encrypt`). Uses a fresh cryptographically secure IV
    /// per encryption (hosted targets).
    #[cfg(feature = "std")]
    pub fn encrypt<'a>(
        &self,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], crate::error::RnsError> {
        let plain = crate::crypt::fernet::PlainText(plaintext);
        self.fernet_enc
            .encrypt(plain, out_buf)
            .map(|token| token.as_bytes())
    }

    /// Encrypt with a caller-provided RNG (bare-metal embedding).
    pub fn encrypt_with_rng<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], crate::error::RnsError> {
        let fernet = crate::crypt::fernet::Fernet::<R>::new_from_slices(
            &self.raw[..GROUP_KEY_SIZE / 2],
            &self.raw[GROUP_KEY_SIZE / 2..],
            rng,
        );
        let plain = crate::crypt::fernet::PlainText(plaintext);
        fernet.encrypt(plain, out_buf).map(|token| token.as_bytes())
    }

    /// Verify and decrypt a token into `out_buf`
    /// (Python `Token.decrypt`).
    pub fn decrypt<'a>(
        &self,
        token: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], crate::error::RnsError> {
        let verified = self
            .fernet
            .verify(crate::crypt::fernet::Token::from(token))?;
        self.fernet.decrypt(verified, out_buf).map(|p| p.as_slice())
    }
}

/// GROUP destinations use name-hash addressing like PLAIN ones, with
/// symmetric-key payload encryption (Python `Destination.prv` /
/// `create_keys` / `load_private_key`). Without a loaded group key the
/// payloads pass unencrypted, matching the reference for destinations
/// that never load one.
impl<D: Direction> Destination<EmptyIdentity, D, Group> {
    pub fn new(identity: EmptyIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            proof_strategy: ProofStrategy::default(),
            accepts_links: true,
            ratchets: None,
            group_key: None,
            latest_ratchet_time: 0,
            ratchet_interval: RATCHET_INTERVAL_SECS,
            retained_ratchets: RATCHET_COUNT,
            proof_requested: None,
            default_app_data: None,
            ratchets_enforced: false,
            desc: DestinationDesc {
                identity: Default::default(),
                name,
                address_hash,
            },
        }
    }

    /// Generate a new symmetric group key for this destination
    /// (Python `Destination.create_keys`).
    pub fn create_group_key<R: CryptoRngCore>(&mut self, rng: R) -> [u8; GROUP_KEY_SIZE] {
        let key = GroupKey::generate(rng);
        let raw = *key.as_bytes();
        self.group_key = Some(key);
        raw
    }

    /// Load an existing symmetric group key
    /// (Python `Destination.load_private_key`).
    pub fn load_group_key(&mut self, key: [u8; GROUP_KEY_SIZE]) {
        self.group_key = Some(GroupKey::from_bytes(key));
    }

    /// The loaded group key, if any (Python `Destination.get_private_key`).
    pub fn group_key(&self) -> Option<&[u8; GROUP_KEY_SIZE]> {
        self.group_key.as_ref().map(|key| key.as_bytes())
    }

    /// Whether payloads on this destination are encrypted.
    pub fn group_encrypted(&self) -> bool {
        self.group_key.is_some()
    }

    /// Encrypt a payload with the destination's group key
    /// (Python `Destination.encrypt` for GROUP). Fresh secure IV per
    /// packet on hosted targets; `_with_rng` form for bare metal.
    #[cfg(feature = "std")]
    pub fn encrypt_group<'a>(
        &self,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], crate::error::RnsError> {
        match &self.group_key {
            Some(key) => key.encrypt(plaintext, out_buf),
            None => Err(crate::error::RnsError::CryptoError),
        }
    }

    /// Encrypt with a caller-provided RNG (bare-metal embedding).
    pub fn encrypt_group_with_rng<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], crate::error::RnsError> {
        match &self.group_key {
            Some(key) => key.encrypt_with_rng(rng, plaintext, out_buf),
            None => Err(crate::error::RnsError::CryptoError),
        }
    }

    /// Decrypt a payload with the destination's group key
    /// (Python `Destination.decrypt` for GROUP).
    pub fn decrypt_group<'a>(
        &self,
        ciphertext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], crate::error::RnsError> {
        match &self.group_key {
            Some(key) => key.decrypt(ciphertext, out_buf),
            None => Err(crate::error::RnsError::CryptoError),
        }
    }
}

fn create_address_hash<I: HashIdentity>(identity: &I, name: &DestinationName) -> AddressHash {
    AddressHash::new_from_hash(&Hash::new(
        Hash::generator()
            .chain_update(name.as_name_hash_slice())
            .chain_update(identity.as_address_hash_slice())
            .finalize()
            .into(),
    ))
}

pub type SingleInputDestination = Destination<PrivateIdentity, Input, Single>;
pub type SingleOutputDestination = Destination<Identity, Output, Single>;
pub type PlainInputDestination = Destination<EmptyIdentity, Input, Plain>;
pub type PlainOutputDestination = Destination<EmptyIdentity, Output, Plain>;
pub type GroupInputDestination = Destination<EmptyIdentity, Input, Group>;
pub type GroupOutputDestination = Destination<EmptyIdentity, Output, Group>;

#[cfg(all(test, feature = "std"))]
mod tests {
    use rand_core::OsRng;

    use crate::buffer::OutputBuffer;
    use crate::hash::Hash;
    use crate::identity::PrivateIdentity;
    use crate::serde::Serialize;

    use std::println;

    use super::DestinationAnnounce;
    use super::DestinationName;
    use super::{ProofStrategy, SingleInputDestination};

    #[test]
    fn proof_strategy_defaults_to_none_and_can_be_overridden() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "proof.default"));

        assert_eq!(destination.proof_strategy(), ProofStrategy::None);
        destination.set_proof_strategy(ProofStrategy::All);
        assert_eq!(destination.proof_strategy(), ProofStrategy::All);
    }

    #[test]
    fn app_strategy_does_not_auto_prove() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use crate::packet::Packet;

        static PROOF_REQUESTED: AtomicBool = AtomicBool::new(false);

        fn on_proof(_packet: &Packet) -> bool {
            PROOF_REQUESTED.store(true, Ordering::SeqCst);
            false
        }

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "proof.app"));
        destination.set_proof_strategy(ProofStrategy::App);

        let packet = Packet::default();
        PROOF_REQUESTED.store(false, Ordering::SeqCst);
        assert!(!destination.should_prove(&packet));
        assert!(!PROOF_REQUESTED.load(Ordering::SeqCst));

        destination.set_proof_requested_callback(on_proof);
        assert!(!destination.should_prove(&packet));
        assert!(PROOF_REQUESTED.load(Ordering::SeqCst));

        destination.set_proof_strategy(ProofStrategy::All);
        PROOF_REQUESTED.store(false, Ordering::SeqCst);
        assert!(destination.should_prove(&packet));
        assert!(!PROOF_REQUESTED.load(Ordering::SeqCst));
    }

    #[test]
    fn enforced_ratchets_reject_static_ciphertext() {
        use crate::identity::{
            RATCHET_ID_LENGTH, generate_ratchet, ratchet_id, ratchet_public_from_private,
        };
        use x25519_dalek::PublicKey;

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let public = *identity.as_identity();
        let mut destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "ratchet.enforce"));

        assert!(!destination.enforce_ratchets());
        let ratchet = generate_ratchet(OsRng);
        destination.enable_ratchets(alloc::vec![ratchet]);
        assert!(destination.enforce_ratchets());

        let plaintext = b"static key packet";
        let mut token_buf = [0u8; 512];
        let static_token = public
            .encrypt(OsRng, plaintext, None, &mut token_buf)
            .expect("static encrypt")
            .to_vec();

        let mut out = [0u8; 512];
        assert!(destination.decrypt(&static_token, &mut out).is_err());

        let ratchet_public = ratchet_public_from_private(&ratchet);
        let mut ratchet_buf = [0u8; 512];
        let ratchet_token = public
            .encrypt(
                OsRng,
                plaintext,
                Some(&PublicKey::from(ratchet_public)),
                &mut ratchet_buf,
            )
            .expect("ratchet encrypt")
            .to_vec();

        let (decrypted, id) = destination
            .decrypt_ratchet(&ratchet_token, &mut out)
            .expect("ratchet decrypt");
        assert_eq!(decrypted, plaintext);
        let hash = ratchet_id(&ratchet_public);
        let mut expected = [0u8; RATCHET_ID_LENGTH];
        expected.copy_from_slice(&hash.as_slice()[..RATCHET_ID_LENGTH]);
        assert_eq!(id, Some(expected));
    }

    #[test]
    fn default_app_data_is_announced_when_omitted() {
        let identity = PrivateIdentity::new_from_name("default-app-data");
        let mut destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "app.data"));
        destination.set_default_app_data(Some(b"default-bytes"));
        destination.set_ratchet_interval(u64::MAX);

        let announce = destination
            .announce_at(OsRng, None, 1_700_000_000)
            .expect("announce");
        assert!(
            announce
                .data
                .as_slice()
                .windows(13)
                .any(|window| window == b"default-bytes")
        );

        let explicit = destination
            .announce_at(OsRng, Some(b"explicit"), 1_700_000_000)
            .expect("announce");
        assert!(
            explicit
                .data
                .as_slice()
                .windows(8)
                .any(|window| window == b"explicit")
        );
        assert!(
            !explicit
                .data
                .as_slice()
                .windows(13)
                .any(|window| window == b"default-bytes")
        );

        destination.clear_default_app_data();
        let cleared = destination
            .announce_at(OsRng, None, 1_700_000_000)
            .expect("announce");
        assert!(
            !cleared
                .data
                .as_slice()
                .windows(13)
                .any(|window| window == b"default-bytes")
        );
    }

    #[test]
    fn create_announce() {
        let identity = PrivateIdentity::new_from_rand(OsRng);

        let mut single_in_destination =
            SingleInputDestination::new(identity, DestinationName::new("test", "in"));

        let announce_packet = single_in_destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        println!("Announce packet {}", announce_packet);
    }

    #[test]
    fn create_path_request_hash() {
        let name = DestinationName::new("rnstransport", "path.request");

        println!("PathRequest Name Hash {}", name.hash);
        println!(
            "PathRequest Destination Hash {}",
            Hash::new_from_slice(name.as_name_hash_slice())
        );
    }

    #[test]
    fn compare_announce() {
        let priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let sign_priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let priv_identity = PrivateIdentity::new(priv_key.into(), sign_priv_key.into());

        println!("identity hash {}", priv_identity.as_identity().address_hash);

        let mut destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        println!("destination name hash {}", destination.desc.name.hash);
        println!("destination hash {}", destination.desc.address_hash);

        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        let mut output_data = [0u8; 4096];
        let mut buffer = OutputBuffer::new(&mut output_data);

        let _ = announce.serialize(&mut buffer).expect("correct data");

        println!("ANNOUNCE {}", buffer);
    }

    #[test]
    fn check_announce() {
        let priv_identity = PrivateIdentity::new_from_rand(OsRng);

        let mut destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        let announce = destination
            .announce(OsRng, None)
            .expect("valid announce packet");

        DestinationAnnounce::validate(&announce).expect("valid announce");
    }

    #[test]
    fn validate_max_length_announce() {
        use crate::packet::PACKET_MDU;

        let priv_identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination = SingleInputDestination::new(
            priv_identity,
            DestinationName::new("test", "max.length"),
        );

        // Fills the packet data buffer exactly, so any signed-bytes
        // truncation or capacity overflow shows up at this boundary.
        let app_data = [0xA5u8; PACKET_MDU - super::MIN_ANNOUNCE_DATA_LENGTH];
        let announce = destination
            .announce(OsRng, Some(&app_data[..]))
            .expect("max-length announce");
        assert_eq!(announce.data.len(), PACKET_MDU);

        let (_, validated) =
            DestinationAnnounce::validate(&announce).expect("valid max-length announce");
        assert_eq!(validated.app_data, Some(&app_data[..]));
    }
}
