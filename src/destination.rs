pub mod link;
pub mod link_map;

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SIGNATURE_LENGTH};
use rand_core::CryptoRngCore;
use sha2::Digest;
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::{
        ratchet_id_from_pub, DerivedKey, EmptyIdentity, EncryptIdentity, HashIdentity, Identity,
        PrivateIdentity, RatchetId, PUBLIC_KEY_LENGTH,
    },
    packet::{
        self, ContextFlag, DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext,
        PacketDataBuffer, PacketType, PropagationType,
    },
};

pub trait Direction {}

pub struct Input;
pub struct Output;

impl Direction for Input {}
impl Direction for Output {}

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
pub const RATCHET_PUBLIC_KEY_LENGTH: usize = 32;
pub const MIN_ANNOUNCE_DATA_LENGTH: usize =
    PUBLIC_KEY_LENGTH * 2 + NAME_HASH_LENGTH + RAND_HASH_LENGTH + SIGNATURE_LENGTH;

const DEFAULT_RATCHET_INTERVAL_SECS: u64 = 30 * 60;
const DEFAULT_RATCHET_RETENTION: usize = 512;

#[derive(Copy, Clone)]
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

    pub fn as_name_hash_slice(&self) -> &[u8] {
        &self.hash.as_slice()[..NAME_HASH_LENGTH]
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

pub type DestinationAnnounce = Packet;

pub struct ValidatedAnnounce<'a> {
    pub destination: SingleOutputDestination,
    pub app_data: &'a [u8],
    pub ratchet: Option<[u8; PUBLIC_KEY_LENGTH]>,
}

impl DestinationAnnounce {
    pub fn validate<'a>(packet: &'a Packet) -> Result<ValidatedAnnounce<'a>, RnsError> {
        if packet.header.packet_type != PacketType::Announce {
            return Err(RnsError::PacketError);
        }

        let announce_data = packet.data.as_slice();
        let has_ratchet = packet.header.context_flag.is_set();
        let min_length = MIN_ANNOUNCE_DATA_LENGTH
            + if has_ratchet {
                RATCHET_PUBLIC_KEY_LENGTH
            } else {
                0
            };

        if announce_data.len() < min_length {
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
        let ratchet_slice = if has_ratchet {
            let slice = &announce_data[offset..(offset + RATCHET_PUBLIC_KEY_LENGTH)];
            offset += RATCHET_PUBLIC_KEY_LENGTH;
            Some(slice)
        } else {
            None
        };
        let signature = &announce_data[offset..(offset + SIGNATURE_LENGTH)];
        offset += SIGNATURE_LENGTH;
        let app_data = &announce_data[offset..];

        let destination = &packet.destination;

        let mut signed_data = PacketDataBuffer::new();
        signed_data
            .chain_write(destination.as_slice())?
            .chain_write(public_key.as_bytes())?
            .chain_write(verifying_key.as_bytes())?
            .chain_write(name_hash)?
            .chain_write(rand_hash)?;

        if let Some(ratchet) = ratchet_slice {
            signed_data.chain_write(ratchet)?;
        }

        signed_data.chain_write(app_data)?;

        let signed_data = signed_data.finalize();

        let signature = Signature::from_slice(signature).map_err(|_| RnsError::CryptoError)?;

        identity.verify(signed_data.as_slice(), &signature)?;

        Ok(ValidatedAnnounce {
            destination: SingleOutputDestination::new(
                identity,
                DestinationName::new_from_hash_slice(name_hash),
            ),
            app_data,
            ratchet: ratchet_slice.map(|bytes| {
                let mut key = [0u8; PUBLIC_KEY_LENGTH];
                key.copy_from_slice(bytes);
                key
            }),
        })
    }
}

pub struct Destination<I: HashIdentity, D: Direction, T: Type> {
    pub direction: PhantomData<D>,
    pub r#type: PhantomData<T>,
    pub identity: I,
    pub desc: DestinationDesc,
    ratchets_enabled: bool,
    ratchet_keys: Vec<StaticSecret>,
    ratchet_rotation_interval: Duration,
    ratchet_retention_limit: usize,
    ratchet_last_rotation: Option<Instant>,
    ratchet_enforce_only: bool,
    latest_ratchet_id: Option<RatchetId>,
    cached_ratchet_public: Option<[u8; PUBLIC_KEY_LENGTH]>,
}

impl<I: HashIdentity, D: Direction, T: Type> Destination<I, D, T> {
    pub fn destination_type(&self) -> packet::DestinationType {
        <T as Type>::destination_type()
    }

    fn new_with_desc(identity: I, desc: DestinationDesc) -> Self {
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            desc,
            ratchets_enabled: false,
            ratchet_keys: Vec::new(),
            ratchet_rotation_interval: Duration::from_secs(DEFAULT_RATCHET_INTERVAL_SECS),
            ratchet_retention_limit: DEFAULT_RATCHET_RETENTION,
            ratchet_last_rotation: None,
            ratchet_enforce_only: false,
            latest_ratchet_id: None,
            cached_ratchet_public: None,
        }
    }
}

pub enum DestinationHandleStatus {
    None,
    LinkProof,
}

impl Destination<PrivateIdentity, Input, Single> {
    pub fn new(identity: PrivateIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        let pub_identity = identity.as_identity().clone();

        Self::new_with_desc(
            identity,
            DestinationDesc {
                identity: pub_identity,
                name,
                address_hash,
            },
        )
    }

    pub fn announce<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        app_data: Option<&[u8]>,
    ) -> Result<Packet, RnsError> {
        let mut packet_data = PacketDataBuffer::new();

        let rand_hash = Hash::new_from_rand(rng);
        let rand_hash = &rand_hash.as_slice()[..RAND_HASH_LENGTH];
        let ratchet_bytes = self.active_ratchet_public(rng);

        let pub_key = self.identity.as_identity().public_key_bytes();
        let verifying_key = self.identity.as_identity().verifying_key_bytes();

        packet_data
            .chain_safe_write(self.desc.address_hash.as_slice())
            .chain_safe_write(pub_key)
            .chain_safe_write(verifying_key)
            .chain_safe_write(self.desc.name.as_name_hash_slice())
            .chain_safe_write(rand_hash);

        if let Some(ratchet) = ratchet_bytes.as_ref() {
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
            .chain_safe_write(rand_hash);

        if let Some(ratchet) = ratchet_bytes.as_ref() {
            packet_data.chain_safe_write(ratchet);
        }

        packet_data.chain_safe_write(&signature.to_bytes());

        if let Some(data) = app_data {
            packet_data.write(data)?;
        }

        let context_flag = if ratchet_bytes.is_some() {
            ContextFlag::Set
        } else {
            ContextFlag::Unset
        };

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data: packet_data,
        })
    }

    pub fn handle_packet(&mut self, packet: &Packet) -> DestinationHandleStatus {
        if self.desc.address_hash != packet.destination {
            return DestinationHandleStatus::None;
        }

        match packet.header.packet_type {
            PacketType::LinkRequest => {
                return DestinationHandleStatus::LinkProof;
            }
            _ => {}
        }

        DestinationHandleStatus::None
    }

    pub fn sign_key(&self) -> &SigningKey {
        self.identity.sign_key()
    }

    pub fn enable_ratchets<R: CryptoRngCore + Copy>(&mut self, rng: R) {
        self.ratchets_enabled = true;
        self.ratchet_keys.clear();
        self.ratchet_last_rotation = None;
        self.rotate_ratchets_if_needed(rng);
    }

    pub fn rotate_ratchets_if_needed<R: CryptoRngCore + Copy>(&mut self, rng: R) -> bool {
        if !self.ratchets_enabled {
            return false;
        }

        let needs_rotation = self
            .ratchet_last_rotation
            .map(|last| last.elapsed() >= self.ratchet_rotation_interval)
            .unwrap_or(true)
            || self.ratchet_keys.is_empty();

        if needs_rotation {
            self.insert_ratchet(rng);
            return true;
        }

        false
    }

    pub fn set_ratchet_interval(&mut self, interval: Duration) {
        if !interval.is_zero() {
            self.ratchet_rotation_interval = interval;
        }
    }

    pub fn set_ratchet_retention_limit(&mut self, limit: usize) {
        self.ratchet_retention_limit = limit.max(1);
        if self.ratchet_keys.len() > self.ratchet_retention_limit {
            self.ratchet_keys.truncate(self.ratchet_retention_limit);
        }
    }

    pub fn set_ratchet_enforcement(&mut self, enforce: bool) {
        self.ratchet_enforce_only = enforce;
    }

    pub fn ratchet_enforcement(&self) -> bool {
        self.ratchet_enforce_only
    }

    pub fn ratchets_enabled(&self) -> bool {
        self.ratchets_enabled
    }

    pub fn retained_ratchet_count(&self) -> usize {
        self.ratchet_keys.len()
    }

    pub fn latest_ratchet_id(&self) -> Option<RatchetId> {
        self.latest_ratchet_id
    }

    pub fn decrypt_payload<'a, R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        ciphertext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let ratchets = if self.ratchets_enabled {
            self.ratchet_keys.as_slice()
        } else {
            &[]
        };

        self.identity.decrypt_token(
            rng,
            ciphertext,
            Some(self.desc.address_hash.as_slice()),
            ratchets,
            self.ratchet_enforce_only,
            &mut self.latest_ratchet_id,
            out_buf,
        )
    }

    fn active_ratchet_public<R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
    ) -> Option<[u8; PUBLIC_KEY_LENGTH]> {
        if !self.ratchets_enabled {
            return None;
        }

        self.rotate_ratchets_if_needed(rng);
        self.ratchet_keys
            .first()
            .map(|secret| PublicKey::from(secret).to_bytes())
    }

    fn insert_ratchet<R: CryptoRngCore + Copy>(&mut self, rng: R) {
        self.ratchet_keys
            .insert(0, StaticSecret::random_from_rng(rng));
        self.ratchet_last_rotation = Some(Instant::now());

        if self.ratchet_keys.len() > self.ratchet_retention_limit {
            self.ratchet_keys.truncate(self.ratchet_retention_limit);
        }
    }
}

impl Destination<Identity, Output, Single> {
    pub fn new(identity: Identity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self::new_with_desc(
            identity,
            DestinationDesc {
                identity,
                name,
                address_hash,
            },
        )
    }

    pub fn remember_ratchet(&mut self, ratchet_public: [u8; PUBLIC_KEY_LENGTH]) {
        self.cached_ratchet_public = Some(ratchet_public);
    }

    pub fn clear_cached_ratchet(&mut self) {
        self.cached_ratchet_public = None;
    }

    pub fn encrypt_payload<'a, R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        plaintext: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let ratchet_public = self
            .cached_ratchet_public
            .map(|bytes| PublicKey::from(bytes));

        self.latest_ratchet_id = self
            .cached_ratchet_public
            .and_then(|bytes| ratchet_id_from_pub(&bytes[..]).ok());

        let target_public = ratchet_public.as_ref().unwrap_or(&self.identity.public_key);
        let derived = DerivedKey::new_from_ephemeral_key(
            rng,
            target_public,
            Some(self.desc.address_hash.as_slice()),
        );

        self.identity.encrypt(rng, plaintext, &derived, out_buf)
    }

    pub fn latest_ratchet_id(&self) -> Option<RatchetId> {
        self.latest_ratchet_id
    }
    pub fn create_packet<'a, R: CryptoRngCore + Copy>(
        &mut self,
        rng: R,
        payload: &[u8],
    ) -> Result<Packet, RnsError> {
        let mut out_buf = vec![0u8; payload.len() + 256];
        let cipher = self.encrypt_payload(rng, payload, &mut out_buf)?;

        let data = PacketDataBuffer::new_from_slice(cipher);

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: self.desc.address_hash,
            transport: None,
            context: PacketContext::None,
            data,
        })
    }
}

impl<D: Direction> Destination<EmptyIdentity, D, Plain> {
    pub fn new(identity: EmptyIdentity, name: DestinationName) -> Self {
        let address_hash = create_address_hash(&identity, &name);
        Self::new_with_desc(
            identity,
            DestinationDesc {
                identity: Default::default(),
                name,
                address_hash,
            },
        )
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

#[cfg(test)]
mod tests {
    use rand_core::OsRng;
    use std::time::{Duration, Instant};

    use crate::buffer::OutputBuffer;
    use crate::error::RnsError;
    use crate::hash::Hash;
    use crate::identity::{
        ratchet_id_from_pub, EncryptIdentity, PrivateIdentity, PUBLIC_KEY_LENGTH,
    };
    use crate::serde::Serialize;

    use super::DestinationAnnounce;
    use super::DestinationName;
    use super::{SingleInputDestination, SingleOutputDestination};
    use x25519_dalek::{PublicKey, StaticSecret};

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
    fn announce_includes_ratchet_when_enabled() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination =
            SingleInputDestination::new(identity, DestinationName::new("ratchet", "demo"));

        destination.enable_ratchets(OsRng);

        let packet = destination
            .announce(OsRng, None)
            .expect("announce should succeed");

        assert!(packet.header.context_flag.is_set());
        assert_eq!(destination.retained_ratchet_count(), 1);
    }

    #[test]
    fn ratchet_rotation_respects_retention_limit() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination =
            SingleInputDestination::new(identity, DestinationName::new("ratchet", "limit"));

        destination.enable_ratchets(OsRng);
        destination.set_ratchet_retention_limit(2);

        for _ in 0..4 {
            destination.ratchet_last_rotation = Some(
                Instant::now() - destination.ratchet_rotation_interval - Duration::from_secs(1),
            );
            destination.rotate_ratchets_if_needed(OsRng);
        }

        assert_eq!(destination.retained_ratchet_count(), 2);
    }

    #[test]
    fn ratchet_enforcement_blocks_identity_ciphertexts() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let mut destination =
            SingleInputDestination::new(identity, DestinationName::new("ratchet", "enforce"));

        let mut cipher_buf = [0u8; 256];
        let public_identity = destination.identity.as_identity().clone();
        let derived = public_identity.derive_key(OsRng);
        let ciphertext = public_identity
            .encrypt(OsRng, b"ratchet-test", &derived, &mut cipher_buf)
            .expect("ciphertext")
            .to_vec();

        let mut out_buf = [0u8; 256];
        destination.set_ratchet_enforcement(true);
        let enforced = destination.decrypt_payload(OsRng, &ciphertext, &mut out_buf);
        assert!(matches!(enforced, Err(RnsError::CryptoError)));

        destination.set_ratchet_enforcement(false);
        let plaintext = destination
            .decrypt_payload(OsRng, &ciphertext, &mut out_buf)
            .expect("decrypts without enforcement");
        assert_eq!(plaintext, b"ratchet-test");
    }

    #[test]
    fn single_output_prefers_cached_ratchet() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let public_identity = identity.as_identity().clone();
        let mut destination =
            SingleOutputDestination::new(public_identity, DestinationName::new("ratchet", "out"));

        let ratchet_secret = StaticSecret::random_from_rng(OsRng);
        let ratchet_public = PublicKey::from(&ratchet_secret).to_bytes();

        let mut out_buf = [0u8; 512];
        destination.remember_ratchet(ratchet_public);
        let ciphertext = destination
            .encrypt_payload(OsRng, b"hello", &mut out_buf)
            .expect("ciphertext");

        assert!(ciphertext.len() > PUBLIC_KEY_LENGTH);
        let expected_id = ratchet_id_from_pub(&ratchet_public[..]).expect("ratchet id");
        assert_eq!(destination.latest_ratchet_id, Some(expected_id));

        destination.clear_cached_ratchet();
        destination
            .encrypt_payload(OsRng, b"hello", &mut out_buf)
            .expect("ciphertext");
        assert!(destination.latest_ratchet_id.is_none());
    }
}
