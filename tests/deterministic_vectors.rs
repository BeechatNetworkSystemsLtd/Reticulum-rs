use rand_core::{CryptoRng, RngCore};
use rand_core::OsRng;
use std::sync::{Mutex, OnceLock};
use reticulum::destination::{DestinationAnnounce, DestinationName, SingleInputDestination, SingleOutputDestination};
use reticulum::identity::{ratchet_id_from_pub, EncryptIdentity, PrivateIdentity};
use reticulum::packet::Packet;
use reticulum::testing::deterministic as det;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(feature = "python-interop")]
mod python_support;
#[cfg(feature = "python-interop")]
use python_support::{python_available, run_python};

const IDENTITY_EPHEMERAL_SECRET: [u8; 32] = [
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
];
const IDENTITY_FERNET_IV: [u8; 16] = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20,
    0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
];
const IDENTITY_EXPECTED_CIPHER_HEX: &str = "4d27bcee3135c4944b28d27dd809b07be10c35160d20131caa7e85575498d07caabbccddeeff102030405060708090a0409424fab8d1f324d4b68341fbf4712b778d03967a91536c768f87d249612273dc3f2bc23cabb23ea58e6c3218894f801bc731216ff618aeec117bf3df89bbb5";
const IDENTITY_PLAINTEXT: &[u8] = b"deterministic-identity-vector";

const RATCHET_SECRET_BYTES: [u8; 32] = [
    0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
    0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
    0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63,
];
const RATCHET_EPHEMERAL_SECRET: [u8; 32] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
];
const RATCHET_FERNET_IV: [u8; 16] = [
    0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a,
    0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa,
];
const RATCHET_EXPECTED_CIPHER_HEX: &str = "5f09b7f97a40b50220697064b43b27411b07a4aa1fe05370b27519826983d30d0a1a2a3a4a5a6a7a8a9aaabacadaeafa60c57c14ba69caa31afde255adca1cde48766c76db4915c17d67ce8f1332042778adecb2e1c202742c58d0a398d9e6066548b347e78c07f9048502d3a13a7055";
const RATCHET_PLAINTEXT: &[u8] = b"ratchet-vector-payload";

const ANNOUNCE_EXPECTED_DEST_HEX: &str = "3e4243ca9bb80ce5fac1730347c0193b";
const ANNOUNCE_EXPECTED_DATA_HEX: &str = "f26ebf86e8b095dc443ef7973d92b153fa9f40a2cdefd3c10521a7f827c73622628c989cd9765f8f9d3c91c17e4f9248bfc59683442b8098de8f0c1d9c88b847252de62590095945919eabfdf7347d6d84c0d2706ebb5d1192d5dd854145b060876fec2a9fdad1fa93dc0fec547f3a3d6583d24084f4dd691e8a81cc333e51a1fb3fd02492fd628615bbb1631efe549d4a89565c712998e84bf8a98b659db3b12586dab46dfc6e4d4bf92833c7fac7ed9b977b04616e6e";

#[test]
fn deterministic_identity_vector_matches_reference() {
    let _guard = test_lock();
    det::clear();
    det::set_next_ephemeral_secret(IDENTITY_EPHEMERAL_SECRET);
    det::set_next_fernet_iv(IDENTITY_FERNET_IV);

    let recipient = PrivateIdentity::new_from_name("vector-identity");
    let identity = recipient.as_identity().clone();
    let derived = identity.derive_key(OsRng);

    det::set_next_fernet_iv(IDENTITY_FERNET_IV);
    let mut out_buf = vec![0u8; 512];
    let cipher = identity
        .encrypt(OsRng, IDENTITY_PLAINTEXT, &derived, &mut out_buf)
        .expect("ciphertext");

    let cipher_hex = hex::encode(cipher);
    maybe_print("identity", &cipher_hex);
    if IDENTITY_EXPECTED_CIPHER_HEX == "__FILL_IDENTITY__" {
        panic!("set IDENTITY_EXPECTED_CIPHER_HEX to {cipher_hex}");
    }
    assert_eq!(cipher_hex, IDENTITY_EXPECTED_CIPHER_HEX);
}

#[test]
fn deterministic_ratchet_vector_matches_reference() {
    let _guard = test_lock();
    det::clear();
    det::set_next_ephemeral_secret(RATCHET_EPHEMERAL_SECRET);
    det::set_next_fernet_iv(RATCHET_FERNET_IV);

    let sender = PrivateIdentity::new_from_name("vector-ratchet");
    let identity = sender.as_identity().clone();
    let mut destination = SingleOutputDestination::new(
        identity,
        DestinationName::new("vectors", "out"),
    );

    let ratchet_secret = StaticSecret::from(RATCHET_SECRET_BYTES);
    let ratchet_public = PublicKey::from(&ratchet_secret).to_bytes();
    let expected_ratchet = ratchet_id_from_pub(&ratchet_public[..]).expect("ratchet id");

    let mut out_buf = vec![0u8; 512];
    let cipher = destination
        .encrypt_payload(
            OsRng,
            RATCHET_PLAINTEXT,
            Some(&ratchet_public),
            &mut out_buf,
        )
        .expect("ciphertext");

    assert_eq!(destination.latest_ratchet_id(), Some(expected_ratchet));

    let cipher_hex = hex::encode(cipher);
    maybe_print("ratchet", &cipher_hex);
    if RATCHET_EXPECTED_CIPHER_HEX == "__FILL_RATCHET__" {
        panic!("set RATCHET_EXPECTED_CIPHER_HEX to {cipher_hex}");
    }
    assert_eq!(cipher_hex, RATCHET_EXPECTED_CIPHER_HEX);
}

#[test]
fn ratchet_enforcement_vector_matches_reference() {
    let _guard = test_lock();
    let ciphertext = hex::decode(IDENTITY_EXPECTED_CIPHER_HEX).expect("identity cipher hex");

    let identity = PrivateIdentity::new_from_name("vector-identity");
    let mut destination = SingleInputDestination::new(
        identity,
        DestinationName::new("vectors", "in"),
    );
    destination.enable_ratchets(OsRng);
    destination.set_ratchet_enforcement(true);

    let mut out_buf = vec![0u8; 512];
    let decrypt = destination.decrypt_payload(OsRng, &ciphertext, &mut out_buf);
    assert!(decrypt.is_err(), "ratchet enforcement must reject identity ciphertext");
}

#[test]
fn announce_with_ratchet_vector_matches_reference() {
    let _guard = test_lock();
    let vector_packet = build_reference_announce();
    let data_hex = hex::encode(vector_packet.data.as_slice());
    let dest_hex = hex::encode(vector_packet.destination.as_slice());

    maybe_print("announce_dest", &dest_hex);
    maybe_print("announce_data", &data_hex);

    if ANNOUNCE_EXPECTED_DATA_HEX == "__FILL_ANNOUNCE__" {
        panic!("set ANNOUNCE_EXPECTED_DATA_HEX to {data_hex}");
    }
    if ANNOUNCE_EXPECTED_DEST_HEX == "__FILL_DEST__" {
        panic!("set ANNOUNCE_EXPECTED_DEST_HEX to {dest_hex}");
    }
    assert_eq!(data_hex, ANNOUNCE_EXPECTED_DATA_HEX);
    assert_eq!(dest_hex, ANNOUNCE_EXPECTED_DEST_HEX);

    let validated = DestinationAnnounce::validate(&vector_packet).expect("valid vector");
    assert!(validated.ratchet.is_some(), "vector must include ratchet");
}

fn build_reference_announce() -> Packet {
    let identity = PrivateIdentity::new_from_name("vector-announce");
    let mut destination = SingleInputDestination::new(
        identity,
        DestinationName::new("vectors", "announce"),
    );
    destination.enable_ratchets(DeterministicRng::new(0x0102_0304_0506_0708));

    destination
        .announce(DeterministicRng::new(0x0f0e_0d0c_0b0a_0908), Some(b"ann"))
        .expect("vector announce")
}

fn maybe_print(label: &str, hex_value: &str) {
    if std::env::var("PRINT_VECTORS").is_ok() {
        eprintln!("{}={}", label, hex_value);
    }
}

#[derive(Clone, Copy)]
struct DeterministicRng {
    state: u128,
}

impl DeterministicRng {
    const fn new(seed: u128) -> Self {
        Self { state: seed }
    }

    fn next_u64_inner(&mut self) -> u64 {
        const MUL: u128 = 6364136223846793005;
        const INC: u128 = 1442695040888963407;
        self.state = self.state.wrapping_mul(MUL).wrapping_add(INC);
        (self.state >> 64) as u64
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64_inner() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next_u64_inner()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let value = self.next_u64_inner();
            let bytes = value.to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&bytes[..len]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

#[cfg(feature = "python-interop")]
#[test]
fn python_decrypts_identity_vector() {
    let _guard = test_lock();
    if !python_available() {
        eprintln!("python RNS not available; skipping deterministic vector check");
        return;
    }

    let identity = PrivateIdentity::new_from_name("vector-identity");
    let priv_hex = identity.to_hex_string();
    let (code, plaintext_hex, stderr) = run_python(&[
        "tests/python/decrypt.py",
        &priv_hex,
        IDENTITY_EXPECTED_CIPHER_HEX,
    ]);

    assert_eq!(code, 0, "python decrypt failed: {stderr}");
    let plaintext = hex::decode(plaintext_hex).expect("python plaintext hex");
    assert_eq!(plaintext.as_slice(), IDENTITY_PLAINTEXT);
}
