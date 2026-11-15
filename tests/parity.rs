//! Ports of the Python Reticulum test-suite vectors
//! (`tests/hashes.py`, `tests/identity.py`, `tests/link.py` announce
//! validation) with byte-exact golden values.

use rand_core::OsRng;

use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::hash::{AddressHash, Hash};
use reticulum::identity::PrivateIdentity;

/// Fixed test identities from Python `tests/identity.py`
const FIXED_KEYS: &[(&str, &str)] = &[
    ("f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964cfb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7", "650b5d76b6bec0390d1f8cfca5bd33f9"),
    ("d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add650ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697", "1469e89450c361b253aefb0c606b6111"),
    ("8893e2bfd30fc08455997caf7abb7a6341716768dbbf9a91cc1455bd7eeaf74cdc10ec72a4d4179696040bac620ee97ebc861e2443e5270537ae766d91b58181", "e5fe93ee4acba095b3b9b6541515ed3e"),
    ("b82c7a4f047561d974de7e38538281d7f005d3663615f30d9663bad35a716063c931672cd452175d55bcdd70bb7aa35a9706872a97963dc52029938ea7341b39", "1333b911fa8ebb16726996adbe3c6262"),
    ("08bb35f92b06a0832991165a0d9b4fd91af7b7765ce4572aa6222070b11b767092b61b0fd18b3a59cae6deb9db6d4bfb1c7fcfe076cfd66eea7ddd5f877543b9", "d13712efc45ef87674fb5ac26c37c912"),
];

/// Signed message and known signature from key 0.
const SIGNED_MESSAGE: &str = "e51a008b8b8ba855993d8892a40daad84a6fb69a7138e1b5f69b427fe03449826ab6ccb81f0d72b4725e8d55c814d3e8e151b495cf5b59702f197ec366d935ad04a98ca519d6964f96ea09910b020351d1cdff3befbad323a2a28a6ec7ced4d0d67f02c525f93b321d9b076d704408475bd2d123cd51916f7e49039246ac56add37ef87e32d7f9853ac44a7f77d26fedc83e4e67a45742b751c2599309f5eda6efa0dafd957f61af1f0e86c4d6c5052e0e5fa577db99846f2b7a0204c31cef4013ca51cb307506c9209fd18d0195a7c9ae628af1a1d9ee7a4cf30037ed190a9fdcaa4ce5bb7bea19803cb5b5cea8c21fdb98d8f73ff5aaad87f5f6c3b7bcfe8974e5b063cc1113d77b9e96bec1c9d10ed37b780c3f7349a34092bb3968daeced40eb0b5130c0d11595e30b9671896385d04289d067f671599386536eed8430a72e186fb95023d5ac5dd442443bfabfe13a84a38d060af73bf20f921f38a768672fdbcb1dfece7458166e2e15948d6b4fa81f42db48747d283c670f576a0b410b31a70d2594823d0e29135a488cb0408c9e5bc1e197ff99aef471924231ccc8e3eddc82dbcea4801f14c5fc7a389a26a52cc93cfe0770953ef595ff410b7033a6ed5c975dd922b3f48f9dffcfb412eeed5758f3aa51de7eb47cd2cb";
const SIG_FROM_KEY_0: &str = "3020ef58f861591826a61c3d2d4a25b949cdb3094085ba6b1177a6f2a05f3cdd24d1095d6fdd078f0b2826e80b261c93c1ff97fbfd4857f25706d57dd073590c";

// ------------------------------------------------------------------
// tests/hashes.py — SHA-256 known-answer vectors
// ------------------------------------------------------------------

#[test]
fn sha256_empty() {
    let digest = Hash::new_from_slice(b"");
    assert_eq!(
        hex(digest.as_slice()),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_less_than_block_length() {
    let digest = Hash::new_from_slice(b"abc");
    assert_eq!(
        hex(digest.as_slice()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_block_length() {
    let digest = Hash::new_from_slice(&[b'a'; 64]);
    assert_eq!(
        hex(digest.as_slice()),
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    );
}

#[test]
fn sha256_several_blocks() {
    let digest = Hash::new_from_slice(&vec![b'a'; 1_000_000]);
    assert_eq!(
        hex(digest.as_slice()),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

// ------------------------------------------------------------------
// tests/identity.py
// ------------------------------------------------------------------

/// Python `test_0_create_from_bytes`: identity hash derivation from the
/// fixed private keys.
#[test]
fn identity_create_from_bytes() {
    for (key, id_hash) in FIXED_KEYS {
        let identity = PrivateIdentity::new_from_hex_string(key).expect("valid key");
        assert_eq!(
            hex(identity.address_hash().as_slice()),
            *id_hash,
            "identity hash mismatch for key {key}"
        );
    }
}

/// Python `test_1_sign`: known signature for `SIGNED_MESSAGE` by key 0.
#[test]
fn identity_sign_known_signature() {
    // Python signs the *UTF-8 bytes of the hex string itself*
    // (`fid.sign(signed_message.encode("utf-8"))`), not the decoded bytes.
    let identity = PrivateIdentity::new_from_hex_string(FIXED_KEYS[0].0).unwrap();
    let signature = identity.sign(SIGNED_MESSAGE.as_bytes());
    assert_eq!(hex(&signature.to_bytes()), SIG_FROM_KEY_0);
}

/// Sign/validate round trips with fresh identities.
#[test]
fn identity_sign_validate() {
    for len in [128usize, 250, 383, 431, 512, 1024, 8192] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 253) as u8).collect();
        let signer = PrivateIdentity::new_from_rand(OsRng);
        let verifier = *signer.as_identity();
        let signature = signer.sign(&msg);
        assert!(verifier.verify(&msg, &signature).is_ok());

        // corrupting the message must fail validation
        let mut corrupted = msg.clone();
        corrupted[0] ^= 1;
        assert!(verifier.verify(&corrupted, &signature).is_err());
    }
}

// ------------------------------------------------------------------
// tests/link.py — announce validation
// ------------------------------------------------------------------

/// Python `test_00_valid_announce`.
#[test]
fn valid_announce() {
    let identity = PrivateIdentity::new_from_hex_string(FIXED_KEYS[3].0).expect("valid key");
    let mut destination =
        SingleInputDestination::new(identity, DestinationName::new("test", "announce"));

    let announce = destination
        .announce(OsRng, None)
        .expect("valid announce packet");

    reticulum::destination::DestinationAnnounce::validate(&announce)
        .expect("announce must validate");
}

/// Python `test_01_invalid_announce`: tampering with the destination hash
/// invalidates the announce.
#[test]
fn invalid_announce() {
    let identity = PrivateIdentity::new_from_hex_string(FIXED_KEYS[4].0).expect("valid key");
    let mut destination =
        SingleInputDestination::new(identity, DestinationName::new("test", "announce"));

    let mut announce = destination
        .announce(OsRng, None)
        .expect("valid announce packet");

    // Replace the announced public key prefix (mimics Python's data swap)
    // with a different identity's bytes, keeping length identical.
    let fake = PrivateIdentity::new_from_hex_string(FIXED_KEYS[0].0).unwrap();
    let mut data = announce.data.as_slice().to_vec();
    let fake_bytes = fake.as_identity().public_key_bytes();
    data[..32].copy_from_slice(fake_bytes);
    announce.data = reticulum::packet::PacketDataBuffer::new_from_slice(&data);

    let result = reticulum::destination::DestinationAnnounce::validate(&announce);
    assert!(result.is_err(), "tampered announce must not validate");
}

/// Fixed destination hashes from Python `test_02_establish`:
/// `Identity.from_bytes(fixed_keys[0])` with the app name
/// "rns_unit_tests", aspects "link", "establish" must produce this hash.
#[test]
fn fixed_destination_hash() {
    let identity = PrivateIdentity::new_from_hex_string(FIXED_KEYS[0].0).unwrap();
    assert_eq!(hex(identity.address_hash().as_slice()), FIXED_KEYS[0].1);

    let destination = reticulum::destination::SingleOutputDestination::new(
        *identity.as_identity(),
        DestinationName::new("rns_unit_tests", "link.establish"),
    );
    assert_eq!(
        hex(destination.desc.address_hash.as_slice()),
        "fb48da0e82e6e01ba0c014513f74540d"
    );
}

/// `AddressHash::new_from_hex_string` must never hash its input.
#[test]
fn address_hash_from_hex_is_raw() {
    let raw = "0123456789abcdef0123456789abcdef";
    let hash = AddressHash::new_from_hex_string(raw).unwrap();
    assert_eq!(hex(hash.as_slice()), raw);
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
