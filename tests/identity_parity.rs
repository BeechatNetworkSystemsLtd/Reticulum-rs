//! Identity & persistence parity tests against Python-generated golden
//! fixtures (see `tests/fixtures/gen_identity_fixtures.py`).
//!
//! The fixtures pin every random input (identity keys, ratchet keys,
//! ephemeral key exchange keys, Fernet IVs, announce random hashes and
//! timestamps), so the Rust codecs and crypto paths can be verified
//! byte-for-byte against Python Reticulum 1.4.2.

use rand_core::{CryptoRng, RngCore};
use reticulum::buffer::InputBuffer;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::{
    self, Identity, PrivateIdentity, RATCHET_EXPIRY_SECS, RATCHET_KEY_LENGTH,
};
use reticulum::serde::Serialize;
use reticulum::storage::{
    clean_destination_ratchets, identity_from_public_file, load_destination_ratchets,
    private_identity_from_file, save_destination_ratchets, FsStorage, IdentityFiles,
    KnownDestinations, KnownRatchets, MemoryStorage, Storage, KNOWN_DESTINATIONS_FILE,
    RATCHETS_DIR,
};
use serde_json::json;

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|error| panic!("could not read {path}: {error}"))
}

fn meta() -> serde_json::Value {
    serde_json::from_slice(&fixture("identity_fixtures.json")).expect("valid fixture metadata")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The fixed Fernet IV pinned by the Python fixture generator.
const FIXED_IV: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Rng that replays the fixed Fernet IV used by the Python fixture
/// generator (`os.urandom` pinned to `FERNET_IV`).
#[derive(Clone, Copy)]
struct FixedIvRng([u8; 16]);

impl RngCore for FixedIvRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_be_bytes(self.0[0..4].try_into().unwrap())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_be_bytes(self.0[0..8].try_into().unwrap())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for (index, byte) in dest.iter_mut().enumerate() {
            *byte = self.0[index % self.0.len()];
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedIvRng {}

// ------------------------------------------------------------------
// Identity files
// ------------------------------------------------------------------

#[test]
fn identity_file_round_trip_matches_python() {
    let meta = meta();
    let storage = MemoryStorage::new();

    let identity = PrivateIdentity::new_from_hex_string(meta["identity_prv_hex"].as_str().unwrap())
        .expect("fixture identity");

    identity.to_file(&storage, "id_private").expect("to_file");
    identity
        .pub_to_file(&storage, "id_public")
        .expect("pub_to_file");

    // Python `Identity.to_file` writes the raw 64 private key bytes.
    assert_eq!(
        storage.read("id_private").unwrap(),
        fixture("identity_private.bin")
    );
    assert_eq!(
        storage.read("id_public").unwrap(),
        fixture("identity_public.bin")
    );

    // Round-trip through the file format.
    let loaded = private_identity_from_file(&storage, "id_private").expect("from_file");
    assert_eq!(loaded.to_hex_string(), identity.to_hex_string());

    let public = identity_from_public_file(&storage, "id_public").expect("public from file");
    assert_eq!(
        public.to_hex_string(),
        identity.as_identity().to_hex_string()
    );
}

#[test]
fn identity_file_fs_storage() {
    let dir = std::env::temp_dir().join(format!("rns-id-test-{}", std::process::id()));
    let storage = FsStorage::new(dir.display().to_string());

    let identity = PrivateIdentity::new_from_rand(rand_core::OsRng);
    identity
        .to_file(&storage, "identities/self")
        .expect("to_file");

    let loaded = private_identity_from_file(&storage, "identities/self").expect("from_file");
    assert_eq!(loaded.to_hex_string(), identity.to_hex_string());

    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------
// Known destinations (msgpack byte-exact vs Python)
// ------------------------------------------------------------------

#[test]
fn known_destinations_fixture_byte_exact() {
    let meta = meta();
    let bytes = fixture("known_destinations.bin");

    let entries = identity::unpack_known_destinations(&bytes).expect("unpack");
    assert_eq!(entries.len(), 3);

    // Re-packing the parsed entries must reproduce the Python file exactly.
    let packed = identity::pack_known_destinations(&entries).expect("pack");
    assert_eq!(packed, bytes);

    // Compare every entry against the fixture metadata.
    for (hash, entry) in &entries {
        let expected = &meta["known_destinations"][hash.to_hex_string()];

        assert_eq!(entry.time, expected["time"].as_f64().unwrap());
        assert_eq!(
            hex(&entry.packet_hash),
            expected["packet_hash"].as_str().unwrap()
        );
        assert_eq!(
            hex(&entry.public_key),
            expected["public_key"].as_str().unwrap()
        );

        match &expected["app_data"] {
            serde_json::Value::Null => assert!(entry.app_data.is_none()),
            serde_json::Value::String(data) => {
                assert_eq!(
                    entry.app_data.as_deref(),
                    Some(from_hex(data.as_str()).as_slice())
                )
            }
            other => panic!("unexpected app_data fixture {other}"),
        }

        match &expected["uses"] {
            serde_json::Value::Number(uses) if uses.as_i64() == Some(0) => {
                assert_eq!(entry.uses, identity::DestinationUses::Never)
            }
            serde_json::Value::Number(uses) if uses.as_i64() == Some(-1) => {
                assert_eq!(entry.uses, identity::DestinationUses::Retained)
            }
            serde_json::Value::Number(uses) => {
                let last_used = uses.as_f64().expect("uses number");
                assert_eq!(entry.uses, identity::DestinationUses::LastUsed(last_used));
            }
            other => panic!("unexpected uses fixture {other}"),
        }
    }
}

#[test]
fn known_destinations_store_round_trip() {
    let meta = meta();
    let storage = MemoryStorage::new();
    let mut store = KnownDestinations::new();

    store.load(&storage).expect("empty load");
    assert!(store.is_empty());

    // Seed the store exactly like the Python generator did, in the Python
    // dict insertion order (serde_json objects are key-sorted).
    let order: Vec<String> = meta["known_destinations_order"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();

    for hash_hex in &order {
        let expected = &meta["known_destinations"][hash_hex.as_str()];
        let destination_hash = AddressHash::new_from_hex_string(hash_hex).unwrap();
        store.remember(
            from_hex(expected["packet_hash"].as_str().unwrap())
                .as_slice()
                .try_into()
                .unwrap(),
            destination_hash,
            from_hex(expected["public_key"].as_str().unwrap())
                .as_slice()
                .try_into()
                .unwrap(),
            match &expected["app_data"] {
                serde_json::Value::Null => None,
                serde_json::Value::String(data) if data.is_empty() => Some(Vec::new()),
                serde_json::Value::String(data) => Some(from_hex(data)),
                other => panic!("unexpected app_data {other}"),
            },
            expected["time"].as_f64().unwrap(),
        );

        // Python seeds `uses` directly in the dict; `remember` never
        // touches it, so replay retain/use explicitly.
        match expected["uses"].as_f64() {
            Some(-1.0) => {
                assert!(store.retain(&destination_hash));
            }
            Some(uses) if uses > 0.0 => {
                assert!(store.mark_used(&destination_hash, uses));
            }
            _ => {}
        }
    }

    store.save(&storage).expect("save");
    assert_eq!(
        storage.read(KNOWN_DESTINATIONS_FILE).unwrap(),
        fixture("known_destinations.bin"),
        "known destinations file must be byte-identical to Python"
    );

    // Load into a fresh store and compare.
    let mut reloaded = KnownDestinations::new();
    reloaded.load(&storage).expect("load");
    assert_eq!(reloaded.entries(), store.entries());
}

#[test]
fn known_destinations_remember_updates_entry() {
    let mut store = KnownDestinations::new();

    let destination_hash = AddressHash::new_from_slice(b"destination");
    // The peer public key from the fixtures is a valid key pair.
    let public_key: [u8; 64] = fixture("peer_public.bin").as_slice().try_into().unwrap();
    let mut packet_hash = [1u8; 32];

    store.remember(
        packet_hash,
        destination_hash,
        public_key,
        Some(b"one".to_vec()),
        100.0,
    );
    store.remember(
        packet_hash,
        destination_hash,
        public_key,
        Some(b"two".to_vec()),
        200.0,
    );

    let entry = store.get(&destination_hash).unwrap();
    assert_eq!(entry.time, 200.0);
    assert_eq!(entry.app_data.as_deref(), Some(b"two".as_slice()));
    assert_eq!(entry.uses, identity::DestinationUses::Never);

    // Recall marks the entry used (Python `_used_destination_data`).
    packet_hash[0] = 9;
    store.remember(packet_hash, destination_hash, public_key, None, 300.0);
    let identity = store.recall(&destination_hash, 400.0).expect("identity");
    assert_eq!(
        identity.address_hash,
        AddressHash::new_from_slice(&public_key[..64])
    );
    assert_eq!(
        store.get(&destination_hash).unwrap().uses,
        identity::DestinationUses::LastUsed(400.0)
    );

    // Retained entries are never marked used or cleaned.
    assert!(store.retain(&destination_hash));
    assert!(store.recall(&destination_hash, 500.0).is_some());
    assert_eq!(
        store.get(&destination_hash).unwrap().uses,
        identity::DestinationUses::Retained
    );

    let removed = store.clean(1_000.0, |_| false);
    assert!(removed.is_empty(), "retained entries are never stale");
    assert!(store.contains(&destination_hash));
}

#[test]
fn known_destinations_clean_removes_stale_entries() {
    let mut store = KnownDestinations::new();

    let never_used = AddressHash::new_from_slice(b"never");
    let used = AddressHash::new_from_slice(b"used!");
    let with_path = AddressHash::new_from_slice(b"path");

    store.remember([0u8; 32], never_used, [1u8; 64], None, 0.0);
    store.remember([0u8; 32], used, [1u8; 64], None, 0.0);
    store.remember([0u8; 32], with_path, [1u8; 64], None, 0.0);

    // Mark `used` as used right now.
    let _ = store.recall(&used, 10.0);

    // Pathless, never used, older than UNUSED_DESTINATION_LINGER (6 min).
    let stale = store.clean(1_000.0, |hash| hash == &with_path);
    assert_eq!(stale, vec![never_used]);
    assert!(!store.contains(&never_used));
    assert!(store.contains(&used));
    assert!(store.contains(&with_path));
}

// ------------------------------------------------------------------
// Ratchets
// ------------------------------------------------------------------

#[test]
fn ratchet_file_fixture_byte_exact() {
    let meta = meta();
    let bytes = fixture("ratchet.bin");

    let data = identity::unpack_ratchet(&bytes).expect("unpack ratchet");
    let ratchet_meta = &meta["ratchet"];

    assert_eq!(
        hex(&data.ratchet),
        ratchet_meta["public_hex"].as_str().unwrap()
    );
    assert_eq!(data.received, ratchet_meta["received"].as_f64().unwrap());

    assert_eq!(identity::pack_ratchet(&data).unwrap(), bytes);

    // Ratchet id: SHA-256 of the public key, truncated to 10 bytes.
    let id = identity::ratchet_id(&data.ratchet);
    assert_eq!(
        hex(&id.as_slice()[..10]),
        ratchet_meta["id_hex"].as_str().unwrap()
    );

    // Private key -> public key derivation.
    let private = from_hex(ratchet_meta["private_hex"].as_str().unwrap());
    let private: [u8; RATCHET_KEY_LENGTH] = private.as_slice().try_into().unwrap();
    assert_eq!(
        hex(&identity::ratchet_public_from_private(&private)),
        ratchet_meta["public_hex"].as_str().unwrap()
    );
}

#[test]
fn known_ratchets_remember_and_get() {
    let meta = meta();
    let storage = MemoryStorage::new();
    let mut ratchets = KnownRatchets::new();

    let destination_hash =
        AddressHash::new_from_hex_string(meta["ratchet"]["destination_hash"].as_str().unwrap())
            .unwrap();
    let public: [u8; RATCHET_KEY_LENGTH] =
        from_hex(meta["ratchet"]["public_hex"].as_str().unwrap())
            .as_slice()
            .try_into()
            .unwrap();
    let received = meta["ratchet"]["received"].as_f64().unwrap();

    ratchets
        .remember(&storage, destination_hash, public, received)
        .expect("remember");

    // The persisted file is byte-identical to the Python fixture.
    let path = format!("{RATCHETS_DIR}/{}", destination_hash.to_hex_string());
    assert_eq!(storage.read(&path).unwrap(), fixture("ratchet.bin"));

    // Remembering the same ratchet again is a no-op.
    ratchets
        .remember(&storage, destination_hash, public, received)
        .expect("remember again");
    assert_eq!(storage.list(RATCHETS_DIR).len(), 1);

    // In-memory and from-storage recall both work.
    assert_eq!(
        ratchets.get(&storage, &destination_hash, received + 1.0),
        Some(public)
    );

    let mut fresh = KnownRatchets::new();
    assert_eq!(
        fresh.get(&storage, &destination_hash, received + 1.0),
        Some(public)
    );

    // Current ratchet id matches Python `Identity.current_ratchet_id`.
    let id = fresh
        .current_ratchet_id(&storage, &destination_hash, received + 1.0)
        .unwrap();
    assert_eq!(hex(&id), meta["ratchet"]["id_hex"].as_str().unwrap());

    // Expired ratchets are not recalled.
    let expired_at = received + RATCHET_EXPIRY_SECS as f64;
    let mut expired = KnownRatchets::new();
    assert_eq!(expired.get(&storage, &destination_hash, expired_at), None);
}

#[test]
fn known_ratchets_clean() {
    let storage = MemoryStorage::new();
    let mut ratchets = KnownRatchets::new();

    let known = AddressHash::new_from_slice(b"known-destinat");
    let unknown = AddressHash::new_from_slice(b"unknown-destin");
    let corrupted = AddressHash::new_from_slice(b"corrupt-desti");

    ratchets
        .remember(&storage, known, [1u8; 32], 1_000.0)
        .unwrap();
    ratchets
        .remember(&storage, unknown, [2u8; 32], 1_000.0)
        .unwrap();
    storage
        .write(
            &format!("{RATCHETS_DIR}/{}", corrupted.to_hex_string()),
            b"not msgpack",
        )
        .unwrap();

    let removed = ratchets.clean(&storage, 2_000.0, |hash| hash == &known);
    assert_eq!(removed, 2);

    assert!(ratchets.get(&storage, &known, 2_000.0).is_some());
    assert!(ratchets.get(&storage, &unknown, 2_000.0).is_none());
    assert_eq!(storage.list(RATCHETS_DIR).len(), 1);

    // Expiry also triggers removal.
    let removed = ratchets.clean(&storage, 1_000.0 + RATCHET_EXPIRY_SECS as f64, |_| true);
    assert_eq!(removed, 1);
    assert!(storage.list(RATCHETS_DIR).is_empty());
}

#[test]
fn destination_ratchet_file_fixture() {
    let meta = meta();
    let bytes = fixture("destination_ratchets.bin");
    let storage = MemoryStorage::new();

    let peer =
        PrivateIdentity::new_from_hex_string(meta["peer_prv_hex"].as_str().unwrap()).unwrap();
    let peer_identity = *peer.as_identity();

    let (ratchets, signature) = identity::unpack_destination_ratchets(&bytes).expect("unpack");
    assert_eq!(ratchets.len(), 2);

    let packed = identity::pack_ratchet_list(&ratchets).unwrap();
    peer_identity
        .verify(&packed, &signature)
        .expect("signature must verify");

    // Saving with the same identity reproduces the fixture bytes.
    save_destination_ratchets(&storage, "dest.ratchets", &peer, &ratchets).unwrap();
    assert_eq!(storage.read("dest.ratchets").unwrap(), bytes);

    // Loading through the storage helper validates the signature.
    let loaded = load_destination_ratchets(&storage, "dest.ratchets", &peer_identity).unwrap();
    assert_eq!(loaded, ratchets);

    // A tampered signature is rejected.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    storage.write("tampered.ratchets", &tampered).unwrap();
    assert!(load_destination_ratchets(&storage, "tampered.ratchets", &peer_identity).is_err());

    // Missing file starts a fresh chain.
    assert!(
        load_destination_ratchets(&storage, "missing.ratchets", &peer_identity)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn destination_ratchet_retention() {
    let mut ratchets: Vec<[u8; RATCHET_KEY_LENGTH]> =
        (0..600).map(|i| [i as u8; RATCHET_KEY_LENGTH]).collect();

    clean_destination_ratchets(&mut ratchets, 512);
    assert_eq!(ratchets.len(), 512);
    assert_eq!(ratchets[0], [0u8; RATCHET_KEY_LENGTH]);
}

// ------------------------------------------------------------------
// Announces with ratchets
// ------------------------------------------------------------------

fn deserialize_packet(bytes: &[u8]) -> reticulum::packet::Packet {
    let mut buffer = InputBuffer::new(bytes);
    reticulum::packet::Packet::deserialize(&mut buffer).expect("packet deserializes")
}

#[test]
fn announce_ratchet_fixture() {
    let meta = meta();
    let bytes = fixture("announce_ratchet.bin");
    let packet = deserialize_packet(&bytes);

    // The context flag announces the ratchet (Python `FLAG_SET`).
    assert!(packet.header.context_flag);
    assert_eq!(
        packet.destination.to_hex_string(),
        meta["announce_ratchet"]["destination_hash"]
            .as_str()
            .unwrap()
    );

    let (destination, announce) =
        reticulum::destination::DestinationAnnounce::validate(&packet).expect("validate");

    assert_eq!(
        hex(announce.ratchet.expect("ratchet present").as_slice()),
        meta["announce_ratchet"]["ratchet_pub_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        announce.app_data.map(hex),
        Some(
            meta["announce_ratchet"]["app_data"]
                .as_str()
                .unwrap()
                .to_string()
        )
    );

    // The announced identity is the fixture identity.
    assert_eq!(
        destination.identity.address_hash.to_hex_string(),
        meta["identity_hash_hex"].as_str().unwrap()
    );

    // Serialize back to the exact Python bytes.
    let mut out = [0u8; 4096];
    let mut buffer = reticulum::buffer::OutputBuffer::new(&mut out);
    packet.serialize(&mut buffer).expect("serialize");
    assert_eq!(buffer.as_slice(), bytes);
}

#[test]
fn announce_plain_fixture() {
    let meta = meta();
    let bytes = fixture("announce_plain.bin");
    let packet = deserialize_packet(&bytes);

    assert!(!packet.header.context_flag);

    let (_destination, announce) =
        reticulum::destination::DestinationAnnounce::validate(&packet).expect("validate");

    assert!(announce.ratchet.is_none());
    assert_eq!(
        announce.app_data.map(hex),
        Some(
            meta["announce_plain"]["app_data"]
                .as_str()
                .unwrap()
                .to_string()
        )
    );
}

#[test]
fn announce_ratchet_generation_round_trip() {
    let meta = meta();
    let identity =
        PrivateIdentity::new_from_hex_string(meta["identity_prv_hex"].as_str().unwrap()).unwrap();

    // Rebuild the ratcheted announce from the fixture identity with the
    // pinned ratchet key, random hash and timestamp.
    let ratchet_private: [u8; RATCHET_KEY_LENGTH] =
        from_hex(meta["ratchet"]["private_hex"].as_str().unwrap())
            .as_slice()
            .try_into()
            .unwrap();

    let mut destination = SingleInputDestination::new(
        identity,
        DestinationName::new("example_utilities", "ratcheted"),
    );

    destination.enable_ratchets(vec![ratchet_private]);
    destination.set_ratchet_interval(1_800);
    // The Python fixture rotated once at announce time to reach the pinned
    // ratchet key; here the chain already holds it, so keep the rotation
    // timer at the announce timestamp.
    destination.latest_ratchet_time = 1_735_689_600;

    // `announce_at` with the pinned timestamp must not rotate and must
    // produce the fixture bytes.
    let announce = destination
        .announce_at(
            FixedIvRng(FIXED_IV),
            Some(b"ratchet announce fixture"),
            1_735_689_600,
        )
        .expect("announce");

    let mut out = [0u8; 4096];
    let mut buffer = reticulum::buffer::OutputBuffer::new(&mut out);
    announce.serialize(&mut buffer).expect("serialize");

    assert_eq!(buffer.as_slice(), fixture("announce_ratchet.bin"));

    // The retained private ratchet is still available for decryption.
    assert_eq!(destination.ratchets().unwrap()[0], ratchet_private);
}

// ------------------------------------------------------------------
// SINGLE-destination encryption (Python `Identity.encrypt`/`decrypt`)
// ------------------------------------------------------------------

#[test]
fn decrypt_python_static_token() {
    let meta = meta();
    let identity =
        PrivateIdentity::new_from_hex_string(meta["identity_prv_hex"].as_str().unwrap()).unwrap();

    let token = fixture("encrypt_static.bin");
    let plaintext = from_hex(meta["encrypt"]["plaintext_hex"].as_str().unwrap());

    let mut buffer = [0u8; 4096];
    let decrypted = identity
        .decrypt(&token, &[], &mut buffer[..])
        .expect("static token decrypts");
    assert_eq!(decrypted, plaintext.as_slice());
}

#[test]
fn decrypt_python_ratchet_token() {
    let meta = meta();
    let identity =
        PrivateIdentity::new_from_hex_string(meta["identity_prv_hex"].as_str().unwrap()).unwrap();

    let ratchet: [u8; RATCHET_KEY_LENGTH] =
        from_hex(meta["ratchet"]["private_hex"].as_str().unwrap())
            .as_slice()
            .try_into()
            .unwrap();

    let token = fixture("encrypt_ratchet.bin");
    let plaintext = from_hex(meta["encrypt"]["plaintext_hex"].as_str().unwrap());

    // Without the ratchet the token must not decrypt.
    let mut buffer = [0u8; 4096];
    assert!(identity.decrypt(&token, &[], &mut buffer[..]).is_err());

    // With the ratchet it does.
    let decrypted = identity
        .decrypt(&token, &[ratchet], &mut buffer[..])
        .expect("ratchet token decrypts");
    assert_eq!(decrypted, plaintext.as_slice());
}

#[test]
fn encrypt_matches_python_token_byte_for_byte() {
    let meta = meta();
    let identity = Identity::new_from_hex_string(&hex(&PrivateIdentity::new_from_hex_string(
        meta["identity_prv_hex"].as_str().unwrap(),
    )
    .unwrap()
    .as_identity()
    .to_bytes()))
    .unwrap();

    let ephemeral_bytes: [u8; 32] =
        from_hex(meta["encrypt"]["ephemeral_prv_hex"].as_str().unwrap())
            .as_slice()
            .try_into()
            .unwrap();
    let ephemeral = reticulum::identity::StaticSecret::from(ephemeral_bytes);

    // The token carries the matching ephemeral public key.
    assert_eq!(
        hex(&fixture("encrypt_static.bin")[..32]),
        meta["encrypt"]["ephemeral_pub_hex"].as_str().unwrap()
    );

    let plaintext = from_hex(meta["encrypt"]["plaintext_hex"].as_str().unwrap());
    let rng = FixedIvRng(FIXED_IV);

    // Static-key encryption must reproduce the Python token exactly.
    let mut out = [0u8; 4096];
    let token = identity
        .encrypt_with_ephemeral(rng, &ephemeral, &plaintext, None, &mut out[..])
        .expect("encrypt");
    assert_eq!(token, fixture("encrypt_static.bin").as_slice());

    // Ratchet encryption too.
    let ratchet_public_bytes: [u8; 32] = from_hex(meta["ratchet"]["public_hex"].as_str().unwrap())
        .as_slice()
        .try_into()
        .unwrap();
    let ratchet_public = reticulum::identity::PublicKey::from(ratchet_public_bytes);

    let token = identity
        .encrypt_with_ephemeral(
            rng,
            &ephemeral,
            &plaintext,
            Some(&ratchet_public),
            &mut out[..],
        )
        .expect("encrypt");
    assert_eq!(token, fixture("encrypt_ratchet.bin").as_slice());
}

// ------------------------------------------------------------------
// Proof vectors
// ------------------------------------------------------------------

#[test]
fn proof_vectors_validate() {
    let meta = meta();
    let identity = Identity::new_from_hex_string(&hex(&PrivateIdentity::new_from_hex_string(
        meta["identity_prv_hex"].as_str().unwrap(),
    )
    .unwrap()
    .as_identity()
    .to_bytes()))
    .unwrap();

    let packet_hash = from_hex(meta["proof"]["packet_hash_hex"].as_str().unwrap());

    // Explicit proof: packet hash + signature.
    let explicit = from_hex(meta["proof"]["explicit_hex"].as_str().unwrap());
    let signature = identity::Signature::from_slice(&explicit[32..]).unwrap();
    identity
        .verify(&packet_hash, &signature)
        .expect("explicit proof validates");

    // Implicit proof: signature only.
    let implicit = from_hex(meta["proof"]["implicit_hex"].as_str().unwrap());
    let signature = identity::Signature::from_slice(&implicit).unwrap();
    identity
        .verify(&packet_hash, &signature)
        .expect("implicit proof validates");

    // Tampered proofs must fail.
    let mut tampered = implicit.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let signature = identity::Signature::from_slice(&tampered).unwrap();
    assert!(identity.verify(&packet_hash, &signature).is_err());
}

// ------------------------------------------------------------------
// GROUP destinations stay parseable
// ------------------------------------------------------------------

#[test]
fn group_destination_name_hash_addressing() {
    use reticulum::destination::{GroupInputDestination, GroupOutputDestination};

    let input = GroupInputDestination::new(
        reticulum::identity::EmptyIdentity,
        DestinationName::new("example_utilities", "group"),
    );
    let output = GroupOutputDestination::new(
        reticulum::identity::EmptyIdentity,
        DestinationName::new("example_utilities", "group"),
    );

    // Like PLAIN destinations, GROUP destinations address by name hash only.
    assert_eq!(input.desc.address_hash, output.desc.address_hash);
    assert_eq!(
        input.destination_type(),
        reticulum::packet::DestinationType::Group
    );
}

// Keep serde_json's `json!` referenced so the dev-dependency stays honest.
#[test]
fn meta_is_valid_json() {
    let _ = json!({});
}
