//! Round-trip and negative tests for the LXMF message format layer.

use lxmf::error::LxmfError;
use lxmf::fields::*;
use lxmf::*;
use rand_core::OsRng;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;

fn fixed_identity(key_hex: &str) -> PrivateIdentity {
    PrivateIdentity::new_from_hex_string(key_hex).expect("valid identity")
}

fn test_identities() -> (PrivateIdentity, PrivateIdentity, AddressHash, AddressHash) {
    let source = fixed_identity(
        "f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964c\
         fb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7",
    );
    let destination = fixed_identity(
        "d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add65\
         0ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697",
    );
    let destination_hash = delivery_destination_hash(destination.as_identity());
    let source_hash = delivery_destination_hash(source.as_identity());
    (source, destination, destination_hash, source_hash)
}

#[test]
fn pack_unpack_roundtrip() {
    let (source, _destination, destination_hash, source_hash) = test_identities();

    let mut fields = Fields::new();
    fields.insert(
        FIELD_TELEMETRY,
        FieldValue::Map(vec![
            (FieldValue::Int(0), FieldValue::Bin(b"temperature".to_vec())),
            (FieldValue::Int(1), FieldValue::F64(21.5)),
            (FieldValue::Int(2), FieldValue::Int(3)),
        ]),
    );
    fields.insert(FIELD_THREAD, FieldValue::Bin(vec![0x11; 32]));
    fields.insert(
        FIELD_CUSTOM_TYPE,
        FieldValue::Str("application/x-test".into()),
    );
    fields.insert(FIELD_CUSTOM_DATA, FieldValue::Bin(vec![1, 2, 3, 255]));
    fields.insert(FIELD_DEBUG, FieldValue::Bool(true));

    let mut message = LXMessage::new(
        destination_hash,
        source_hash,
        "A title".as_bytes(),
        "Some content for the roundtrip test".as_bytes(),
    );
    message.set_fields(fields.clone());
    message.timestamp = Some(1735689600.5);
    message.pack(&source).expect("pack");

    assert_eq!(message.title_as_string().unwrap(), "A title");
    assert_eq!(
        message.content_as_string().unwrap(),
        "Some content for the roundtrip test"
    );

    let source_identity = *source.as_identity();
    let unpacked = LXMessage::unpack_from_bytes_with(message.packed.as_ref().unwrap(), &|hash| {
        (*hash == source_hash).then_some(source_identity)
    })
    .expect("unpack");

    assert!(unpacked.signature_validated);
    assert_eq!(unpacked.unverified_reason, None);
    assert_eq!(unpacked.title, message.title);
    assert_eq!(unpacked.content, message.content);
    assert_eq!(unpacked.timestamp, message.timestamp);
    assert_eq!(unpacked.hash, message.hash);
    assert_eq!(unpacked.signature, message.signature);
    assert_eq!(unpacked.get_fields(), &fields);
    assert_eq!(unpacked.packed_size, message.packed_size);
    assert!(unpacked.incoming);
}

#[test]
fn stamp_roundtrip() {
    let (source, _destination, destination_hash, source_hash) = test_identities();

    // Generate a real stamp at low cost for speed (peering work block)
    let mut message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.stamp_cost = Some(8);
    message.defer_stamp = false;
    message.timestamp = Some(1735689600.5);
    message.pack(&source).expect("pack");

    // The stamp is included as the 5th payload element
    assert!(message.stamp.is_some());
    let payload = message.packed_payload.as_ref().unwrap();
    assert_eq!(
        &payload[payload.len() - 32..],
        message.stamp.as_ref().unwrap().as_slice()
    );

    // And it validates on the receiving side
    let mut unpacked = LXMessage::unpack_from_bytes(message.packed.as_ref().unwrap()).unwrap();
    assert!(unpacked.stamp.is_some());
    assert!(unpacked.validate_stamp(Some(8), Some(&[])));
    assert!(unpacked.stamp_value.unwrap() >= 8);
    assert!(!unpacked.validate_stamp(Some(20), Some(&[])));
}

#[test]
fn outbound_ticket_stamp() {
    let (source, _destination, destination_hash, source_hash) = test_identities();

    let mut message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.outbound_ticket = Some([9u8; TICKET_LENGTH]);
    message.defer_stamp = false;
    message.stamp_cost = Some(12);
    message.timestamp = Some(1735689600.5);
    message.pack(&source).expect("pack");

    // The ticket-derived stamp validates against the presented ticket
    let ticket = [9u8; TICKET_LENGTH];
    let mut unpacked = LXMessage::unpack_from_bytes(message.packed.as_ref().unwrap()).unwrap();
    assert!(unpacked.validate_stamp(Some(12), Some(&[ticket])));
    assert_eq!(unpacked.stamp_value, Some(COST_TICKET));
    // ... but not as hashcash work
    assert!(!unpacked.validate_stamp(Some(12), Some(&[])));
}

#[test]
fn directory_persistence_roundtrip() {
    let (source, _destination, destination_hash, source_hash) = test_identities();

    let mut message = LXMessage::new(
        destination_hash,
        source_hash,
        b"Persisted",
        b"Persisted content",
    );
    message.timestamp = Some(1735689600.5);
    message.pack(&source).expect("pack");
    message.determine_transport_encryption();

    let directory = std::env::temp_dir().join(format!(
        "lxmf-persist-{}-{}",
        std::process::id(),
        message.hash.unwrap().as_slice()[0]
    ));
    std::fs::create_dir_all(&directory).expect("create dir");

    let path = message.write_to_directory(&directory).expect("write");
    assert!(path.exists());
    assert_eq!(
        path.file_name().unwrap().to_string_lossy(),
        to_hex(message.hash.unwrap().as_slice())
    );

    let restored = LXMessage::unpack_from_file(&path, &|_| None).expect("read back");
    assert_eq!(restored.title, b"Persisted");
    assert_eq!(restored.content, b"Persisted content");
    assert_eq!(restored.hash, message.hash);
    assert_eq!(restored.transport_encryption, message.transport_encryption);
    assert_eq!(restored.method, message.method);

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn oversized_opportunistic_fails() {
    let (source, _destination, destination_hash, source_hash) = test_identities();

    // One byte over the opportunistic single-packet content limit falls
    // back to DIRECT delivery (which still fits in a single link packet).
    let oversized = "x".repeat(ENCRYPTED_PACKET_MAX_CONTENT + 1);
    let mut message = LXMessage::new(destination_hash, source_hash, b"", oversized.as_bytes());
    message.desired_method = Some(OPPORTUNISTIC);
    message.timestamp = Some(1735689600.5);
    message.pack(&source).expect("pack");
    assert_eq!(message.method, DIRECT);
    assert_eq!(message.representation, PACKET);

    // A message larger than the link packet limit is marked for resource
    // transfer.
    let mut large = LXMessage::new(
        destination_hash,
        source_hash,
        b"",
        "y".repeat(LINK_PACKET_MAX_CONTENT + 1).as_bytes(),
    );
    large.timestamp = Some(1735689600.5);
    large.pack(&source).expect("pack");
    assert_eq!(large.method, DIRECT);
    assert_eq!(large.representation, RESOURCE);

    // Exactly at the limit still fits in a packet
    let mut fitting = LXMessage::new(
        destination_hash,
        source_hash,
        b"",
        "y".repeat(LINK_PACKET_MAX_CONTENT - 8 - 8).as_bytes(),
    );
    fitting.timestamp = Some(1735689600.5);
    fitting.pack(&source).expect("pack");
    assert_eq!(fitting.method, DIRECT);
    assert_eq!(fitting.representation, PACKET);
}

#[test]
fn double_pack_rejected() {
    let (source, _destination, destination_hash, source_hash) = test_identities();
    let mut message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.pack(&source).expect("pack");
    assert!(matches!(
        message.pack(&source),
        Err(LxmfError::AlreadyPacked)
    ));
}

#[test]
fn truncated_and_garbage_data_rejected() {
    let (source, _destination, destination_hash, source_hash) = test_identities();
    let mut message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.pack(&source).expect("pack");
    let packed = message.packed.unwrap();

    for len in [0usize, 1, 15, 32, 47, 95] {
        assert!(
            LXMessage::unpack_from_bytes(&packed[..len]).is_err(),
            "truncation at {len} must fail"
        );
    }

    assert!(LXMessage::unpack_from_bytes(b"not a message at all").is_err());
    assert!(LXMessage::unpack_from_bytes(&packed[..96]).is_err());
}

#[test]
fn signature_negative_tests() {
    let (source, _destination, destination_hash, source_hash) = test_identities();
    let source_identity = *source.as_identity();

    let mut message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.timestamp = Some(1735689600.5);
    message.pack(&source).expect("pack");
    let packed = message.packed.clone().unwrap();

    // Flip a signature byte
    let mut bad_signature = packed.clone();
    bad_signature[40] ^= 0xFF;
    let unpacked = LXMessage::unpack_from_bytes_with(&bad_signature, &|hash| {
        (*hash == source_hash).then_some(source_identity)
    })
    .unwrap();
    assert!(!unpacked.signature_validated);
    assert_eq!(unverified_reason_of(&unpacked), SIGNATURE_INVALID);

    // A different known identity also fails validation
    let other = fixed_identity(
        "8893e2bfd30fc08455997caf7abb7a6341716768dbbf9a91cc1455bd7eeaf74c\
         dc10ec72a4d4179696040bac620ee97ebc861e2443e5270537ae766d91b58181",
    );
    let unpacked = LXMessage::unpack_from_bytes_with(&packed, &|hash| {
        (*hash == source_hash).then_some(*other.as_identity())
    })
    .unwrap();
    assert!(!unpacked.signature_validated);
    assert_eq!(unverified_reason_of(&unpacked), SIGNATURE_INVALID);

    // Unknown source identity
    let unpacked = LXMessage::unpack_from_bytes_with(&packed, &|_| None).unwrap();
    assert!(!unpacked.signature_validated);
    assert_eq!(unverified_reason_of(&unpacked), SOURCE_UNKNOWN);
}

fn unverified_reason_of(message: &LXMessage) -> u8 {
    message.unverified_reason.unwrap_or(0xFF)
}

#[test]
fn fields_map_semantics() {
    let mut fields = Fields::new();
    fields.insert(1, FieldValue::Int(10));
    fields.insert(2, FieldValue::Int(20));
    // Re-inserting keeps the original position but updates the value
    fields.insert(1, FieldValue::Int(11));
    assert_eq!(fields.get(1), Some(&FieldValue::Int(11)));
    let packed_order: Vec<u8> = fields.iter().map(|(k, _)| *k).collect();
    assert_eq!(packed_order, vec![1, 2]);

    // Removal and len semantics
    assert_eq!(fields.remove(2), Some(FieldValue::Int(20)));
    assert_eq!(fields.len(), 1);
    assert!(fields.contains_key(1));
    assert!(!fields.contains_key(2));

    // Non-u8 keys are rejected when unpacking
    let mut bad = Vec::new();
    FieldValue::Map(vec![(FieldValue::Int(0x1000), FieldValue::Nil)]).pack(&mut bad);
    assert!(matches!(
        Fields::unpack(&mut bad.as_slice()),
        Err(LxmfError::UnsupportedFieldKey)
    ));
}

#[test]
fn uri_and_base64_edge_cases() {
    // Round-trip all byte values through the URL-safe base64 codec
    let data: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    let encoded = lxmf::message::base64_urlsafe_nopad(&data);
    assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
    assert_eq!(
        lxmf::message::base64_urlsafe_decode(&encoded).unwrap(),
        data
    );

    // Padding is tolerated
    let padded = format!("{}==", encoded);
    assert_eq!(lxmf::message::base64_urlsafe_decode(&padded).unwrap(), data);

    // as_uri requires a paper message
    let (source, _destination, destination_hash, source_hash) = test_identities();
    let mut message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.timestamp = Some(1735689600.5);
    message.pack(&source).expect("pack");
    assert!(message.as_uri().is_err());
}

#[test]
fn pack_propagation_requires_identity() {
    let (source, destination, destination_hash, source_hash) = test_identities();

    // Without a destination identity the propagation pack fails
    let mut message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.timestamp = Some(1735689600.5);
    assert!(message.pack_propagation(&source, OsRng).is_err());

    // With the identity it produces the propagation container
    message = LXMessage::new(destination_hash, source_hash, b"t", b"c");
    message.timestamp = Some(1735689600.5);
    message.destination_identity = Some(*destination.as_identity());
    message.pack_propagation(&source, OsRng).expect("pack");
    assert_eq!(message.method, PROPAGATED);
    assert!(message.propagation_packed.is_some());
    assert!(message.transient_id.is_some());

    // The container decrypts back to the packed message
    let mut rd: &[u8] = message.propagation_packed.as_ref().unwrap();
    let value = FieldValue::unpack(&mut rd).unwrap();
    let FieldValue::Array(items) = value else {
        unreachable!()
    };
    let FieldValue::Array(inner) = &items[1] else {
        unreachable!()
    };
    let FieldValue::Bin(lxmf_data) = &inner[0] else {
        unreachable!()
    };
    assert_eq!(&lxmf_data[..16], destination_hash.as_slice());

    let decrypted = lxmf::message::decrypt_for_identity(&destination, &lxmf_data[16..]).unwrap();
    assert_eq!(
        decrypted.as_slice(),
        &message.packed.as_ref().unwrap()[16..]
    );

    // Propagation stamp generation uses the transient id as material
    let stamp = message
        .get_propagation_stamp(8, Some(&source))
        .expect("stamp generation");
    assert!(stamp.is_some());
    assert!(message.propagation_stamp_valid);
}
