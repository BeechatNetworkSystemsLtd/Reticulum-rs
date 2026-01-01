#![cfg(feature = "python-interop")]

use rand_core::OsRng;
use reticulum::destination::{DestinationAnnounce, DestinationName, SingleInputDestination};
use reticulum::hash::{AddressHash, ADDRESS_HASH_SIZE};
use reticulum::identity::PrivateIdentity;
use reticulum::packet::{Header, HeaderType, Packet, PacketContext, PacketDataBuffer};

mod python_support;
use python_support::{python_available, run_python};

const APP_NAME: &str = "interop";
const APP_ASPECT: &str = "announce";

fn destination_name() -> DestinationName {
    DestinationName::new(APP_NAME, APP_ASPECT)
}

fn packet_to_bytes(packet: &Packet) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + (ADDRESS_HASH_SIZE * 2) + packet.data.len());
    bytes.push(packet.header.to_meta());
    bytes.push(packet.header.hops);

    if packet.header.header_type == HeaderType::Type2 {
        if let Some(transport) = &packet.transport {
            bytes.extend_from_slice(transport.as_slice());
        } else {
            panic!("type2 packet missing transport address");
        }
    }

    bytes.extend_from_slice(packet.destination.as_slice());
    bytes.push(packet.context as u8);
    bytes.extend_from_slice(packet.data.as_slice());
    bytes
}

fn packet_from_bytes(raw: &[u8]) -> Packet {
    assert!(raw.len() >= 2 + ADDRESS_HASH_SIZE + 1, "packet too short");

    let mut offset = 0usize;
    let meta = raw[offset];
    offset += 1;
    let hops = raw[offset];
    offset += 1;

    let mut header = Header::from_meta(meta);
    header.hops = hops;

    let transport = if header.header_type == HeaderType::Type2 {
        let mut transport_bytes = [0u8; ADDRESS_HASH_SIZE];
        transport_bytes.copy_from_slice(&raw[offset..offset + ADDRESS_HASH_SIZE]);
        offset += ADDRESS_HASH_SIZE;
        Some(AddressHash::new(transport_bytes))
    } else {
        None
    };

    let mut destination_bytes = [0u8; ADDRESS_HASH_SIZE];
    destination_bytes.copy_from_slice(&raw[offset..offset + ADDRESS_HASH_SIZE]);
    let destination = AddressHash::new(destination_bytes);
    offset += ADDRESS_HASH_SIZE;

    let context = PacketContext::from(raw[offset]);
    offset += 1;

    let mut data = PacketDataBuffer::new();
    data.safe_write(&raw[offset..]);

    Packet {
        header,
        ifac: None,
        destination,
        transport,
        context,
        data,
    }
}

fn deterministic_identity(label: &str) -> PrivateIdentity {
    PrivateIdentity::new_from_name(label)
}

fn python_or_skip() -> bool {
    if python_available() {
        true
    } else {
        eprintln!("python RNS not available; skipping interop test");
        false
    }
}

#[test]
fn python_validates_rust_announce_without_ratchet() {
    if !python_or_skip() {
        return;
    }

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let mut destination = SingleInputDestination::new(identity, destination_name());

    let packet = destination
        .announce(OsRng, None)
        .expect("announce should be generated");

    assert!(!packet.header.context_flag.is_set());

    let packet_hex = hex::encode(packet_to_bytes(&packet));
    let (code, _out, err) =
        run_python(&["tests/python/validate_announce.py", &packet_hex]);
    assert_eq!(code, 0, "python failed to validate announce: {err}");
}

#[test]
fn python_validates_rust_announce_with_ratchet() {
    if !python_or_skip() {
        return;
    }

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let mut destination = SingleInputDestination::new(identity, destination_name());
    destination.enable_ratchets(OsRng);

    let packet = destination
        .announce(OsRng, None)
        .expect("announce should be generated");

    assert!(packet.header.context_flag.is_set());

    let packet_hex = hex::encode(packet_to_bytes(&packet));
    let (code, _out, err) =
        run_python(&["tests/python/validate_announce.py", &packet_hex]);
    assert_eq!(code, 0, "python failed to validate ratcheted announce: {err}");
}

#[test]
fn rust_validates_python_announce_without_ratchet() {
    if !python_or_skip() {
        return;
    }

    let identity = deterministic_identity("python-rust-announce-no-ratchet");
    let packet_hex = {
        let priv_hex = identity.to_hex_string();
        let (code, out, err) = run_python(&[
            "tests/python/create_announce.py",
            &priv_hex,
            APP_NAME,
            APP_ASPECT,
            "0",
        ]);
        assert_eq!(code, 0, "python announce creation failed: {err}");
        out
    };

    let raw = hex::decode(&packet_hex).expect("valid packet hex");
    let packet = packet_from_bytes(&raw);
    assert!(!packet.header.context_flag.is_set());

    DestinationAnnounce::validate(&packet).expect("rust should accept python announce");
}

#[test]
fn rust_validates_python_announce_with_ratchet() {
    if !python_or_skip() {
        return;
    }

    let identity = deterministic_identity("python-rust-announce-with-ratchet");
    let packet_hex = {
        let priv_hex = identity.to_hex_string();
        let (code, out, err) = run_python(&[
            "tests/python/create_announce.py",
            &priv_hex,
            APP_NAME,
            APP_ASPECT,
            "1",
        ]);
        assert_eq!(code, 0, "python ratcheted announce creation failed: {err}");
        out
    };

    let raw = hex::decode(&packet_hex).expect("valid packet hex");
    let packet = packet_from_bytes(&raw);
    assert!(packet.header.context_flag.is_set());

    DestinationAnnounce::validate(&packet).expect("rust should accept python ratchet announce");
}
