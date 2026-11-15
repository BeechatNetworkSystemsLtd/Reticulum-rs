//! GROUP destination parity: symmetric Token crypto (Python
//! `Destination.prv`) and a transport round trip.

use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, GroupInputDestination, GroupKey};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;

/// Fixed key shared with the Python golden vector (64 bytes = AES-256,
/// the default mode of both `Token.generate_key()` and this crate).
fn key() -> [u8; reticulum::destination::GROUP_KEY_SIZE] {
    core::array::from_fn(|i| i as u8)
}

#[test]
fn group_key_roundtrip() {
    let gk = GroupKey::from_bytes(key());
    let mut buffer = [0u8; 1024];
    let token = gk
        .encrypt(b"group parity payload", &mut buffer[..])
        .unwrap();

    // Token format: iv(16) || ciphertext(plaintext padded to AES blocks)
    // || hmac(32); 20 bytes pad to 32.
    assert_eq!(token.len(), 16 + 32 + 32);

    let mut plain = [0u8; 1024];
    let decrypted = gk.decrypt(token, &mut plain[..]).unwrap();
    assert_eq!(decrypted, b"group parity payload");
}

#[test]
fn group_key_rejects_wrong_key() {
    let gk = GroupKey::from_bytes(key());
    let mut buffer = [0u8; 1024];
    let token = gk.encrypt(b"secret", &mut buffer[..]).unwrap().to_vec();

    let mut other_key = key();
    other_key[0] ^= 0xFF;
    let wrong = GroupKey::from_bytes(other_key);

    let mut plain = [0u8; 1024];
    assert!(wrong.decrypt(&token, &mut plain[..]).is_err());
}

#[test]
fn group_destination_key_lifecycle() {
    let mut destination = GroupInputDestination::new(
        reticulum::identity::EmptyIdentity,
        DestinationName::new("app", "group"),
    );

    assert!(!destination.group_encrypted());
    let generated = destination.create_group_key(OsRng);
    assert!(destination.group_encrypted());
    assert_eq!(destination.group_key(), Some(&generated));

    let mut buffer = [0u8; 1024];
    let token = destination
        .encrypt_group(b"payload", &mut buffer[..])
        .unwrap();

    let mut plain = [0u8; 1024];
    assert_eq!(
        destination.decrypt_group(token, &mut plain[..]).unwrap(),
        b"payload"
    );

    // Reload from raw bytes keeps the key working.
    destination.load_group_key(generated);
    assert_eq!(
        destination.decrypt_group(token, &mut plain[..]).unwrap(),
        b"payload"
    );
}

#[tokio::test]
async fn group_transport_roundtrip_encrypted() {
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let a = TransportConfig::new("grp-a", &identity_a).build();
    let mut b = TransportConfig::new("grp-b", &identity_b).build();

    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4512", Some("127.0.0.1:4513"), true),
            UdpInterface::spawn,
        );
    }
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4513", Some("127.0.0.1:4512"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let name = DestinationName::new("grouptest", "channel");
    let receiver = b.add_group_destination(name).await;
    receiver.lock().await.load_group_key(key());

    let mut received = b.received_data_events();
    a.send_to_group_destination(name, b"encrypted group payload", Some(&key()))
        .await
        .expect("send");

    let event = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .expect("timeout waiting for group packet")
        .expect("channel closed");

    // Delivered decrypted, flagged as such.
    assert!(event.decrypted);
    assert_eq!(event.data.as_slice(), b"encrypted group payload");
}
