use reticulum::crypt::fernet::FERNET_OVERHEAD_SIZE;
use reticulum::packet::{Packet, PACKET_MDU};

#[test]
fn packet_fragmentation_respects_limit() {
    let data = vec![0u8; 4096];
    let packets = Packet::fragment_for_lxmf(&data).unwrap();
    assert!(packets
        .iter()
        .all(|p| p.data.len() <= Packet::LXMF_MAX_PAYLOAD));
    assert_eq!(Packet::LXMF_MAX_PAYLOAD, PACKET_MDU - FERNET_OVERHEAD_SIZE);
}
