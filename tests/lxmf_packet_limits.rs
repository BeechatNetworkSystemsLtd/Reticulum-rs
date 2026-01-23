use reticulum::packet::Packet;

#[test]
fn packet_fragmentation_respects_limit() {
    let data = vec![0u8; 4096];
    let packets = Packet::fragment_for_lxmf(&data).unwrap();
    assert!(packets
        .iter()
        .all(|p| p.data.len() <= Packet::LXMF_MAX_PAYLOAD));
}
