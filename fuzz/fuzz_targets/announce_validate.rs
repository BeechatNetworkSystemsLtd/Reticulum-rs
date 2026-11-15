#![no_main]
use libfuzzer_sys::fuzz_target;
use reticulum::destination::DestinationAnnounce;
use reticulum::packet::{DestinationType, Header, HeaderType, IfacFlag, Packet,
    PacketContext, PacketDataBuffer, PacketType, PropagationType};
use reticulum::hash::AddressHash;

fuzz_target!(|data: &[u8]| {
    // Announce validation (signature verification path) must never panic
    // on arbitrary payloads.
    let mut buffer = PacketDataBuffer::new();
    buffer.safe_write(data);

    let packet = Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            context_flag: false,
            header_type: HeaderType::Type2,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops: 1,
        },
        ifac: None,
        destination: AddressHash::new_from_slice(&[1u8; 16]),
        transport: None,
        context: PacketContext::None,
        data: buffer,
    };

    let _ = DestinationAnnounce::validate(&packet);
});
