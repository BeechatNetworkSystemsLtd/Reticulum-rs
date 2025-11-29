use rand_core::OsRng;

use crate::destination::DestinationName;
use crate::destination::PlainInputDestination;
use crate::hash::AddressHash;
use crate::identity::EmptyIdentity;
use crate::packet::DestinationType;
use crate::packet::Header;
use crate::packet::HeaderType;
use crate::packet::IfacFlag;
use crate::packet::Packet;
use crate::packet::PacketContext;
use crate::packet::PacketDataBuffer;
use crate::packet::PacketType;
use crate::packet::PropagationType;

pub fn create_path_request_destination() -> PlainInputDestination {
    PlainInputDestination::new(
        EmptyIdentity { },
        DestinationName::new("rnstransport","path.request")
    )
}

pub type TagBytes = Vec<u8>;

pub fn create_random_tag() -> TagBytes {
    AddressHash::new_from_rand(OsRng).as_slice().into()
}

pub struct PathRequests {
    transport_id: Option<AddressHash>,
    controlled_destination: PlainInputDestination,
}

impl PathRequests {
    pub fn new(transport_id: Option<AddressHash>) -> Self {
        Self {
            transport_id,
            controlled_destination: create_path_request_destination(),
        }
    }

    pub fn generate(
        &mut self,
        destination: &AddressHash,
        tag: Option<TagBytes>
    ) -> Packet {
        let mut data = PacketDataBuffer::new_from_slice(destination.as_slice());

        if let Some(transport_id) = self.transport_id {
            data.safe_write(transport_id.as_slice());
        }

        data.safe_write(tag.unwrap_or_else(|| create_random_tag()).as_slice());

        let destination = self.controlled_destination.desc.address_hash.clone();

        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Plain,
                packet_type: PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination,
            transport: self.transport_id.clone(), // TODO
            context: PacketContext::None,
            data
        }
    }
}
