use crate::{
    buffer::{InputBuffer, OutputBuffer, StaticBuffer},
    error::RnsError,
    hash::AddressHash,
    packet::{Header, HeaderType, Packet, PacketContext},
};

pub trait Serialize {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError>;
}

impl Serialize for AddressHash {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(self.as_slice())
    }
}

impl Serialize for Header {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[self.to_meta(), self.hops])
    }
}
impl Serialize for PacketContext {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[*self as u8])
    }
}

impl Serialize for Packet {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        self.header.serialize(buffer)?;

        if self.header.header_type == HeaderType::Type2 {
            if let Some(transport) = &self.transport {
                transport.serialize(buffer)?;
            }
        }

        self.destination.serialize(buffer)?;

        self.context.serialize(buffer)?;

        buffer.write(self.data.as_slice())
    }
}

impl Header {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Header, RnsError> {
        let mut header = Header::from_meta(buffer.read_byte()?);
        header.hops = buffer.read_byte()?;

        Ok(header)
    }
}

impl AddressHash {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<AddressHash, RnsError> {
        let mut address = AddressHash::new_empty();

        buffer.read(&mut address.as_mut_slice())?;

        Ok(address)
    }
}

impl PacketContext {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<PacketContext, RnsError> {
        Ok(PacketContext::from(buffer.read_byte()?))
    }
}
impl Packet {
    pub fn deserialize(buffer: &mut InputBuffer) -> Result<Packet, RnsError> {
        let header = Header::deserialize(buffer)?;

        let transport = if header.header_type == HeaderType::Type2 {
            Some(AddressHash::deserialize(buffer)?)
        } else {
            None
        };

        let destination = AddressHash::deserialize(buffer)?;

        let context = PacketContext::deserialize(buffer)?;

        let mut packet = Packet {
            header,
            ifac: None,
            destination,
            transport,
            context,
            data: StaticBuffer::new(),
        };

        buffer.read(&mut packet.data.accuire_buf(buffer.bytes_left()))?;

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use crate::{
        buffer::{InputBuffer, OutputBuffer, StaticBuffer},
        hash::AddressHash,
        packet::{
            ContextFlag, DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext,
            PacketType, PropagationType,
        },
    };

    use super::Serialize;

    #[test]
    fn serialize_packet() {
        let mut output_data = [0u8; 4096];

        let mut buffer = OutputBuffer::new(&mut output_data);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: StaticBuffer::new(),
        };

        packet.serialize(&mut buffer).expect("serialized packet");

        println!("{}", buffer);
    }

    #[test]
    fn deserialize_packet() {
        let mut output_data = [0u8; 4096];

        let mut buffer = OutputBuffer::new(&mut output_data);

        let mut packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                context_flag: ContextFlag::Unset,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: StaticBuffer::new(),
        };

        packet.data.safe_write(b"Hello, world!");

        packet.serialize(&mut buffer).expect("serialized packet");

        let mut input_buffer = InputBuffer::new(buffer.as_slice());

        let new_packet = Packet::deserialize(&mut input_buffer).expect("deserialized packet");

        assert_eq!(packet.header, new_packet.header);
        assert_eq!(packet.destination, new_packet.destination);
        assert_eq!(packet.transport, new_packet.transport);
        assert_eq!(packet.context, new_packet.context);
        assert_eq!(packet.data.as_slice(), new_packet.data.as_slice());
    }
}
