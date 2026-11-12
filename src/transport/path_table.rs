use std::collections::HashMap;

use crate::{
    destination::{DestinationAnnounce, RAND_HASH_LENGTH},
    hash::AddressHash,
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType},
};

/// Maximum number of announce random hashes kept per destination
const MAX_RANDOM_BLOBS: usize = 64;

pub struct PathEntry {
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    /// Random hashes of the accepted announces for this destination, oldest first
    pub random_blobs: Vec<[u8; RAND_HASH_LENGTH]>,
}

pub struct PathTable {
    map: HashMap<AddressHash, PathEntry>,
    // unused since announces are accepted by random hash, to be removed
    #[allow(dead_code)]
    reroute_eager: bool,
}

impl PathTable {
    pub fn new(reroute_eager: bool) -> Self {
        Self {
            map: HashMap::new(),
            reroute_eager,
        }
    }

    pub fn get(&self, destination: &AddressHash) -> Option<&PathEntry> {
        self.map.get(destination)
    }

    /// Updates the path to the announced destination if the announce is new and returns
    /// whether it was. An announce is new if the destination is unknown, or if its
    /// random hash was not heard before and it was emitted after every announce heard
    /// before. The first copy of the newest announce wins, even if a later copy has
    /// fewer hops.
    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
    ) -> bool {
        let Some(random_hash) = DestinationAnnounce::random_hash(announce) else {
            log::debug!("{} mising random hash", announce.destination);
            return false;
        };

        let hops = announce.header.hops.saturating_add(1);

        let mut random_blobs = match self.map.get(&announce.destination) {
            Some(existing_entry) => {
                let path_emitted = existing_entry
                    .random_blobs
                    .last()
                    .map(DestinationAnnounce::emitted)
                    .unwrap_or(0);

                if existing_entry.random_blobs.contains(&random_hash)
                    || DestinationAnnounce::emitted(&random_hash) <= path_emitted
                {
                    // already seen or not newer than previous announces
                    return false;
                }

                existing_entry.random_blobs.clone()
            }
            None => Vec::new(),
        };

        random_blobs.push(random_hash);
        if random_blobs.len() > MAX_RANDOM_BLOBS {
            random_blobs.remove(0);
        }

        let received_from = transport_id.unwrap_or(announce.destination);
        let new_entry = PathEntry {
            received_from,
            hops,
            iface,
            random_blobs,
        };
        // updates existing entry if it exists
        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );

        true
    }

    /// Returns the packet in transport to forward towards its destination and the
    /// interface of the path. On the last hop, when the next hop is the destination
    /// itself, the packet is taken out of transport (header 1, without transport ID),
    /// or otherwise the next hop is set as transport ID.
    pub fn handle_inbound_packet(&self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        let (header_type, transport) = if entry.hops <= 1 {
            (HeaderType::Type1, None)
        } else {
            (HeaderType::Type2, Some(entry.received_from))
        };

        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type,
                    hops: original_packet.header.hops.saturating_add(1),
                    .. original_packet.header
                },
                ifac: None,
                destination: original_packet.destination,
                transport,
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }

    /// Returns the packet to send towards its destination and the interface of the path:
    /// if the destination is more than one hop away, the packet is put in transport with
    /// the next hop as transport id, otherwise it is sent as it is.
    pub fn handle_packet(&self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        if original_packet.header.header_type == HeaderType::Type2 {
            return (*original_packet, None);
        }

        if original_packet.header.packet_type == PacketType::Announce {
            return (*original_packet, None);
        }

        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (*original_packet, None);
        }

        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (*original_packet, None),
        };

        if entry.hops <= 1 {
            return (*original_packet, Some(entry.iface));
        }

        (
            Packet {
                header: Header {
                    header_type: HeaderType::Type2,
                    .. original_packet.header
                },
                ifac: original_packet.ifac,
                destination: original_packet.destination,
                transport: Some(entry.received_from),
                context: original_packet.context,
                data: original_packet.data,
            },
            Some(entry.iface),
        )
    }
}
