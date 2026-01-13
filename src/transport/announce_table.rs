use alloc::vec::Vec;
use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::packet::{
    DestinationType, Header, HeaderType, IfacFlag,
    Packet, PacketContext, PacketType, PropagationType
};

pub struct AnnounceEntry {
    pub packet: Packet,
    pub timestamp: Instant,
    pub timeout: Instant,
    pub received_from: AddressHash,
    pub retries: u8,
    pub hops: u8,
}

impl AnnounceEntry {
    pub fn retransmit(
        &mut self,
        transport_id: &AddressHash,
    ) -> Option<(AddressHash, Packet)> {
        if self.retries == 0 || Instant::now() >= self.timeout {
            return None;
        }

        self.retries = self.retries.saturating_sub(1);

        let new_packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type2,
                context_flag: self.packet.header.context_flag,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: self.hops,
            },
            ifac: None,
            destination: self.packet.destination, // TODO
            transport: Some(transport_id.clone()),
            context: PacketContext::None,
            data: self.packet.data,
        };

        Some((self.received_from, new_packet))
    }
}

pub struct AnnounceTable {
    map: HashMap<AddressHash, AnnounceEntry>,
    stale: Vec<AddressHash>,
}

impl AnnounceTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            stale: Vec::new(),
        }
    }

    pub fn add(
        &mut self,
        announce: &Packet,
        destination: AddressHash,
        received_from: AddressHash
    ) {
        if self.map.contains_key(&destination) {
            return;
        }

        let now = Instant::now();
        let hops = announce.header.hops + 1;

        let entry = AnnounceEntry {
            packet: announce.clone(),
            timestamp: now,
            timeout: now + Duration::from_secs(60), // TODO
            received_from,
            retries: 20, // TODO
            hops,
        };

        self.map.insert(destination, entry);
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.stale.clear();
    }

    pub fn stale(&mut self, destination: &AddressHash) {
        self.map.remove(destination);
    }

    pub fn new_packet(
        &mut self,
        dest_hash: &AddressHash,
        transport_id: &AddressHash,
    ) -> Option<(AddressHash, Packet)> {
        // temporary hack
        self.map.get_mut(dest_hash).map_or(None, |e| e.retransmit(transport_id))
    }


    pub fn to_retransmit(
        &mut self,
        transport_id: &AddressHash,
    ) -> Vec<(AddressHash, Packet)> {
        let mut packets = vec![];
        let mut completed = vec![];

        for (destination, ref mut entry) in &mut self.map {
            if let Some(pair) = entry.retransmit(transport_id) {
                packets.push(pair);
            } else {
                completed.push(destination.clone());
            }
        }

        if !(packets.is_empty() && completed.is_empty()) {
            log::trace!(
                "Announce cache: {} to retransmit, {} dropped",
                packets.len(),
                completed.len(),
            );
        }

        for destination in completed {
            self.map.remove(&destination);
        }

        packets
    }
}
