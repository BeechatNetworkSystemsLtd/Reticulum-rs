use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, HeaderType, IfacFlag, Packet};

pub struct LinkEntry {
    pub timestamp: Instant,
    pub proof_timeout: Instant,
    pub next_hop: AddressHash,
    pub next_hop_iface: AddressHash,
    pub received_from: AddressHash,
    pub original_destination: AddressHash,
    pub taken_hops: u8,
    pub remaining_hops: u8,
    pub validated: bool,
}

fn send_backwards(packet: &Packet, entry: &LinkEntry) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: IfacFlag::Authenticated,
            header_type: HeaderType::Type2,
            context_flag: packet.header.context_flag,
            propagation_type: packet.header.propagation_type,
            destination_type: packet.header.destination_type,
            packet_type: packet.header.packet_type,
            hops: packet.header.hops + 1,
        },
        ifac: None,
        destination: packet.destination,
        transport: Some(entry.next_hop),
        context: packet.context,
        data: packet.data,
    };

    (propagated, entry.received_from)
}

pub struct LinkTable(HashMap<LinkId, LinkEntry>);

impl LinkTable {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add(
        &mut self,
        link_request: &Packet,
        destination: AddressHash,
        received_from: AddressHash,
        next_hop: AddressHash,
        iface: AddressHash,
    ) {
        let link_id = LinkId::from(link_request);

        if self.0.contains_key(&link_id) {
            return;
        }

        let now = Instant::now();
        let taken_hops = link_request.header.hops + 1;

        let entry = LinkEntry {
            timestamp: now,
            proof_timeout: now + Duration::from_secs(600), // TODO
            next_hop: next_hop,
            next_hop_iface: iface,
            received_from,
            original_destination: destination,
            taken_hops,
            remaining_hops: 0,
            validated: false
        };

        self.0.insert(link_id, entry);
    }

    pub fn original_destination(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0.get(&link_id).filter(|e| e.validated).map(|e| e.original_destination)
    }

    pub fn handle_keepalive(&self, packet: &Packet) -> Option<(Packet, AddressHash)> {
        self.0.get(&packet.destination).map(|entry| send_backwards(packet, entry))
    }

    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        match self.0.get_mut(&proof.destination) {
            Some(entry) => {
                entry.remaining_hops = proof.header.hops;
                entry.validated = true;

                Some(send_backwards(proof, entry))
            },
            None => None
        }
    }

    pub fn remove_stale(&mut self) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &self.0 {
            if entry.validated {
                // TODO remove active timed out links
            } else {
                if entry.proof_timeout <= now {
                    stale.push(link_id.clone());
                }
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
    }
}
