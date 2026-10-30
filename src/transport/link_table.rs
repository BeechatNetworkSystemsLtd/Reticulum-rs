use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use reticulum_core::packet::PacketType;

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::{Header, HeaderType, IfacFlag, Packet};

pub struct LinkEntry {
    pub proof_timeout: Instant,
    /// The transport identity of the next node.
    pub next_hop_id: AddressHash,
    /// Interface the link request was sent on, towards the destination
    pub next_hop_iface: AddressHash,
    /// Interface the link request was received on, towards the initiator
    pub received_from: AddressHash,
    /// Hops of the link request when received, and so of all link packets received from
    /// the initiator
    pub taken_hops: u8,
    /// Hops of the link proof when received, and so of all link packets received from
    /// the destination
    pub remaining_hops: u8,
    pub validated: bool,
}

fn send_backwards(packet: &Packet, entry: &LinkEntry) -> (Packet, AddressHash) {
    let propagated = Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            header_type: HeaderType::Type2,
            hops: packet.header.hops + 1,
            .. packet.header
        },
        ifac: None,
        destination: packet.destination,
        transport: Some(entry.next_hop_id),
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
        received_from: AddressHash,
        next_hop_id: AddressHash,
        next_hop_iface: AddressHash,
    ) {
        debug_assert_eq!(link_request.header.packet_type, PacketType::LinkRequest);
        let link_id = LinkId::from(link_request);

        if self.0.contains_key(&link_id) {
            return;
        }

        let now = Instant::now();

        let entry = LinkEntry {
            proof_timeout: now + Duration::from_secs(600), // TODO
            next_hop_id,
            next_hop_iface,
            received_from,
            taken_hops: link_request.header.hops,
            remaining_hops: 0,
            validated: false
        };

        self.0.insert(link_id, entry);
    }

    /// Returns the packet of a validated link to transport and the interface to send
    /// it on. The hops of the packet must be those expected from the direction it came
    /// from, so that copies overheard on a shared interface are not transported again.
    pub fn handle_link_packet(
        &self,
        packet: &Packet,
        iface: AddressHash,
    ) -> Option<(Packet, AddressHash)> {
        let entry = self.0.get(&packet.destination).filter(|entry| entry.validated)?;
        let hops = packet.header.hops;

        let out_iface = if entry.next_hop_iface == entry.received_from {
            // both directions share one interface: repeat on it
            (hops == entry.remaining_hops || hops == entry.taken_hops).then_some(entry.next_hop_iface)
        } else if iface == entry.next_hop_iface {
            // from the destination: send towards the initiator
            (hops == entry.remaining_hops).then_some(entry.received_from)
        } else if iface == entry.received_from {
            // from the initiator: send towards the destination
            (hops == entry.taken_hops).then_some(entry.next_hop_iface)
        } else {
            // received on an interface that is not part of this link: drop
            None
        }?;

        let mut transported = *packet;
        transported.header.hops += 1;

        Some((transported, out_iface))
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
            } else if entry.proof_timeout <= now {
                stale.push(*link_id);
            }
        }

        for link_id in stale {
            self.0.remove(&link_id);
        }
    }
}
