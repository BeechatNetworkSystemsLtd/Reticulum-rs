use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use reticulum_core::packet::PacketType;

use crate::destination::link::LinkId;
use crate::hash::AddressHash;
use crate::packet::Packet;

/// Time allowed for the proof of a link request to arrive, for each hop to the
/// destination
const PROOF_TIMEOUT_PER_HOP: Duration = Duration::from_secs(6);

/// Route of a repeated link request for a validated link, e.g. of a restarted link
/// after a path change
struct PendingRoute {
    timeout: Instant,
    next_hop_id: AddressHash,
    next_hop_iface: AddressHash,
    received_from: AddressHash,
    taken_hops: u8,
}

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
    /// Replaces the route when a proof arrives, the current route is used until then.
    /// Only the first copy of a request is kept, later copies may be overheard from
    /// the next node on a shared interface and have the wrong hops.
    pending_route: Option<PendingRoute>,
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
        remaining_hops: u8,
    ) {
        debug_assert_eq!(link_request.header.packet_type, PacketType::LinkRequest);
        let link_id = LinkId::from(link_request);

        let now = Instant::now();

        if let Some(entry) = self.0.get_mut(&link_id) {
            if entry.validated && entry.pending_route.is_none() {
                entry.pending_route = Some(PendingRoute {
                    timeout: now + PROOF_TIMEOUT_PER_HOP * remaining_hops.max(1) as u32,
                    next_hop_id,
                    next_hop_iface,
                    received_from,
                    taken_hops: link_request.header.hops,
                });
            }

            return;
        }

        let entry = LinkEntry {
            proof_timeout: now + Duration::from_secs(600), // TODO
            next_hop_id,
            next_hop_iface,
            received_from,
            taken_hops: link_request.header.hops,
            remaining_hops: 0,
            validated: false,
            pending_route: None,
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
                if let Some(route) = entry.pending_route.take() {
                    entry.next_hop_id = route.next_hop_id;
                    entry.next_hop_iface = route.next_hop_iface;
                    entry.received_from = route.received_from;
                    entry.taken_hops = route.taken_hops;
                }

                entry.remaining_hops = proof.header.hops;
                entry.validated = true;

                // send proof back towards the initiator on; as in Python, only the hops are
                // changed, the proof is not put in transport
                let mut propagated = *proof;
                propagated.header.hops += 1;

                Some((propagated, entry.received_from))
            },
            None => None
        }
    }

    pub fn remove_stale(&mut self) {
        let mut stale = vec![];
        let now = Instant::now();

        for (link_id, entry) in &mut self.0 {
            if entry.validated {
                entry.pending_route.take_if(|route| route.timeout <= now);
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
