use std::collections::HashMap;
use tokio::time::{Duration, Instant};

use reticulum_core::packet::PacketType;

use crate::destination::link::LinkId;
use crate::hash::{AddressHash, Hash};
use crate::packet::Packet;

/// Time allowed for the proof of a link request to arrive, for each hop to the
/// destination
const PROOF_TIMEOUT_PER_HOP: Duration = Duration::from_secs(6);

pub const VALIDATED_IDLE: Duration = Duration::from_secs(3600);

const MAX_HOPS: u8 = 128;

/// Most links relayed at once; when full, an unproved request (or else the idlest link) goes.
const MAX_RELAYED_LINKS: usize = 1024;

/// Route of a repeated link request for a validated link, e.g. of a restarted link
/// after a path change
struct PendingRoute {
    timeout: Instant,
    next_hop_id: AddressHash,
    next_hop_iface: AddressHash,
    received_from: AddressHash,
    taken_hops: u8,
    expected_proof_hops: u8,
}

impl LinkEntry {
    /// The pending route, while it may still be taken.
    fn live_route(&self, now: Instant) -> Option<&PendingRoute> {
        self.pending_route.as_ref().filter(|route| route.timeout > now)
    }

    /// A restarted link taking a new path, not a repeat of the same request.
    fn rerouted(&self, now: Instant) -> bool {
        self.live_route(now).is_some_and(|route| {
            route.next_hop_id != self.next_hop_id || route.next_hop_iface != self.next_hop_iface
        })
    }
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
    expected_proof_hops: u8,
    pub validated: bool,
    pub destination: AddressHash,
    pub last_used: Instant,
    proof_hash: Option<Hash>,
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
                    expected_proof_hops: remaining_hops.saturating_sub(1),
                });
            }

            return;
        }

        if self.0.len() >= MAX_RELAYED_LINKS {
            self.remove_stale();
        }
        if self.0.len() >= MAX_RELAYED_LINKS {
            self.evict_one();
        }

        let entry = LinkEntry {
            proof_timeout: now + PROOF_TIMEOUT_PER_HOP * remaining_hops.max(1) as u32,
            next_hop_id,
            next_hop_iface,
            received_from,
            taken_hops: link_request.header.hops,
            remaining_hops: 0,
            expected_proof_hops: remaining_hops.saturating_sub(1),
            validated: false,
            destination: link_request.destination,
            last_used: now,
            proof_hash: None,
            pending_route: None,
        };

        self.0.insert(link_id, entry);
    }

    pub fn destination_of(&self, link_id: &LinkId) -> Option<AddressHash> {
        self.0.get(link_id).map(|entry| entry.destination)
    }

    /// Whether a repeated proof passes the duplicate filter: any before validation, a reroute,
    /// or no more hops than the accepted one (more hops: bounced between relays).
    pub fn accepts_repeat_proof(&self, proof: &Packet) -> bool {
        let now = Instant::now();
        self.0.get(&proof.destination).is_some_and(|entry| {
            !entry.validated
                || entry.rerouted(now)
                || proof.header.hops <= entry.remaining_hops
        })
    }

    /// Whether a link we relay was proved by its destination.
    #[cfg(test)]
    pub fn validated(&self, link_id: &LinkId) -> bool {
        self.0.get(link_id).is_some_and(|entry| entry.validated)
    }

    pub fn relays(&self, link_id: &LinkId) -> bool {
        self.0.contains_key(link_id)
    }

    /// Returns the packet of a validated link to transport and the interface to send
    /// it on. The hops of the packet must be those expected from the direction it came
    /// from, so that copies overheard on a shared interface are not transported again.
    pub fn handle_link_packet(
        &mut self,
        packet: &Packet,
        iface: AddressHash,
    ) -> Option<(Packet, AddressHash)> {
        let entry = self.0.get_mut(&packet.destination).filter(|entry| entry.validated)?;
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

        if hops >= MAX_HOPS {
            return None;
        }
        entry.last_used = Instant::now();

        let mut transported = *packet;
        transported.header.hops = hops.saturating_add(1);

        Some((transported, out_iface))
    }

    pub fn handle_proof(&mut self, proof: &Packet) -> Option<(Packet, AddressHash)> {
        if proof.header.hops >= MAX_HOPS {
            return None;
        }
        let now = Instant::now();
        match self.0.get_mut(&proof.destination) {
            Some(entry) => {
                let rerouted = entry.rerouted(now);
                let repeat = entry.validated && entry.proof_hash == Some(proof.hash());
                if repeat && !rerouted {
                    // same proof again: pass it on unchanged, unless bounced (more hops)
                    if proof.header.hops > entry.remaining_hops {
                        return None;
                    }
                } else {
                    // First, restarted or rerouted proof: take its hops and the pending route.
                    // Fewer hops than expected means overheard; the next hop's copy follows.
                    let expected = entry
                        .live_route(now)
                        .map_or(entry.expected_proof_hops, |route| route.expected_proof_hops);
                    if proof.header.hops < expected {
                        return None;
                    }
                    if let Some(route) = entry.pending_route.take().filter(|route| route.timeout > now) {
                        entry.next_hop_id = route.next_hop_id;
                        entry.next_hop_iface = route.next_hop_iface;
                        entry.received_from = route.received_from;
                        entry.taken_hops = route.taken_hops;
                    }
                    entry.remaining_hops = proof.header.hops;
                    entry.proof_hash = Some(proof.hash());
                }
                entry.validated = true;
                entry.last_used = Instant::now();

                // send proof back towards the initiator on; as in Python, only the hops are
                // changed, the proof is not put in transport
                let mut propagated = *proof;
                propagated.header.hops = proof.header.hops.saturating_add(1);

                Some((propagated, entry.received_from))
            },
            None => None
        }
    }

    /// Drops the unproved link closest to its proof timeout, or else the idlest proved link.
    fn evict_one(&mut self) {
        let unproved = self
            .0
            .iter()
            .filter(|(_, entry)| !entry.validated)
            .min_by_key(|(_, entry)| entry.proof_timeout);
        let victim = unproved
            .or_else(|| self.0.iter().min_by_key(|(_, entry)| entry.last_used))
            .map(|(link_id, _)| *link_id);
        if let Some(link_id) = victim {
            self.0.remove(&link_id);
        }
    }

    pub fn remove_stale(&mut self) {
        let now = Instant::now();

        // unproved: after the proof timeout; proved: after VALIDATED_IDLE without traffic
        self.0.retain(|_, entry| {
            if entry.validated {
                entry.pending_route.take_if(|route| route.timeout <= now);
                now.duration_since(entry.last_used) < VALIDATED_IDLE
            } else {
                entry.proof_timeout > now
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(seed: u8) -> Packet {
        let mut packet = Packet::default();
        packet.header.packet_type = PacketType::LinkRequest;
        packet.destination = AddressHash::new([seed; 16]);
        packet.data.safe_write(&[seed; 64]);
        packet
    }

    fn add(table: &mut LinkTable, request: &Packet) {
        table.add(request, AddressHash::new([7; 16]), AddressHash::new([8; 16]), AddressHash::new([9; 16]), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn relayed_links_are_forgotten_when_idle_and_traffic_keeps_them() {
        let mut table = LinkTable::new();
        let (busy, idle) = (request(1), request(2));
        add(&mut table, &busy);
        add(&mut table, &idle);
        for entry in table.0.values_mut() {
            entry.validated = true;
        }
        let busy_id = LinkId::from(&busy);
        let packet = Packet { destination: busy_id, ..Default::default() };
        for _ in 0..4 {
            tokio::time::advance(VALIDATED_IDLE / 3).await;
            // from the initiator, with the request's hops
            assert!(table.handle_link_packet(&packet, AddressHash::new([7; 16])).is_some());
            table.remove_stale();
        }
        assert!(table.destination_of(&busy_id).is_some());
        assert!(table.destination_of(&LinkId::from(&idle)).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn unproved_links_are_capped_and_expire_after_the_per_hop_timeout() {
        let mut table = LinkTable::new();
        let proved = request(0);
        add(&mut table, &proved);
        table.0.get_mut(&LinkId::from(&proved)).unwrap().validated = true;
        for seed in 1..=(MAX_RELAYED_LINKS as u32 + 100) {
            let mut forged = Packet::default();
            forged.header.packet_type = PacketType::LinkRequest;
            forged.destination = AddressHash::new([1; 16]);
            forged.data.safe_write(&seed.to_be_bytes());
            add(&mut table, &forged);
            tokio::time::advance(Duration::from_millis(1)).await;
        }
        assert_eq!(table.0.len(), MAX_RELAYED_LINKS);
        assert!(table.destination_of(&LinkId::from(&proved)).is_some(), "the proved link is kept");

        // one hop to the destination: unproved links expire after one per-hop timeout
        tokio::time::advance(PROOF_TIMEOUT_PER_HOP).await;
        table.remove_stale();
        assert_eq!(table.0.len(), 1);
    }

    #[test]
    fn a_repeated_proof_keeps_its_hops_and_copies_from_other_relays_are_refused() {
        let mut table = LinkTable::new();
        let request = request(3);
        add(&mut table, &request);
        let mut proof = Packet::default();
        proof.header.packet_type = PacketType::Proof;
        proof.destination = LinkId::from(&request);
        proof.header.hops = 1;
        assert!(table.handle_proof(&proof).is_some());
        assert!(table.accepts_repeat_proof(&proof), "the responder proving again");
        let mut bounced = proof;
        bounced.header.hops = 3;
        assert!(!table.accepts_repeat_proof(&bounced), "a copy another relay sent back");
        table.handle_proof(&bounced);
        assert!(table.accepts_repeat_proof(&proof), "the first proof's hops are kept");
        let mut far = proof;
        far.header.hops = 200;
        assert_eq!(table.handle_proof(&far), None);
    }

    #[test]
    fn a_bounced_proof_is_refused_while_the_same_request_is_repeated() {
        let mut table = LinkTable::new();
        let request = request(4);
        add(&mut table, &request);
        let mut proof = Packet::default();
        proof.header.packet_type = PacketType::Proof;
        proof.destination = LinkId::from(&request);
        proof.header.hops = 1;
        assert!(table.handle_proof(&proof).is_some());

        // the initiator repeats its request along the same path
        add(&mut table, &request);
        let mut bounced = proof;
        bounced.header.hops = 2;
        assert!(!table.accepts_repeat_proof(&bounced), "a copy another relay sent back");
        assert_eq!(table.handle_proof(&bounced), None);

        // packets from the destination are still relayed, with the first proof's hops
        let mut from_destination = Packet { destination: LinkId::from(&request), ..Default::default() };
        from_destination.header.hops = 1;
        assert!(table.handle_link_packet(&from_destination, AddressHash::new([9; 16])).is_some());
        assert!(table.accepts_repeat_proof(&proof), "the responder proving again");
    }

    #[test]
    fn a_restarted_link_through_the_same_next_hop_takes_the_longer_path() {
        let mut table = LinkTable::new();
        let request = request(6);
        add(&mut table, &request);
        let mut proof = Packet::default();
        proof.header.packet_type = PacketType::Proof;
        proof.destination = LinkId::from(&request);
        proof.header.hops = 1;
        proof.data.safe_write(&[1; 8]);
        assert!(table.handle_proof(&proof).is_some());

        // the same request again, through the same next hop, whose own path got longer: the
        // destination proves with new keys
        add(&mut table, &request);
        let mut new_proof = Packet::default();
        new_proof.header.packet_type = PacketType::Proof;
        new_proof.destination = LinkId::from(&request);
        new_proof.header.hops = 2;
        new_proof.data.safe_write(&[2; 8]);
        assert!(table.handle_proof(&new_proof).is_some(), "a new proof is not a bounced copy");
        let mut from_destination = Packet { destination: LinkId::from(&request), ..Default::default() };
        from_destination.header.hops = 2;
        assert!(table.handle_link_packet(&from_destination, AddressHash::new([9; 16])).is_some());
    }

    #[test]
    fn a_restarted_link_on_a_new_path_takes_its_new_hops() {
        let mut table = LinkTable::new();
        let request = request(5);
        add(&mut table, &request);
        let mut proof = Packet::default();
        proof.header.packet_type = PacketType::Proof;
        proof.destination = LinkId::from(&request);
        proof.header.hops = 1;
        assert!(table.handle_proof(&proof).is_some());

        // repeated through another next hop
        table.add(&request, AddressHash::new([7; 16]), AddressHash::new([6; 16]), AddressHash::new([5; 16]), 3);
        let mut longer = proof;
        longer.header.hops = 3;
        assert!(table.accepts_repeat_proof(&longer));
        assert!(table.handle_proof(&longer).is_some());
        let mut from_destination = Packet { destination: LinkId::from(&request), ..Default::default() };
        from_destination.header.hops = 3;
        assert!(table.handle_link_packet(&from_destination, AddressHash::new([5; 16])).is_some());
    }
}
