//! GROUP relays on shared media (`group_forwarding`): counter-based flooding.
//!
//! Each node relays a GROUP packet it could read once, after a random wait, so neighbours
//! that heard it together do not collide. Copies heard during the wait (the hash leaves out
//! the hops) cancel the relay once they reach the threshold: `suppress_after`, raised to the
//! direct neighbours (if known) up to [`NEIGHBOURS_CAP`], so a bridge still relays to the
//! side only it reaches while a dense cluster stays quiet.
//!
//! Waiting relays are queued by due time; one transport task sends them (no task per packet).

use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

use tokio::time::Instant;

use crate::hash::Hash;
use crate::iface::TxMessage;

/// Most relays waiting; past it new ones are dropped, never sent unchecked.
const MAX_PENDING: usize = 4096;
/// Most copies the neighbour count can require: in a clique of n, waiting for n - 1 would
/// let n - 2 nodes relay every packet.
pub const NEIGHBOURS_CAP: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupRelayConfig {
    /// A relay waits a random time in [min_wait, max_wait]. Both zero: sent at once, never
    /// cancelled.
    pub min_wait: Duration,
    pub max_wait: Duration,
    /// Copies that cancel a relay (at least). 0: never cancelled.
    pub suppress_after: u8,
    /// Relayed only while the hops after the relay stay below this.
    pub max_hops: u8,
}

impl Default for GroupRelayConfig {
    /// A plain flood: at once, never cancelled, up to the transport's hop limit.
    fn default() -> Self {
        Self { min_wait: Duration::ZERO, max_wait: Duration::ZERO, suppress_after: 0, max_hops: crate::transport::PATHFINDER_M as u8 }
    }
}

impl GroupRelayConfig {
    /// For a shared medium where neighbours hear each other: 10-40 ms waits, cancelled
    /// after 2 copies.
    pub fn shared_medium(max_hops: u8) -> Self {
        Self { min_wait: Duration::from_millis(10), max_wait: Duration::from_millis(40), suppress_after: 2, max_hops }
    }

    pub fn waits(&self) -> bool {
        !self.min_wait.is_zero() || !self.max_wait.is_zero()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupRelayStats {
    pub relayed: u64,
    /// Cancelled by copies from others.
    pub suppressed: u64,
    /// Dropped with the queue full.
    pub dropped: u64,
}

/// What [`GroupRelay::schedule`] did with a relay.
#[derive(Debug, PartialEq, Eq)]
pub enum Scheduled {
    /// Send it now (no waits configured).
    Now(TxMessage),
    /// Queued; `first`: due before all others, so the relay task must wake.
    Waiting { first: bool },
    /// Not relayed: the queue is full, or it is already queued.
    Dropped,
}

struct Pending {
    /// Copies heard, the first included.
    copies: u8,
    message: TxMessage,
}

pub struct GroupRelay {
    config: GroupRelayConfig,
    /// Direct neighbours; 0: not known.
    neighbours: u8,
    pending: HashMap<Hash, Pending>,
    /// `pending` by due time.
    queue: BTreeSet<(Instant, Hash)>,
    stats: GroupRelayStats,
}

impl GroupRelay {
    pub fn new(config: GroupRelayConfig) -> Self {
        Self { config, neighbours: 0, pending: HashMap::new(), queue: BTreeSet::new(), stats: GroupRelayStats::default() }
    }

    pub fn waits(&self) -> bool {
        self.config.waits()
    }

    /// Whether a packet that arrived with `hops` may be relayed.
    pub fn may_relay(&self, hops: u8) -> bool {
        (hops as usize) + 1 < self.config.max_hops as usize
    }

    /// Queues the relay of packet `hash`; `roll` in [0, 1) picks the wait.
    pub fn schedule(&mut self, hash: Hash, message: TxMessage, roll: f64, now: Instant) -> Scheduled {
        if !self.config.waits() {
            self.stats.relayed += 1;
            return Scheduled::Now(message);
        }
        if self.pending.contains_key(&hash) {
            return Scheduled::Dropped;
        }
        if self.pending.len() >= MAX_PENDING {
            self.stats.dropped += 1;
            return Scheduled::Dropped;
        }
        let spread = self.config.max_wait.saturating_sub(self.config.min_wait);
        let due = now + self.config.min_wait + spread.mul_f64(roll.clamp(0.0, 1.0));
        let first = self.next_due().is_none_or(|next| due < next);
        // The copy just heard counts, so where all heard the sender the first relay cancels
        // the rest.
        self.pending.insert(hash, Pending { copies: 1, message });
        self.queue.insert((due, hash));
        Scheduled::Waiting { first }
    }

    /// A copy of `hash` heard again.
    pub fn heard_copy(&mut self, hash: &Hash) {
        if let Some(pending) = self.pending.get_mut(hash) {
            pending.copies = pending.copies.saturating_add(1);
        }
    }

    pub fn next_due(&self) -> Option<Instant> {
        self.queue.first().map(|(due, _)| *due)
    }

    /// Relays due by `now` that still go out, in order; cancelled ones are dropped.
    pub fn due(&mut self, now: Instant) -> Vec<TxMessage> {
        let threshold = self.threshold();
        let mut out = Vec::new();
        while let Some(&(due, hash)) = self.queue.first() {
            if due > now {
                break;
            }
            self.queue.pop_first();
            let Some(pending) = self.pending.remove(&hash) else { continue };
            if pending.copies >= threshold {
                self.stats.suppressed += 1;
            } else {
                self.stats.relayed += 1;
                out.push(pending.message);
            }
        }
        out
    }

    pub fn set_neighbours(&mut self, neighbours: u8) {
        self.neighbours = neighbours;
    }

    pub fn stats(&self) -> GroupRelayStats {
        self.stats
    }

    fn threshold(&self) -> u8 {
        if self.config.suppress_after == 0 {
            u8::MAX
        } else {
            self.config.suppress_after.max(self.neighbours.min(NEIGHBOURS_CAP))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::TxMessageType;
    use crate::packet::Packet;

    fn hash(byte: u8) -> Hash {
        Hash::new([byte; 32])
    }

    fn message() -> TxMessage {
        TxMessage { tx_type: TxMessageType::Broadcast(None), packet: Packet::default() }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn without_waits_everything_is_relayed_at_once() {
        let mut relay = GroupRelay::new(GroupRelayConfig::default());
        assert_eq!(relay.schedule(hash(1), message(), 0.5, Instant::now()), Scheduled::Now(message()));
        assert_eq!(relay.stats().relayed, 1);
        assert_eq!(relay.next_due(), None);
    }

    #[test]
    fn relays_fall_due_within_the_window_in_order() {
        let mut relay = GroupRelay::new(GroupRelayConfig::shared_medium(8));
        let now = Instant::now();
        assert_eq!(relay.schedule(hash(1), message(), 1.0, now), Scheduled::Waiting { first: true });
        assert_eq!(relay.next_due(), Some(now + ms(40)));
        assert_eq!(relay.schedule(hash(2), message(), 0.0, now), Scheduled::Waiting { first: true }, "sooner: the task must wake");
        assert_eq!(relay.schedule(hash(3), message(), 0.5, now), Scheduled::Waiting { first: false });
        assert_eq!(relay.next_due(), Some(now + ms(10)));
        assert!(relay.due(now + ms(9)).is_empty());
        assert_eq!(relay.due(now + ms(25)).len(), 2, "10 and 25 ms");
        assert_eq!(relay.next_due(), Some(now + ms(40)));
        assert_eq!(relay.due(now + ms(40)).len(), 1);
        assert_eq!(relay.next_due(), None);
        assert_eq!(relay.stats().relayed, 3);
    }

    #[test]
    fn a_packet_already_queued_is_not_queued_twice() {
        let mut relay = GroupRelay::new(GroupRelayConfig::shared_medium(8));
        let now = Instant::now();
        relay.schedule(hash(1), message(), 0.5, now);
        assert_eq!(relay.schedule(hash(1), message(), 0.0, now), Scheduled::Dropped);
        assert_eq!(relay.due(now + ms(40)).len(), 1);
    }

    #[test]
    fn a_full_queue_drops_new_relays() {
        let mut relay = GroupRelay::new(GroupRelayConfig::shared_medium(8));
        let now = Instant::now();
        for i in 0..MAX_PENDING as u32 {
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&i.to_be_bytes());
            assert!(matches!(relay.schedule(Hash::new(bytes), message(), 0.5, now), Scheduled::Waiting { .. }));
        }
        assert_eq!(relay.schedule(hash(0xff), message(), 0.5, now), Scheduled::Dropped);
        assert_eq!(relay.stats().dropped, 1);
    }

    #[test]
    fn a_copy_heard_while_waiting_cancels_the_relay() {
        let mut relay = GroupRelay::new(GroupRelayConfig::shared_medium(8));
        let now = Instant::now();
        relay.schedule(hash(1), message(), 0.5, now);
        relay.schedule(hash(2), message(), 0.5, now);
        relay.heard_copy(&hash(1));
        assert_eq!(relay.due(now + ms(40)).len(), 1, "only 2: nobody else relayed it");
        assert_eq!(relay.stats(), GroupRelayStats { relayed: 1, suppressed: 1, dropped: 0 });
        assert!(relay.due(now + ms(80)).is_empty(), "each goes out once");
    }

    #[test]
    fn a_bridge_needs_a_copy_from_its_neighbours_up_to_the_cap() {
        let mut relay = GroupRelay::new(GroupRelayConfig::shared_medium(8));
        relay.set_neighbours(3);
        let now = Instant::now();
        relay.schedule(hash(1), message(), 0.5, now);
        relay.heard_copy(&hash(1));
        assert_eq!(relay.due(now + ms(40)).len(), 1, "2 copies, 3 neighbours: one may not have it");
        relay.schedule(hash(2), message(), 0.5, now);
        relay.heard_copy(&hash(2));
        relay.heard_copy(&hash(2));
        assert!(relay.due(now + ms(40)).is_empty());
        // In a big cluster, 3 copies are enough.
        relay.set_neighbours(20);
        relay.schedule(hash(3), message(), 0.5, now);
        relay.heard_copy(&hash(3));
        relay.heard_copy(&hash(3));
        assert!(relay.due(now + ms(40)).is_empty(), "capped at {NEIGHBOURS_CAP}");
    }

    #[test]
    fn suppress_after_zero_never_cancels() {
        let mut relay = GroupRelay::new(GroupRelayConfig { suppress_after: 0, ..GroupRelayConfig::shared_medium(8) });
        let now = Instant::now();
        relay.schedule(hash(1), message(), 0.5, now);
        for _ in 0..10 {
            relay.heard_copy(&hash(1));
        }
        assert_eq!(relay.due(now + ms(40)).len(), 1);
    }

    #[test]
    fn the_hop_limit_counts_the_relay() {
        let relay = GroupRelay::new(GroupRelayConfig::shared_medium(4));
        assert!(relay.may_relay(0));
        assert!(relay.may_relay(2));
        assert!(!relay.may_relay(3), "a 4th hop would reach the limit");
    }
}
