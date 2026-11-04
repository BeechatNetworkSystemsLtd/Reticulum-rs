use std::{
    cmp::min,
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::{hash::Hash, packet::Packet};

pub struct PacketTrack {
    pub time: Instant,
    pub min_hops: u8,
}

pub struct PacketCache {
    map: HashMap<Hash, PacketTrack>,
    remove_cache: Vec<Hash>,
    announce_capacity: usize,
    /// Force-cached announce packets by packet hash
    /// (Python `Transport.cache(force_cache=True, packet_type="announce")`).
    announces: HashMap<Hash, Packet>,
    announce_order: VecDeque<Hash>,
}

impl PacketCache {
    /// `announce_capacity` bounds retained announce packets; 0 disables caching.
    pub fn new(announce_capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            remove_cache: Vec::new(),
            announce_capacity,
            announces: HashMap::new(),
            announce_order: VecDeque::new(),
        }
    }

    pub fn release(&mut self, duration: Duration) {
        for entry in &self.map {
            if entry.1.time.elapsed() > duration {
                self.remove_cache.push(*entry.0);
            }
        }

        for hash in &self.remove_cache {
            self.map.remove(hash);
        }

        self.remove_cache.clear();
    }

    pub fn update(&mut self, packet: &Packet) -> bool {
        let hash = packet.hash();

        let mut is_new_packet = false;

        let track = self.map.get_mut(&hash);
        if let Some(track) = track {
            track.time = Instant::now();
            track.min_hops = min(packet.header.hops, track.min_hops);
        } else {
            is_new_packet = true;

            self.map.insert(
                hash,
                PacketTrack {
                    time: Instant::now(),
                    min_hops: packet.header.hops,
                },
            );
        }

        is_new_packet
    }

    /// Cache an announce packet for later path responses and cache requests
    /// (Python `Transport.cache(force_cache=True, packet_type="announce")`).
    pub fn cache_announce(&mut self, packet: &Packet) {
        if self.announce_capacity == 0 {
            return;
        }

        let hash = packet.hash();

        // Duplicate hashes only replace the stored packet; they must not
        // consume a FIFO slot or evict an unrelated entry.
        if !self.announces.contains_key(&hash) {
            // Evict before cloning so the incoming packet's copy never
            // coexists with an over-capacity cache.
            while self.announce_order.len() >= self.announce_capacity {
                if let Some(evicted) = self.announce_order.pop_front() {
                    self.announces.remove(&evicted);
                } else {
                    break;
                }
            }
            self.announce_order.push_back(hash);
        }

        self.announces.insert(hash, packet.clone());
    }

    /// Retrieve a cached announce by packet hash
    /// (Python `Transport.get_cached_packet(hash, packet_type="announce")`).
    pub fn get_cached_announce(&self, hash: &Hash) -> Option<Packet> {
        self.announces.get(hash).cloned()
    }

    /// Hashes currently in the duplicate filter (Python `packet_hashlist`).
    pub fn hashes(&self) -> Vec<Hash> {
        self.map.keys().copied().collect()
    }

    /// Remember a hash loaded from storage without treating it as a fresh arrival.
    pub fn remember_hash(&mut self, hash: Hash) {
        self.map.entry(hash).or_insert(PacketTrack {
            time: Instant::now(),
            min_hops: 0,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::AddressHash;
    use crate::packet::{
        DestinationType, Header, HeaderType, IfacFlag, PacketContext, PacketDataBuffer, PacketType,
        PropagationType,
    };

    fn announce_packet(seed: u8) -> Packet {
        Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                context_flag: false,
                header_type: HeaderType::Type2,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new([1; 16]),
            transport: None,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[seed; 32]),
        }
    }

    #[test]
    fn announce_cache_roundtrip() {
        let mut cache = PacketCache::new(8);
        let packet = announce_packet(2);
        let hash = packet.hash();

        assert!(cache.get_cached_announce(&hash).is_none());
        cache.cache_announce(&packet);
        assert_eq!(cache.get_cached_announce(&hash), Some(packet));
        assert!(cache.get_cached_announce(&hash).is_some());
    }

    #[test]
    fn announce_cache_evicts_oldest_at_capacity() {
        let mut cache = PacketCache::new(2);
        let first = announce_packet(1);
        let second = announce_packet(2);
        let third = announce_packet(3);

        cache.cache_announce(&first);
        cache.cache_announce(&second);
        cache.cache_announce(&third);

        assert!(cache.get_cached_announce(&first.hash()).is_none());
        assert_eq!(cache.get_cached_announce(&second.hash()), Some(second));
        assert_eq!(cache.get_cached_announce(&third.hash()), Some(third));
    }

    #[test]
    fn announce_cache_reannounce_keeps_fifo_slot() {
        let mut cache = PacketCache::new(2);
        let first = announce_packet(1);
        let mut first_updated = first.clone();
        first_updated.header.hops = 2;
        let second = announce_packet(2);
        let third = announce_packet(3);

        cache.cache_announce(&first);
        cache.cache_announce(&second);
        // Same packet hash: updates the stored packet without consuming a
        // FIFO slot, so `second` must not be evicted by `third`.
        cache.cache_announce(&first_updated);
        assert_eq!(
            cache.get_cached_announce(&first.hash()),
            Some(first_updated)
        );
        cache.cache_announce(&third);

        assert!(cache.get_cached_announce(&first.hash()).is_none());
        assert_eq!(cache.get_cached_announce(&second.hash()), Some(second));
        assert_eq!(cache.get_cached_announce(&third.hash()), Some(third));
    }

    #[test]
    fn announce_cache_zero_capacity_disables() {
        let mut cache = PacketCache::new(0);
        let packet = announce_packet(1);

        cache.cache_announce(&packet);

        assert!(cache.get_cached_announce(&packet.hash()).is_none());
    }
}
