use std::collections::HashMap;

use tokio::time::Instant;

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
    /// When the last new announce for this destination was accepted.
    pub last_heard: Instant,
    /// A link over this path went silent: the next announce through another node, or any
    /// new one, replaces it.
    pub unresponsive: bool,
}

/// What an announce did to the path table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathUpdate {
    /// Heard before, or older than the path: nothing changed.
    Ignored,
    /// A new announce: the path follows it.
    New,
    /// A known announce through another node replaced an unresponsive path. Not passed on.
    Rerouted,
}

pub struct PathTable {
    map: HashMap<AddressHash, PathEntry>,
    // unused since announces are accepted by random hash, to be removed
    #[allow(dead_code)]
    reroute_eager: bool,
    /// See [`TimerConfig::path_refresh`](crate::transport::TimerConfig::path_refresh).
    refresh_after: Option<std::time::Duration>,
}

impl PathTable {
    pub fn new(reroute_eager: bool, refresh_after: Option<std::time::Duration>) -> Self {
        Self {
            map: HashMap::new(),
            reroute_eager,
            refresh_after,
        }
    }

    pub fn get(&self, destination: &AddressHash) -> Option<&PathEntry> {
        self.map.get(destination)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn remove(&mut self, destination: &AddressHash) -> Option<PathEntry> {
        self.map.remove(destination)
    }

    /// The destination heard least recently among those `evictable` accepts.
    pub fn least_recently_heard(
        &self,
        evictable: impl Fn(&AddressHash) -> bool,
    ) -> Option<AddressHash> {
        self.map
            .iter()
            .filter(|(destination, _)| evictable(destination))
            .min_by_key(|(_, entry)| entry.last_heard)
            .map(|(destination, _)| *destination)
    }

    /// Updates the path if the announce is new, and returns what it did. An announce is new
    /// if it was not heard before and is newer than the last one; the first copy wins. An
    /// unresponsive or long unrefreshed path also takes an older announce, and an
    /// unresponsive one a known announce through another node.
    pub fn handle_announce(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
    ) -> PathUpdate {
        let Some(random_hash) = DestinationAnnounce::random_hash(announce) else {
            log::debug!("{} mising random hash", announce.destination);
            return PathUpdate::Ignored;
        };

        let hops = announce.header.hops.saturating_add(1);
        let received_from = transport_id.unwrap_or(announce.destination);

        let mut update = PathUpdate::New;
        let mut random_blobs = match self.map.get(&announce.destination) {
            Some(existing_entry) => {
                let path_emitted = existing_entry
                    .random_blobs
                    .last()
                    .map(DestinationAnnounce::emitted)
                    .unwrap_or(0);

                let known = existing_entry.random_blobs.contains(&random_hash);
                let newer = DestinationAnnounce::emitted(&random_hash) > path_emitted;
                let refresh = existing_entry.unresponsive
                    || self.refresh_after.is_some_and(|after| existing_entry.last_heard.elapsed() > after);
                let accepted = if known {
                    existing_entry.unresponsive && received_from != existing_entry.received_from
                } else {
                    newer || refresh
                };
                if !accepted {
                    // already seen or not newer than previous announces
                    return PathUpdate::Ignored;
                }
                if known {
                    update = PathUpdate::Rerouted;
                }

                existing_entry.random_blobs.clone()
            }
            None => Vec::new(),
        };

        if !random_blobs.contains(&random_hash) {
            random_blobs.push(random_hash);
        }
        if random_blobs.len() > MAX_RANDOM_BLOBS {
            random_blobs.remove(0);
        }

        let new_entry = PathEntry {
            received_from,
            hops,
            iface,
            random_blobs,
            last_heard: Instant::now(),
            unresponsive: false,
        };
        // updates existing entry if it exists
        self.map.insert(announce.destination, new_entry);

        log::debug!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );

        update
    }

    /// A link to the destination went silent: keep the path until an announce through
    /// another node, or a new one, replaces it. Returns the path's hops.
    pub fn mark_unresponsive(&mut self, destination: &AddressHash) -> Option<u8> {
        let entry = self.map.get_mut(destination)?;
        if !entry.unresponsive {
            log::debug!("{} is unresponsive through {}", destination, entry.received_from);
        }
        entry.unresponsive = true;
        Some(entry.hops)
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

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::destination::{DestinationName, SingleInputDestination, NAME_HASH_LENGTH};
    use crate::identity::PrivateIdentity;

    /// After the X25519 and Ed25519 keys and the name hash.
    const RANDOM_HASH_AT: usize = 32 * 2 + NAME_HASH_LENGTH;
    /// No refresh: `TimerConfig::path_refresh`'s default.
    const REFRESH: Option<std::time::Duration> = None;

    /// An announce of `destination` as if emitted at unix second `emitted`.
    fn announce(destination: &SingleInputDestination, emitted: u64) -> Packet {
        let mut packet = destination.announce(OsRng, None).unwrap();
        let at = RANDOM_HASH_AT + RAND_HASH_LENGTH / 2;
        packet.data.as_mut_slice()[at..at + 5].copy_from_slice(&emitted.to_be_bytes()[3..]);
        packet
    }

    fn destination() -> SingleInputDestination {
        SingleInputDestination::new(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "path"))
    }

    #[test]
    fn a_node_whose_clock_went_back_is_heard_again_once_its_path_stopped_working() {
        let (mut table, destination) = (PathTable::new(false, REFRESH), destination());
        let (relay, iface) = (AddressHash::new([7; 16]), AddressHash::new([1; 16]));
        let address = destination.desc.address_hash;
        assert!(PathUpdate::Ignored != table.handle_announce(&announce(&destination, 2_000_000_000), Some(relay), iface));
        // It rebooted with its clock behind: its new announces look older and are ignored...
        let rebooted = announce(&destination, 1_700_000_000);
        assert!(PathUpdate::Ignored == table.handle_announce(&rebooted, Some(relay), iface));
        // ...until a link over the path stopped hearing it.
        assert_eq!(table.mark_unresponsive(&address), Some(1), "its hops");
        assert!(PathUpdate::Ignored != table.handle_announce(&rebooted, Some(relay), iface));
        assert!(!table.get(&address).unwrap().unresponsive);
        // From then on its announces count from its new clock.
        assert!(PathUpdate::Ignored != table.handle_announce(&announce(&destination, 1_700_000_120), Some(relay), iface));
        assert!(PathUpdate::Ignored == table.handle_announce(&rebooted, Some(relay), iface), "heard before");
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_whose_clock_went_back_is_heard_again_after_the_configured_refresh() {
        let refresh = std::time::Duration::from_secs(30);
        let (mut table, destination) = (PathTable::new(false, Some(refresh)), destination());
        let (relay, iface) = (AddressHash::new([7; 16]), AddressHash::new([1; 16]));
        assert!(PathUpdate::Ignored != table.handle_announce(&announce(&destination, 2_000_000_000), Some(relay), iface));
        let rebooted = announce(&destination, 1_700_000_000);
        tokio::time::advance(refresh - std::time::Duration::from_secs(1)).await;
        assert!(PathUpdate::Ignored == table.handle_announce(&rebooted, Some(relay), iface), "the path is still fresh");
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        assert!(PathUpdate::Ignored != table.handle_announce(&rebooted, Some(relay), iface), "not refreshed for longer than the setting");
    }

    #[test]
    fn an_unresponsive_path_moves_to_a_copy_heard_through_another_node() {
        let (mut table, destination) = (PathTable::new(false, REFRESH), destination());
        let (dead, other, iface) = (AddressHash::new([7; 16]), AddressHash::new([8; 16]), AddressHash::new([1; 16]));
        let address = destination.desc.address_hash;
        let packet = announce(&destination, 2_000_000_000);
        assert!(PathUpdate::Ignored != table.handle_announce(&packet, Some(dead), iface));
        // The same announce through another relay (its rebroadcast, or its path response).
        assert!(PathUpdate::Ignored == table.handle_announce(&packet, Some(other), iface), "the first copy wins");
        table.mark_unresponsive(&address);
        assert!(PathUpdate::Ignored == table.handle_announce(&packet, Some(dead), iface), "not through the relay that stopped working");
        assert_eq!(table.handle_announce(&packet, Some(other), iface), PathUpdate::Rerouted, "not passed on");
        let entry = table.get(&address).unwrap();
        assert_eq!(entry.received_from, other);
        assert_eq!(entry.random_blobs.len(), 1);
        assert!(PathUpdate::Ignored == table.handle_announce(&packet, Some(dead), iface), "settled again");
    }
}
