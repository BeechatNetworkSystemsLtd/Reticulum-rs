use std::collections::HashMap;

use crate::iface::InterfaceMode;
use crate::{
    hash::AddressHash,
    packet::{DestinationType, Header, HeaderType, IfacFlag, Packet, PacketType, PropagationType},
};

/// Path expiry time (Python `Transport.PATHFINDER_E` = 1 week).
/// Full-mode paths, and every mode other than access point and roaming,
/// use this lifetime. Python's `DESTINATION_TIMEOUT` is the same duration.
pub const PATHFINDER_E: core::time::Duration = core::time::Duration::from_secs(60 * 60 * 24 * 7);

/// Access-point path lifetime (Python `Transport.AP_PATH_TIME` = 1 day).
pub const AP_PATH_TIME: core::time::Duration = core::time::Duration::from_secs(60 * 60 * 24);

/// Roaming path lifetime (Python `Transport.ROAMING_PATH_TIME` = 6 hours).
pub const ROAMING_PATH_TIME: core::time::Duration = core::time::Duration::from_secs(60 * 60 * 6);

/// Announce random-blob length (Python slices 10 bytes at
/// `KEYSIZE//8 + NAME_HASH_LENGTH//8`).
const RANDOM_BLOB_LEN: usize = 10;

/// In-memory cap on remembered announce blobs (Python `MAX_RANDOM_BLOBS`).
const MAX_RANDOM_BLOBS: usize = 64;

pub struct PathEntry {
    pub received_from: AddressHash,
    pub hops: u8,
    pub iface: AddressHash,
    /// Monotonic nanoseconds since process start when the path was learned.
    /// Negative when a restored path is older than this process. Zero is the
    /// boot instant, not an expiry sentinel.
    pub timestamp: i64,
    /// Set by `mark_path_unresponsive`. The path stays visible to `get` and
    /// `hops_to` and is still routed. An equal-hop announce may replace it
    /// (Python `path_is_unresponsive` only affects path selection).
    pub unresponsive: bool,
    /// Hash of the announce packet that created this path, for analytics.
    pub packet_hash: crate::hash::Hash,
    /// Interface mode that learned this path. Access-point and roaming
    /// entries expire on shorter lifetimes than every other mode.
    pub mode: InterfaceMode,
    /// Unix time the path expires, recorded when the entry is inserted.
    /// Refreshing `timestamp` on traffic does not move it.
    pub expires_unix: f64,
    /// Announce random blobs, oldest first. The emission timebase is the
    /// maximum of `timebase_from_random_blob` over these (Python
    /// `IDX_PT_RANDBLOBS` / `timebase_from_random_blobs`).
    pub random_blobs: Vec<[u8; RANDOM_BLOB_LEN]>,
    /// Receiving-interface gravity. `None` is Python `None`: gravity is
    /// compared only when both the current path and the new announce have one.
    pub gravity: Option<i64>,
}

/// Big-endian emission time in bytes `[5:10]` of one stored announce blob.
/// Same 5-byte tail `announce_emitted` reads from an incoming packet.
pub fn timebase_from_random_blob(random_blob: &[u8]) -> u64 {
    if random_blob.len() < RANDOM_BLOB_LEN {
        return 0;
    }
    let mut bytes = [0u8; 8];
    bytes[3..8].copy_from_slice(&random_blob[5..RANDOM_BLOB_LEN]);
    u64::from_be_bytes(bytes)
}

/// Newest emission time among stored announce blobs
/// (Python `Transport.timebase_from_random_blobs`).
pub fn timebase_from_random_blobs(random_blobs: &[[u8; RANDOM_BLOB_LEN]]) -> u64 {
    random_blobs
        .iter()
        .map(|blob| timebase_from_random_blob(blob))
        .max()
        .unwrap_or(0)
}

pub(super) fn path_lifetime(mode: InterfaceMode) -> core::time::Duration {
    match mode {
        InterfaceMode::AccessPoint => AP_PATH_TIME,
        InterfaceMode::Roaming => ROAMING_PATH_TIME,
        _ => PATHFINDER_E,
    }
}

/// Absolute expiry for a path inserted now (Python writes `IDX_PT_EXPIRES`
/// once, from the mode lifetime, and leaves it alone afterwards).
pub(super) fn path_expires_unix(mode: InterfaceMode) -> f64 {
    unix_secs() + path_lifetime(mode).as_secs_f64()
}

fn unix_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

pub(super) fn monotonic_ns(now: core::time::Duration) -> i64 {
    now.as_nanos().min(i64::MAX as u128) as i64
}

/// Age of a path learned at `timestamp_ns` (see [`PathEntry::timestamp`]).
pub(super) fn path_age(now: core::time::Duration, timestamp_ns: i64) -> core::time::Duration {
    let delta = monotonic_ns(now).saturating_sub(timestamp_ns);
    if delta <= 0 {
        core::time::Duration::ZERO
    } else {
        core::time::Duration::from_nanos(delta as u64)
    }
}

fn announce_random_blob(packet: &Packet) -> Option<[u8; RANDOM_BLOB_LEN]> {
    let data = packet.data.as_slice();
    let start = crate::iface::control::RANDOM_BLOB_OFFSET;
    let end = start + RANDOM_BLOB_LEN;
    if data.len() < end {
        return None;
    }
    let mut blob = [0u8; RANDOM_BLOB_LEN];
    blob.copy_from_slice(&data[start..end]);
    Some(blob)
}

fn remember_blob(blobs: &mut Vec<[u8; RANDOM_BLOB_LEN]>, blob: Option<[u8; RANDOM_BLOB_LEN]>) {
    let Some(blob) = blob else {
        return;
    };
    if blobs.contains(&blob) {
        return;
    }
    blobs.push(blob);
    if blobs.len() > MAX_RANDOM_BLOBS {
        let overflow = blobs.len() - MAX_RANDOM_BLOBS;
        blobs.drain(0..overflow);
    }
}

pub struct PathTable {
    map: HashMap<AddressHash, PathEntry>,
    reroute_eager: bool,
    now: fn() -> core::time::Duration,
}

impl PathTable {
    pub fn new(reroute_eager: bool) -> Self {
        Self {
            map: HashMap::new(),
            reroute_eager,
            now: crate::time::now,
        }
    }

    /// Drop paths whose age exceeds the lifetime of the interface mode
    /// that learned them (Python `Transport.expire_paths`: access point
    /// after `AP_PATH_TIME`, roaming after `ROAMING_PATH_TIME`, otherwise
    /// `DESTINATION_TIMEOUT`, which equals `PATHFINDER_E`).
    pub fn expire_paths(&mut self) -> usize {
        let now = (self.now)();
        let before = self.map.len();
        self.map
            .retain(|_, entry| path_age(now, entry.timestamp) < path_lifetime(entry.mode));
        before - self.map.len()
    }

    /// Mark a path unresponsive (Python `Transport.mark_path_unresponsive`).
    /// The entry stays routable. An equal-hop announce may replace it.
    pub fn mark_path_unresponsive(&mut self, destination: &AddressHash) -> bool {
        match self.map.get_mut(destination) {
            Some(entry) => {
                entry.unresponsive = true;
                true
            }
            None => false,
        }
    }

    /// Clear the unresponsive mark (Python `Transport.mark_path_responsive`).
    pub fn mark_path_responsive(&mut self, destination: &AddressHash) -> bool {
        match self.map.get_mut(destination) {
            Some(entry) => {
                entry.unresponsive = false;
                true
            }
            None => false,
        }
    }

    pub fn path_is_unresponsive(&self, destination: &AddressHash) -> bool {
        self.map
            .get(destination)
            .map(|e| e.unresponsive)
            .unwrap_or(false)
    }

    /// Remove a single path (Python `Transport.drop_path`).
    pub fn drop_path(&mut self, destination: &AddressHash) -> bool {
        self.map.remove(destination).is_some()
    }

    /// Remove all paths learned via an interface (Python `drop_all_via`).
    pub fn drop_all_via(&mut self, iface: &AddressHash) -> usize {
        let before = self.map.len();
        self.map.retain(|_, entry| &entry.iface != iface);
        before - self.map.len()
    }

    /// Drop paths whose interface is no longer attached.
    pub fn drop_ifaces_not_in(&mut self, live: &[AddressHash]) -> usize {
        let before = self.map.len();
        self.map.retain(|_, entry| live.contains(&entry.iface));
        before - self.map.len()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Insert an entry loaded from storage. The caller has already checked
    /// that the interface is still attached and the identity is not blackholed.
    pub fn restore(&mut self, destination: AddressHash, entry: PathEntry) {
        self.map.insert(destination, entry);
    }

    pub fn get(&self, destination: &AddressHash) -> Option<&PathEntry> {
        self.map.get(destination)
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, destination: &AddressHash) -> Option<&mut PathEntry> {
        self.map.get_mut(destination)
    }

    /// Make a path due for removal on the next [`Self::expire_paths`]
    /// (Python `Transport.expire_path` zeroes the unix timestamp so the
    /// next cull sees it as long expired). Does not use timestamp zero:
    /// that value is the boot instant.
    pub fn expire_path(&mut self, destination: &AddressHash) -> bool {
        match self.map.get_mut(destination) {
            Some(entry) => {
                let now_ns = monotonic_ns((self.now)());
                let life_ns = path_lifetime(entry.mode).as_nanos().min(i64::MAX as u128) as i64;
                entry.timestamp = now_ns.saturating_sub(life_ns).saturating_sub(1);
                true
            }
            None => false,
        }
    }

    /// Whether an entry exists, including retained unresponsive entries used
    /// for diagnostics and equal-hop recovery.
    pub fn contains(&self, destination: &AddressHash) -> bool {
        self.map.contains_key(destination)
    }

    /// Insert a path restored from a tunnel table entry
    /// (Python `handle_tunnel` restore: writes the tunnel path entry
    /// directly into the path table).
    pub fn insert_restored(
        &mut self,
        destination: AddressHash,
        received_from: AddressHash,
        hops: u8,
        iface: AddressHash,
        packet_hash: crate::hash::Hash,
    ) {
        self.map.insert(
            destination,
            PathEntry {
                received_from,
                hops,
                iface,
                timestamp: monotonic_ns((self.now)()),
                unresponsive: false,
                packet_hash,
                mode: InterfaceMode::Full,
                expires_unix: path_expires_unix(InterfaceMode::Full),
                random_blobs: Vec::new(),
                gravity: None,
            },
        );
    }

    pub fn next_hop_full(&self, destination: &AddressHash) -> Option<(AddressHash, AddressHash)> {
        self.map
            .get(destination)
            .map(|entry| (entry.received_from, entry.iface))
    }

    /// Record an announce heard on an interface of `mode` with optional
    /// `gravity`.
    ///
    /// Fewer hops replace the current path. More hops do not. An equal hop
    /// count replaces it when `announce_emitted` is newer than
    /// `timebase_from_random_blobs` of the stored blobs, then when both
    /// gravities are set and the new one is strictly heavier, then when
    /// the path is unresponsive or `reroute_eager` is set.
    pub fn handle_announce_with_mode(
        &mut self,
        announce: &Packet,
        transport_id: Option<AddressHash>,
        iface: AddressHash,
        mode: InterfaceMode,
        gravity: Option<i64>,
    ) {
        let hops = announce.header.hops + 1;
        let new_blob = announce_random_blob(announce);
        let emitted = crate::iface::control::announce_emitted(announce);

        let mut random_blobs = if let Some(existing) = self.map.get(&announce.destination) {
            if !self.should_replace_path(existing, hops, new_blob, emitted, gravity) {
                return;
            }
            // Move the history out of the old entry so an accepted update
            // keeps the Vec backing allocation instead of cloning it.
            self.map
                .get_mut(&announce.destination)
                .map(|entry| std::mem::take(&mut entry.random_blobs))
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        remember_blob(&mut random_blobs, new_blob);

        let received_from = transport_id.unwrap_or(announce.destination);
        let new_entry = PathEntry {
            received_from,
            hops,
            iface,
            timestamp: monotonic_ns((self.now)()),
            unresponsive: false,
            packet_hash: announce.hash(),
            mode,
            expires_unix: path_expires_unix(mode),
            random_blobs,
            gravity,
        };

        self.map.insert(announce.destination, new_entry);

        log::info!(
            "{} is now reachable over {} hops through {}",
            announce.destination,
            hops,
            received_from,
        );
    }

    /// Fewer hops replace the path. More hops do not. Equal hops replace it
    /// when the emission timebase is newer, then when both gravities are
    /// set and the new one is heavier, then when the path is unresponsive
    /// or `reroute_eager` is set.
    fn should_replace_path(
        &self,
        existing: &PathEntry,
        hops: u8,
        new_blob: Option<[u8; RANDOM_BLOB_LEN]>,
        emitted: u64,
        gravity: Option<i64>,
    ) -> bool {
        if hops > existing.hops {
            return false;
        }
        if hops < existing.hops {
            return true;
        }

        let path_timebase = timebase_from_random_blobs(&existing.random_blobs);
        if let Some(blob) = new_blob {
            if !existing.random_blobs.contains(&blob) && emitted > path_timebase {
                return true;
            }
            if emitted == path_timebase {
                if let (Some(announce_gravity), Some(current_gravity)) = (gravity, existing.gravity)
                {
                    if announce_gravity > current_gravity {
                        return true;
                    }
                }
            }
        }

        existing.unresponsive || self.reroute_eager
    }

    pub fn handle_inbound_packet(
        &mut self,
        original_packet: &Packet,
        lookup: Option<AddressHash>,
    ) -> (Packet, Option<AddressHash>) {
        let lookup = lookup.unwrap_or(original_packet.destination);

        let entry = match self.map.get(&lookup) {
            Some(entry) => entry,
            None => return (original_packet.clone(), None),
        };

        // Python `Transport.inbound` path-forwarding: with more than one
        // hop to go the packet stays addressed (HEADER_2 + TRANSPORT
        // propagation) to the next transport node; when the destination
        // itself is the next hop (single hop left) the transport headers
        // are stripped (HEADER_1 + BROADCAST) so the endpoint receives a
        // plain broadcast-form packet.
        let last_hop = entry.hops <= 1;
        let iface = entry.iface;
        let next_hop = entry.received_from;

        // Routed traffic refreshes the path timestamp (Python updates
        // `IDX_PT_TIMESTAMP` after forwarding).
        if let Some(entry) = self.map.get_mut(&lookup) {
            entry.timestamp = monotonic_ns((self.now)());
        }

        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: if last_hop {
                        HeaderType::Type1
                    } else {
                        HeaderType::Type2
                    },
                    propagation_type: if last_hop {
                        PropagationType::Broadcast
                    } else {
                        PropagationType::Transport
                    },
                    hops: original_packet.header.hops + 1,
                    ..original_packet.header
                },
                ifac: None,
                destination: original_packet.destination,
                transport: if last_hop { None } else { Some(next_hop) },
                context: original_packet.context,
                data: original_packet.data.clone(),
            },
            Some(iface),
        )
    }

    /// Route an outbound packet (Python `Transport.outbound`).
    ///
    /// Only packets with more than one hop to the destination are inserted
    /// into transport (header type 2 with the next-hop transport id);
    /// directly reachable destinations are transmitted as-is. Python drops
    /// data packets carrying a transport id that is not its own, so
    /// wrapping single-hop packets would never be delivered.
    /// Update the hop count of a known path (link-request proof
    /// rebalancing, Python writes `IDX_PT_HOPS` directly).
    pub fn rebalance_hops(&mut self, destination: &AddressHash, hops: u8) -> bool {
        match self.map.get_mut(destination) {
            Some(entry) => {
                entry.hops = hops;
                true
            }
            None => false,
        }
    }

    /// Route a locally-originated packet toward its destination.
    /// Python `Transport.outbound` writes the packet's own hop count
    /// (0 for freshly created packets); relays add hops on receive.
    pub fn handle_local_packet(
        &mut self,
        original_packet: &Packet,
    ) -> (Packet, Option<AddressHash>) {
        let lookup = original_packet.destination;

        let entry = match self.map.get(&lookup) {
            Some(entry) => entry,
            None => return (original_packet.clone(), None),
        };

        // Python `Transport.outbound`: packets for destinations more than
        // one hop away are inserted into transport (HEADER_2 + TRANSPORT
        // propagation, next-hop transport id, own hop count); paths with a
        // single hop transmit the packet unchanged on the path interface.
        let direct = entry.hops <= 1;
        let iface = entry.iface;
        let next_hop = entry.received_from;

        if let Some(entry) = self.map.get_mut(&lookup) {
            entry.timestamp = monotonic_ns((self.now)());
        }

        if direct {
            return (original_packet.clone(), Some(iface));
        }

        (
            Packet {
                header: Header {
                    ifac_flag: IfacFlag::Open,
                    header_type: HeaderType::Type2,
                    propagation_type: PropagationType::Transport,
                    hops: original_packet.header.hops,
                    ..original_packet.header
                },
                ifac: None,
                destination: original_packet.destination,
                transport: Some(next_hop),
                context: original_packet.context,
                data: original_packet.data.clone(),
            },
            Some(iface),
        )
    }

    pub fn handle_packet(&mut self, original_packet: &Packet) -> (Packet, Option<AddressHash>) {
        if original_packet.header.header_type == HeaderType::Type2 {
            return (original_packet.clone(), None);
        }

        if original_packet.header.packet_type == PacketType::Announce {
            return (original_packet.clone(), None);
        }

        if original_packet.header.destination_type == DestinationType::Plain
            || original_packet.header.destination_type == DestinationType::Group
        {
            return (original_packet.clone(), None);
        }

        let entry = match self.map.get(&original_packet.destination) {
            Some(entry) => entry,
            None => return (original_packet.clone(), None),
        };

        if entry.hops <= 1 {
            // Directly reachable: transmit the packet unchanged.
            return (original_packet.clone(), Some(entry.iface));
        }

        (
            Packet {
                header: Header {
                    header_type: HeaderType::Type2,
                    ..original_packet.header
                },
                ifac: original_packet.ifac,
                destination: original_packet.destination,
                transport: Some(entry.received_from),
                context: original_packet.context,
                data: original_packet.data.clone(),
            },
            Some(entry.iface),
        )
    }
}

// ---------------------------------------------------------------------------
// Read-only snapshots for tooling (`rnpath`/`rnstatus`, Phase 8 utilities).
// Appended for the Phase 7/8 utilities work; the routing logic above is
// untouched.
// ---------------------------------------------------------------------------

impl PathTable {
    /// Iterate over all known paths (destination, entry).
    #[allow(dead_code)] // len/is_empty used by rnstatus tooling builds
    pub fn iter(&self) -> impl Iterator<Item = (&AddressHash, &PathEntry)> {
        self.map.iter()
    }

    /// Any known destination hash (diagnostics/tests).
    pub fn any_destination(&self) -> Option<AddressHash> {
        self.map.keys().next().copied()
    }

    /// Number of known paths.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether any path is known.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketContext, PacketDataBuffer};

    fn address(byte: u8) -> AddressHash {
        AddressHash::new_from_slice(&[byte; 32])
    }

    fn announce(destination: AddressHash, hops: u8, marker: u8) -> Packet {
        Packet {
            header: Header {
                packet_type: PacketType::Announce,
                hops,
                ..Default::default()
            },
            destination,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&[marker]),
            ..Default::default()
        }
    }

    #[test]
    fn unresponsive_paths_stay_visible_until_an_equal_hop_announce() {
        let destination = address(1);
        let first_iface = address(2);
        let recovered_iface = address(3);
        let mut table = PathTable::new(false);
        table.handle_announce_with_mode(
            &announce(destination, 0, 1),
            None,
            first_iface,
            InterfaceMode::Full,
            None,
        );
        assert!(table.get(&destination).is_some());

        assert!(table.mark_path_unresponsive(&destination));
        assert!(table.contains(&destination));
        assert_eq!(table.get(&destination).unwrap().hops, 1);
        assert_eq!(
            table.next_hop_full(&destination),
            Some((destination, first_iface))
        );
        assert_eq!(table.iter().count(), 1, "diagnostics retain the entry");

        let packet = Packet {
            destination,
            ..Default::default()
        };
        assert_eq!(table.handle_packet(&packet).1, Some(first_iface));
        assert_eq!(
            table.handle_inbound_packet(&packet, None).1,
            Some(first_iface)
        );

        // A fresh equal-hop announce replaces the unresponsive path even
        // without eager rerouting.
        table.handle_announce_with_mode(
            &announce(destination, 0, 2),
            None,
            recovered_iface,
            InterfaceMode::Full,
            None,
        );
        assert!(!table.path_is_unresponsive(&destination));
        assert_eq!(table.get(&destination).unwrap().iface, recovered_iface);

        assert!(table.mark_path_unresponsive(&destination));
        assert!(table.mark_path_responsive(&destination));
        assert!(table.get(&destination).is_some());
    }

    use std::cell::Cell;

    thread_local! {
        static CLOCK_SECS: Cell<u64> = const { Cell::new(0) };
    }

    fn clock() -> core::time::Duration {
        CLOCK_SECS.with(|cell| core::time::Duration::from_secs(cell.get()))
    }

    fn set_clock(secs: u64) {
        CLOCK_SECS.with(|cell| cell.set(secs));
    }

    fn announce_at(destination: AddressHash, hops: u8, emitted: u64, marker: u8) -> Packet {
        let mut data = vec![0u8; crate::iface::control::RANDOM_BLOB_OFFSET + RANDOM_BLOB_LEN];
        let start = crate::iface::control::RANDOM_BLOB_OFFSET;
        data[start] = marker;
        let timestamp = emitted.to_be_bytes();
        data[start + 5..start + RANDOM_BLOB_LEN].copy_from_slice(&timestamp[3..8]);
        Packet {
            header: Header {
                packet_type: PacketType::Announce,
                hops,
                ..Default::default()
            },
            destination,
            context: PacketContext::None,
            data: PacketDataBuffer::new_from_slice(&data),
            ..Default::default()
        }
    }

    fn learn(
        table: &mut PathTable,
        destination: AddressHash,
        iface: AddressHash,
        mode: InterfaceMode,
        gravity: Option<i64>,
        emitted: u64,
        marker: u8,
    ) {
        table.handle_announce_with_mode(
            &announce_at(destination, 0, emitted, marker),
            None,
            iface,
            mode,
            gravity,
        );
    }

    #[test]
    fn expiry_follows_interface_mode() {
        let destination = address(1);
        let iface = address(2);
        let cases = [
            (InterfaceMode::Full, PATHFINDER_E),
            (InterfaceMode::AccessPoint, AP_PATH_TIME),
            (InterfaceMode::Roaming, ROAMING_PATH_TIME),
        ];

        for (mode, lifetime) in cases {
            let mut table = PathTable::new(false);
            table.now = clock;
            set_clock(1_000);
            learn(&mut table, destination, iface, mode, None, 50, 1);

            set_clock(1_000 + lifetime.as_secs() - 1);
            assert_eq!(
                table.expire_paths(),
                0,
                "{mode:?} stays inside its lifetime"
            );
            assert!(table.contains(&destination));

            set_clock(1_000 + lifetime.as_secs());
            assert_eq!(table.expire_paths(), 1, "{mode:?} expires at its lifetime");
            assert!(!table.contains(&destination));
        }
    }

    #[test]
    fn newer_timebase_replaces_equal_hop_path() {
        let destination = address(4);
        let first = address(5);
        let second = address(6);
        let mut table = PathTable::new(false);

        learn(
            &mut table,
            destination,
            first,
            InterfaceMode::Full,
            None,
            1_000,
            1,
        );
        // Same hop count, older emission: keep the current path.
        learn(
            &mut table,
            destination,
            second,
            InterfaceMode::Full,
            None,
            999,
            2,
        );
        let entry = table.get(&destination).unwrap();
        assert_eq!(entry.iface, first);
        assert_eq!(
            entry.random_blobs.len(),
            1,
            "rejected announce leaves blob history untouched"
        );

        // Same emission time, no gravity advantage: still keep it.
        learn(
            &mut table,
            destination,
            second,
            InterfaceMode::Full,
            None,
            1_000,
            3,
        );
        assert_eq!(table.get(&destination).unwrap().iface, first);

        learn(
            &mut table,
            destination,
            second,
            InterfaceMode::Full,
            None,
            1_001,
            4,
        );
        let entry = table.get(&destination).unwrap();
        assert_eq!(entry.iface, second);
        assert_eq!(timebase_from_random_blobs(&entry.random_blobs), 1_001);
        assert!(entry.random_blobs.len() >= 2);
    }

    #[test]
    fn higher_gravity_wins_equal_hops() {
        let destination = address(7);
        let low_iface = address(8);
        let high_iface = address(9);
        let mut table = PathTable::new(false);

        learn(
            &mut table,
            destination,
            low_iface,
            InterfaceMode::Full,
            Some(1),
            5_000,
            1,
        );
        // Equal hops and equal emission: a lower or equal gravity must not
        // take the path from the heavier interface.
        learn(
            &mut table,
            destination,
            high_iface,
            InterfaceMode::Full,
            Some(1),
            5_000,
            2,
        );
        assert_eq!(table.get(&destination).unwrap().iface, low_iface);
        learn(
            &mut table,
            destination,
            high_iface,
            InterfaceMode::Full,
            Some(0),
            5_000,
            3,
        );
        assert_eq!(table.get(&destination).unwrap().iface, low_iface);

        learn(
            &mut table,
            destination,
            high_iface,
            InterfaceMode::Full,
            Some(4),
            5_000,
            4,
        );
        assert_eq!(table.get(&destination).unwrap().iface, high_iface);
        assert_eq!(table.get(&destination).unwrap().gravity, Some(4));

        learn(
            &mut table,
            destination,
            low_iface,
            InterfaceMode::Full,
            Some(2),
            5_000,
            5,
        );
        assert_eq!(table.get(&destination).unwrap().iface, high_iface);
    }

    #[test]
    fn repeated_announces_keep_blob_history_capped_at_max() {
        let destination = address(10);
        let iface = address(11);
        let mut table = PathTable::new(false);

        let total = MAX_RANDOM_BLOBS + 6;
        for i in 0..total as u64 {
            learn(
                &mut table,
                destination,
                iface,
                InterfaceMode::Full,
                None,
                10_000 + i,
                i as u8,
            );
        }

        let entry = table.get(&destination).unwrap();
        assert_eq!(entry.random_blobs.len(), MAX_RANDOM_BLOBS);

        // The newest blob stays findable while the evicted oldest is not.
        let newest = announce_random_blob(&announce_at(
            destination,
            0,
            10_000 + total as u64 - 1,
            (total - 1) as u8,
        ))
        .unwrap();
        let evicted = announce_random_blob(&announce_at(destination, 0, 10_000, 0)).unwrap();
        assert!(entry.random_blobs.contains(&newest));
        assert!(!entry.random_blobs.contains(&evicted));
        assert_eq!(
            timebase_from_random_blobs(&entry.random_blobs),
            10_000 + total as u64 - 1
        );
    }

    #[test]
    fn expire_path_is_due_on_the_next_cull_even_at_boot() {
        let destination = address(11);
        let iface = address(12);
        let mut table = PathTable::new(false);
        table.now = clock;
        set_clock(0);
        learn(
            &mut table,
            destination,
            iface,
            InterfaceMode::Full,
            None,
            1,
            1,
        );
        assert_eq!(table.get(&destination).unwrap().timestamp, 0);
        assert!(table.expire_path(&destination));
        assert_ne!(table.get(&destination).unwrap().timestamp, 0);
        assert_eq!(table.expire_paths(), 1);
        assert!(!table.contains(&destination));
    }

    #[test]
    fn restored_age_is_not_a_fresh_lifetime_when_uptime_is_short() {
        let destination = address(13);
        let iface = address(14);
        let mut table = PathTable::new(false);
        table.now = clock;
        set_clock(10);
        learn(
            &mut table,
            destination,
            iface,
            InterfaceMode::Full,
            None,
            1,
            1,
        );
        let learned = table.get(&destination).unwrap().timestamp;
        // One second of lifetime left, but the process has only been up 10s.
        let almost_expired = learned - (PATHFINDER_E.as_nanos() as i64) + 1_000_000_000;
        table.get_mut(&destination).unwrap().timestamp = almost_expired;
        assert_eq!(table.expire_paths(), 0);
        set_clock(12);
        assert_eq!(table.expire_paths(), 1);
    }

    #[test]
    fn timebase_from_random_blob_reads_bytes_5_through_10() {
        let mut blob = [0u8; RANDOM_BLOB_LEN];
        blob[5..].copy_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(timebase_from_random_blob(&blob), 0x1_0000);
        assert_eq!(timebase_from_random_blob(&blob[..5]), 0);
        let older = [0u8; RANDOM_BLOB_LEN];
        assert_eq!(timebase_from_random_blobs(&[older, blob]), 0x1_0000);
        let packet = announce_at(address(1), 0, 0x1_0000, 7);
        assert_eq!(
            crate::iface::control::announce_emitted(&packet),
            timebase_from_random_blob(&announce_random_blob(&packet).unwrap())
        );
    }
}
