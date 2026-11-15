//! Identity blackholing: announces and paths from blackholed identities are
//! dropped network-wide (Python `Reticulum.blackhole_identity`, the
//! `/list` request handler and the on-disk blackhole store).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::hash::AddressHash;
use crate::storage::Storage;

/// Storage directory of the blackhole lists
/// (Python `RNS.Reticulum.blackholepath`).
pub const BLACKHOLE_DIR: &str = "blackhole";

/// One blackholed identity.
///
/// Python `Transport.blackholed_identities` maps
/// `identity_hash -> {"source": <identity hash>, "until": <unix ts>|None, "reason": <str>|None}`.
#[derive(Clone, Debug, PartialEq)]
pub struct BlackholeEntry {
    /// Identity that published the blackhole entry.
    pub source: AddressHash,
    /// Unix timestamp after which the entry expires (`None` = never).
    pub until: Option<f64>,
    /// Optional human-readable reason.
    pub reason: Option<String>,
}

/// A set of blackholed identity hashes with source tracking.
pub struct Blackholes {
    entries: HashMap<AddressHash, BlackholeEntry>,
    /// Whether this node republishes the blackhole list
    /// (Python `publish_blackhole`).
    publish: bool,
    /// Injected unix-time clock (seconds) for tests.
    now: fn() -> f64,
}

fn unix_now() -> f64 {
    crate::time::unix_time_as_secs() as f64
}

impl Default for Blackholes {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            publish: false,
            now: unix_now,
        }
    }
}

impl Blackholes {
    pub fn new(publish: bool) -> Self {
        Self {
            entries: HashMap::new(),
            publish,
            now: unix_now,
        }
    }

    /// Replace the clock used for expiry (tests).
    pub fn with_clock(mut self, now: fn() -> f64) -> Self {
        self.now = now;
        self
    }

    /// Blackhole an identity (Python `Reticulum.blackhole_identity`).
    pub fn blackhole(
        &mut self,
        identity: AddressHash,
        source: AddressHash,
        until: Option<f64>,
        reason: Option<String>,
    ) {
        self.entries.insert(
            identity,
            BlackholeEntry {
                source,
                until,
                reason,
            },
        );
    }

    /// Remove an identity from the blacklist
    /// (Python `Reticulum.unblackhole_identity`).
    pub fn unblackhole(&mut self, identity: &AddressHash) -> bool {
        self.entries.remove(identity).is_some()
    }

    /// Whether an identity is currently blackholed
    /// (entries past their `until` still count until `clean` runs,
    /// exactly like Python's table).
    pub fn is_blackholed(&self, identity: &AddressHash) -> bool {
        self.entries.contains_key(identity)
    }

    /// All currently blackholed identities.
    pub fn blackholed_identities(&self) -> Vec<AddressHash> {
        self.entries.keys().copied().collect()
    }

    /// Whether this node publishes its blacklist
    /// (Python `Reticulum.publish_blackhole_enabled`).
    pub fn publish_enabled(&self) -> bool {
        self.publish
    }

    /// Drop entries whose `until` has passed
    /// (Python's 60s blackhole check job; in-memory only — persisted
    /// lists are filtered again on reload).
    pub fn clean(&mut self) -> usize {
        let now = (self.now)();
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| entry.until.is_none_or(|until| now < until));
        before - self.entries.len()
    }

    /// Pack the whole table as the Python wire/storage format:
    /// msgpack map `{<16-byte hash>: {"source": <hash>, "until": <f64|nil>, "reason": <str|nil>}}`
    /// (Python `blackhole_list_handler` returns this exact dict).
    pub fn pack_table(&self) -> Vec<u8> {
        let mut out = Vec::new();
        rmp::encode::write_map_len(&mut out, self.entries.len() as u32).ok();
        for (hash, entry) in &self.entries {
            rmp::encode::write_bin(&mut out, hash.as_slice()).ok();
            pack_entry(&mut out, entry);
        }
        out
    }

    /// Parse a packed table; `None` when it is not the expected dict shape.
    pub fn parse_table(packed: &[u8]) -> Option<Vec<(AddressHash, BlackholeEntry)>> {
        let mut cursor: &[u8] = packed;
        let count = rmp::decode::read_map_len(&mut cursor).ok()?;
        let mut out = Vec::new();
        for _ in 0..count {
            let len = rmp::decode::read_bin_len(&mut cursor).ok()? as usize;
            if len != 16 || cursor.len() < len {
                return None;
            }
            let hash = AddressHash::new(cursor[..len].try_into().ok()?);
            cursor = &cursor[len..];
            let entry = parse_entry(&mut cursor)?;
            out.push((hash, entry));
        }
        Some(out)
    }

    /// Merge a packed table fetched from `publisher`
    /// (Python `Discovery.BlackholeUpdater.update_response_received`):
    /// every unknown identity is inserted verbatim, existing entries are
    /// never replaced.
    pub fn merge_table(
        &mut self,
        packed: &[u8],
        publisher: AddressHash,
        _local_identity: AddressHash,
    ) -> usize {
        let Some(list) = Self::parse_table(packed) else {
            return 0;
        };
        let mut merged = 0;
        for (hash, mut entry) in list {
            if entry.source != publisher {
                entry.source = publisher;
            }
            if let std::collections::hash_map::Entry::Vacant(slot) = self.entries.entry(hash) {
                slot.insert(entry);
                merged += 1;
            }
        }
        merged
    }

    /// Persist the locally sourced entries to `<storage>/blackhole/local`
    /// (Python `Transport.persist_blackhole`: only entries sourced from
    /// this node's identity, written atomically as msgpack).
    pub fn persist_local(
        &self,
        storage: &dyn Storage,
        own: &AddressHash,
    ) -> Result<(), crate::error::RnsError> {
        let mut out = Vec::new();
        let local: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| &entry.source == own)
            .collect();
        rmp::encode::write_map_len(&mut out, local.len() as u32).ok();
        for (hash, entry) in local {
            rmp::encode::write_bin(&mut out, hash.as_slice()).ok();
            pack_entry(&mut out, entry);
        }
        storage.write(&format!("{BLACKHOLE_DIR}/local"), &out)
    }

    /// Load blackhole lists from storage
    /// (Python `Transport.reload_blackhole`): the `local` file is sourced
    /// from this node's identity, every other file from the identity hash
    /// in its (hex) file name — skipped when that source is not in
    /// `allowed_sources` (Python `Reticulum.blackhole_sources`). Entries
    /// whose `until` has passed are ignored and locally sourced entries
    /// always win over remote ones.
    pub fn reload(
        &mut self,
        storage: &dyn Storage,
        own: &AddressHash,
        allowed_sources: &[AddressHash],
    ) -> usize {
        let now = (self.now)();
        let mut loaded = 0;
        for filename in storage.list(BLACKHOLE_DIR) {
            let source = match filename.as_str() {
                "local" => *own,
                name => {
                    let Ok(source) = hex_to_hash(name) else {
                        continue;
                    };
                    if !allowed_sources.contains(&source) {
                        continue;
                    }
                    source
                }
            };
            let Some(packed) = storage.read(&format!("{BLACKHOLE_DIR}/{filename}")) else {
                continue;
            };
            let Some(list) = Self::parse_table(&packed) else {
                continue;
            };
            for (hash, mut entry) in list {
                if entry.until.is_some_and(|until| now >= until) {
                    continue;
                }
                entry.source = source;
                match self.entries.get(&hash) {
                    Some(existing) if existing.source == *own => {}
                    _ => {
                        self.entries.insert(hash, entry);
                        loaded += 1;
                    }
                }
            }
        }
        loaded
    }
}

fn pack_entry(out: &mut Vec<u8>, entry: &BlackholeEntry) {
    rmp::encode::write_map_len(out, 3).ok();
    rmp::encode::write_str(out, "source").ok();
    rmp::encode::write_bin(out, entry.source.as_slice()).ok();
    rmp::encode::write_str(out, "until").ok();
    match entry.until {
        Some(until) => {
            rmp::encode::write_f64(out, until).ok();
        }
        None => {
            rmp::encode::write_nil(out).ok();
        }
    }
    rmp::encode::write_str(out, "reason").ok();
    match &entry.reason {
        Some(reason) => {
            rmp::encode::write_str(out, reason).ok();
        }
        None => {
            rmp::encode::write_nil(out).ok();
        }
    }
}

/// Read a msgpack string without a length cap
/// (unknown/future keys may be arbitrarily long).
fn read_str_raw(cursor: &mut &[u8]) -> Option<String> {
    let len = rmp::decode::read_str_len(cursor).ok()? as usize;
    if cursor.len() < len {
        return None;
    }
    let value = core::str::from_utf8(&cursor[..len]).ok()?;
    *cursor = &cursor[len..];
    Some(value.to_string())
}

fn parse_entry(cursor: &mut &[u8]) -> Option<BlackholeEntry> {
    let count = rmp::decode::read_map_len(cursor).ok()?;
    let mut source = None;
    let mut until = None;
    let mut reason = None;
    for _ in 0..count {
        let key = read_str_raw(cursor)?;
        // Entry values are heterogeneous (`nil`, `f64`, `str`): read one
        // msgpack value of any type and interpret it per key, like
        // Python's dict access.
        let value = rmpv::decode::read_value(cursor).ok()?;
        match key.as_str() {
            "source" => {
                let bytes = match &value {
                    rmpv::Value::Binary(bytes) => bytes.as_slice(),
                    _ => return None,
                };
                let array: [u8; 16] = bytes.try_into().ok()?;
                source = Some(AddressHash::new(array));
            }
            "until" => {
                until = value.as_f64();
            }
            "reason" => {
                reason = value.as_str().map(str::to_string);
            }
            _ => {
                // Unknown (future) key: tolerate it, Python accesses
                // entries by name and ignores extra fields.
            }
        }
    }
    Some(BlackholeEntry {
        source: source?,
        until,
        reason,
    })
}

/// Decode a hex string without pulling in a hex crate
/// (lower-case and upper-case both accepted).
fn decode_hex(input: &str) -> Result<Vec<u8>, ()> {
    fn value(c: u8) -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(()),
        }
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        out.push((value(pair[0])? << 4) | value(pair[1])?);
    }
    Ok(out)
}

/// Parse a 32-character hex identity hash
/// (Python validates `len(filename) == dest_len` in `reload_blackhole`).
fn hex_to_hash(hex: &str) -> Result<AddressHash, ()> {
    let bytes = decode_hex(hex)?;
    let array: [u8; 16] = bytes.try_into().map_err(|_| ())?;
    Ok(AddressHash::new(array))
}

/// Shared blackhole store used by the transport.
pub type SharedBlackholes = Arc<RwLock<Blackholes>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn hash(byte: u8) -> AddressHash {
        AddressHash::new([byte; 16])
    }

    #[test]
    fn blackhole_roundtrip() {
        let mut bh = Blackholes::new(false);
        let id = hash(1);
        assert!(!bh.is_blackholed(&id));
        bh.blackhole(id, hash(9), None, None);
        assert!(bh.is_blackholed(&id));
        assert!(bh.unblackhole(&id));
        assert!(!bh.is_blackholed(&id));
    }

    #[test]
    fn pack_parse_table_roundtrip() {
        let mut bh = Blackholes::new(true);
        bh.blackhole(hash(1), hash(9), Some(1_800_000_000.5), Some("spam".into()));
        bh.blackhole(hash(2), hash(9), None, None);
        let packed = bh.pack_table();
        let parsed = Blackholes::parse_table(&packed).unwrap();
        assert_eq!(parsed.len(), 2);
        // map iteration order differs; check by key
        assert!(parsed.iter().any(|(h, e)| *h == hash(1)
            && e.source == hash(9)
            && e.until == Some(1_800_000_000.5)
            && e.reason.as_deref() == Some("spam")));
        assert!(parsed
            .iter()
            .any(|(h, e)| *h == hash(2) && e.until.is_none() && e.reason.is_none()));
    }

    #[test]
    fn merge_table_matches_python_shape() {
        // A packed table exactly like a Python node serves it.
        let mut packed = Vec::new();
        rmp::encode::write_map_len(&mut packed, 2).ok();
        for b in [1u8, 2u8] {
            rmp::encode::write_bin(&mut packed, &[b; 16]).ok();
            rmp::encode::write_map_len(&mut packed, 3).ok();
            rmp::encode::write_str(&mut packed, "source").ok();
            rmp::encode::write_bin(&mut packed, &[9u8; 16]).ok();
            rmp::encode::write_str(&mut packed, "until").ok();
            rmp::encode::write_f64(&mut packed, 4e9).ok();
            rmp::encode::write_str(&mut packed, "reason").ok();
            rmp::encode::write_nil(&mut packed).ok();
        }
        let mut other = Blackholes::new(false);
        let merged = other.merge_table(&packed, hash(9), hash(8));
        assert_eq!(merged, 2);
        assert!(other.is_blackholed(&hash(1)));
        assert!(other.is_blackholed(&hash(2)));
        // merging again adds nothing
        assert_eq!(other.merge_table(&packed, hash(9), hash(8)), 0);
    }

    #[test]
    fn merge_preserves_local_source() {
        let local = hash(0xaa);
        let publisher = hash(0xbb);
        let mut bh = Blackholes::new(false);
        bh.blackhole(local, local, None, None);

        let mut packed = Vec::new();
        rmp::encode::write_map_len(&mut packed, 1).ok();
        rmp::encode::write_bin(&mut packed, local.as_slice()).ok();
        rmp::encode::write_map_len(&mut packed, 3).ok();
        rmp::encode::write_str(&mut packed, "source").ok();
        rmp::encode::write_bin(&mut packed, publisher.as_slice()).ok();
        rmp::encode::write_str(&mut packed, "until").ok();
        rmp::encode::write_nil(&mut packed).ok();
        rmp::encode::write_str(&mut packed, "reason").ok();
        rmp::encode::write_nil(&mut packed).ok();
        // The existing entry stays untouched, whatever its source.
        assert_eq!(bh.merge_table(&packed, publisher, local), 0);
        assert_eq!(bh.entries[&local].source, local);
    }

    #[test]
    fn clean_expires_entries_past_until() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static FAKE_NOW: AtomicU64 = AtomicU64::new(1000);
        fn fake_now() -> f64 {
            FAKE_NOW.load(Ordering::SeqCst) as f64
        }

        let mut bh = Blackholes::new(false).with_clock(fake_now);
        bh.blackhole(hash(1), hash(9), None, None); // never expires
        bh.blackhole(hash(2), hash(9), Some(1100.0), None);
        bh.blackhole(hash(3), hash(9), Some(10_000.0), None);

        FAKE_NOW.store(2000, Ordering::SeqCst);
        assert_eq!(bh.clean(), 1);
        assert!(bh.is_blackholed(&hash(1)));
        assert!(!bh.is_blackholed(&hash(2)));
        assert!(bh.is_blackholed(&hash(3)));
    }

    #[test]
    fn malformed_table_is_ignored() {
        let mut bh = Blackholes::new(false);
        assert_eq!(bh.merge_table(&[0xff, 0xff], hash(9), hash(8)), 0);
        assert_eq!(bh.merge_table(&[], hash(9), hash(8)), 0);
        // an array (legacy Rust format) is not the Python dict shape
        assert_eq!(bh.merge_table(&[0x92, 0xc4, 0x10], hash(9), hash(8)), 0);
    }

    #[test]
    fn persist_and_reload_local() {
        let storage = MemoryStorage::new();
        let own = hash(0xaa);
        let mut bh = Blackholes::new(false);
        bh.blackhole(hash(1), own, None, Some("local entry".into()));
        bh.blackhole(hash(2), hash(0xbb), None, None); // remote: not persisted
        bh.persist_local(&storage, &own).unwrap();

        let mut fresh = Blackholes::new(false);
        let loaded = fresh.reload(&storage, &own, &[]);
        assert_eq!(loaded, 1);
        assert!(fresh.is_blackholed(&hash(1)));
        assert!(!fresh.is_blackholed(&hash(2)));
        assert_eq!(
            fresh.entries[&hash(1)].reason.as_deref(),
            Some("local entry")
        );
    }

    #[test]
    fn reload_skips_disabled_and_expired_sources() {
        let storage = MemoryStorage::new();
        let own = hash(0xaa);
        let allowed = hash(0xbb);
        let disabled = hash(0xcc);

        let pack_for = |source: AddressHash, until: Option<f64>| {
            let mut packed = Vec::new();
            rmp::encode::write_map_len(&mut packed, 1).ok();
            rmp::encode::write_bin(&mut packed, hash(7).as_slice()).ok();
            rmp::encode::write_map_len(&mut packed, 3).ok();
            rmp::encode::write_str(&mut packed, "source").ok();
            rmp::encode::write_bin(&mut packed, source.as_slice()).ok();
            rmp::encode::write_str(&mut packed, "until").ok();
            match until {
                Some(u) => {
                    rmp::encode::write_f64(&mut packed, u).ok();
                }
                None => {
                    rmp::encode::write_nil(&mut packed).ok();
                }
            }
            rmp::encode::write_str(&mut packed, "reason").ok();
            rmp::encode::write_nil(&mut packed).ok();
            packed
        };

        storage
            .write(
                &format!("{BLACKHOLE_DIR}/{}", allowed.to_hex_string()),
                &pack_for(allowed, None),
            )
            .unwrap();
        storage
            .write(
                &format!("{BLACKHOLE_DIR}/{}", disabled.to_hex_string()),
                &pack_for(disabled, None),
            )
            .unwrap();
        storage
            .write(
                &format!("{BLACKHOLE_DIR}/{}", hash(0xdd).to_hex_string()),
                &pack_for(hash(0xdd), Some(1.0)),
            )
            .unwrap();

        let mut bh = Blackholes::new(false);
        let loaded = bh.reload(&storage, &own, &[allowed]);
        assert_eq!(loaded, 1);
        assert!(bh.is_blackholed(&hash(7)));
        assert_eq!(bh.entries[&hash(7)].source, allowed);
    }

    #[test]
    fn reload_prefers_local_entries() {
        let storage = MemoryStorage::new();
        let own = hash(0xaa);
        let remote = hash(0xbb);

        storage
            .write(&format!("{BLACKHOLE_DIR}/local"), &{
                let mut packed = Vec::new();
                rmp::encode::write_map_len(&mut packed, 1).ok();
                rmp::encode::write_bin(&mut packed, hash(5).as_slice()).ok();
                rmp::encode::write_map_len(&mut packed, 3).ok();
                rmp::encode::write_str(&mut packed, "source").ok();
                rmp::encode::write_bin(&mut packed, own.as_slice()).ok();
                rmp::encode::write_str(&mut packed, "until").ok();
                rmp::encode::write_nil(&mut packed).ok();
                rmp::encode::write_str(&mut packed, "reason").ok();
                rmp::encode::write_str(&mut packed, "local reason").ok();
                packed
            })
            .unwrap();
        storage
            .write(&format!("{BLACKHOLE_DIR}/{remote}"), &{
                let mut packed = Vec::new();
                rmp::encode::write_map_len(&mut packed, 1).ok();
                rmp::encode::write_bin(&mut packed, hash(5).as_slice()).ok();
                rmp::encode::write_map_len(&mut packed, 3).ok();
                rmp::encode::write_str(&mut packed, "source").ok();
                rmp::encode::write_bin(&mut packed, remote.as_slice()).ok();
                rmp::encode::write_str(&mut packed, "until").ok();
                rmp::encode::write_nil(&mut packed).ok();
                rmp::encode::write_str(&mut packed, "reason").ok();
                rmp::encode::write_str(&mut packed, "remote reason").ok();
                packed
            })
            .unwrap();

        let mut bh = Blackholes::new(false);
        assert_eq!(bh.reload(&storage, &own, &[remote]), 1);
        // whichever file is read second must not replace the local entry
        assert_eq!(bh.entries[&hash(5)].source, own);
    }
}
