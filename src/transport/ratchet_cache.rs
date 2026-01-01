use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use crate::identity::{ratchet_id_from_pub, RatchetId, PUBLIC_KEY_LENGTH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedRatchet {
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
    pub received_at: Instant,
    pub ratchet_id: Option<RatchetId>,
}

impl CachedRatchet {
    pub fn new(public_key: [u8; PUBLIC_KEY_LENGTH]) -> Self {
        let ratchet_id = ratchet_id_from_pub(&public_key[..]).ok();
        Self {
            public_key,
            received_at: Instant::now(),
            ratchet_id,
        }
    }
}

#[derive(Default)]
pub struct RatchetCache {
    entries: HashMap<AddressHash, CachedRatchet>,
}

impl RatchetCache {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn update(
        &mut self,
        destination: AddressHash,
        public_key: [u8; PUBLIC_KEY_LENGTH],
    ) -> CachedRatchet {
        let entry = CachedRatchet::new(public_key);
        self.entries.insert(destination, entry.clone());
        entry
    }

    pub fn get(&self, destination: &AddressHash) -> Option<&CachedRatchet> {
        self.entries.get(destination)
    }

    pub fn prune_older_than(&mut self, retention: Duration) {
        if retention.is_zero() {
            return;
        }

        if let Some(threshold) = Instant::now().checked_sub(retention) {
            self.entries
                .retain(|_, entry| entry.received_at >= threshold);
        }
    }
}
