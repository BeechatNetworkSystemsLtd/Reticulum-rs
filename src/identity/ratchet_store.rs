use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::hash::AddressHash;
use super::{ratchet_id_from_pub, RatchetId, PUBLIC_KEY_LENGTH};

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
pub struct RatchetStore {
    entries: Mutex<HashMap<AddressHash, CachedRatchet>>,
}

impl RatchetStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn remember(
        &self,
        destination: AddressHash,
        public_key: [u8; PUBLIC_KEY_LENGTH],
    ) -> CachedRatchet {
        let mut entries = self.entries.lock().expect("ratchet store poisoned");
        let entry = CachedRatchet::new(public_key);
        entries.insert(destination, entry.clone());
        entry
    }

    pub fn get(&self, destination: &AddressHash) -> Option<CachedRatchet> {
        let entries = self.entries.lock().expect("ratchet store poisoned");
        entries.get(destination).cloned()
    }

    pub fn prune_older_than(&self, retention: Duration) {
        if retention.is_zero() {
            return;
        }

        if let Some(threshold) = Instant::now().checked_sub(retention) {
            let mut entries = self.entries.lock().expect("ratchet store poisoned");
            entries.retain(|_, entry| entry.received_at >= threshold);
        }
    }

    #[cfg(test)]
    pub fn clear(&self) {
        self.entries.lock().expect("ratchet store poisoned").clear();
    }
}

static RATCHET_STORE: OnceLock<RatchetStore> = OnceLock::new();

pub fn global_ratchet_store() -> &'static RatchetStore {
    RATCHET_STORE.get_or_init(RatchetStore::new)
}
