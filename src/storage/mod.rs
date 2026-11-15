//! Identity & destination persistence (Python `Identity` storage parity).
//!
//! Python keeps two on-disk structures under `Reticulum.storagepath`:
//!
//! * `known_destinations` — a msgpack map of
//!   `destination hash -> [time, packet_hash, public_key, app_data, uses]`
//!   (`Identity.save_known_destinations` / `load_known_destinations`)
//! * `ratchets/<destination hash hex>` — a msgpack map
//!   `{"ratchet": <32 byte public key>, "received": <unix time>}`
//!   (`Identity._remember_ratchet`)
//!
//! Destination ratchet files (`Destination.enable_ratchets(path)`) hold the
//! *private* ratchet keys of an announcing destination as
//! `{"signature": <64 bytes>, "ratchets": <packed list of private keys>}`.
//!
//! All file access goes through the [`Storage`] trait, so tests can run on
//! [`MemoryStorage`] while `FsStorage` matches the Python directory layout.

use std::collections::BTreeMap;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use reticulum_core::destination::RATCHET_COUNT;
use reticulum_core::error::RnsError;
use reticulum_core::hash::{AddressHash, HASH_SIZE};
use reticulum_core::identity::{
    pack_destination_ratchets, pack_known_destinations, pack_ratchet, pack_ratchet_list,
    ratchet_id, unpack_destination_ratchets, unpack_known_destinations, unpack_ratchet,
    DestinationUses, Identity, KnownDestinationData, PrivateIdentity, RatchetFileData,
    RATCHET_EXPIRY_SECS, RATCHET_KEY_LENGTH,
};

/// File name of the known-destinations store inside the storage path
/// (Python `RNS.Reticulum.storagepath + "/known_destinations"`).
pub const KNOWN_DESTINATIONS_FILE: &str = "known_destinations";

/// Duplicate-filter snapshot (Python `packet_hashlist.raw`).
pub const PACKET_HASHLIST_FILE: &str = "packet_hashlist.raw";

/// Persisted path table. The file name matches Python's `destination_table`,
/// but each msgpack record is a reticulum-rs path entry (destination, stable
/// interface id, hops, unix learned-at, mode, gravity, unresponsive flag,
/// random blobs, announce bytes, received-from, packet hash). This is not
/// Python's on-disk schema and is not read as one.
pub const DESTINATION_TABLE_FILE: &str = "destination_table";

/// Persisted tunnel table. The file name matches Python's `tunnels`, but
/// the msgpack records are reticulum-rs tunnel entries. This is not a
/// Python schema reader.
pub const TUNNELS_FILE: &str = "tunnels";

/// Directory of remembered remote ratchets
/// (Python `RNS.Reticulum.storagepath + "/ratchets"`).
pub const RATCHETS_DIR: &str = "ratchets";

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Minimal file backend used by the persistence layer.
pub trait Storage: Send + Sync {
    /// Read a file, `None` when it does not exist.
    fn read(&self, path: &str) -> Option<Vec<u8>>;

    /// Write a file, creating or replacing it.
    fn write(&self, path: &str, data: &[u8]) -> Result<(), RnsError>;

    /// List the file names inside a directory (empty when it is missing).
    fn list(&self, dir: &str) -> Vec<String>;

    /// Remove a file, `false` when it does not exist.
    fn remove(&self, path: &str) -> bool;
}

/// Filesystem storage backend (`std::fs`).
#[derive(Default, Clone, Debug)]
pub struct FsStorage {
    /// Base directory all paths are resolved against
    /// (Python `RNS.Reticulum.storagepath`).
    pub base: String,
}

impl FsStorage {
    pub fn new<T: Into<String>>(base: T) -> Self {
        Self { base: base.into() }
    }

    fn full(&self, path: &str) -> String {
        format!("{}/{}", self.base.trim_end_matches('/'), path)
    }
}

#[cfg(not(windows))]
fn replace_file(temp: &str, destination: &str) -> std::io::Result<()> {
    std::fs::rename(temp, destination)
}

#[cfg(windows)]
fn replace_file(temp: &str, destination: &str) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temp: Vec<u16> = std::ffi::OsStr::new(temp)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = std::ffi::OsStr::new(destination)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: both pointers reference NUL-terminated UTF-16 buffers that
    // remain alive for the duration of the call.
    if unsafe {
        MoveFileExW(
            temp.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl Storage for FsStorage {
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        std::fs::read(self.full(path)).ok()
    }

    fn write(&self, path: &str, data: &[u8]) -> Result<(), RnsError> {
        let full = self.full(path);

        if let Some(parent) = std::path::Path::new(&full).parent() {
            std::fs::create_dir_all(parent).map_err(|_| RnsError::Storage)?;
        }

        // Python writes to a temp file and renames it into place, keeping
        // readers from observing partially written files.
        let temp = format!(
            "{full}.{}.{}.tmp",
            std::process::id(),
            TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed),
        );
        let write_result = (|| {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|_| RnsError::Storage)?;
            file.write_all(data).map_err(|_| RnsError::Storage)?;
            file.sync_all().map_err(|_| RnsError::Storage)?;
            replace_file(&temp, &full).map_err(|_| RnsError::Storage)
        })();
        if write_result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        write_result?;

        Ok(())
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let mut names = std::fs::read_dir(self.full(dir))
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.file_type().map(|t| t.is_file()).unwrap_or(false))
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn remove(&self, path: &str) -> bool {
        std::fs::remove_file(self.full(path)).is_ok()
    }
}

/// In-memory storage backend for tests.
#[derive(Default)]
pub struct MemoryStorage {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    fn read(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().expect("storage").get(path).cloned()
    }

    fn write(&self, path: &str, data: &[u8]) -> Result<(), RnsError> {
        self.files
            .lock()
            .expect("storage")
            .insert(path.to_string(), data.to_vec());
        Ok(())
    }

    fn list(&self, dir: &str) -> Vec<String> {
        let prefix = format!("{dir}/");
        let mut names: Vec<String> = self
            .files
            .lock()
            .expect("storage")
            .keys()
            .filter(|path| path.starts_with(&prefix))
            .map(|path| path[prefix.len()..].to_string())
            .collect();
        names.sort();
        names
    }

    fn remove(&self, path: &str) -> bool {
        self.files.lock().expect("storage").remove(path).is_some()
    }
}

//***************************************************************************/
// Identity files (Python `Identity.to_file` / `from_file` / `pub_to_file`)
//***************************************************************************/
/// Identity file persistence, mirroring Python `Identity` file methods on
/// top of the [`Storage`] trait.
pub trait IdentityFiles {
    /// Write the private key to a file (Python `Identity.to_file`): 64 raw
    /// bytes, `x25519 private || ed25519 signing private`.
    fn to_file(&self, storage: &dyn Storage, path: &str) -> Result<(), RnsError>;

    /// Write the public key to a file (Python `Identity.pub_to_file`): 64
    /// raw bytes, `x25519 public || ed25519 public`.
    fn pub_to_file(&self, storage: &dyn Storage, path: &str) -> Result<(), RnsError>;
}

/// Load a private identity from a file
/// (Python `Identity.from_file` / `Identity.load`).
pub fn private_identity_from_file(
    storage: &dyn Storage,
    path: &str,
) -> Result<PrivateIdentity, RnsError> {
    let bytes = storage.read(path).ok_or(RnsError::Storage)?;
    PrivateIdentity::new_from_bytes(&bytes)
}

/// Load a public identity from a file written by [`IdentityFiles::pub_to_file`].
pub fn identity_from_public_file(storage: &dyn Storage, path: &str) -> Result<Identity, RnsError> {
    let bytes = storage.read(path).ok_or(RnsError::Storage)?;
    if bytes.len() != reticulum_core::identity::PUBLIC_KEY_LENGTH * 2 {
        return Err(RnsError::IncorrectHash);
    }
    Ok(Identity::new_from_slices(
        &bytes[..reticulum_core::identity::PUBLIC_KEY_LENGTH],
        &bytes[reticulum_core::identity::PUBLIC_KEY_LENGTH..],
    ))
}

impl IdentityFiles for PrivateIdentity {
    fn to_file(&self, storage: &dyn Storage, path: &str) -> Result<(), RnsError> {
        storage.write(path, &self.to_bytes())
    }

    fn pub_to_file(&self, storage: &dyn Storage, path: &str) -> Result<(), RnsError> {
        storage.write(path, &self.as_identity().to_bytes())
    }
}

impl IdentityFiles for Identity {
    fn to_file(&self, _storage: &dyn Storage, _path: &str) -> Result<(), RnsError> {
        // A public identity holds no private key material to persist.
        Err(RnsError::Unsupported)
    }

    fn pub_to_file(&self, storage: &dyn Storage, path: &str) -> Result<(), RnsError> {
        storage.write(path, &self.to_bytes())
    }
}

//***************************************************************************/
// Known destinations (Python `Identity.known_destinations`)
//***************************************************************************/
/// In-memory mirror of Python `Identity.known_destinations`, persisted as
/// msgpack into [`KNOWN_DESTINATIONS_FILE`].
///
/// Like a Python dict, entries keep insertion order: re-remembering a
/// destination updates it in place, and new destinations are appended.
/// The persisted file therefore matches Python byte for byte.
#[derive(Default)]
pub struct KnownDestinations {
    entries: Vec<(AddressHash, KnownDestinationData)>,
    index: BTreeMap<AddressHash, usize>,
    dirty: bool,
}

impl KnownDestinations {
    pub fn new() -> Self {
        Self::default()
    }

    fn position(&self, destination_hash: &AddressHash) -> Option<usize> {
        self.index.get(destination_hash).copied()
    }

    /// Remember the identity of an announced destination
    /// (Python `Identity.remember`).
    pub fn remember(
        &mut self,
        packet_hash: [u8; HASH_SIZE],
        destination_hash: AddressHash,
        public_key: [u8; reticulum_core::identity::PUBLIC_KEY_LENGTH * 2],
        app_data: Option<Vec<u8>>,
        now: f64,
    ) {
        match self.position(&destination_hash) {
            Some(position) => {
                let entry = &mut self.entries[position].1;
                entry.time = now;
                entry.packet_hash = packet_hash;
                entry.public_key = public_key;
                entry.app_data = app_data;
            }
            None => {
                self.index.insert(destination_hash, self.entries.len());
                self.entries.push((
                    destination_hash,
                    KnownDestinationData {
                        time: now,
                        packet_hash,
                        public_key,
                        app_data,
                        uses: DestinationUses::Never,
                    },
                ));
            }
        }

        self.dirty = true;
    }

    /// Recall the identity announced for a destination hash
    /// (Python `Identity.recall`), marking the entry used.
    pub fn recall(&mut self, destination_hash: &AddressHash, now: f64) -> Option<Identity> {
        let identity = self.recall_no_use(destination_hash)?;
        self.mark_used(destination_hash, now);
        Some(identity)
    }

    /// Recall without marking the entry used (Python `recall(_no_use=True)`).
    pub fn recall_no_use(&self, destination_hash: &AddressHash) -> Option<Identity> {
        let (_, entry) = self.entries.get(self.position(destination_hash)?)?;
        Some(Identity::new_from_slices(
            &entry.public_key[..reticulum_core::identity::PUBLIC_KEY_LENGTH],
            &entry.public_key[reticulum_core::identity::PUBLIC_KEY_LENGTH..],
        ))
    }

    /// Last heard app data for a destination (Python `recall_app_data`).
    pub fn recall_app_data(&mut self, destination_hash: &AddressHash, now: f64) -> Option<Vec<u8>> {
        let app_data = self
            .entries
            .get(self.position(destination_hash)?)
            .and_then(|(_, entry)| entry.app_data.clone())?;
        self.mark_used(destination_hash, now);
        Some(app_data)
    }

    /// Mark destination data used (Python `_used_destination_data`).
    pub fn mark_used(&mut self, destination_hash: &AddressHash, now: f64) -> bool {
        let Some(position) = self.position(destination_hash) else {
            return false;
        };

        let entry = &mut self.entries[position].1;
        if entry.uses.is_retained() {
            return false;
        }

        entry.uses = DestinationUses::LastUsed(now);
        self.dirty = true;
        true
    }

    /// Keep destination data across cleanups (Python `_retain_destination_data`).
    pub fn retain(&mut self, destination_hash: &AddressHash) -> bool {
        self.set_uses(destination_hash, DestinationUses::Retained)
    }

    /// Stop retaining destination data (Python `_unretain_destination_data`).
    pub fn unretain(&mut self, destination_hash: &AddressHash, now: f64) -> bool {
        self.set_uses(destination_hash, DestinationUses::LastUsed(now))
    }

    fn set_uses(&mut self, destination_hash: &AddressHash, uses: DestinationUses) -> bool {
        if let Some(position) = self.position(destination_hash) {
            self.entries[position].1.uses = uses;
            self.dirty = true;
            return true;
        }

        false
    }

    /// Retain every destination belonging to an identity hash
    /// (Python `Identity._retain_identity`, comparing
    /// `Identity.truncated_hash(public_key)`).
    pub fn retain_identity(&mut self, identity_hash: &AddressHash) -> bool {
        let mut retained = false;

        let hashes: Vec<AddressHash> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                let identity = Identity::new_from_slices(
                    &entry.public_key[..reticulum_core::identity::PUBLIC_KEY_LENGTH],
                    &entry.public_key[reticulum_core::identity::PUBLIC_KEY_LENGTH..],
                );
                identity.address_hash == *identity_hash
            })
            .map(|(hash, _)| *hash)
            .collect();

        for hash in hashes {
            retained |= self.retain(&hash);
        }

        retained
    }

    /// Remove stale destinations (Python `Identity.clean_known_destinations`).
    /// `has_path` decides whether a path to the destination is currently
    /// known. Returns the removed destination hashes.
    pub fn clean<F>(&mut self, now: f64, has_path: F) -> Vec<AddressHash>
    where
        F: Fn(&AddressHash) -> bool,
    {
        const UNUSED_DESTINATION_LINGER: f64 = 6.0 * 60.0;
        const DESTINATION_TIMEOUT: f64 = 60.0 * 60.0 * 24.0 * 7.0;

        let stale: Vec<AddressHash> = self
            .entries
            .iter()
            .filter(|(hash, entry)| {
                if entry.uses.is_retained() {
                    return false;
                }

                if has_path(hash) {
                    return false;
                }

                match entry.uses.unused_for(now) {
                    // Never used: linger after the last announce
                    None => now - entry.time > UNUSED_DESTINATION_LINGER,
                    // Used before: expire after the destination timeout
                    Some(unused_for) => unused_for > DESTINATION_TIMEOUT * 1.25,
                }
            })
            .map(|(hash, _)| *hash)
            .collect();

        let stale_set: std::collections::HashSet<AddressHash> = stale.iter().copied().collect();
        self.entries.retain(|(hash, _)| !stale_set.contains(hash));
        self.reindex();

        if !stale.is_empty() {
            self.dirty = true;
        }

        stale
    }

    fn reindex(&mut self) {
        self.index = self
            .entries
            .iter()
            .enumerate()
            .map(|(position, (hash, _))| (*hash, position))
            .collect();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, destination_hash: &AddressHash) -> Option<&KnownDestinationData> {
        let (_, entry) = self.entries.get(self.position(destination_hash)?)?;
        Some(entry)
    }

    pub fn contains(&self, destination_hash: &AddressHash) -> bool {
        self.position(destination_hash).is_some()
    }

    /// All entries in insertion order, matching the Python dict order that
    /// is written to the storage file.
    pub fn entries(&self) -> Vec<(AddressHash, KnownDestinationData)> {
        self.entries.clone()
    }

    /// Serialise to the Python `known_destinations` file format.
    pub fn pack(&self) -> Result<Vec<u8>, RnsError> {
        pack_known_destinations(&self.entries())
    }

    /// Persist to `storage` (Python `Identity.save_known_destinations`).
    /// Writing is skipped when nothing changed since the last save.
    pub fn save(&mut self, storage: &dyn Storage) -> Result<(), RnsError> {
        if !self.dirty && storage.read(KNOWN_DESTINATIONS_FILE).is_some() {
            return Ok(());
        }

        let packed = self.pack()?;
        storage.write(KNOWN_DESTINATIONS_FILE, &packed)?;
        self.dirty = false;

        Ok(())
    }

    /// Load from `storage` (Python `Identity.load_known_destinations`).
    pub fn load(&mut self, storage: &dyn Storage) -> Result<(), RnsError> {
        let Some(bytes) = storage.read(KNOWN_DESTINATIONS_FILE) else {
            return Ok(());
        };

        let entries = unpack_known_destinations(&bytes)?;
        self.entries = entries;
        self.reindex();
        self.dirty = false;

        Ok(())
    }
}

//***************************************************************************/
// Known ratchets (Python `Identity.known_ratchets`)
//***************************************************************************/
/// Remembered *public* ratchet keys of remote destinations, persisted as
/// `ratchets/<destination hash hex>` files.
#[derive(Default)]
pub struct KnownRatchets {
    ratchets: BTreeMap<AddressHash, ([u8; RATCHET_KEY_LENGTH], f64)>,
}

impl KnownRatchets {
    pub fn new() -> Self {
        Self::default()
    }

    fn ratchet_path(destination_hash: &AddressHash) -> String {
        format!("{RATCHETS_DIR}/{}", destination_hash.to_hex_string())
    }

    /// Remember the ratchet of an announced destination
    /// (Python `Identity._remember_ratchet`): updates the in-memory map and
    /// persists `{"ratchet": .., "received": ..}` to storage.
    pub fn remember(
        &mut self,
        storage: &dyn Storage,
        destination_hash: AddressHash,
        ratchet: [u8; RATCHET_KEY_LENGTH],
        now: f64,
    ) -> Result<(), RnsError> {
        if self
            .ratchets
            .get(&destination_hash)
            .map(|(known, _)| *known)
            == Some(ratchet)
        {
            return Ok(());
        }

        self.ratchets.insert(destination_hash, (ratchet, now));

        let data = RatchetFileData {
            ratchet,
            received: now,
        };
        storage.write(
            &Self::ratchet_path(&destination_hash),
            &pack_ratchet(&data)?,
        )
    }

    /// Recall the current ratchet of a destination
    /// (Python `Identity.get_ratchet`), loading it from storage (and
    /// checking expiry) when it is not in memory.
    pub fn get(
        &mut self,
        storage: &dyn Storage,
        destination_hash: &AddressHash,
        now: f64,
    ) -> Option<[u8; RATCHET_KEY_LENGTH]> {
        if !self.ratchets.contains_key(destination_hash) {
            let bytes = storage.read(&Self::ratchet_path(destination_hash))?;
            let data = unpack_ratchet(&bytes).ok()?;

            self.ratchets
                .insert(*destination_hash, (data.ratchet, data.received));
        }

        let (ratchet, received) = self.ratchets.get(destination_hash).copied()?;

        if now >= received + RATCHET_EXPIRY_SECS as f64 {
            return None;
        }

        Some(ratchet)
    }

    /// The id of the current ratchet
    /// (Python `Identity.current_ratchet_id`).
    pub fn current_ratchet_id(
        &mut self,
        storage: &dyn Storage,
        destination_hash: &AddressHash,
        now: f64,
    ) -> Option<[u8; 10]> {
        let ratchet = self.get(storage, destination_hash, now)?;
        let id = ratchet_id(&ratchet);
        Some(id.as_slice()[..10].try_into().expect("ratchet id length"))
    }

    /// Remove expired, corrupted and unknown ratchets
    /// (Python `Identity._clean_ratchets`).
    ///
    /// `known` decides whether the destination of a ratchet file is still
    /// present in the known-destinations store. Returns the number of
    /// removed files.
    pub fn clean(
        &mut self,
        storage: &dyn Storage,
        now: f64,
        known: impl Fn(&AddressHash) -> bool,
    ) -> usize {
        let mut removed = 0;

        for filename in storage.list(RATCHETS_DIR) {
            let path = format!("{RATCHETS_DIR}/{filename}");
            let destination_hash = match AddressHash::new_from_hex_string(&filename) {
                Ok(hash) => hash,
                Err(_) => {
                    storage.remove(&path);
                    removed += 1;
                    continue;
                }
            };

            let remove = match storage
                .read(&path)
                .and_then(|bytes| unpack_ratchet(&bytes).ok())
            {
                Some(data) => now >= data.received + RATCHET_EXPIRY_SECS as f64,
                None => true,
            };

            if remove || !known(&destination_hash) {
                storage.remove(&path);
                self.ratchets.remove(&destination_hash);
                removed += 1;
            }
        }

        removed
    }
}

//***************************************************************************/
// Destination ratchet files (Python `Destination._persist_ratchets`)
//***************************************************************************/
/// Load the private ratchet keys of an announcing destination
/// (Python `Destination._reload_ratchets`). Returns an empty list when the
/// file does not exist yet, exactly like a fresh destination in Python.
pub fn load_destination_ratchets(
    storage: &dyn Storage,
    path: &str,
    identity: &Identity,
) -> Result<Vec<[u8; RATCHET_KEY_LENGTH]>, RnsError> {
    let Some(bytes) = storage.read(path) else {
        return Ok(Vec::new());
    };

    let (ratchets, signature) = unpack_destination_ratchets(&bytes)?;

    // Python verifies the packed ratchet list signature before accepting it.
    let packed = pack_ratchet_list(&ratchets)?;
    identity
        .verify(&packed, &signature)
        .map_err(|_| RnsError::IncorrectSignature)?;

    Ok(ratchets)
}

/// Persist the private ratchet keys of an announcing destination, signed by
/// its identity (Python `Destination._persist_ratchets`).
pub fn save_destination_ratchets(
    storage: &dyn Storage,
    path: &str,
    identity: &PrivateIdentity,
    ratchets: &[[u8; RATCHET_KEY_LENGTH]],
) -> Result<(), RnsError> {
    let packed = pack_ratchet_list(ratchets)?;
    let signature = identity.sign(&packed);

    storage.write(path, &pack_destination_ratchets(ratchets, &signature)?)
}

/// Clamp a destination ratchet list to the retained count
/// (Python `Destination._clean_ratchets`).
pub fn clean_destination_ratchets(ratchets: &mut Vec<[u8; RATCHET_KEY_LENGTH]>, retained: usize) {
    let retained = retained.clamp(1, RATCHET_COUNT);
    ratchets.truncate(retained);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_writes_replace_existing_files_and_clean_temporaries() {
        let dir = std::env::temp_dir().join(format!(
            "reticulum-storage-replace-{}-{}",
            std::process::id(),
            TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = FsStorage::new(dir.to_string_lossy().into_owned());

        for value in 0u8..32 {
            storage.write("nested/value", &[value; 64]).unwrap();
            assert_eq!(storage.read("nested/value"), Some(vec![value; 64]));
        }

        let entries = std::fs::read_dir(dir.join("nested"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![std::ffi::OsString::from("value")]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
