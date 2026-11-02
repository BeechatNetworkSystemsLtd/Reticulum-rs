//! Outbound (sender) side of a resource transfer.

use alloc::vec::Vec;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand_core::OsRng;
use sha2::Digest;

use crate::destination::link::{Link, LinkId};
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::packet::{Packet, PacketContext, PacketType};

use super::advertisement::{ResourceAdvertisement, COLLISION_GUARD_SIZE, HASHMAP_MAX_LEN};
use super::{
    map_hash, maybe_compress, should_auto_compress, unix_time, ResourceStatus, ResourceTx,
    MAPHASH_LEN, MAX_ADV_RETRIES, MAX_EFFICIENT_SIZE, MAX_RETRIES, RANDOM_HASH_SIZE,
    RESPONSE_MAX_GRACE_TIME, SDU, SENDER_GRACE_TIME, WINDOW_MAX,
};

/// `dyn Read + Seek` is not a legal trait object: only auto traits may
/// follow the first trait. This marker adds no methods.
trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// Where segment bytes come from. The memory source retains the original
/// buffer. A stream source retains a handle plus the current segment, so
/// the rest of a file stays on disk until the receiver has the previous
/// segment (Python `input_file`).
enum PayloadSource {
    /// Metadata prefix followed by the original bytes. The buffer stays
    /// resident until this source moves into the last segment.
    Memory(Vec<u8>),
    Stream {
        // Packet tasks await `&TransportHandler`, so the handler is `Sync`.
        // The caller's reader is only `Send`; the mutex supplies `Sync`
        // without requiring it of the reader. Never held across `.await`.
        reader: std::sync::Mutex<Box<dyn ReadSeek + Send>>,
        metadata: Vec<u8>,
        /// Reader length, not including the metadata prefix.
        len: u64,
        /// Set only for streams we spooled ourselves; removed on drop.
        spool_path: Option<PathBuf>,
    },
}

impl Drop for PayloadSource {
    fn drop(&mut self) {
        if let PayloadSource::Stream {
            spool_path: Some(path),
            ..
        } = self
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl PayloadSource {
    fn read_range(&mut self, range: core::ops::Range<usize>) -> Result<Vec<u8>, RnsError> {
        if range.start > range.end {
            return Err(RnsError::ResourceMsg("resource segment out of range"));
        }
        match self {
            Self::Memory(buf) => {
                if range.end > buf.len() {
                    return Err(RnsError::ResourceMsg("resource segment out of range"));
                }
                Ok(buf[range].to_vec())
            }
            Self::Stream {
                reader,
                metadata,
                len,
                ..
            } => {
                let mut out = Vec::with_capacity(range.end - range.start);
                let meta_len = metadata.len();
                if range.start < meta_len {
                    let end = range.end.min(meta_len);
                    out.extend_from_slice(&metadata[range.start..end]);
                }
                if range.end > meta_len {
                    let file_start = range.start.saturating_sub(meta_len) as u64;
                    let file_end = (range.end - meta_len) as u64;
                    if file_start > *len || file_end > *len {
                        return Err(RnsError::ResourceMsg("resource segment out of range"));
                    }
                    let reader = reader.get_mut().unwrap_or_else(|err| err.into_inner());
                    reader
                        .seek(SeekFrom::Start(file_start))
                        .map_err(|_| RnsError::ResourceMsg("could not read resource stream"))?;
                    let mut remaining = (file_end - file_start) as usize;
                    let mut buf = [0u8; 16 * 1024];
                    while remaining > 0 {
                        let want = remaining.min(buf.len());
                        let n = reader
                            .read(&mut buf[..want])
                            .map_err(|_| RnsError::ResourceMsg("could not read resource stream"))?;
                        if n == 0 {
                            return Err(RnsError::ResourceMsg("resource stream ended early"));
                        }
                        out.extend_from_slice(&buf[..n]);
                        remaining -= n;
                    }
                }
                Ok(out)
            }
        }
    }
}

struct SpoolGuard(PathBuf);

impl Drop for SpoolGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub use super::ResourceOptions;

/// A prepared resource awaiting advertisement, or an active sender.
pub struct OutgoingResource {
    pub link_id: LinkId,
    pub status: ResourceStatus,
    pub hash: Hash,
    pub truncated_hash: AddressHash,
    pub expected_proof: Hash,
    pub original_hash: Hash,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    /// Transfer size: length of the encrypted stream.
    pub size: usize,
    /// Uncompressed data size (metadata + data).
    pub total_size: usize,
    pub compressed: bool,
    pub encrypted: bool,
    pub split: bool,
    pub has_metadata: bool,
    pub metadata_size: usize,
    pub segment_index: usize,
    pub total_segments: usize,
    pub request_id: Option<AddressHash>,
    pub is_response: bool,
    pub auto_compress: bool,
    pub auto_compress_limit: Option<usize>,
    /// Original input length excluding metadata. Python compares this, not
    /// the segment length, against the auto-compress limit.
    pub input_len: usize,
    pub sdu: usize,

    /// Pre-built part packets with per-part map hashes.
    pub parts: Vec<Packet>,
    pub part_hashes: Vec<[u8; MAPHASH_LEN]>,
    pub part_sent: Vec<bool>,
    pub hashmap: Vec<u8>,
    pub sent_parts: usize,

    pub receiver_min_consecutive_height: usize,
    pub req_hashlist: Vec<Hash>,

    pub rtt: Option<f64>,
    pub adv_sent: Option<f64>,
    pub last_activity: f64,
    pub last_part_sent: f64,
    pub retries_left: usize,
    pub max_retries: usize,
    pub timeout: f64,
    pub timeout_factor: f64,
    pub sender_grace_time: f64,

    /// Remaining unread source. Moved into the next segment when that
    /// segment is prepared. A memory source still retains the original
    /// buffer; a stream source retains a handle plus the current segment.
    source: Option<PayloadSource>,
    /// Prepared next segment (already compressed/split), advertised when
    /// the current segment completes.
    pub next_segment: Option<Box<OutgoingResource>>,
    pub advertise_next: bool,
}

/// 3-byte length prefix + caller-supplied msgpack metadata, matching
/// Python `struct.pack(">I", metadata_size)[1:] + umsgpack.packb(metadata)`.
fn metadata_prefix(opts: &ResourceOptions) -> Result<(Vec<u8>, bool, usize), RnsError> {
    let Some(packed) = opts.metadata.as_ref() else {
        return Ok((Vec::new(), false, 0));
    };
    if packed.len() > super::METADATA_MAX_SIZE {
        return Err(RnsError::ResourceMsg("resource metadata size exceeded"));
    }
    let len = packed.len() as u32;
    let mut blob = Vec::with_capacity(3 + packed.len());
    blob.extend_from_slice(&len.to_be_bytes()[1..]);
    blob.extend_from_slice(packed);
    let size = blob.len();
    Ok((blob, true, size))
}

fn spool_path() -> PathBuf {
    let rand = Hash::new_from_rand(OsRng);
    let mut name = format!("reticulum-resource-{}", std::process::id());
    for byte in &rand.as_slice()[..8] {
        name.push_str(&format!("{byte:02x}"));
    }
    std::env::temp_dir().join(name)
}

/// First segment plaintext plus the unread remainder. Built without a
/// link so spooling and the first read happen before any transport lock.
pub(crate) struct StagedSource {
    segment_data: Vec<u8>,
    source: PayloadSource,
    input_len: usize,
    total_size: usize,
    total_segments: usize,
    has_metadata: bool,
    metadata_size: usize,
}

impl OutgoingResource {
    /// Create an outbound resource for `data` (metadata prepended when
    /// given), splitting, compressing, encrypting and hashing exactly like
    /// Python `RNS.Resource.__init__`.
    pub fn new(data: Vec<u8>, link: &Link, opts: ResourceOptions) -> Result<Self, RnsError> {
        let staged = Self::stage_bytes(data, &opts)?;
        Self::finish_staged(staged, link, opts)
    }

    /// Read the first segment of an in-memory payload. Encryption happens
    /// in [`Self::finish_staged`].
    pub(crate) fn stage_bytes(
        data: Vec<u8>,
        opts: &ResourceOptions,
    ) -> Result<StagedSource, RnsError> {
        let (metadata_blob, has_metadata, metadata_size) = metadata_prefix(opts)?;
        let input_len = data.len();
        let mut stream = Vec::with_capacity(metadata_size + data.len());
        stream.extend_from_slice(&metadata_blob);
        stream.extend_from_slice(&data);
        let total_size = stream.len();
        Self::stage_source(
            PayloadSource::Memory(stream),
            input_len,
            total_size,
            has_metadata,
            metadata_size,
        )
    }

    /// Advertise a file without reading past the first segment. Later
    /// segments are read when the previous one is proven, matching Python's
    /// `input_file` seek/read.
    pub fn from_path(path: &Path, link: &Link, opts: ResourceOptions) -> Result<Self, RnsError> {
        let staged = Self::stage_path(path, &opts)?;
        Self::finish_staged(staged, link, opts)
    }

    /// Open `path` and read only the first segment. No link required.
    pub(crate) fn stage_path(
        path: &Path,
        opts: &ResourceOptions,
    ) -> Result<StagedSource, RnsError> {
        let file = std::fs::File::open(path)
            .map_err(|_| RnsError::ResourceMsg("could not open resource file"))?;
        Self::stage_reader(file, opts)
    }

    /// Advertise a seekable stream. Length comes from seeking to the end,
    /// which does not read the body; only the first segment is read before
    /// the resource is advertised.
    pub fn from_reader<R: Read + Seek + Send + 'static>(
        reader: R,
        link: &Link,
        opts: ResourceOptions,
    ) -> Result<Self, RnsError> {
        let staged = Self::stage_reader(reader, &opts)?;
        Self::finish_staged(staged, link, opts)
    }

    /// Seek to discover the length and read only the first segment.
    pub(crate) fn stage_reader<R: Read + Seek + Send + 'static>(
        reader: R,
        opts: &ResourceOptions,
    ) -> Result<StagedSource, RnsError> {
        Self::stage_seekable(Box::new(reader), None, opts)
    }

    /// Spool a non-seekable stream to a temporary file (Python proxies a
    /// size-less `BufferedReader` through `TemporaryFile`) and advertise
    /// from that file. The spool is removed when the transfer is dropped.
    /// The whole stream is consumed, but only in small chunks — it is not
    /// held as one buffer, and only the first segment is loaded afterwards.
    pub fn from_read<R: Read>(
        reader: R,
        link: &Link,
        opts: ResourceOptions,
    ) -> Result<Self, RnsError> {
        let staged = Self::stage_read(reader, &opts)?;
        Self::finish_staged(staged, link, opts)
    }

    /// Spool `reader` and read the first segment. The link is not touched,
    /// so this can run before the transport handler lock is taken.
    pub(crate) fn stage_read<R: Read>(
        mut reader: R,
        opts: &ResourceOptions,
    ) -> Result<StagedSource, RnsError> {
        let path = spool_path();
        let guard = SpoolGuard(path.clone());
        {
            // `File::create` is write-only. Reopen for reading once the
            // spool is on disk so the transfer can seek and read segments.
            let mut file = std::fs::File::create(&path)
                .map_err(|_| RnsError::ResourceMsg("could not spool resource stream"))?;
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = reader
                    .read(&mut buf)
                    .map_err(|_| RnsError::ResourceMsg("could not read resource stream"))?;
                if n == 0 {
                    break;
                }
                file.write_all(&buf[..n])
                    .map_err(|_| RnsError::ResourceMsg("could not spool resource stream"))?;
            }
        }
        let file = std::fs::File::open(&path)
            .map_err(|_| RnsError::ResourceMsg("could not read resource stream"))?;
        let staged = Self::stage_seekable(Box::new(file), Some(path), opts)?;
        // `PayloadSource` owns the path from here and deletes it on drop.
        // Forgetting earlier would leak the spool when staging fails.
        std::mem::forget(guard);
        Ok(staged)
    }

    fn stage_seekable(
        mut reader: Box<dyn ReadSeek + Send>,
        spool_path: Option<PathBuf>,
        opts: &ResourceOptions,
    ) -> Result<StagedSource, RnsError> {
        let (metadata_blob, has_metadata, metadata_size) = metadata_prefix(opts)?;
        let end = reader
            .seek(SeekFrom::End(0))
            .map_err(|_| RnsError::ResourceMsg("could not read resource stream"))?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| RnsError::ResourceMsg("could not read resource stream"))?;
        let input_len = usize::try_from(end)
            .map_err(|_| RnsError::ResourceMsg("resource stream is too large"))?;
        let total_size = metadata_size + input_len;
        Self::stage_source(
            PayloadSource::Stream {
                reader: std::sync::Mutex::new(reader),
                metadata: metadata_blob,
                len: end,
                spool_path,
            },
            input_len,
            total_size,
            has_metadata,
            metadata_size,
        )
    }

    fn stage_source(
        mut source: PayloadSource,
        input_len: usize,
        total_size: usize,
        has_metadata: bool,
        metadata_size: usize,
    ) -> Result<StagedSource, RnsError> {
        let total_segments = if total_size <= MAX_EFFICIENT_SIZE {
            1
        } else {
            (total_size - 1) / MAX_EFFICIENT_SIZE + 1
        };
        let range = Self::segment_range(total_size, metadata_size, 1);
        // Only this segment is pulled into memory. The rest stays in
        // `source` until the receiver proves the segment.
        let segment_data = source.read_range(range)?;
        Ok(StagedSource {
            segment_data,
            source,
            input_len,
            total_size,
            total_segments,
            has_metadata,
            metadata_size,
        })
    }

    /// Compress, encrypt and hash a staged first segment.
    pub(crate) fn finish_staged(
        staged: StagedSource,
        link: &Link,
        opts: ResourceOptions,
    ) -> Result<Self, RnsError> {
        Self::from_segment_bytes(
            staged.segment_data,
            staged.source,
            staged.input_len,
            staged.total_size,
            staged.total_segments,
            1,
            None,
            link,
            opts,
            staged.has_metadata,
            staged.metadata_size,
        )
        .map_err(|(err, _source)| err)
    }

    /// Build one segment. `segment_data` is only this segment's plaintext.
    /// On failure the source is returned so the caller can keep it: dropping
    /// it would unlink a spool and look like the transfer had no next segment.
    #[allow(clippy::too_many_arguments)]
    fn from_segment_bytes(
        segment_data: Vec<u8>,
        source: PayloadSource,
        input_len: usize,
        total_size: usize,
        total_segments: usize,
        segment_index: usize,
        original_hash: Option<Hash>,
        link: &Link,
        opts: ResourceOptions,
        has_metadata: bool,
        metadata_size: usize,
    ) -> Result<Self, (RnsError, PayloadSource)> {
        let split = total_segments > 1;

        // Python gates on the original input size, then keeps the
        // compressed form only when it is actually smaller.
        let (prepared, compressed) = maybe_compress(
            &segment_data,
            should_auto_compress(&opts, input_len),
            usize::MAX,
        );

        // Random hash prefix + payload
        let random_hash = Hash::new_from_rand(OsRng);
        let mut plaintext: Vec<u8> = Vec::with_capacity(RANDOM_HASH_SIZE + prepared.len());
        plaintext.extend_from_slice(&random_hash.as_slice()[..RANDOM_HASH_SIZE]);
        plaintext.extend_from_slice(&prepared);

        // Encrypt the whole stream with the link token
        let sdu = if link.mtu() > 0 { link.sdu() } else { SDU };
        let mut encrypted = Vec::with_capacity(plaintext.len() + super::PART_ENCRYPT_OVERHEAD);
        let cipher_len = match link.encrypt_alloc(&plaintext, &mut encrypted) {
            Ok(len) => len,
            Err(err) => return Err((err, source)),
        };
        encrypted.truncate(cipher_len);

        let size = encrypted.len();
        let total_parts = size.div_ceil(sdu);

        // Build parts and hashmap with collision guard
        let mut parts = Vec::with_capacity(total_parts);
        let mut part_hashes = Vec::with_capacity(total_parts);
        let part_sent = vec![false; total_parts];
        let mut hashmap = Vec::with_capacity(total_parts * MAPHASH_LEN);
        let mut collision_guard: Vec<[u8; MAPHASH_LEN]> = Vec::new();

        let mut random_hash_bytes: [u8; RANDOM_HASH_SIZE] = random_hash.as_slice()
            [..RANDOM_HASH_SIZE]
            .try_into()
            .unwrap();

        'hashmap: loop {
            parts.clear();
            part_hashes.clear();
            hashmap.clear();
            collision_guard.clear();

            let mut regenerated_random = None;

            for i in 0..total_parts {
                let chunk = &encrypted[i * sdu..core::cmp::min((i + 1) * sdu, size)];
                let mh = map_hash(chunk, &random_hash_bytes);
                if collision_guard.contains(&mh) {
                    // remap with a new random hash and start over
                    let new_random = Hash::new_from_rand(OsRng);
                    regenerated_random = Some(new_random);
                    break;
                }
                collision_guard.push(mh);
                if collision_guard.len() > COLLISION_GUARD_SIZE {
                    collision_guard.remove(0);
                }

                let packet = match link.raw_packet(chunk, PacketType::Data, PacketContext::Resource)
                {
                    Ok(packet) => packet,
                    Err(err) => return Err((err, source)),
                };
                parts.push(packet);
                part_hashes.push(mh);
                hashmap.extend_from_slice(&mh);
            }

            match regenerated_random {
                Some(new_random) => {
                    // re-encrypt with the new random hash prefix
                    plaintext.splice(
                        ..RANDOM_HASH_SIZE,
                        new_random.as_slice()[..RANDOM_HASH_SIZE].iter().copied(),
                    );
                    encrypted.clear();
                    let cipher_len = match link.encrypt_alloc(&plaintext, &mut encrypted) {
                        Ok(len) => len,
                        Err(err) => return Err((err, source)),
                    };
                    encrypted.truncate(cipher_len);
                    random_hash_bytes.copy_from_slice(&new_random.as_slice()[..RANDOM_HASH_SIZE]);
                    continue 'hashmap;
                }
                None => break,
            }
        }

        let random_hash = random_hash_bytes;
        // Hash is computed over this SEGMENT's uncompressed data + random
        // hash (Python: `Identity.full_hash(data + self.random_hash)`
        // where `data` is the segment's bytes — receivers assemble and
        // hash the segment, not the whole stream).
        let hash = Hash::new(
            Hash::generator()
                .chain_update(&segment_data)
                .chain_update(random_hash)
                .finalize()
                .into(),
        );
        let truncated_hash = AddressHash::new_from_hash(&hash);
        // Proof over the segment data + hash (Python
        // `full_hash(self.data + self.hash)`).
        let expected_proof = Hash::new(
            Hash::generator()
                .chain_update(&segment_data)
                .chain_update(hash.as_slice())
                .finalize()
                .into(),
        );
        // `original_hash` correlates the segments of one logical resource:
        // segment 1 uses its own (segment) hash, later segments receive
        // segment 1's hash (Python `original_hash = self.hash` /
        // advertisement field `o`).
        let original_hash = original_hash.unwrap_or(hash);

        let rtt = link.rtt().as_secs_f64();
        let timeout = opts
            .timeout
            .unwrap_or(rtt * super::TRAFFIC_TIMEOUT_FACTOR + RESPONSE_MAX_GRACE_TIME * 1.125);

        Ok(Self {
            link_id: *link.id(),
            status: ResourceStatus::None,
            hash,
            truncated_hash,
            expected_proof,
            original_hash,
            random_hash,
            size,
            total_size,
            compressed,
            encrypted: true,
            split,
            has_metadata,
            metadata_size,
            segment_index,
            total_segments,
            request_id: opts.request_id,
            is_response: opts.is_response,
            auto_compress: opts.auto_compress,
            auto_compress_limit: opts.auto_compress_limit,
            input_len,
            sdu,
            parts,
            part_hashes,
            part_sent,
            hashmap,
            sent_parts: 0,
            receiver_min_consecutive_height: 0,
            req_hashlist: Vec::new(),
            rtt: None,
            adv_sent: None,
            last_activity: unix_time(),
            last_part_sent: 0.0,
            retries_left: MAX_ADV_RETRIES,
            max_retries: MAX_RETRIES,
            timeout,
            timeout_factor: super::TRAFFIC_TIMEOUT_FACTOR,
            sender_grace_time: SENDER_GRACE_TIME,
            source: Some(source),
            next_segment: None,
            advertise_next: false,
        })
    }

    /// Byte range of segment `segment_index` (1-based) within the full
    /// original `stream` of length `total_size`.
    pub fn segment_range(
        total_size: usize,
        metadata_size: usize,
        segment_index: usize,
    ) -> core::ops::Range<usize> {
        let _ = metadata_size;
        let start = (segment_index - 1) * MAX_EFFICIENT_SIZE;
        let end = core::cmp::min(segment_index * MAX_EFFICIENT_SIZE, total_size);
        start..end
    }

    pub fn advertisement(&self) -> ResourceAdvertisement {
        let mut flags = 0u8;
        if self.encrypted {
            flags |= super::advertisement::FLAG_ENCRYPTED;
        }
        if self.compressed {
            flags |= super::advertisement::FLAG_COMPRESSED;
        }
        if self.split {
            flags |= super::advertisement::FLAG_SPLIT;
        }
        if self.has_metadata {
            flags |= super::advertisement::FLAG_HAS_METADATA;
        }
        if self.request_id.is_some() {
            if self.is_response {
                flags |= super::advertisement::FLAG_IS_RESPONSE;
            } else {
                flags |= super::advertisement::FLAG_IS_REQUEST;
            }
        }

        // First HASHMAP_MAX_LEN map hashes go into the advertisement
        let entries = core::cmp::min(HASHMAP_MAX_LEN, self.part_hashes.len());
        let mut hashmap = Vec::with_capacity(entries * MAPHASH_LEN);
        for mh in &self.part_hashes[..entries] {
            hashmap.extend_from_slice(mh);
        }

        ResourceAdvertisement {
            transfer_size: self.size,
            data_size: self.total_size,
            parts: self.parts.len(),
            hash: self.hash,
            random_hash: self.random_hash,
            original_hash: self.original_hash,
            segment_index: self.segment_index,
            total_segments: self.total_segments,
            request_id: self.request_id,
            flags,
            hashmap,
        }
    }

    /// Resend the current advertisement WITHOUT resetting the retry
    /// counter (Python's watchdog re-sends `advertisement_packet` and
    /// only decrements; `advertise()` itself never resets retries).
    pub fn resend_advertisement(&mut self, link: &Link, tx: &mut ResourceTx) {
        let packed = self.advertisement().pack();
        if let Ok(packet) = link.context_packet(&packed, PacketContext::ResourceAdvertisement) {
            self.adv_sent = Some(unix_time());
            self.last_activity = self.adv_sent.unwrap_or_default();
            tx.push(packet);
        }
    }

    /// Send (or queue) the advertisement packet. Mirrors Python `advertise`.
    pub fn advertise(&mut self, link: &Link, tx: &mut ResourceTx) -> Result<(), RnsError> {
        let packed = self.advertisement().pack();
        let packet = link.context_packet(&packed, PacketContext::ResourceAdvertisement)?;
        self.status = ResourceStatus::Advertised;
        let now = unix_time();
        self.adv_sent = Some(now);
        self.last_activity = now;
        self.rtt = None;
        self.retries_left = MAX_ADV_RETRIES;
        tx.push(packet);
        Ok(())
    }

    /// Handle an incoming RESOURCE_REQ packet plaintext. Mirrors Python
    /// `Resource.request`.
    pub fn request(&mut self, link: &Link, request_data: &[u8], tx: &mut ResourceTx) {
        let now = unix_time();
        if let Some(adv_sent) = self.adv_sent {
            if self.rtt.is_none() {
                self.rtt = Some(now - adv_sent);
            }
        }

        if self.status != ResourceStatus::Transferring {
            self.status = ResourceStatus::Transferring;
        }

        self.retries_left = self.max_retries;

        let wants_more_hashmap = request_data.first() == Some(&super::HASHMAP_IS_EXHAUSTED);
        let pad = if wants_more_hashmap {
            1 + MAPHASH_LEN
        } else {
            1
        };

        if request_data.len() < pad + 32 {
            log::debug!("resource: malformed part request, ignoring");
            return;
        }

        let requested_hashes = &request_data[pad + 32..];
        let map_hashes: Vec<[u8; MAPHASH_LEN]> =
            requested_hashes.as_chunks::<MAPHASH_LEN>().0.to_vec();

        let search_start = self.receiver_min_consecutive_height;
        let search_end = core::cmp::min(
            self.receiver_min_consecutive_height + COLLISION_GUARD_SIZE,
            self.parts.len(),
        );

        for i in search_start..search_end {
            if map_hashes.contains(&self.part_hashes[i]) {
                let packet = self.parts[i];
                if !self.part_sent[i] {
                    self.part_sent[i] = true;
                    self.sent_parts += 1;
                }
                tx.push(packet);
                self.last_activity = now;
                self.last_part_sent = now;
            }
        }

        if wants_more_hashmap {
            let last_map_hash: [u8; MAPHASH_LEN] =
                request_data[1..1 + MAPHASH_LEN].try_into().unwrap();

            let mut part_index = self.receiver_min_consecutive_height;
            'search: for i in search_start..search_end {
                part_index += 1;
                if self.part_hashes[i] == last_map_hash {
                    break 'search;
                }
            }

            self.receiver_min_consecutive_height = part_index.saturating_sub(1 + WINDOW_MAX);

            if !part_index.is_multiple_of(HASHMAP_MAX_LEN) {
                log::error!("resource: sequencing error in hashmap update, cancelling");
                self.status = ResourceStatus::Failed;
                return;
            }
            let segment = part_index / HASHMAP_MAX_LEN;

            let hashmap_start = segment * HASHMAP_MAX_LEN;
            let hashmap_end = core::cmp::min((segment + 1) * HASHMAP_MAX_LEN, self.parts.len());

            let mut hashmap = Vec::new();
            for i in hashmap_start..hashmap_end {
                hashmap.extend_from_slice(&self.part_hashes[i]);
            }

            if hashmap.is_empty() {
                log::error!("resource: hashmap update error, cancelling");
                self.status = ResourceStatus::Failed;
                return;
            }

            let mut hmu = self.hash.as_slice().to_vec();
            let mut packed = Vec::with_capacity(8 + hashmap.len());
            rmp::encode::write_array_len(&mut packed, 2).unwrap();
            rmp::encode::write_uint(&mut packed, segment as u64).unwrap();
            rmp::encode::write_bin(&mut packed, &hashmap).unwrap();
            hmu.extend_from_slice(&packed);

            if let Ok(packet) = link.context_packet(&hmu, PacketContext::ResourceHashUpdate) {
                tx.push(packet);
                self.last_activity = now;
            }
        }

        if self.sent_parts == self.parts.len() {
            self.status = ResourceStatus::AwaitingProof;
            self.retries_left = 3;
        }
    }

    /// Validate a RESOURCE_PRF proof payload (`hash + proof_hash`).
    /// Build the next segment of a split resource
    /// (Python `__prepare_next_segment`). Returns `None` for the last
    /// segment or non-split resources.
    pub(super) fn prepare_next_segment(
        &mut self,
        link: &Link,
    ) -> Result<Option<Box<OutgoingResource>>, RnsError> {
        if !self.split || self.segment_index >= self.total_segments {
            return Ok(None);
        }

        // Segments remain, but the only source is gone. That is a failed
        // transfer, not "there is no next segment".
        let Some(mut source) = self.source.take() else {
            return Err(RnsError::ResourceMsg("resource source missing"));
        };

        let next_segment = self.segment_index + 1;
        let range = Self::segment_range(self.total_size, self.metadata_size, next_segment);

        if range.start >= self.total_size {
            self.source = Some(source);
            return Ok(None);
        }

        let segment_data = match source.read_range(range) {
            Ok(data) => data,
            Err(err) => {
                self.source = Some(source);
                return Err(err);
            }
        };
        let next_opts = ResourceOptions {
            auto_compress: self.auto_compress,
            auto_compress_limit: self.auto_compress_limit,
            timeout: Some(self.timeout),
            request_id: self.request_id,
            is_response: self.is_response,
            metadata: None,
        };

        match Self::from_segment_bytes(
            segment_data,
            source,
            self.input_len,
            self.total_size,
            self.total_segments,
            next_segment,
            Some(self.original_hash),
            link,
            next_opts,
            self.has_metadata,
            self.metadata_size,
        ) {
            Ok(next) => Ok(Some(Box::new(next))),
            Err((err, source)) => {
                self.source = Some(source);
                Err(err)
            }
        }
    }

    /// Take the prepared next segment for advertisement when this segment
    /// completes (Python advertises `next_segment` on proof).
    pub fn take_next_segment(&mut self) -> Option<Box<OutgoingResource>> {
        self.next_segment.take()
    }

    pub fn validate_proof(&mut self, proof_data: &[u8]) -> bool {
        if proof_data.len() == 64 {
            let proof_hash = &proof_data[32..];
            if proof_hash == self.expected_proof.as_slice() {
                self.status = ResourceStatus::Complete;
                return true;
            }
        }
        false
    }

    /// Build a cancel packet (initiator cancel).
    pub fn cancel_packet(&mut self, link: &Link, tx: &mut ResourceTx) {
        if let Ok(packet) =
            link.context_packet(self.hash.as_slice(), PacketContext::ResourceInitiatorCancel)
        {
            tx.push(packet);
        }
        self.status = ResourceStatus::Failed;
    }

    /// Cancel this transfer as the initiator (Python `Resource.cancel`):
    /// builds the RESOURCE_ICL packet, stops advertising/transferring and
    /// returns the packets that must be transmitted.
    pub fn cancel(&mut self, link: &Link) -> ResourceTx {
        let mut tx = ResourceTx::default();
        self.cancel_packet(link, &mut tx);
        tx
    }

    /// The hash callers use to identify this segment's logical resource
    /// (`original_hash` correlates split segments).
    pub fn resource_hash(&self) -> crate::hash::Hash {
        self.original_hash
    }

    /// Watchdog state machine for the sender side. Returns packets to send
    /// and whether the resource should be removed.
    pub fn check(&mut self, link: &Link, tx: &mut ResourceTx) -> bool {
        let now = unix_time();
        match self.status {
            ResourceStatus::Advertised => {
                let adv_sent = self.adv_sent.unwrap_or(now);
                if now > adv_sent + self.timeout + super::PROCESSING_GRACE {
                    if self.retries_left == 0 {
                        log::debug!("resource: transfer timeout after advertisement");
                        self.status = ResourceStatus::Failed;
                        return true;
                    }
                    self.retries_left -= 1;
                    self.resend_advertisement(link, tx);
                }
                false
            }
            ResourceStatus::Transferring => {
                let rtt = self.rtt.unwrap_or_else(|| link.rtt().as_secs_f64());
                let max_extra_wait: f64 = (0..super::MAX_RETRIES)
                    .map(|r| (r + 1) as f64 * super::PER_RETRY_DELAY)
                    .sum();
                let max_wait = rtt * self.timeout_factor * self.max_retries as f64
                    + self.sender_grace_time
                    + max_extra_wait;
                if now > self.last_activity + max_wait {
                    log::debug!("resource: timed out waiting for part requests");
                    self.status = ResourceStatus::Failed;
                    return true;
                }
                false
            }
            ResourceStatus::AwaitingProof => {
                self.timeout_factor = super::PROOF_TIMEOUT_FACTOR;
                let rtt = self.rtt.unwrap_or_else(|| link.rtt().as_secs_f64());
                if now > self.last_part_sent + (rtt * self.timeout_factor + self.sender_grace_time)
                {
                    if self.retries_left == 0 {
                        log::debug!("resource: timed out waiting for proof");
                        self.status = ResourceStatus::Failed;
                        return true;
                    }
                    self.retries_left -= 1;
                    // Python queries the network cache for the expected
                    // proof packet here (`Resource.AWAITING_PROOF`): the
                    // peer that already has the proof re-sends it from
                    // its own packet cache.
                    let mut expected_proof = Vec::with_capacity(64);
                    expected_proof.extend_from_slice(self.hash.as_slice());
                    expected_proof.extend_from_slice(self.expected_proof.as_slice());
                    let expected_packet_hash = crate::hash::Hash::new_from_slice(&{
                        let mut hasher = crate::hash::Hash::generator();
                        hasher.update([0x0f]);
                        hasher.update(link.id().as_slice());
                        hasher.update([PacketContext::ResourceProof as u8]);
                        hasher.update(&expected_proof);
                        hasher.finalize()
                    });
                    if let Ok(cache_request) = link.context_packet(
                        expected_packet_hash.as_slice(),
                        PacketContext::CacheRequest,
                    ) {
                        tx.push(cache_request);
                    }
                    self.last_part_sent = now;
                }
                false
            }
            _ => false,
        }
    }

    /// Transfer progress (0.0 - 1.0), including segmentation weighting.
    pub fn progress(&self) -> f64 {
        if self.status == ResourceStatus::Complete && self.segment_index == self.total_segments {
            return 1.0;
        }
        if !self.split {
            return (self.sent_parts as f64 / self.parts.len() as f64).min(1.0);
        }
        let max_parts_per_segment = (MAX_EFFICIENT_SIZE as f64 / self.sdu as f64).ceil() as usize;
        let processed_segments = self.segment_index - 1;
        let current_segment_parts = self.parts.len();
        let factor = if current_segment_parts < max_parts_per_segment {
            max_parts_per_segment as f64 / current_segment_parts as f64
        } else {
            1.0
        };
        let processed = processed_segments as f64 * max_parts_per_segment as f64
            + self.sent_parts as f64 * factor;
        let total = self.total_segments as f64 * max_parts_per_segment as f64;
        (processed / total).min(1.0)
    }
}
