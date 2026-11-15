//! Resource advertisement wire format, byte-compatible with Python
//! `RNS.Resource.ResourceAdvertisement`.

use alloc::vec::Vec;
use core::fmt;

use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};

/// Serialisation overhead of the advertisement msgpack map
/// (Python `ResourceAdvertisement.OVERHEAD`).
pub const OVERHEAD: usize = 134;

/// Number of map hashes that fit into a single link-MDU advertisement.
pub const HASHMAP_MAX_LEN: usize = (crate::packet::LINK_MDU - OVERHEAD) / super::MAPHASH_LEN;

/// Window around the currently requested map region that the sender
/// keeps searchable for part requests.
pub const COLLISION_GUARD_SIZE: usize = 2 * super::WINDOW_MAX + HASHMAP_MAX_LEN;

pub const FLAG_ENCRYPTED: u8 = 0x01;
pub const FLAG_COMPRESSED: u8 = 0x02;
pub const FLAG_SPLIT: u8 = 0x04;
pub const FLAG_IS_REQUEST: u8 = 0x08;
pub const FLAG_IS_RESPONSE: u8 = 0x10;
pub const FLAG_HAS_METADATA: u8 = 0x20;

#[derive(Clone, PartialEq, Eq)]
pub struct ResourceAdvertisement {
    /// Transfer size (size of the encrypted stream) - key `t`.
    pub transfer_size: usize,
    /// Total data size (uncompressed) - key `d`.
    pub data_size: usize,
    /// Number of parts - key `n`.
    pub parts: usize,
    /// Resource hash - key `h`.
    pub hash: Hash,
    /// Random hash (4 bytes) - key `r`.
    pub random_hash: [u8; super::RANDOM_HASH_SIZE],
    /// Original (first segment) hash - key `o`.
    pub original_hash: Hash,
    /// Segment index (1-based) - key `i`.
    pub segment_index: usize,
    /// Total number of segments - key `l`.
    pub total_segments: usize,
    /// Associated request id (truncated hash) - key `q`.
    pub request_id: Option<AddressHash>,
    /// Flags byte - key `f`.
    pub flags: u8,
    /// Hashmap slice (4-byte map hashes, first `HASHMAP_MAX_LEN` parts) - key `m`.
    pub hashmap: Vec<u8>,
}

impl fmt::Debug for ResourceAdvertisement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceAdvertisement")
            .field("hash", &self.hash)
            .field("transfer_size", &self.transfer_size)
            .field("data_size", &self.data_size)
            .field("parts", &self.parts)
            .field("segment", &[self.segment_index, self.total_segments])
            .field("flags", &format_args!("{:02x}", self.flags))
            .finish()
    }
}

impl ResourceAdvertisement {
    pub fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }

    pub fn compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }

    pub fn split(&self) -> bool {
        self.flags & FLAG_SPLIT != 0
    }

    pub fn is_request(&self) -> bool {
        self.request_id.is_some() && self.flags & FLAG_IS_REQUEST != 0
    }

    pub fn is_response(&self) -> bool {
        self.request_id.is_some() && self.flags & FLAG_IS_RESPONSE != 0
    }

    pub fn has_metadata(&self) -> bool {
        self.flags & FLAG_HAS_METADATA != 0
    }

    /// Pack the advertisement into the msgpack map layout used by Python
    /// `ResourceAdvertisement.pack` (keys: `t d n h r o i l q f m`).
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OVERHEAD + self.hashmap.len());
        // fixmap with 11 entries
        out.push(0x80 | 11);

        let key = |out: &mut Vec<u8>, k: u8| {
            // fixstr of length 1
            out.push(0xa0 | 1);
            out.push(k);
        };

        key(&mut out, b't');
        rmp::encode::write_uint(&mut out, self.transfer_size as u64).unwrap();

        key(&mut out, b'd');
        rmp::encode::write_uint(&mut out, self.data_size as u64).unwrap();

        key(&mut out, b'n');
        rmp::encode::write_uint(&mut out, self.parts as u64).unwrap();

        key(&mut out, b'h');
        rmp::encode::write_bin(&mut out, self.hash.as_slice()).unwrap();

        key(&mut out, b'r');
        rmp::encode::write_bin(&mut out, &self.random_hash).unwrap();

        key(&mut out, b'o');
        rmp::encode::write_bin(&mut out, self.original_hash.as_slice()).unwrap();

        key(&mut out, b'i');
        rmp::encode::write_uint(&mut out, self.segment_index as u64).unwrap();

        key(&mut out, b'l');
        rmp::encode::write_uint(&mut out, self.total_segments as u64).unwrap();

        key(&mut out, b'q');
        match &self.request_id {
            Some(id) => rmp::encode::write_bin(&mut out, id.as_slice()).unwrap(),
            None => rmp::encode::write_nil(&mut out).unwrap(),
        }

        key(&mut out, b'f');
        rmp::encode::write_uint(&mut out, self.flags as u64).unwrap();

        key(&mut out, b'm');
        rmp::encode::write_bin(&mut out, &self.hashmap).unwrap();

        out
    }

    /// Unpack an advertisement produced by Python `pack` or this crate.
    pub fn unpack(data: &[u8]) -> Result<Self, RnsError> {
        let mut cursor = data;

        let entries = read_map_len(&mut cursor)?;
        if entries != 11 {
            return Err(RnsError::PacketError);
        }

        let mut transfer_size = None;
        let mut data_size = None;
        let mut parts = None;
        let mut hash = None;
        let mut random_hash = None;
        let mut original_hash = None;
        let mut segment_index = None;
        let mut total_segments = None;
        let mut request_id = None;
        let mut flags = None;
        let mut hashmap = None;

        for _ in 0..entries {
            let key = read_short_key(&mut cursor)?;
            match key {
                b't' => transfer_size = Some(read_uint(&mut cursor)? as usize),
                b'd' => data_size = Some(read_uint(&mut cursor)? as usize),
                b'n' => parts = Some(read_uint(&mut cursor)? as usize),
                b'h' => hash = Some(read_hash(&mut cursor)?),
                b'r' => random_hash = Some(read_fixed_bin(&mut cursor)?),
                b'o' => original_hash = Some(read_hash(&mut cursor)?),
                b'i' => segment_index = Some(read_uint(&mut cursor)? as usize),
                b'l' => total_segments = Some(read_uint(&mut cursor)? as usize),
                b'q' => {
                    if peek_nil(&mut cursor)? {
                        cursor = &cursor[1..];
                        request_id = None;
                    } else {
                        let data = read_bin(&mut cursor)?;
                        if data.len() != 16 {
                            return Err(RnsError::PacketError);
                        }
                        request_id = Some(AddressHash::new(data.as_slice().try_into().unwrap()));
                    }
                }
                b'f' => flags = Some(read_uint(&mut cursor)? as u8),
                b'm' => hashmap = Some(read_bin(&mut cursor)?),
                _ => return Err(RnsError::PacketError),
            }
        }

        let hash = hash.ok_or(RnsError::PacketError)?;
        let original_hash = original_hash.ok_or(RnsError::PacketError)?;
        let transfer_size = transfer_size.ok_or(RnsError::PacketError)?;
        let random_hash: [u8; super::RANDOM_HASH_SIZE] =
            random_hash.ok_or(RnsError::PacketError)?;
        let flags = flags.unwrap_or(0);

        if transfer_size > super::MAX_EFFICIENT_SIZE * 3 {
            return Err(RnsError::PacketError);
        }

        Ok(Self {
            transfer_size,
            data_size: data_size.ok_or(RnsError::PacketError)?,
            parts: parts.ok_or(RnsError::PacketError)?,
            hash,
            random_hash,
            original_hash,
            segment_index: segment_index.unwrap_or(1).max(1),
            total_segments: total_segments.unwrap_or(1).max(1),
            request_id,
            flags,
            hashmap: hashmap.unwrap_or_default(),
        })
    }
}

fn read_map_len(cursor: &mut &[u8]) -> Result<usize, RnsError> {
    let len = rmp::decode::read_map_len(cursor).map_err(|_| RnsError::PacketError)?;
    Ok(len as usize)
}

fn read_short_key(cursor: &mut &[u8]) -> Result<u8, RnsError> {
    let byte = *cursor.first().ok_or(RnsError::PacketError)?;
    if byte >> 5 == 0b101 {
        // fixstr
        let len = (byte & 0x1f) as usize;
        *cursor = &cursor[1..];
        if len != 1 || cursor.is_empty() {
            return Err(RnsError::PacketError);
        }
        let key = cursor[0];
        *cursor = &cursor[1..];
        Ok(key)
    } else {
        Err(RnsError::PacketError)
    }
}

fn read_uint(cursor: &mut &[u8]) -> Result<u64, RnsError> {
    let value: u64 = rmp::decode::read_int(cursor).map_err(|_| RnsError::PacketError)?;
    Ok(value)
}

fn peek_nil(cursor: &mut &[u8]) -> Result<bool, RnsError> {
    match cursor.first() {
        Some(0xc0) => Ok(true),
        Some(_) => Ok(false),
        None => Err(RnsError::PacketError),
    }
}

fn read_bin(cursor: &mut &[u8]) -> Result<Vec<u8>, RnsError> {
    let len = rmp::decode::read_bin_len(cursor).map_err(|_| RnsError::PacketError)? as usize;
    if cursor.len() < len {
        return Err(RnsError::PacketError);
    }
    let data = cursor[..len].to_vec();
    *cursor = &cursor[len..];
    Ok(data)
}

fn read_fixed_bin<const N: usize>(cursor: &mut &[u8]) -> Result<[u8; N], RnsError> {
    let data = read_bin(cursor)?;
    if data.len() != N {
        return Err(RnsError::PacketError);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&data);
    Ok(out)
}

fn read_hash(cursor: &mut &[u8]) -> Result<Hash, RnsError> {
    let data = read_bin(cursor)?;
    if data.len() != crate::hash::HASH_SIZE {
        return Err(RnsError::PacketError);
    }
    let mut bytes = [0u8; crate::hash::HASH_SIZE];
    bytes.copy_from_slice(&data);
    Ok(Hash::new(bytes))
}
