use alloc::sync::Arc;
use alloc::vec::Vec;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::error::RnsError;
use crate::hash::{AddressHash, Hash, ADDRESS_HASH_SIZE};
use crate::utils::cache_set::CacheSet;

pub const RESOURCE_ID_LEN: usize = ADDRESS_HASH_SIZE;
pub const RESOURCE_VERSION: u8 = 1;

const FLAG_HAS_REQUEST_ID: u8 = 0x01;
const FLAG_IS_RESPONSE: u8 = 0x02;
const FLAG_IS_REQUEST: u8 = 0x04;

pub const RESOURCE_ADV_HEADER_LEN: usize =
    1 + 1 + RESOURCE_ID_LEN + RESOURCE_ID_LEN + 4 + 4 + 4;
pub const RESOURCE_PART_HEADER_LEN: usize = 1 + RESOURCE_ID_LEN + 4;
pub const RESOURCE_PROOF_LEN: usize = 1 + RESOURCE_ID_LEN + 1;
pub const RESOURCE_REQUEST_HEADER_LEN: usize = 1 + RESOURCE_ID_LEN + 2;
pub const RESOURCE_HASH_UPDATE_HEADER_LEN: usize = 1 + RESOURCE_ID_LEN;
pub const RESOURCE_CANCEL_LEN: usize = 1 + RESOURCE_ID_LEN;
pub const RESOURCE_DEFAULT_MAX_RETRIES: u32 = 3;
pub const RESOURCE_PROOF_STATUS_OK: u8 = 0x01;
pub const RESOURCE_PROOF_STATUS_FAILED: u8 = 0x00;
pub const RESOURCE_MAPHASH_LEN: usize = 4;
pub const RESOURCE_HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const RESOURCE_HASHMAP_IS_EXHAUSTED: u8 = 0xff;

fn compute_map_hash(data: &[u8]) -> [u8; RESOURCE_MAPHASH_LEN] {
    let hash = Hash::new_from_slice(data);
    let mut out = [0u8; RESOURCE_MAPHASH_LEN];
    out.copy_from_slice(&hash.as_slice()[..RESOURCE_MAPHASH_LEN]);
    out
}
const RESOURCE_COMPLETED_CACHE_SIZE: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceAdvertisement {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub request_id: Option<[u8; RESOURCE_ID_LEN]>,
    pub total_len: u32,
    pub part_size: u32,
    pub total_parts: u32,
    pub is_response: bool,
    pub is_request: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceAdvertisementResult {
    Accepted,
    AlreadyCompleted,
}

impl ResourceAdvertisement {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESOURCE_ADV_HEADER_LEN);
        out.push(RESOURCE_VERSION);
        let mut flags = 0u8;
        if self.request_id.is_some() {
            flags |= FLAG_HAS_REQUEST_ID;
        }
        if self.is_response {
            flags |= FLAG_IS_RESPONSE;
        }
        if self.is_request {
            flags |= FLAG_IS_REQUEST;
        }
        out.push(flags);
        out.extend_from_slice(&self.resource_id);
        if let Some(request_id) = self.request_id {
            out.extend_from_slice(&request_id);
        } else {
            out.extend_from_slice(&[0u8; RESOURCE_ID_LEN]);
        }
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.total_parts.to_be_bytes());
        out.extend_from_slice(&self.part_size.to_be_bytes());
        out
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RnsError> {
        if buffer.len() < RESOURCE_ADV_HEADER_LEN {
            return Err(RnsError::OutOfMemory);
        }
        if buffer[0] != RESOURCE_VERSION {
            return Err(RnsError::InvalidArgument);
        }
        let flags = buffer[1];
        let mut resource_id = [0u8; RESOURCE_ID_LEN];
        resource_id.copy_from_slice(&buffer[2..2 + RESOURCE_ID_LEN]);
        let mut request_id_buf = [0u8; RESOURCE_ID_LEN];
        let request_id_start = 2 + RESOURCE_ID_LEN;
        request_id_buf.copy_from_slice(
            &buffer[request_id_start..request_id_start + RESOURCE_ID_LEN],
        );
        let mut offset = request_id_start + RESOURCE_ID_LEN;
        let total_len = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        let total_parts = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        let part_size = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);

        let request_id = if flags & FLAG_HAS_REQUEST_ID != 0 {
            Some(request_id_buf)
        } else {
            None
        };

        Ok(ResourceAdvertisement {
            resource_id,
            request_id,
            total_len,
            part_size,
            total_parts,
            is_response: flags & FLAG_IS_RESPONSE != 0,
            is_request: flags & FLAG_IS_REQUEST != 0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePart {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub part_index: u32,
    pub data: Vec<u8>,
}

impl ResourcePart {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESOURCE_PART_HEADER_LEN + self.data.len());
        out.push(RESOURCE_VERSION);
        out.extend_from_slice(&self.resource_id);
        out.extend_from_slice(&self.part_index.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RnsError> {
        if buffer.len() < RESOURCE_PART_HEADER_LEN {
            return Err(RnsError::OutOfMemory);
        }
        if buffer[0] != RESOURCE_VERSION {
            return Err(RnsError::InvalidArgument);
        }
        let mut resource_id = [0u8; RESOURCE_ID_LEN];
        resource_id.copy_from_slice(&buffer[1..1 + RESOURCE_ID_LEN]);
        let index_offset = 1 + RESOURCE_ID_LEN;
        let part_index = u32::from_be_bytes([
            buffer[index_offset],
            buffer[index_offset + 1],
            buffer[index_offset + 2],
            buffer[index_offset + 3],
        ]);
        let data = buffer[index_offset + 4..].to_vec();
        Ok(ResourcePart {
            resource_id,
            part_index,
            data,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceProof {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub status: u8,
}

impl ResourceProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESOURCE_PROOF_LEN);
        out.push(RESOURCE_VERSION);
        out.extend_from_slice(&self.resource_id);
        out.push(self.status);
        out
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RnsError> {
        if buffer.len() < RESOURCE_PROOF_LEN {
            return Err(RnsError::OutOfMemory);
        }
        if buffer[0] != RESOURCE_VERSION {
            return Err(RnsError::InvalidArgument);
        }
        let mut resource_id = [0u8; RESOURCE_ID_LEN];
        resource_id.copy_from_slice(&buffer[1..1 + RESOURCE_ID_LEN]);
        Ok(ResourceProof {
            resource_id,
            status: buffer[1 + RESOURCE_ID_LEN],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRequest {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub hashmap_exhausted: bool,
    pub last_map_hash: Option<[u8; RESOURCE_MAPHASH_LEN]>,
    pub requested_hashes: Vec<[u8; RESOURCE_MAPHASH_LEN]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceHashUpdate {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub segment: u32,
    pub hashmap: Vec<u8>,
}

impl ResourceHashUpdate {
    pub fn encode(&self) -> Vec<u8> {
        let mut msgpack = Vec::new();
        let _ = rmp::encode::write_array_len(&mut msgpack, 2);
        let _ = rmp::encode::write_uint(&mut msgpack, self.segment as u64);
        let _ = rmp::encode::write_bin(&mut msgpack, &self.hashmap);

        let mut out = Vec::with_capacity(RESOURCE_HASH_UPDATE_HEADER_LEN + msgpack.len());
        out.push(RESOURCE_VERSION);
        out.extend_from_slice(&self.resource_id);
        out.extend_from_slice(&msgpack);
        out
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RnsError> {
        if buffer.len() < RESOURCE_HASH_UPDATE_HEADER_LEN {
            return Err(RnsError::OutOfMemory);
        }
        if buffer[0] != RESOURCE_VERSION {
            return Err(RnsError::InvalidArgument);
        }
        let mut resource_id = [0u8; RESOURCE_ID_LEN];
        resource_id.copy_from_slice(&buffer[1..1 + RESOURCE_ID_LEN]);
        let mut cursor = std::io::Cursor::new(&buffer[1 + RESOURCE_ID_LEN..]);
        let array_len = rmp::decode::read_array_len(&mut cursor)
            .map_err(|_| RnsError::InvalidArgument)?;
        if array_len != 2 {
            return Err(RnsError::InvalidArgument);
        }
        let segment: u64 = rmp::decode::read_int(&mut cursor)
            .map_err(|_| RnsError::InvalidArgument)?;
        if segment > u32::MAX as u64 {
            return Err(RnsError::InvalidArgument);
        }
        let bin_len = rmp::decode::read_bin_len(&mut cursor)
            .map_err(|_| RnsError::InvalidArgument)? as usize;
        let mut hashmap = vec![0u8; bin_len];
        use std::io::Read;
        cursor
            .read_exact(&mut hashmap)
            .map_err(|_| RnsError::InvalidArgument)?;
        Ok(ResourceHashUpdate {
            resource_id,
            segment: segment as u32,
            hashmap,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceCancel {
    pub resource_id: [u8; RESOURCE_ID_LEN],
}

impl ResourceCancel {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESOURCE_CANCEL_LEN);
        out.push(RESOURCE_VERSION);
        out.extend_from_slice(&self.resource_id);
        out
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RnsError> {
        if buffer.len() < RESOURCE_CANCEL_LEN {
            return Err(RnsError::OutOfMemory);
        }
        if buffer[0] != RESOURCE_VERSION {
            return Err(RnsError::InvalidArgument);
        }
        let mut resource_id = [0u8; RESOURCE_ID_LEN];
        resource_id.copy_from_slice(&buffer[1..1 + RESOURCE_ID_LEN]);
        Ok(ResourceCancel { resource_id })
    }
}

impl ResourceRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + RESOURCE_MAPHASH_LEN + RESOURCE_ID_LEN + self.requested_hashes.len() * RESOURCE_MAPHASH_LEN,
        );
        if self.hashmap_exhausted {
            out.push(RESOURCE_HASHMAP_IS_EXHAUSTED);
            out.extend_from_slice(
                &self
                    .last_map_hash
                    .unwrap_or([0u8; RESOURCE_MAPHASH_LEN]),
            );
        } else {
            out.push(RESOURCE_HASHMAP_IS_NOT_EXHAUSTED);
        }
        out.extend_from_slice(&self.resource_id);
        for hash in &self.requested_hashes {
            out.extend_from_slice(hash);
        }
        out
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, RnsError> {
        if buffer.is_empty() {
            return Err(RnsError::OutOfMemory);
        }
        let mut offset = 0;
        let flag = buffer[offset];
        offset += 1;
        let hashmap_exhausted = flag == RESOURCE_HASHMAP_IS_EXHAUSTED;
        let last_map_hash = if hashmap_exhausted {
            if offset + RESOURCE_MAPHASH_LEN > buffer.len() {
                return Err(RnsError::OutOfMemory);
            }
            let mut hash = [0u8; RESOURCE_MAPHASH_LEN];
            hash.copy_from_slice(&buffer[offset..offset + RESOURCE_MAPHASH_LEN]);
            offset += RESOURCE_MAPHASH_LEN;
            Some(hash)
        } else {
            None
        };
        if offset + RESOURCE_ID_LEN > buffer.len() {
            return Err(RnsError::OutOfMemory);
        }
        let mut resource_id = [0u8; RESOURCE_ID_LEN];
        resource_id.copy_from_slice(&buffer[offset..offset + RESOURCE_ID_LEN]);
        offset += RESOURCE_ID_LEN;

        let mut requested_hashes = Vec::new();
        while offset + RESOURCE_MAPHASH_LEN <= buffer.len() {
            let mut hash = [0u8; RESOURCE_MAPHASH_LEN];
            hash.copy_from_slice(&buffer[offset..offset + RESOURCE_MAPHASH_LEN]);
            requested_hashes.push(hash);
            offset += RESOURCE_MAPHASH_LEN;
        }
        if offset != buffer.len() {
            return Err(RnsError::InvalidArgument);
        }
        if hashmap_exhausted && last_map_hash.is_none() {
            return Err(RnsError::InvalidArgument);
        }
        Ok(ResourceRequest {
            resource_id,
            hashmap_exhausted,
            last_map_hash,
            requested_hashes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceReceiptStatus {
    Sent,
    Completed,
    Failed,
}

#[derive(Debug, Clone)]
pub struct ResourceReceipt {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub status: ResourceReceiptStatus,
    pub sent_at: Instant,
    pub concluded_at: Option<Instant>,
    pub timeout: Duration,
}

pub type ResourceReceiptHandle = Arc<Mutex<ResourceReceipt>>;

#[derive(Debug, Clone)]
pub struct ResourceCompletion {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub data: Vec<u8>,
    pub request_id: Option<[u8; RESOURCE_ID_LEN]>,
    pub is_response: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct ResourceProgress {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub request_id: Option<[u8; RESOURCE_ID_LEN]>,
    pub is_response: bool,
    pub progress: f32,
}

#[derive(Debug, Clone)]
pub enum ResourceEvent {
    Progress(ResourceProgress),
    Complete(ResourceCompletion),
}

#[derive(Debug, Clone)]
pub struct ResourceCancelEvent {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub request_id: Option<[u8; RESOURCE_ID_LEN]>,
    pub is_response: bool,
}

#[derive(Debug, Clone)]
pub struct ResourceTimeout {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub link_id: [u8; RESOURCE_ID_LEN],
    pub request_id: Option<[u8; RESOURCE_ID_LEN]>,
    pub is_response: bool,
    pub requested_hashes: Vec<[u8; RESOURCE_MAPHASH_LEN]>,
    pub hashmap_exhausted: bool,
    pub last_map_hash: Option<[u8; RESOURCE_MAPHASH_LEN]>,
    pub failed: bool,
}

struct ResourceAssembly {
    resource_id: [u8; RESOURCE_ID_LEN],
    link_id: [u8; RESOURCE_ID_LEN],
    request_id: Option<[u8; RESOURCE_ID_LEN]>,
    is_response: bool,
    total_len: usize,
    total_parts: u32,
    part_size: usize,
    received: Vec<Option<Vec<u8>>>,
    received_count: u32,
    hashmap: Vec<Option<[u8; RESOURCE_MAPHASH_LEN]>>,
    last_activity: Instant,
    retries: u32,
    max_retries: u32,
}

pub struct ResourceTracker {
    incoming: HashMap<[u8; RESOURCE_ID_LEN], ResourceAssembly>,
    timeout: Duration,
    completed: CacheSet<[u8; RESOURCE_ID_LEN]>,
}

impl ResourceTracker {
    pub fn new(timeout: Duration) -> Self {
        Self {
            incoming: HashMap::new(),
            timeout,
            completed: CacheSet::new(RESOURCE_COMPLETED_CACHE_SIZE),
        }
    }

    pub fn handle_advertisement(
        &mut self,
        advert: ResourceAdvertisement,
        link_id: [u8; RESOURCE_ID_LEN],
        now: Instant,
    ) -> Result<ResourceAdvertisementResult, RnsError> {
        if self.completed.contains(&advert.resource_id) {
            return Ok(ResourceAdvertisementResult::AlreadyCompleted);
        }
        if advert.total_parts == 0 {
            return Err(RnsError::InvalidArgument);
        }
        let total_parts = advert.total_parts as usize;
        if total_parts == 0 {
            return Err(RnsError::InvalidArgument);
        }
        let assembly = ResourceAssembly {
            resource_id: advert.resource_id,
            link_id,
            request_id: advert.request_id,
            is_response: advert.is_response,
            total_len: advert.total_len as usize,
            total_parts: advert.total_parts,
            part_size: advert.part_size as usize,
            received: vec![None; total_parts],
            received_count: 0,
            hashmap: vec![None; total_parts],
            last_activity: now,
            retries: 0,
            max_retries: RESOURCE_DEFAULT_MAX_RETRIES,
        };
        self.incoming.insert(advert.resource_id, assembly);
        Ok(ResourceAdvertisementResult::Accepted)
    }

    pub fn handle_part(&mut self, part: ResourcePart) -> Result<Option<ResourceEvent>, RnsError> {
        let assembly = match self.incoming.get_mut(&part.resource_id) {
            Some(assembly) => assembly,
            None => return Ok(None),
        };
        if part.data.len() > assembly.part_size {
            return Err(RnsError::OutOfMemory);
        }
        let index = part.part_index as usize;
        if index >= assembly.received.len() {
            return Err(RnsError::InvalidArgument);
        }
        if assembly.received[index].is_none() {
            assembly.received[index] = Some(part.data);
            assembly.received_count += 1;
        }
        if assembly.hashmap[index].is_none() {
            if let Some(data) = assembly.received[index].as_ref() {
                assembly.hashmap[index] = Some(compute_map_hash(data));
            }
        }
        assembly.last_activity = Instant::now();
        if assembly.received_count == assembly.total_parts {
            let resource_id = assembly.resource_id;
            let mut data = Vec::with_capacity(assembly.total_len);
            for chunk in assembly.received.iter() {
                if let Some(chunk) = chunk {
                    data.extend_from_slice(chunk);
                }
            }
            data.truncate(assembly.total_len);
            let completion = ResourceCompletion {
                resource_id,
                data,
                request_id: assembly.request_id,
                is_response: assembly.is_response,
            };
            self.incoming.remove(&resource_id);
            self.completed.insert(&resource_id);
            return Ok(Some(ResourceEvent::Complete(completion)));
        }
        let progress = (assembly.received_count as f32) / (assembly.total_parts as f32);
        Ok(Some(ResourceEvent::Progress(ResourceProgress {
            resource_id: assembly.resource_id,
            request_id: assembly.request_id,
            is_response: assembly.is_response,
            progress,
        })))
    }

    pub fn handle_hash_update(
        &mut self,
        update: ResourceHashUpdate,
        now: Instant,
    ) -> bool {
        if let Some(assembly) = self.incoming.get_mut(&update.resource_id) {
            if update.hashmap.len() % RESOURCE_MAPHASH_LEN != 0 {
                return false;
            }
            let entries = update.hashmap.len() / RESOURCE_MAPHASH_LEN;
            let start = update.segment as usize * entries;
            for i in 0..entries {
                let idx = start + i;
                if idx >= assembly.hashmap.len() {
                    break;
                }
                let mut hash = [0u8; RESOURCE_MAPHASH_LEN];
                let offset = i * RESOURCE_MAPHASH_LEN;
                hash.copy_from_slice(&update.hashmap[offset..offset + RESOURCE_MAPHASH_LEN]);
                assembly.hashmap[idx] = Some(hash);
            }
            assembly.last_activity = now;
            true
        } else {
            false
        }
    }

    pub fn handle_cancel(
        &mut self,
        resource_id: [u8; RESOURCE_ID_LEN],
    ) -> Option<ResourceCancelEvent> {
        let assembly = self.incoming.remove(&resource_id)?;
        self.completed.insert(&resource_id);
        Some(ResourceCancelEvent {
            resource_id,
            request_id: assembly.request_id,
            is_response: assembly.is_response,
        })
    }

    pub fn poll_timeouts(&mut self, now: Instant) -> Vec<ResourceTimeout> {
        let mut expired = Vec::new();
        let keys: Vec<[u8; RESOURCE_ID_LEN]> = self
            .incoming
            .keys()
            .copied()
            .collect();
        for key in keys {
            let timeout_hit = match self.incoming.get(&key) {
                Some(assembly) => now.duration_since(assembly.last_activity) >= self.timeout,
                None => false,
            };
            if !timeout_hit {
                continue;
            }
            let mut failed = false;
            let mut requested_hashes = Vec::new();
            let mut hashmap_exhausted = false;
            let mut last_map_hash = None;
            if let Some(assembly) = self.incoming.get_mut(&key) {
                if assembly.retries >= assembly.max_retries {
                    failed = true;
                } else {
                    assembly.retries += 1;
                    assembly.last_activity = now;
                }
                for (idx, chunk) in assembly.received.iter().enumerate() {
                    if chunk.is_none() {
                        if let Some(hash) = assembly.hashmap.get(idx).and_then(|h| *h) {
                            requested_hashes.push(hash);
                        } else {
                            hashmap_exhausted = true;
                        }
                    }
                }
                last_map_hash = assembly
                    .hashmap
                    .iter()
                    .rposition(|h| h.is_some())
                    .and_then(|idx| assembly.hashmap[idx]);
            }
            if failed {
                if let Some(assembly) = self.incoming.remove(&key) {
                    expired.push(ResourceTimeout {
                        resource_id: assembly.resource_id,
                        link_id: assembly.link_id,
                        request_id: assembly.request_id,
                        is_response: assembly.is_response,
                        requested_hashes,
                        hashmap_exhausted,
                        last_map_hash,
                        failed: true,
                    });
                }
            } else if let Some(assembly) = self.incoming.get(&key) {
                expired.push(ResourceTimeout {
                    resource_id: assembly.resource_id,
                    link_id: assembly.link_id,
                    request_id: assembly.request_id,
                    is_response: assembly.is_response,
                    requested_hashes,
                    hashmap_exhausted,
                    last_map_hash,
                    failed: false,
                });
            }
        }
        expired
    }
}

pub struct ResourceSender;

impl ResourceSender {
    pub fn split(
        data: &[u8],
        part_size: usize,
        request_id: Option<[u8; RESOURCE_ID_LEN]>,
        is_response: bool,
        is_request: bool,
    ) -> Result<(ResourceAdvertisement, Vec<ResourcePart>), RnsError> {
        if part_size == 0 {
            return Err(RnsError::InvalidArgument);
        }
        let total_len = data.len();
        let total_parts = ((total_len + part_size - 1) / part_size) as u32;
        let hash = Hash::new_from_slice(data);
        let address_hash = AddressHash::new_from_hash(&hash);
        let mut resource_id = [0u8; RESOURCE_ID_LEN];
        resource_id.copy_from_slice(address_hash.as_slice());
        let advert = ResourceAdvertisement {
            resource_id,
            request_id,
            total_len: total_len as u32,
            part_size: part_size as u32,
            total_parts,
            is_response,
            is_request,
        };
        let mut parts = Vec::with_capacity(total_parts as usize);
        for (idx, chunk) in data.chunks(part_size).enumerate() {
            parts.push(ResourcePart {
                resource_id,
                part_index: idx as u32,
                data: chunk.to_vec(),
            });
        }
        Ok((advert, parts))
    }
}

#[derive(Debug, Clone)]
pub struct ResourceSendState {
    pub resource_id: [u8; RESOURCE_ID_LEN],
    pub destination: AddressHash,
    pub request_id: Option<[u8; RESOURCE_ID_LEN]>,
    pub is_response: bool,
    pub is_request: bool,
    pub advert: ResourceAdvertisement,
    pub parts: Vec<ResourcePart>,
    pub receipt: ResourceReceiptHandle,
    timeout: Duration,
    last_sent: Instant,
    retries: u32,
    max_retries: u32,
}

impl ResourceSendState {
    pub fn new(
        destination: AddressHash,
        data: &[u8],
        part_size: usize,
        request_id: Option<[u8; RESOURCE_ID_LEN]>,
        is_response: bool,
        is_request: bool,
        timeout: Duration,
        max_retries: u32,
    ) -> Result<Self, RnsError> {
        let (advert, parts) =
            ResourceSender::split(data, part_size, request_id, is_response, is_request)?;
        let receipt = Arc::new(Mutex::new(ResourceReceipt {
            resource_id: advert.resource_id,
            status: ResourceReceiptStatus::Sent,
            sent_at: Instant::now(),
            concluded_at: None,
            timeout,
        }));
        Ok(Self {
            resource_id: advert.resource_id,
            destination,
            request_id: advert.request_id,
            is_response,
            is_request,
            advert,
            parts,
            receipt,
            timeout,
            last_sent: Instant::now(),
            retries: 0,
            max_retries,
        })
    }

    pub fn mark_sent(&mut self, now: Instant) {
        self.last_sent = now;
    }

    pub fn handle_proof(&mut self, proof: &ResourceProof) -> bool {
        if proof.resource_id != self.resource_id {
            return false;
        }
        let mut receipt = self.receipt.lock().unwrap();
        if proof.status == RESOURCE_PROOF_STATUS_OK {
            receipt.status = ResourceReceiptStatus::Completed;
        } else {
            receipt.status = ResourceReceiptStatus::Failed;
        }
        receipt.concluded_at = Some(Instant::now());
        true
    }

    pub fn mark_failed(&mut self, now: Instant) {
        let mut receipt = self.receipt.lock().unwrap();
        receipt.status = ResourceReceiptStatus::Failed;
        receipt.concluded_at = Some(now);
    }

    pub fn handle_request(&self, request: &ResourceRequest) -> Vec<ResourcePart> {
        if request.resource_id != self.resource_id {
            return Vec::new();
        }
        if request.requested_hashes.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for part in &self.parts {
            let map_hash = compute_map_hash(&part.data);
            if request.requested_hashes.iter().any(|h| *h == map_hash) {
                out.push(part.clone());
            }
        }
        out
    }

    pub fn poll_retry(&mut self, now: Instant) -> Option<Vec<ResourcePart>> {
        if now.duration_since(self.last_sent) < self.timeout {
            return None;
        }
        if self.retries >= self.max_retries {
            let mut receipt = self.receipt.lock().unwrap();
            receipt.status = ResourceReceiptStatus::Failed;
            receipt.concluded_at = Some(now);
            return None;
        }
        self.retries += 1;
        self.last_sent = now;
        Some(self.parts.clone())
    }

    pub fn status(&self) -> ResourceReceiptStatus {
        self.receipt.lock().unwrap().status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_round_trip() {
        let advert = ResourceAdvertisement {
            resource_id: [0x11u8; RESOURCE_ID_LEN],
            request_id: Some([0x22u8; RESOURCE_ID_LEN]),
            total_len: 123,
            part_size: 32,
            total_parts: 4,
            is_response: true,
            is_request: false,
        };
        let encoded = advert.encode();
        let decoded = ResourceAdvertisement::decode(&encoded).expect("decode");
        assert_eq!(decoded.resource_id, advert.resource_id);
        assert_eq!(decoded.request_id, advert.request_id);
        assert_eq!(decoded.total_len, advert.total_len);
        assert!(decoded.is_response);
        assert!(!decoded.is_request);
    }

    #[test]
    fn tracker_completes_resource() {
        let payload = vec![0x42u8; 80];
        let (advert, parts) =
            ResourceSender::split(&payload, 32, None, false, false).expect("split");
        let mut tracker = ResourceTracker::new(Duration::from_secs(10));
        let result = tracker
            .handle_advertisement(advert, [0u8; RESOURCE_ID_LEN], Instant::now())
            .expect("advert");
        assert_eq!(result, ResourceAdvertisementResult::Accepted);
        let mut completion = None;
        for part in parts {
            match tracker.handle_part(part).expect("part") {
                Some(ResourceEvent::Complete(done)) => completion = Some(done),
                _ => {}
            }
        }
        let completion = completion.expect("completion");
        assert_eq!(completion.data, payload);
    }

    #[test]
    fn advertisement_after_completion_is_cached() {
        let payload = vec![0x10u8; 48];
        let (advert, parts) =
            ResourceSender::split(&payload, 16, None, false, false).expect("split");
        let mut tracker = ResourceTracker::new(Duration::from_secs(10));
        tracker
            .handle_advertisement(advert, [0u8; RESOURCE_ID_LEN], Instant::now())
            .expect("advert");
        for part in parts {
            let _ = tracker.handle_part(part).expect("part");
        }
        let result = tracker
            .handle_advertisement(advert, [0u8; RESOURCE_ID_LEN], Instant::now())
            .expect("advert");
        assert_eq!(result, ResourceAdvertisementResult::AlreadyCompleted);
    }

    #[test]
    fn request_round_trip() {
        let req = ResourceRequest {
            resource_id: [0x11u8; RESOURCE_ID_LEN],
            hashmap_exhausted: false,
            last_map_hash: None,
            requested_hashes: vec![
                [0x01u8; RESOURCE_MAPHASH_LEN],
                [0x02u8; RESOURCE_MAPHASH_LEN],
            ],
        };
        let encoded = req.encode();
        let decoded = ResourceRequest::decode(&encoded).expect("decode");
        assert_eq!(decoded.resource_id, req.resource_id);
        assert_eq!(decoded.hashmap_exhausted, req.hashmap_exhausted);
        assert_eq!(decoded.last_map_hash, req.last_map_hash);
        assert_eq!(decoded.requested_hashes, req.requested_hashes);
    }

    #[test]
    fn request_matches_python_format() {
        let req = ResourceRequest {
            resource_id: [0x11u8; RESOURCE_ID_LEN],
            hashmap_exhausted: true,
            last_map_hash: Some([0xaau8, 0xbbu8, 0xccu8, 0xddu8]),
            requested_hashes: vec![
                [0x01u8; RESOURCE_MAPHASH_LEN],
                [0x02u8; RESOURCE_MAPHASH_LEN],
            ],
        };
        let encoded = req.encode();
        let mut expected = Vec::new();
        expected.push(RESOURCE_HASHMAP_IS_EXHAUSTED);
        expected.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
        expected.extend_from_slice(&req.resource_id);
        expected.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]);
        expected.extend_from_slice(&[0x02, 0x02, 0x02, 0x02]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn request_rejects_invalid_exhausted_without_hash() {
        let mut encoded = Vec::new();
        encoded.push(RESOURCE_HASHMAP_IS_EXHAUSTED);
        encoded.extend_from_slice(&[0u8; RESOURCE_ID_LEN]);
        assert!(ResourceRequest::decode(&encoded).is_err());
    }

    #[test]
    fn request_rejects_trailing_bytes() {
        let mut encoded = Vec::new();
        encoded.push(RESOURCE_HASHMAP_IS_NOT_EXHAUSTED);
        encoded.extend_from_slice(&[0u8; RESOURCE_ID_LEN]);
        encoded.extend_from_slice(&[0x01, 0x02]);
        assert!(ResourceRequest::decode(&encoded).is_err());
    }

    #[test]
    fn handle_request_selects_hashes() {
        let data: Vec<u8> = (0u8..64u8).collect();
        let dest = AddressHash::new_empty();
        let state = ResourceSendState::new(
            dest,
            &data,
            16,
            None,
            false,
            false,
            Duration::from_secs(1),
            1,
        )
        .expect("state");
        let hashes: Vec<[u8; RESOURCE_MAPHASH_LEN]> = state
            .parts
            .iter()
            .map(|part| compute_map_hash(&part.data))
            .collect();
        let mut unique = hashes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), hashes.len());

        let target_hash = hashes[0];
        let request = ResourceRequest {
            resource_id: state.resource_id,
            hashmap_exhausted: false,
            last_map_hash: None,
            requested_hashes: vec![target_hash],
        };
        let parts = state.handle_request(&request);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].part_index, 0);
    }

    #[test]
    fn hash_update_round_trip() {
        let update = ResourceHashUpdate {
            resource_id: [0x33u8; RESOURCE_ID_LEN],
            segment: 2,
            hashmap: vec![0x01, 0x02, 0x03],
        };
        let encoded = update.encode();
        let decoded = ResourceHashUpdate::decode(&encoded).expect("decode");
        assert_eq!(decoded.resource_id, update.resource_id);
        assert_eq!(decoded.segment, update.segment);
        assert_eq!(decoded.hashmap, update.hashmap);
    }

    #[test]
    fn hash_update_matches_msgpack_format() {
        let update = ResourceHashUpdate {
            resource_id: [0x10u8; RESOURCE_ID_LEN],
            segment: 1,
            hashmap: vec![0xaa, 0xbb, 0xcc, 0xdd],
        };
        let encoded = update.encode();
        let mut expected = Vec::new();
        expected.push(RESOURCE_VERSION);
        expected.extend_from_slice(&update.resource_id);
        expected.extend_from_slice(&[0x92, 0x01, 0xc4, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn cancel_round_trip() {
        let cancel = ResourceCancel {
            resource_id: [0x44u8; RESOURCE_ID_LEN],
        };
        let encoded = cancel.encode();
        let decoded = ResourceCancel::decode(&encoded).expect("decode");
        assert_eq!(decoded.resource_id, cancel.resource_id);
    }

    #[test]
    fn send_state_proof_marks_completed() {
        let data = vec![0x21u8; 64];
        let dest = AddressHash::new_empty();
        let mut state = ResourceSendState::new(
            dest,
            &data,
            16,
            None,
            false,
            false,
            Duration::from_secs(1),
            1,
        )
        .expect("state");

        let proof = ResourceProof {
            resource_id: state.resource_id,
            status: RESOURCE_PROOF_STATUS_OK,
        };
        assert!(state.handle_proof(&proof));
        assert_eq!(state.status(), ResourceReceiptStatus::Completed);
    }

    #[test]
    fn tracker_cancel_removes_assembly() {
        let payload = vec![0x22u8; 32];
        let (advert, _parts) =
            ResourceSender::split(&payload, 16, None, false, false).expect("split");
        let mut tracker = ResourceTracker::new(Duration::from_secs(10));
        tracker
            .handle_advertisement(advert, [0u8; RESOURCE_ID_LEN], Instant::now())
            .expect("advert");
        let cancel = tracker.handle_cancel(advert.resource_id).expect("cancel");
        assert_eq!(cancel.resource_id, advert.resource_id);
        let result = tracker
            .handle_advertisement(advert, [0u8; RESOURCE_ID_LEN], Instant::now())
            .expect("advert");
        assert_eq!(result, ResourceAdvertisementResult::AlreadyCompleted);
    }

    #[test]
    fn tracker_times_out_and_fails() {
        let payload = vec![0x55u8; 48];
        let (advert, _parts) =
            ResourceSender::split(&payload, 16, None, false, false).expect("split");
        let mut tracker = ResourceTracker::new(Duration::from_secs(1));
        tracker
            .handle_advertisement(advert, [0u8; RESOURCE_ID_LEN], Instant::now())
            .expect("advert");
        let mut now = Instant::now();
        let mut last_timeout = None;
        for _ in 0..=RESOURCE_DEFAULT_MAX_RETRIES {
            now = now + Duration::from_secs(2);
            let timeouts = tracker.poll_timeouts(now);
            assert_eq!(timeouts.len(), 1);
            last_timeout = Some(timeouts[0].clone());
        }
        let last_timeout = last_timeout.expect("timeout");
        assert!(last_timeout.failed);
        assert!(last_timeout.hashmap_exhausted || !last_timeout.requested_hashes.is_empty());
        assert!(tracker.poll_timeouts(now + Duration::from_secs(2)).is_empty());
    }
}
