//! Inbound (receiver) side of a resource transfer.

use alloc::vec::Vec;
use sha2::Digest;

use crate::destination::link::{Link, LinkId};
use crate::hash::{AddressHash, Hash};
use crate::packet::{Packet, PacketContext, PacketType};

use super::advertisement::{ResourceAdvertisement, HASHMAP_MAX_LEN};
use super::{
    map_hash, unix_time, ResourceStatus, ResourceTx, FAST_RATE_THRESHOLD, HASHMAP_IS_EXHAUSTED,
    HASHMAP_IS_NOT_EXHAUSTED, MAPHASH_LEN, MAX_EFFICIENT_SIZE, MAX_RETRIES, PART_TIMEOUT_FACTOR,
    PART_TIMEOUT_FACTOR_AFTER_RTT, RANDOM_HASH_SIZE, RATE_FAST, RATE_VERY_SLOW, RETRY_GRACE_TIME,
    VERY_SLOW_RATE_THRESHOLD, WINDOW, WINDOW_FLEXIBILITY, WINDOW_MAX_FAST, WINDOW_MAX_SLOW,
    WINDOW_MAX_VERY_SLOW, WINDOW_MIN,
};

/// An accepted resource advertisement, transfer in progress.
pub struct IncomingResource {
    pub link_id: LinkId,
    pub status: ResourceStatus,
    pub hash: Hash,
    pub original_hash: Hash,
    pub random_hash: [u8; RANDOM_HASH_SIZE],
    /// Transfer size (encrypted stream length).
    pub size: usize,
    /// Uncompressed data size.
    pub total_size: usize,
    pub compressed: bool,
    pub encrypted: bool,
    pub split: bool,
    pub has_metadata: bool,
    pub segment_index: usize,
    pub total_segments: usize,
    pub request_id: Option<AddressHash>,
    pub is_response: bool,

    pub sdu: usize,
    pub total_parts: usize,
    pub received_count: usize,
    pub outstanding_parts: usize,
    /// Ciphertext chunks indexed by part number.
    pub parts: Vec<Option<Vec<u8>>>,
    pub hashmap: Vec<Option<[u8; MAPHASH_LEN]>>,
    pub hashmap_height: usize,
    pub waiting_for_hmu: bool,
    pub consecutive_completed_height: isize,

    pub window: usize,
    pub window_max: usize,
    pub window_min: usize,
    pub window_flexibility: usize,

    pub last_activity: f64,
    pub started_transferring: f64,
    pub req_sent: f64,
    pub req_sent_bytes: usize,
    pub req_resp: Option<f64>,
    pub rtt: Option<f64>,
    pub rtt_rxd_bytes: usize,
    pub rtt_rxd_bytes_at_part_req: usize,
    pub req_resp_rtt_rate: f64,
    pub req_data_rtt_rate: f64,
    pub eifr: Option<f64>,
    pub previous_eifr: Option<f64>,
    pub fast_rate_rounds: usize,
    pub very_slow_rate_rounds: usize,

    pub retries_left: usize,
    pub max_retries: usize,
    pub part_timeout_factor: f64,
    pub timeout_factor: f64,
    pub sender_grace_time: f64,

    /// Raw advertisement packet (for rejections).
    pub advertisement_packet: Packet,
    /// Set once all parts arrived and assembly succeeded.
    pub assembled: Option<Vec<u8>>,
    /// Metadata extracted from the head of a metadata-carrying resource.
    pub metadata: Option<Vec<u8>>,
}

impl IncomingResource {
    /// Accept an advertised resource (Python `Resource.accept`).
    pub fn accept(
        advertisement_packet: &Packet,
        plaintext: &[u8],
        link: &Link,
    ) -> Result<Self, crate::error::RnsError> {
        let adv = ResourceAdvertisement::unpack(plaintext)?;

        let sdu = if link.mtu() > 0 {
            link.sdu()
        } else {
            super::SDU
        };

        let total_parts = adv.transfer_size.div_ceil(sdu).max(1);

        let now = unix_time();

        let (window, previous_eifr) = {
            let w = link.last_resource_window().unwrap_or(WINDOW);
            let e = link.last_resource_eifr();
            (w, e)
        };

        Ok(Self {
            link_id: *link.id(),
            status: ResourceStatus::Transferring,
            hash: adv.hash,
            original_hash: adv.original_hash,
            random_hash: adv.random_hash,
            size: adv.transfer_size,
            total_size: adv.data_size,
            compressed: adv.compressed(),
            encrypted: adv.encrypted(),
            split: adv.split(),
            has_metadata: adv.has_metadata(),
            segment_index: adv.segment_index,
            total_segments: adv.total_segments,
            request_id: adv.request_id,
            is_response: adv.is_response(),
            sdu,
            total_parts,
            received_count: 0,
            outstanding_parts: 0,
            parts: alloc::vec![None; total_parts],
            hashmap: alloc::vec![None; total_parts],
            hashmap_height: 0,
            waiting_for_hmu: false,
            consecutive_completed_height: -1,
            window,
            window_max: WINDOW_MAX_SLOW,
            window_min: WINDOW_MIN,
            window_flexibility: WINDOW_FLEXIBILITY,
            last_activity: now,
            started_transferring: now,
            req_sent: 0.0,
            req_sent_bytes: 0,
            req_resp: None,
            rtt: None,
            rtt_rxd_bytes: 0,
            rtt_rxd_bytes_at_part_req: 0,
            req_resp_rtt_rate: 0.0,
            req_data_rtt_rate: 0.0,
            eifr: None,
            previous_eifr,
            fast_rate_rounds: 0,
            very_slow_rate_rounds: 0,
            retries_left: MAX_RETRIES,
            max_retries: MAX_RETRIES,
            part_timeout_factor: PART_TIMEOUT_FACTOR,
            timeout_factor: super::TRAFFIC_TIMEOUT_FACTOR,
            sender_grace_time: super::SENDER_GRACE_TIME,
            advertisement_packet: advertisement_packet.clone(),
            assembled: None,
            metadata: None,
        })
    }

    /// Process the initial hashmap from the advertisement.
    pub fn hashmap_update(&mut self, segment: usize, hashmap: &[u8]) {
        if self.status == ResourceStatus::Failed {
            return;
        }
        self.status = ResourceStatus::Transferring;
        let seg_len = HASHMAP_MAX_LEN;
        let hashes = hashmap.len() / MAPHASH_LEN;
        // The segment index is attacker-controlled: bound it before the
        // multiply so a hostile HMU cannot overflow the index arithmetic.
        let max_segment = self.hashmap.len() / seg_len + 1;
        if segment > max_segment {
            log::debug!("resource: hashmap update segment out of range");
            return;
        }
        for i in 0..hashes {
            let idx = i + segment * seg_len;
            if idx >= self.hashmap.len() {
                break;
            }
            if self.hashmap[idx].is_none() {
                self.hashmap_height += 1;
            }
            let bytes: [u8; MAPHASH_LEN] = hashmap[i * MAPHASH_LEN..(i + 1) * MAPHASH_LEN]
                .try_into()
                .unwrap();
            self.hashmap[idx] = Some(bytes);
        }

        if hashes < 1 {
            log::error!("resource: invalid HMU received, cancelling transfer");
            self.status = ResourceStatus::Failed;
        } else {
            self.waiting_for_hmu = false;
        }
    }

    /// Handle a RESOURCE_HMU packet plaintext: `hash + msgpack([segment, hashmap])`.
    pub fn hashmap_update_packet(&mut self, plaintext: &[u8]) {
        if self.status == ResourceStatus::Failed {
            return;
        }
        if !self.waiting_for_hmu {
            return;
        }
        self.last_activity = unix_time();
        self.retries_left = self.max_retries;

        if plaintext.len() < 32 {
            return;
        }
        let payload: &[u8] = &plaintext[32..];
        let mut cursor: &[u8] = payload;
        let arr = match rmp::decode::read_array_len(&mut cursor) {
            Ok(len) if len == 2 => len,
            _ => {
                log::debug!("resource: malformed hashmap update");
                return;
            }
        };
        let _ = arr;
        let segment: u64 = match rmp::decode::read_int(&mut cursor) {
            Ok(v) => v,
            Err(_) => {
                log::debug!("resource: malformed hashmap update segment");
                return;
            }
        };
        // `u64::try_into` instead of `as`: a hostile 128-bit-ish encoded
        // integer must fail loudly rather than wrap.
        let Ok(segment) = usize::try_from(segment) else {
            log::debug!("resource: hashmap update segment out of range");
            return;
        };
        let hashmap = match rmp::decode::read_bin_len(&mut cursor) {
            Ok(len) => {
                let len = len as usize;
                if cursor.len() < len {
                    return;
                }
                cursor[..len].to_vec()
            }
            Err(_) => {
                log::debug!("resource: malformed hashmap update payload");
                return;
            }
        };

        self.hashmap_update(segment, &hashmap);
    }

    fn update_eifr(&mut self, link: &Link) {
        let rtt = self
            .rtt
            .unwrap_or_else(|| link.rtt().as_secs_f64())
            .max(0.0001);
        let expected_inflight_rate = if self.req_data_rtt_rate != 0.0 {
            self.req_data_rtt_rate * 8.0
        } else if let Some(prev) = self.previous_eifr {
            prev
        } else {
            link.establishment_cost() as f64 * 8.0 / rtt
        };
        self.eifr = Some(expected_inflight_rate);
    }

    /// Handle an incoming resource part packet (ciphertext chunk).
    /// Returns true when the transfer just completed assembly; packets
    /// produced (next part requests) are pushed onto `tx`.
    pub fn receive_part(&mut self, packet: &Packet, link: &Link, tx: &mut ResourceTx) -> bool {
        if self.status == ResourceStatus::Failed {
            return false;
        }

        let now = unix_time();
        self.last_activity = now;
        self.retries_left = self.max_retries;

        if self.req_resp.is_none() && self.req_sent > 0.0 {
            self.req_resp = Some(now);
            let rtt = now - self.req_sent;
            self.part_timeout_factor = PART_TIMEOUT_FACTOR_AFTER_RTT;
            match self.rtt {
                None => self.rtt = Some(link.rtt().as_secs_f64()),
                Some(current) => {
                    if rtt < current {
                        self.rtt = Some((current - current * 0.05).max(rtt));
                    } else if rtt > current {
                        self.rtt = Some((current + current * 0.05).min(rtt));
                    }
                }
            }

            if rtt > 0.0 {
                let req_resp_cost = packet.data.len() + self.req_sent_bytes;
                self.req_resp_rtt_rate = req_resp_cost as f64 / rtt;

                if self.req_resp_rtt_rate > RATE_FAST && self.fast_rate_rounds < FAST_RATE_THRESHOLD
                {
                    self.fast_rate_rounds += 1;
                    if self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                        self.window_max = WINDOW_MAX_FAST;
                    }
                }
            }
        }

        self.status = ResourceStatus::Transferring;
        let part_data = packet.data.as_slice();
        let part_hash = map_hash(part_data, &self.random_hash);

        let consecutive_index = if self.consecutive_completed_height >= 0 {
            self.consecutive_completed_height as usize
        } else {
            0
        };

        let mut i = consecutive_index;
        let window_end = core::cmp::min(consecutive_index + self.window, self.hashmap.len());
        while i < window_end {
            if let Some(map_hash) = &self.hashmap[i] {
                if *map_hash == part_hash {
                    if self.parts[i].is_none() {
                        self.parts[i] = Some(part_data.to_vec());
                        self.rtt_rxd_bytes += part_data.len();
                        self.received_count += 1;
                        self.outstanding_parts = self.outstanding_parts.saturating_sub(1);

                        if i as isize == self.consecutive_completed_height + 1 {
                            self.consecutive_completed_height = i as isize;
                        }

                        let mut cp = i + 1;
                        while cp < self.parts.len() && self.parts[cp].is_some() {
                            self.consecutive_completed_height = cp as isize;
                            cp += 1;
                        }
                    }
                    break;
                }
            }
            i += 1;
        }

        if self.received_count == self.total_parts
            && self.status != ResourceStatus::Assembling
            && self.assembled.is_none()
        {
            self.status = ResourceStatus::Assembling;
            return true;
        } else if self.outstanding_parts == 0 {
            if self.window < self.window_max {
                self.window += 1;
                if self.window.saturating_sub(self.window_min) > self.window_flexibility - 1 {
                    self.window_min += 1;
                }
            }

            if self.req_sent > 0.0 {
                let rtt = now - self.req_sent;
                let req_transferred = self.rtt_rxd_bytes - self.rtt_rxd_bytes_at_part_req;

                if rtt > 0.0 {
                    self.req_data_rtt_rate = req_transferred as f64 / rtt;
                    self.rtt_rxd_bytes_at_part_req = self.rtt_rxd_bytes;

                    if self.req_data_rtt_rate > RATE_FAST
                        && self.fast_rate_rounds < FAST_RATE_THRESHOLD
                    {
                        self.fast_rate_rounds += 1;
                        if self.fast_rate_rounds == FAST_RATE_THRESHOLD {
                            self.window_max = WINDOW_MAX_FAST;
                        }
                    }

                    if self.fast_rate_rounds == 0
                        && self.req_data_rtt_rate < RATE_VERY_SLOW
                        && self.very_slow_rate_rounds < VERY_SLOW_RATE_THRESHOLD
                    {
                        self.very_slow_rate_rounds += 1;
                        if self.very_slow_rate_rounds == VERY_SLOW_RATE_THRESHOLD {
                            self.window_max = WINDOW_MAX_VERY_SLOW;
                        }
                    }
                }
            }

            // Request the next window of parts immediately
            self.request_next(link, tx);
        }
        false
    }

    /// Build and send the next part request (Python `request_next`).
    pub fn request_next(&mut self, link: &Link, tx: &mut ResourceTx) {
        if self.status == ResourceStatus::Failed || self.waiting_for_hmu {
            return;
        }

        self.outstanding_parts = 0;
        let mut hashmap_exhausted = HASHMAP_IS_NOT_EXHAUSTED;
        let mut requested_hashes: Vec<u8> = Vec::new();

        let mut i = 0usize;
        let mut pn = (self.consecutive_completed_height + 1).max(0) as usize;
        let search_start = pn;
        let search_size = self.window;

        while pn < self.parts.len() && pn < search_start + search_size {
            if self.parts[pn].is_none() {
                if let Some(part_hash) = &self.hashmap[pn] {
                    requested_hashes.extend_from_slice(part_hash);
                    self.outstanding_parts += 1;
                    i += 1;
                } else {
                    hashmap_exhausted = HASHMAP_IS_EXHAUSTED;
                }
            }

            pn += 1;
            if i >= self.window || hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
                break;
            }
        }

        let mut hmu_part = alloc::vec![hashmap_exhausted];
        if hashmap_exhausted == HASHMAP_IS_EXHAUSTED {
            if self.hashmap_height == 0 {
                log::error!("resource: hashmap exhausted with empty map, cancelling");
                self.status = ResourceStatus::Failed;
                return;
            }
            let last = self.hashmap[self.hashmap_height - 1];
            if let Some(last) = last {
                hmu_part.extend_from_slice(&last);
            } else {
                log::error!("resource: hashmap update requested with unknown hash");
                self.status = ResourceStatus::Failed;
                return;
            }
            self.waiting_for_hmu = true;
        }

        let mut request_data = hmu_part;
        request_data.extend_from_slice(self.hash.as_slice());
        request_data.extend_from_slice(&requested_hashes);

        match link.context_packet(&request_data, PacketContext::ResourceRequest) {
            Ok(packet) => {
                let now = unix_time();
                self.last_activity = now;
                self.req_sent = now;
                self.req_sent_bytes = 19 + packet.data.len();
                self.rtt_rxd_bytes_at_part_req = self.rtt_rxd_bytes;
                self.req_resp = None;
                tx.push(packet);
            }
            Err(err) => {
                log::debug!("resource: could not create part request: {err:?}");
                self.status = ResourceStatus::Failed;
            }
        }
    }

    /// Assemble all received parts: decrypt, strip random hash, decompress,
    /// verify the resource hash. Returns the data of this segment (with the
    /// metadata head stripped when present).
    pub fn assemble(
        &mut self,
        link: &Link,
        max_decompressed_size: usize,
    ) -> Result<Vec<u8>, crate::error::RnsError> {
        let mut stream = Vec::with_capacity(self.size);
        for part in self.parts.iter().flatten() {
            stream.extend_from_slice(part);
        }

        let decrypted = if self.encrypted {
            let mut buffer = vec![0u8; stream.len() + 256];
            let plain = link
                .decrypt(&stream, &mut buffer)
                .map_err(|err| {
                    log::debug!("resource: could not decrypt stream: {err:?}");
                    crate::error::RnsError::ResourceMsg("resource decryption failed")
                })?
                .to_vec();
            plain
        } else {
            stream
        };

        // Strip off random hash
        let payload = &decrypted[RANDOM_HASH_SIZE.min(decrypted.len())..];

        let data = if self.compressed {
            super::decompress(payload, max_decompressed_size)?
        } else {
            payload.to_vec()
        };

        let digest = Hash::generator()
            .chain_update(&data)
            .chain_update(self.random_hash)
            .finalize();
        let calculated = Hash::new(digest.into());
        if calculated != self.hash {
            self.status = ResourceStatus::Corrupt;
            return Err(crate::error::RnsError::ResourceMsg(
                "resource hash mismatch",
            ));
        }

        // Strip the `[3-byte metadata length][metadata]` prefix when the
        // advertisement promised metadata. A prefix that does not fit the
        // segment is corrupt data, not a payload (Python would slice past
        // the end of the buffer and error).
        if self.has_metadata && self.segment_index == 1 {
            if data.len() < 3 {
                self.status = ResourceStatus::Corrupt;
                return Err(crate::error::RnsError::ResourceMsg(
                    "metadata resource shorter than its length prefix",
                ));
            }
            let metadata_size =
                ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);
            if 3 + metadata_size > data.len() {
                self.status = ResourceStatus::Corrupt;
                return Err(crate::error::RnsError::ResourceMsg(
                    "metadata length exceeds segment",
                ));
            }
            self.metadata = Some(data[3..3 + metadata_size].to_vec());
            self.assembled = Some(data.clone());
            return Ok(data[3 + metadata_size..].to_vec());
        }

        self.assembled = Some(data.clone());
        Ok(data)
    }

    /// Build the resource proof packet (sent by the receiver on completion).
    pub fn prove(&mut self, link: &Link, data: &[u8], tx: &mut ResourceTx) {
        let digest = Hash::generator()
            .chain_update(data)
            .chain_update(self.hash.as_slice())
            .finalize();
        let proof_hash = Hash::new(digest.into());

        let mut proof_data = self.hash.as_slice().to_vec();
        proof_data.extend_from_slice(proof_hash.as_slice());

        match link.raw_packet(&proof_data, PacketType::Proof, PacketContext::ResourceProof) {
            Ok(packet) => {
                self.status = ResourceStatus::Complete;
                tx.push(packet);
            }
            Err(err) => {
                log::debug!("resource: could not send proof: {err:?}");
                self.status = ResourceStatus::Failed;
            }
        }
    }

    /// Build a reject packet for this advertisement.
    ///
    /// RESOURCE_RCL is link-encrypted like any other link data packet
    /// (Python `Packet.pack` only leaves RESOURCE parts and proofs
    /// unencrypted).
    pub fn reject_packet(&self, link: &Link, tx: &mut ResourceTx) {
        if let Ok(packet) =
            link.context_packet(self.hash.as_slice(), PacketContext::ResourceReceiverCancel)
        {
            tx.push(packet);
        }
    }

    /// Build a cancel packet for a receiver-initiated cancel
    /// (Python `Resource.cancel` sends RESOURCE_RCL from the receiver).
    pub fn cancel_packet(&self, link: &Link, tx: &mut ResourceTx) {
        if let Ok(packet) =
            link.context_packet(self.hash.as_slice(), PacketContext::ResourceReceiverCancel)
        {
            tx.push(packet);
        }
    }

    /// Reconstruct the advertisement for this resource (for events).
    pub fn advertisement_of(&self) -> ResourceAdvertisement {
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

        let entries = core::cmp::min(HASHMAP_MAX_LEN, self.hashmap.len());
        let mut hashmap = Vec::new();
        for mh in self.hashmap[..entries].iter().flatten() {
            hashmap.extend_from_slice(mh);
        }

        ResourceAdvertisement {
            transfer_size: self.size,
            data_size: self.total_size,
            parts: self.total_parts,
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

    /// Build a reject packet for an advertisement that was declined before
    /// an `IncomingResource` exists.
    pub fn reject_packet_for(adv: &ResourceAdvertisement, link: &Link) -> Vec<Packet> {
        let mut tx = ResourceTx::default();
        if let Ok(packet) =
            link.context_packet(adv.hash.as_slice(), PacketContext::ResourceReceiverCancel)
        {
            tx.push(packet);
        }
        tx.packets
    }

    /// Watchdog for the receiver side: handles timeouts, retries and window
    /// backoff. Returns packets to send and whether the resource failed.
    pub fn check(&mut self, link: &Link, tx: &mut ResourceTx) -> bool {
        if self.status.is_concluded() || self.status == ResourceStatus::Assembling {
            return false;
        }
        let now = unix_time();
        if self.status != ResourceStatus::Transferring {
            return false;
        }

        self.update_eifr(link);
        let eifr = self.eifr.unwrap_or(1.0).max(0.0001);

        let retries_used = self.max_retries - self.retries_left;
        let extra_wait = retries_used as f64 * super::PER_RETRY_DELAY;

        let expected_hmu_wait_remaining = if self.waiting_for_hmu || self.outstanding_parts == 0 {
            (self.sdu as f64 * 8.0 * super::HMU_WAIT_FACTOR) / eifr
        } else {
            0.0
        };
        let expected_tof_remaining = (self.outstanding_parts as f64 * self.sdu as f64 * 8.0) / eifr;

        let sleep_time = if self.req_resp_rtt_rate != 0.0 {
            self.last_activity
                + self.part_timeout_factor * expected_tof_remaining
                + expected_hmu_wait_remaining
                + RETRY_GRACE_TIME
                + extra_wait
                - now
        } else {
            self.last_activity
                + self.part_timeout_factor * ((3.0 * self.sdu as f64) / eifr)
                + RETRY_GRACE_TIME
                + extra_wait
                - now
        };

        if sleep_time < 0.0 {
            if self.retries_left > 0 {
                log::debug!(
                    "resource: timed out waiting for {} parts, retrying",
                    self.outstanding_parts
                );
                if self.window > self.window_min {
                    self.window -= 1;
                    if self.window_max > self.window_min {
                        self.window_max -= 1;
                        if self.window_max - self.window > self.window_flexibility - 1 {
                            self.window_max -= 1;
                        }
                    }
                }
                self.retries_left -= 1;
                self.waiting_for_hmu = false;
                self.request_next(link, tx);
            } else {
                self.status = ResourceStatus::Failed;
                return true;
            }
        }
        false
    }

    /// Progress of a response resource, for `RequestEvent::Progress`.
    /// `None` when this transfer is not a response to a request.
    pub fn request_progress(&self) -> Option<(AddressHash, f64)> {
        if !self.is_response {
            return None;
        }
        self.request_id.map(|id| (id, self.progress()))
    }

    /// Transfer progress (0.0 - 1.0) including segmentation weighting.
    pub fn progress(&self) -> f64 {
        if self.status == ResourceStatus::Complete && self.segment_index == self.total_segments {
            return 1.0;
        }
        if !self.split {
            return (self.received_count as f64 / self.total_parts as f64).min(1.0);
        }
        let max_parts_per_segment = (MAX_EFFICIENT_SIZE as f64 / self.sdu as f64).ceil();
        let processed_segments = (self.segment_index - 1) as f64;
        let current_segment_parts = self.total_parts as f64;
        let factor = if current_segment_parts < max_parts_per_segment {
            max_parts_per_segment / current_segment_parts
        } else {
            1.0
        };
        let processed =
            processed_segments * max_parts_per_segment + self.received_count as f64 * factor;
        let total = self.total_segments as f64 * max_parts_per_segment;
        // 1.0 is reserved for the proven final segment: all parts of the
        // last segment being present is not completion until the proof
        // validates.
        (processed / total).min(0.999)
    }
}
