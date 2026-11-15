//! Resource transfers over links, a port of Python `RNS.Resource`.
//!
//! A resource carries arbitrary amounts of data over a single link. The
//! whole payload is encrypted once with the link token, split into
//! link-MDU sized parts, and transferred with a windowed request/response
//! scheme with automatic retries, hashmap updates for large transfers,
//! bzip2 compression and multi-megabyte segmentation.

pub mod advertisement;
pub mod inbound;
pub mod manager;
pub mod outbound;

pub use advertisement::ResourceAdvertisement;
pub use inbound::IncomingResource;
pub use manager::{
    msgpack_bin, pack_request, pack_request_element, pack_response, request_id, unpack_request,
    unpack_response, RequestAllow, RequestContext, RequestHandlerConfig, RequestOptions,
    RequestResponse, ResourceAcceptCallback, ResourceStartedCallback, ResourceStrategy,
};
pub use outbound::OutgoingResource;

use alloc::vec::Vec;
use core::time::Duration;

use sha2::Digest;

use crate::destination::link::LinkId;
use crate::error::RnsError;
use crate::hash::{AddressHash, Hash};
use crate::packet::Packet;

use crate::time::now;

/// The initial window size at beginning of transfer
pub const WINDOW: usize = 4;
/// Absolute minimum window size during transfer
pub const WINDOW_MIN: usize = 2;
/// The maximum window size for transfers on slow links
pub const WINDOW_MAX_SLOW: usize = 10;
/// The maximum window size for transfers on very slow links
pub const WINDOW_MAX_VERY_SLOW: usize = 4;
/// The maximum window size for transfers on fast links
pub const WINDOW_MAX_FAST: usize = 75;
/// For calculating maps and guard segment, this
/// must be set to the global maximum window.
pub const WINDOW_MAX: usize = WINDOW_MAX_FAST;
/// If the fast rate is sustained for this many request
/// rounds, the fast link window size will be allowed.
pub const FAST_RATE_THRESHOLD: usize = WINDOW_MAX_SLOW - WINDOW - 2;
/// If the very slow rate is sustained for this many request
/// rounds, window will be capped to the very slow limit.
pub const VERY_SLOW_RATE_THRESHOLD: usize = 2;
/// If the RTT rate is higher than this value (bytes/second),
/// the max window size for fast links will be used (50 Kbps).
pub const RATE_FAST: f64 = (50.0 * 1000.0) / 8.0;
/// If the RTT rate is lower than this value (bytes/second),
/// the window size will be capped (2 Kbps).
pub const RATE_VERY_SLOW: f64 = (2.0 * 1000.0) / 8.0;
/// The minimum allowed flexibility of the window size.
pub const WINDOW_FLEXIBILITY: usize = 4;
/// Number of bytes in a map hash
pub const MAPHASH_LEN: usize = 4;
/// Default part size when the link MTU is unknown
pub const SDU: usize = crate::packet::PACKET_PROTOCOL_MDU;
pub const RANDOM_HASH_SIZE: usize = 4;
/// Maximum size handled in reasonable time on small systems;
/// also the per-segment limit (fits 3 bytes in advertisements).
pub const MAX_EFFICIENT_SIZE: usize = 1024 * 1024 - 1; // 0xFFFFFF
pub const RESPONSE_MAX_GRACE_TIME: f64 = 10.0;
/// Max metadata size (3-byte length prefix in stream)
pub const METADATA_MAX_SIZE: usize = 16 * 1024 * 1024 - 1;
/// The maximum size to auto-compress with bz2 before sending.
pub const AUTO_COMPRESS_MAX_SIZE: usize = 64 * 1024 * 1024;

pub const PART_TIMEOUT_FACTOR: f64 = 4.0;
pub const PART_TIMEOUT_FACTOR_AFTER_RTT: f64 = 2.0;
pub const PROOF_TIMEOUT_FACTOR: f64 = 3.0;
pub const HMU_WAIT_FACTOR: f64 = 3.5;
pub const MAX_RETRIES: usize = 16;
pub const MAX_ADV_RETRIES: usize = 4;
pub const SENDER_GRACE_TIME: f64 = 10.0;
pub const PROCESSING_GRACE: f64 = 1.0;
pub const RETRY_GRACE_TIME: f64 = 0.25;
pub const PER_RETRY_DELAY: f64 = 0.5;

/// Link RTT timeout factor used for resource timeouts
/// (Python `Link.TRAFFIC_TIMEOUT_FACTOR`).
pub const TRAFFIC_TIMEOUT_FACTOR: f64 = 6.0;

/// Worst-case Fernet token overhead when pre-allocating encrypted streams.
pub const PART_ENCRYPT_OVERHEAD: usize = 128;

pub const WATCHDOG_MAX_SLEEP: Duration = Duration::from_secs(1);

pub const HASHMAP_IS_NOT_EXHAUSTED: u8 = 0x00;
pub const HASHMAP_IS_EXHAUSTED: u8 = 0xFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceStatus {
    None = 0x00,
    Queued = 0x01,
    Advertised = 0x02,
    Transferring = 0x03,
    AwaitingProof = 0x04,
    Assembling = 0x05,
    Complete = 0x06,
    Failed = 0x07,
    Corrupt = 0x08,
    Rejected = 0x09,
}

impl ResourceStatus {
    pub fn is_concluded(&self) -> bool {
        matches!(
            self,
            ResourceStatus::Complete
                | ResourceStatus::Failed
                | ResourceStatus::Corrupt
                | ResourceStatus::Rejected
        )
    }
}

/// Events emitted for every resource transfer on this transport.
#[derive(Clone, Debug)]
pub struct ResourceEvent {
    pub link_id: LinkId,
    pub hash: Hash,
    pub status: ResourceStatus,
    /// Transfer progress between 0.0 and 1.0
    pub progress: f64,
    /// Present when an incoming resource completed (final segment).
    pub data: Option<Vec<u8>>,
    /// Optional metadata attached to the resource (final segment).
    pub metadata: Option<Vec<u8>>,
    /// Advertisement fields, available from `Advertised` onwards.
    pub advertisement: Option<ResourceAdvertisement>,
}

/// Result of running one resource state machine step: packets to transmit.
#[derive(Default)]
pub struct ResourceTx {
    pub packets: Vec<Packet>,
}

impl ResourceTx {
    fn push(&mut self, packet: Packet) {
        self.packets.push(packet);
    }
}

/// Options for creating an outbound resource (mirrors the Python
/// `RNS.Resource(data, link, ...)` constructor arguments).
#[derive(Clone)]
pub struct ResourceOptions {
    pub auto_compress: bool,
    /// Python `auto_compress=<int>`: compress only when the original input
    /// (file or buffer, not including metadata) is at most this many bytes.
    /// `None` uses [`AUTO_COMPRESS_MAX_SIZE`].
    pub auto_compress_limit: Option<usize>,
    pub metadata: Option<Vec<u8>>,
    pub timeout: Option<f64>,
    pub request_id: Option<AddressHash>,
    pub is_response: bool,
}

impl Default for ResourceOptions {
    fn default() -> Self {
        Self {
            auto_compress: true,
            auto_compress_limit: None,
            metadata: None,
            timeout: None,
            request_id: None,
            is_response: false,
        }
    }
}

/// Whether this input should be bz2-compressed, matching Python
/// `Resource.__init__`: a bool enables compression up to
/// `AUTO_COMPRESS_MAX_SIZE`, and an int limit replaces that cap. The
/// original input length is what is compared, not the segment length.
pub fn should_auto_compress(opts: &ResourceOptions, original_len: usize) -> bool {
    if !opts.auto_compress {
        return false;
    }
    let limit = opts.auto_compress_limit.unwrap_or(AUTO_COMPRESS_MAX_SIZE);
    original_len <= limit
}

pub(crate) fn unix_time() -> f64 {
    now().as_secs_f64()
}

/// Compress data with bzip2 when enabled by feature `bz2` (and beneficial),
/// mirroring Python's `bz2.compress` usage. When the feature is disabled the
/// data is returned unchanged so transfers still work uncompressed.
pub fn maybe_compress(data: &[u8], enabled: bool, max_size: usize) -> (Vec<u8>, bool) {
    if !enabled || data.is_empty() || data.len() > max_size {
        return (data.to_vec(), false);
    }
    #[cfg(feature = "bz2")]
    {
        use std::io::Write;
        let mut encoder = bzip2::write::BzEncoder::new(
            Vec::with_capacity(data.len() / 2),
            bzip2::Compression::new(9),
        );
        if encoder.write_all(data).is_err() {
            return (data.to_vec(), false);
        }
        match encoder.finish() {
            Ok(compressed) if compressed.len() < data.len() => (compressed, true),
            _ => (data.to_vec(), false),
        }
    }
    #[cfg(not(feature = "bz2"))]
    {
        (data.to_vec(), false)
    }
}

/// Decompress a bzip2 resource stream, enforcing Python's
/// `max_decompressed_size` semantics (bombs are rejected).
pub fn decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>, RnsError> {
    #[cfg(feature = "bz2")]
    {
        use std::io::Read;
        let mut decoder = bzip2::read::BzDecoder::new(data);
        let mut out = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match decoder.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if out.len() + n > max_size {
                        return Err(RnsError::ResourceMsg(
                            "decompressed resource exceeded maximum size",
                        ));
                    }
                    out.extend_from_slice(&chunk[..n]);
                }
                Err(_) => {
                    return Err(RnsError::ResourceMsg("bz2 decompression failed"));
                }
            }
        }
        Ok(out)
    }
    #[cfg(not(feature = "bz2"))]
    {
        let _ = (data, max_size);
        Err(RnsError::ResourceMsg("bz2 support not compiled in"))
    }
}

/// Compute the map hash of a part: `full_hash(data + random_hash)[:4]`.
pub fn map_hash(data: &[u8], random_hash: &[u8; RANDOM_HASH_SIZE]) -> [u8; MAPHASH_LEN] {
    let digest = Hash::generator()
        .chain_update(data)
        .chain_update(random_hash)
        .finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_compress_limit_uses_the_original_length() {
        let mut opts = ResourceOptions::default();
        assert!(should_auto_compress(&opts, 1));
        assert!(should_auto_compress(&opts, AUTO_COMPRESS_MAX_SIZE));
        assert!(!should_auto_compress(&opts, AUTO_COMPRESS_MAX_SIZE + 1));

        opts.auto_compress = false;
        assert!(!should_auto_compress(&opts, 1));

        opts.auto_compress = true;
        opts.auto_compress_limit = Some(1000);
        assert!(should_auto_compress(&opts, 1000));
        assert!(!should_auto_compress(&opts, 1001));
    }
}
