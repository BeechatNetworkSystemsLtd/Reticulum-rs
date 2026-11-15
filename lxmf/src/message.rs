//! LXMessage - the LXMF wire message format.
//!
//! This module is a port of `LXMF/LXMF/LXMessage.py` from the Python LXMF
//! distribution. The packed representation is byte-for-byte identical to the
//! Python implementation:
//!
//! ```text
//! packed := destination_hash (16) || source_hash (16) ||
//!           signature (64) || msgpack([timestamp (f64), title (bin),
//!                                      content (bin), fields (map)
//!                                      [, stamp (bin)]])
//! ```
//!
//! The message `hash` (and `message_id`) is `sha256(destination_hash ||
//! source_hash || msgpack(payload_without_stamp))`, and the Ed25519 signature
//! is calculated over `hash_input || message_hash`.

use core::fmt;

use ed25519_dalek::Signature;
use rand_core::CryptoRngCore;
use reticulum_core::crypt::fernet::{Fernet, PlainText, Token};
use reticulum_core::hash::{AddressHash, Hash, ADDRESS_HASH_SIZE, HASH_SIZE};
use reticulum_core::identity::{Identity, PrivateIdentity};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::error::LxmfError;
use crate::fields::{FieldValue, Fields};
use crate::stamper;

/// Message states, as defined on the Python `LXMessage` class.
/// Message is being generated.
pub const GENERATING: u8 = 0x00;
/// Message is queued for delivery.
pub const OUTBOUND: u8 = 0x01;
/// Message transfer is in progress.
pub const SENDING: u8 = 0x02;
/// Message was handed to the transport.
pub const SENT: u8 = 0x04;
/// Message delivery was confirmed by the recipient.
pub const DELIVERED: u8 = 0x08;
/// Message was rejected by the recipient.
pub const REJECTED: u8 = 0xFD;
/// Message delivery was cancelled locally.
pub const CANCELLED: u8 = 0xFE;
/// Message delivery failed.
pub const FAILED: u8 = 0xFF;
/// All valid message states.
pub const STATES: [u8; 8] = [
    GENERATING, OUTBOUND, SENDING, SENT, DELIVERED, REJECTED, CANCELLED, FAILED,
];

/// Message transport representations.
/// No transport representation yet.
pub const UNKNOWN: u8 = 0x00;
/// Message transferred as a single packet.
pub const PACKET: u8 = 0x01;
/// Message transferred as a sequenced resource.
pub const RESOURCE: u8 = 0x02;
/// All valid transport representations.
pub const REPRESENTATIONS: [u8; 3] = [UNKNOWN, PACKET, RESOURCE];

/// Delivery methods.
/// Single-packet delivery without a link.
pub const OPPORTUNISTIC: u8 = 0x01;
/// Delivery over a direct link.
pub const DIRECT: u8 = 0x02;
/// Delivery via a propagation node.
pub const PROPAGATED: u8 = 0x03;
/// Out-of-band (paper) delivery.
pub const PAPER: u8 = 0x05;
/// All valid delivery methods.
pub const VALID_METHODS: [u8; 4] = [OPPORTUNISTIC, DIRECT, PROPAGATED, PAPER];

/// Reasons a message signature could not be verified.
/// The source identity could not be recalled.
pub const SOURCE_UNKNOWN: u8 = 0x01;
/// The message signature did not validate.
pub const SIGNATURE_INVALID: u8 = 0x02;
/// All unverified reasons.
pub const UNVERIFIED_REASONS: [u8; 2] = [SOURCE_UNKNOWN, SIGNATURE_INVALID];

/// Length of a destination hash (16 bytes).
pub const DESTINATION_LENGTH: usize = ADDRESS_HASH_SIZE;
/// Length of an Ed25519 signature (64 bytes).
pub const SIGNATURE_LENGTH: usize = 64;
/// Length of a reply ticket (16 bytes).
pub const TICKET_LENGTH: usize = ADDRESS_HASH_SIZE;

/// Default ticket expiry (3 weeks).
pub const TICKET_EXPIRY: f64 = 21.0 * 24.0 * 60.0 * 60.0;
/// Ticket validity grace period (5 days).
pub const TICKET_GRACE: f64 = 5.0 * 24.0 * 60.0 * 60.0;
/// Tickets automatically renew with less than this validity left.
pub const TICKET_RENEW: f64 = 14.0 * 24.0 * 60.0 * 60.0;
/// Minimum interval between ticket deliveries to one destination.
pub const TICKET_INTERVAL: f64 = 1.0 * 24.0 * 60.0 * 60.0;
/// Stamp work value attributed to a valid ticket.
pub const COST_TICKET: u64 = 0x100;

// LXMF overhead is 112 bytes per message:
//   16  bytes for destination hash
//   16  bytes for source hash
//   64  bytes for Ed25519 signature
//   8   bytes for timestamp
//   8   bytes for msgpack structure
/// Size of the packed timestamp in bytes.
pub const TIMESTAMP_SIZE: usize = 8;
/// msgpack structure overhead of the payload in bytes.
pub const STRUCT_OVERHEAD: usize = 8;
/// LXMF overhead is 112 bytes per message: 16 bytes for the destination
/// hash, 16 bytes for the source hash, 64 bytes for the Ed25519 signature,
/// 8 bytes for the timestamp and 8 bytes for the msgpack structure.
pub const LXMF_OVERHEAD: usize =
    2 * DESTINATION_LENGTH + SIGNATURE_LENGTH + TIMESTAMP_SIZE + STRUCT_OVERHEAD;

// With an MTU of 500, the maximum amount of data
// we can send in a single encrypted packet is 383 bytes
// (`RNS.Packet.ENCRYPTED_MDU`).
/// Maximum LXMF data in an encrypted single packet (`RNS.Packet.ENCRYPTED_MDU` + timestamp).
pub const ENCRYPTED_PACKET_MDU: usize = 383 + TIMESTAMP_SIZE;

/// The max content length we can fit in an LXMF message inside a single
/// RNS packet is the encrypted MDU, minus the LXMF overhead. We can
/// optimise a bit though, by inferring the destination hash from the
/// destination field of the packet, therefore we also add the length of
/// a destination hash to the calculation.
/// The max content length that fits in an LXMF message inside a single
/// encrypted RNS packet. The destination hash can be inferred from the
/// packet destination field, so its length is added back to the budget.
pub const ENCRYPTED_PACKET_MAX_CONTENT: usize =
    ENCRYPTED_PACKET_MDU - LXMF_OVERHEAD + DESTINATION_LENGTH;

// Links can carry a larger MDU, due to less overhead per packet. The link
// MDU with default Reticulum parameters is 431 bytes (`RNS.Link.MDU`).
/// Link packet MDU with default Reticulum parameters (`RNS.Link.MDU`).
pub const LINK_PACKET_MDU: usize = 431;

/// We can deliver single-packet LXMF messages with content of up to 319
/// bytes over a link. If a message is larger than that, LXMF will sequence
/// and transfer it as a RNS resource over the link instead.
/// The max content length of a single-packet LXMF message over a link.
/// Larger messages are transferred as resources instead.
pub const LINK_PACKET_MAX_CONTENT: usize = LINK_PACKET_MDU - LXMF_OVERHEAD;

// For plain packets without encryption, we can fit up to 368 bytes of
// content (`RNS.Packet.PLAIN_MDU`).
/// Plain packet MDU (`RNS.Packet.PLAIN_MDU`).
pub const PLAIN_PACKET_MDU: usize = 464;
/// The max content length of a plain (unencrypted) single packet.
pub const PLAIN_PACKET_MAX_CONTENT: usize = PLAIN_PACKET_MDU - LXMF_OVERHEAD + DESTINATION_LENGTH;

// Descriptive strings regarding transport encryption
/// Transport encryption description for group destinations.
pub const ENCRYPTION_DESCRIPTION_AES: &str = "AES-128";
/// Transport encryption description for single destinations and links.
pub const ENCRYPTION_DESCRIPTION_EC: &str = "Curve25519";
/// Transport encryption description for plain destinations.
pub const ENCRYPTION_DESCRIPTION_UNENCRYPTED: &str = "Unencrypted";

// Constants for QR/URI encoding LXMs
/// URI schema of paper messages.
pub const URI_SCHEMA: &str = "lxm";
/// QR error correction level for paper messages.
pub const QR_ERROR_CORRECTION: &str = "ERROR_CORRECT_L";
/// Maximum QR code storage capacity.
pub const QR_MAX_STORAGE: usize = 2953;
/// Maximum paper message payload size, given the QR storage capacity.
pub const PAPER_MDU: usize = ((QR_MAX_STORAGE - (URI_SCHEMA.len() + "://".len())) * 6) / 8;

/// Transport encryption description, mirroring the string values stored by
/// the Python implementation in `LXMessage.transport_encryption`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportEncryption {
    /// AES-128 encrypted transport (group destinations).
    Aes128,
    /// Curve25519 encrypted transport (single destinations and links).
    Curve25519,
    /// Unencrypted transport (plain destinations).
    Unencrypted,
}

impl TransportEncryption {
    /// The description string used by the Python implementation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransportEncryption::Aes128 => ENCRYPTION_DESCRIPTION_AES,
            TransportEncryption::Curve25519 => ENCRYPTION_DESCRIPTION_EC,
            TransportEncryption::Unencrypted => ENCRYPTION_DESCRIPTION_UNENCRYPTED,
        }
    }
}

/// Get the current unix timestamp as an f64 (`time.time()`).
pub fn now_as_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// SHA-256 of `data` (`RNS.Identity.full_hash`).
pub fn full_hash(data: &[u8]) -> Hash {
    Hash::new_from_slice(data)
}

/// Truncated SHA-256 of `data` (`RNS.Identity.truncated_hash`).
pub fn truncated_hash(data: &[u8]) -> AddressHash {
    AddressHash::new_from_hash(&full_hash(data))
}

/// Encrypt `plaintext` for the (public) `identity` of a SINGLE destination,
/// using the exact construction of `RNS.Identity.encrypt` without ratchets:
/// an ephemeral X25519 key exchange, HKDF-SHA256 with the destination
/// identity hash as salt, and the RNS Fernet token format.
///
/// Returns `ephemeral_pub || iv || ciphertext || hmac`.
pub fn encrypt_for_identity<R: CryptoRngCore + Copy>(
    rng: R,
    identity: &Identity,
    plaintext: &[u8],
) -> Result<Vec<u8>, LxmfError> {
    let ephemeral = EphemeralSecret::random_from_rng(rng);
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&identity.public_key);

    let derived =
        hkdf::Hkdf::<sha2::Sha256>::new(Some(identity.address_hash.as_slice()), shared.as_bytes());

    let mut key = [0u8; 64];
    derived
        .expand(&[], &mut key)
        .map_err(|e| LxmfError::Crypto(format!("hkdf: {e}")))?;

    // The Python `Token` splits a 64 byte derived key into a 32 byte
    // signing key and a 32 byte AES-256 key.
    let fernet = Fernet::new_from_slices(&key[..32], &key[32..], rng);

    let mut token_buf = vec![0u8; plaintext.len() + 128];
    let token = fernet
        .encrypt(PlainText::from(plaintext), &mut token_buf)
        .map_err(|e| LxmfError::Crypto(format!("encrypt: {e:?}")))?;

    let mut out = Vec::with_capacity(32 + token.len());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(token.as_bytes());
    Ok(out)
}

/// Decrypt data produced by [`encrypt_for_identity`] (or by the Python
/// `RNS.Identity.encrypt`) using the private identity owning the SINGLE
/// destination. Ratchets are not supported.
pub fn decrypt_for_identity(identity: &PrivateIdentity, data: &[u8]) -> Result<Vec<u8>, LxmfError> {
    if data.len() <= 32 {
        return Err(LxmfError::InvalidFormat);
    }

    let peer_bytes: [u8; 32] = data[..32]
        .try_into()
        .map_err(|_| LxmfError::InvalidFormat)?;
    let peer_pub = X25519PublicKey::from(peer_bytes);
    let ciphertext = &data[32..];

    let shared = identity.exchange(&peer_pub);
    let derived = hkdf::Hkdf::<sha2::Sha256>::new(
        Some(identity.address_hash().as_slice()),
        shared.as_bytes(),
    );

    let mut key = [0u8; 64];
    derived
        .expand(&[], &mut key)
        .map_err(|e| LxmfError::Crypto(format!("hkdf: {e}")))?;

    let fernet = Fernet::new_from_slices(&key[..32], &key[32..], rand_core::OsRng);

    let token = fernet
        .verify(Token::from(ciphertext))
        .map_err(|e| LxmfError::Crypto(format!("verify: {e:?}")))?;

    let mut out_buf = vec![0u8; ciphertext.len()];
    let plaintext = fernet
        .decrypt(token, &mut out_buf)
        .map_err(|e| LxmfError::Crypto(format!("decrypt: {e:?}")))?;

    Ok(plaintext.as_slice().to_vec())
}

/// Base64 (URL-safe, without padding) encoding of `data`, as used by the
/// `lxm://` paper message URI format.
pub fn base64_urlsafe_nopad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3f] as char);
        }
    }
    out
}

/// Decode base64 (URL-safe, padding tolerated) as produced by
/// [`base64_urlsafe_nopad`].
pub fn base64_urlsafe_decode(data: &str) -> Result<Vec<u8>, LxmfError> {
    fn value(c: u8) -> Result<u32, LxmfError> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' | b'+' => Ok(62),
            b'_' | b'/' => Ok(63),
            _ => Err(LxmfError::InvalidFormat),
        }
    }

    let cleaned: Vec<u8> = data
        .bytes()
        .filter(|b| *b != b'=' && *b != b'\n' && *b != b'\r')
        .collect();

    let mut out = Vec::with_capacity(cleaned.len().div_ceil(4) * 3);
    for chunk in cleaned.chunks(4) {
        let mut n: u32 = 0;
        for (i, c) in chunk.iter().enumerate() {
            n |= value(*c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// An LXMF message, ported from the Python `LXMessage` class.
#[derive(Clone, Debug)]
pub struct LXMessage {
    /// Destination hash of the "lxmf.delivery" destination of the recipient.
    pub destination_hash: AddressHash,
    /// Destination hash of the "lxmf.delivery" destination of the sender.
    pub source_hash: AddressHash,

    /// The public identity of the message destination, if known. Required
    /// for paper and propagation packing (encryption) and opportunistic
    /// delivery.
    pub destination_identity: Option<Identity>,
    /// The public identity of the message source, if known or recalled.
    pub source_identity: Option<Identity>,

    /// Message title, as raw UTF-8 bytes.
    pub title: Vec<u8>,
    /// Message content, as raw UTF-8 bytes.
    pub content: Vec<u8>,
    /// Message fields (the insertion-ordered `fields` dict of the Python
    /// implementation).
    pub fields: Fields,

    /// The msgpack-packed message payload bytes (with the stamp included
    /// when the message was packed with `defer_stamp == false`).
    pub packed_payload: Option<Vec<u8>>,

    /// Message timestamp (unix epoch, seconds).
    pub timestamp: Option<f64>,
    /// Ed25519 signature over `hash_input || hash`.
    pub signature: Option<[u8; SIGNATURE_LENGTH]>,
    /// Full (32 byte) SHA-256 hash of the packed message.
    pub hash: Option<Hash>,
    /// Alias of `hash`, kept for parity with the Python implementation.
    pub message_id: Option<Hash>,
    /// Full hash of the transport-form data (destination hash prefixed,
    /// encrypted for the propagation node or paper recipient).
    pub transient_id: Option<Hash>,

    /// The packed message bytes.
    pub packed: Option<Vec<u8>>,
    /// Size of the packed message in bytes.
    pub packed_size: Option<usize>,
    /// The packed propagation transfer container (PROPAGATED delivery).
    pub propagation_packed: Option<Vec<u8>>,
    /// The packed, encrypted paper message (PAPER delivery).
    pub paper_packed: Option<Vec<u8>>,

    /// Whether resource transfers of this message should be compressed.
    pub auto_compress: bool,
    /// Current message state (one of the `STATES` values).
    pub state: u8,
    /// The delivery method in use (one of the `VALID_METHODS` values).
    pub method: u8,
    /// The requested delivery method, if set explicitly.
    pub desired_method: Option<u8>,
    /// The transport representation (one of the `REPRESENTATIONS` values).
    pub representation: u8,
    /// Transfer progress in the range 0.0 to 1.0.
    pub progress: f32,

    /// Physical interface statistics, when available.
    pub rssi: Option<f32>,
    /// Physical interface statistics, when available.
    pub snr: Option<f32>,
    /// Physical interface statistics, when available.
    pub q: Option<f32>,

    /// The message stamp. Hashcash stamps are 32 bytes; stamps derived from
    /// tickets are 16 byte truncated hashes.
    pub stamp: Option<Vec<u8>>,
    /// The stamp cost required by the destination, if any.
    pub stamp_cost: Option<u8>,
    /// The work value of the validated (or generated) stamp.
    pub stamp_value: Option<u64>,
    /// Whether the inbound stamp validated.
    pub stamp_valid: bool,
    /// Whether the inbound stamp has been checked yet.
    pub stamp_checked: bool,
    /// The propagation node stamp (PROPAGATED delivery).
    pub propagation_stamp: Option<Vec<u8>>,
    /// The work value of the propagation stamp.
    pub propagation_stamp_value: Option<u64>,
    /// Whether the propagation stamp validated.
    pub propagation_stamp_valid: bool,
    /// The propagation stamp cost required by the propagation node.
    pub propagation_target_cost: Option<u8>,
    /// Whether stamp generation is deferred until the message is sent.
    pub defer_stamp: bool,
    /// Whether propagation stamp generation is deferred.
    pub defer_propagation_stamp: bool,
    /// A ticket issued by the destination, used to derive a stamp.
    pub outbound_ticket: Option<[u8; TICKET_LENGTH]>,
    /// Whether to include a reply ticket in the message fields.
    pub include_ticket: bool,

    /// Whether this message was received (rather than created locally).
    pub incoming: bool,
    /// Whether the message signature has been validated successfully.
    pub signature_validated: bool,
    /// Why the signature could not be validated, if it was not.
    pub unverified_reason: Option<u8>,
    /// The ratchet (link) id the message was received over, if any.
    pub ratchet_id: Option<AddressHash>,

    /// Number of delivery attempts made so far.
    pub delivery_attempts: u32,
    /// Whether the transport layer encrypted this message.
    pub transport_encrypted: bool,
    /// Description of the transport encryption in use.
    pub transport_encryption: Option<TransportEncryption>,
    /// The type of the target delivery destination, used by
    /// [`LXMessage::determine_transport_encryption`] (Python
    /// `LXMessage.__destination.type`). Defaults to `Single`: LXMF delivery
    /// destinations are SINGLE destinations.
    pub destination_type: reticulum_core::packet::DestinationType,
    /// Explicit transport-encryption override set via
    /// [`LXMessage::set_transport_encryption`]; when present it wins over
    /// the automatic determination.
    transport_encryption_override: Option<TransportEncryption>,
}

impl Default for LXMessage {
    fn default() -> Self {
        Self::new(AddressHash::new_empty(), AddressHash::new_empty(), b"", b"")
    }
}

impl fmt::Display for LXMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.hash {
            Some(hash) => write!(f, "<LXMessage {}>", hash),
            None => write!(f, "<LXMessage>"),
        }
    }
}

impl LXMessage {
    /// Create a new outbound message with raw byte title and content, in
    /// the `GENERATING` state.
    pub fn new(
        destination_hash: AddressHash,
        source_hash: AddressHash,
        title: &[u8],
        content: &[u8],
    ) -> Self {
        Self {
            destination_hash,
            source_hash,
            destination_identity: None,
            source_identity: None,
            title: title.to_vec(),
            content: content.to_vec(),
            fields: Fields::new(),
            packed_payload: None,
            timestamp: None,
            signature: None,
            hash: None,
            message_id: None,
            transient_id: None,
            packed: None,
            packed_size: None,
            propagation_packed: None,
            paper_packed: None,
            auto_compress: true,
            state: GENERATING,
            method: UNKNOWN,
            desired_method: None,
            representation: UNKNOWN,
            progress: 0.0,
            rssi: None,
            snr: None,
            q: None,
            stamp: None,
            stamp_cost: None,
            stamp_value: None,
            stamp_valid: false,
            stamp_checked: false,
            propagation_stamp: None,
            propagation_stamp_value: None,
            propagation_stamp_valid: false,
            propagation_target_cost: None,
            defer_stamp: true,
            defer_propagation_stamp: true,
            outbound_ticket: None,
            include_ticket: false,
            incoming: false,
            signature_validated: false,
            unverified_reason: None,
            ratchet_id: None,
            delivery_attempts: 0,
            transport_encrypted: false,
            transport_encryption: None,
            destination_type: reticulum_core::packet::DestinationType::Single,
            transport_encryption_override: None,
        }
    }

    /// Set the title from a UTF-8 string.
    pub fn set_title_from_string(&mut self, title: &str) {
        self.title = title.as_bytes().to_vec();
    }

    /// Set the title from raw bytes.
    pub fn set_title_from_bytes(&mut self, title: &[u8]) {
        self.title = title.to_vec();
    }

    /// Decode the title as a UTF-8 string.
    pub fn title_as_string(&self) -> Result<String, LxmfError> {
        String::from_utf8(self.title.clone()).map_err(|_| LxmfError::InvalidFormat)
    }

    /// Set the content from a UTF-8 string.
    pub fn set_content_from_string(&mut self, content: &str) {
        self.content = content.as_bytes().to_vec();
    }

    /// Set the content from raw bytes.
    pub fn set_content_from_bytes(&mut self, content: &[u8]) {
        self.content = content.to_vec();
    }

    /// Decode the content as a UTF-8 string.
    pub fn content_as_string(&self) -> Result<String, LxmfError> {
        String::from_utf8(self.content.clone()).map_err(|_| LxmfError::InvalidFormat)
    }

    /// Replace the message fields.
    pub fn set_fields(&mut self, fields: Fields) {
        self.fields = fields;
    }

    /// Access the message fields.
    pub fn get_fields(&self) -> &Fields {
        &self.fields
    }

    /// Pack the msgpack message payload exactly as the Python `pack()` does.
    fn pack_payload(&self, timestamp: f64, stamp: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            32 + self.title.len() + self.content.len() + 2 + self.fields.len() * 8,
        );
        let element_count: u32 = if stamp.is_some() { 5 } else { 4 };
        rmp::encode::write_array_len(&mut out, element_count).ok();
        // The Python implementation always packs timestamps as IEEE-754
        // doubles (msgpack float64 marker).
        rmp::encode::write_f64(&mut out, timestamp).ok();
        rmp::encode::write_bin_len(&mut out, self.title.len() as u32).ok();
        out.extend_from_slice(&self.title);
        rmp::encode::write_bin_len(&mut out, self.content.len() as u32).ok();
        out.extend_from_slice(&self.content);
        self.fields.pack(&mut out);
        if let Some(stamp) = stamp {
            rmp::encode::write_bin_len(&mut out, stamp.len() as u32).ok();
            out.extend_from_slice(stamp);
        }
        out
    }

    /// Generate (or reuse) the outbound stamp, mirroring `LXMessage.get_stamp`.
    fn get_stamp(&mut self) -> Option<Vec<u8>> {
        // If an outbound ticket exists, use this for
        // generating a valid stamp.
        if let Some(ticket) = self.outbound_ticket {
            let mut material = Vec::with_capacity(TICKET_LENGTH + HASH_SIZE);
            material.extend_from_slice(&ticket);
            material.extend_from_slice(self.message_id?.as_slice());
            let stamp = truncated_hash(&material);
            self.stamp_value = Some(COST_TICKET);
            return Some(stamp.as_slice().to_vec());
        }

        // If no stamp cost is required, we can just
        // return immediately.
        let stamp_cost = self.stamp_cost?;

        // If a stamp was already generated, return it immediately.
        if let Some(stamp) = &self.stamp {
            return Some(stamp.clone());
        }

        // Otherwise, we will need to generate a valid stamp
        // according to the cost that the receiver has specified.
        let (stamp, value) =
            stamper::generate_stamp(self.message_id?.as_slice(), stamp_cost as u32);
        if let Some(stamp) = stamp {
            self.stamp_value = Some(value);
            self.stamp_valid = true;
            Some(stamp.to_vec())
        } else {
            None
        }
    }

    /// Core of the Python `pack()` method: build the payload, compute the
    /// message hash, sign it and produce the packed bytes. Shared by all
    /// delivery methods. Does not select a delivery method.
    fn pack_core(&mut self, source: &PrivateIdentity) -> Result<(), LxmfError> {
        if self.packed.is_some() {
            return Err(LxmfError::AlreadyPacked);
        }

        let timestamp = self.timestamp.unwrap_or_else(now_as_f64);
        self.timestamp = Some(timestamp);

        self.propagation_packed = None;
        self.paper_packed = None;

        // self.payload = [timestamp, title, content, fields]
        let plain_payload = self.pack_payload(timestamp, None);

        let mut hashed_part = Vec::with_capacity(2 * DESTINATION_LENGTH + plain_payload.len());
        hashed_part.extend_from_slice(self.destination_hash.as_slice());
        hashed_part.extend_from_slice(self.source_hash.as_slice());
        hashed_part.extend_from_slice(&plain_payload);
        let hash = full_hash(&hashed_part);
        self.hash = Some(hash);
        self.message_id = Some(hash);

        let stamp = if !self.defer_stamp {
            let stamp = self.get_stamp();
            if let Some(stamp) = &stamp {
                self.stamp = Some(stamp.clone());
            }
            stamp
        } else {
            None
        };

        let mut signed_part = Vec::with_capacity(hashed_part.len() + HASH_SIZE);
        signed_part.extend_from_slice(&hashed_part);
        signed_part.extend_from_slice(hash.as_slice());

        let signature = source.sign(&signed_part);
        self.signature = Some(signature.to_bytes());
        self.signature_validated = true;

        let packed_payload = self.pack_payload(timestamp, stamp.as_deref());
        self.packed_payload = Some(packed_payload.clone());

        let mut packed =
            Vec::with_capacity(2 * DESTINATION_LENGTH + SIGNATURE_LENGTH + packed_payload.len());
        packed.extend_from_slice(self.destination_hash.as_slice());
        packed.extend_from_slice(self.source_hash.as_slice());
        packed.extend_from_slice(&signature.to_bytes());
        packed.extend_from_slice(&packed_payload);
        self.packed = Some(packed);
        self.packed_size = Some(self.packed.as_ref().unwrap().len());

        Ok(())
    }

    /// Pack the message for OPPORTUNISTIC or DIRECT delivery, mirroring the
    /// Python `pack()` including the method/representation selection rules.
    ///
    /// The signing identity must be the private identity owning the source
    /// "lxmf.delivery" destination.
    pub fn pack(&mut self, source: &PrivateIdentity) -> Result<(), LxmfError> {
        self.pack_core(source)?;

        let packed_payload = self.packed_payload.as_ref().ok_or(LxmfError::NotPacked)?;
        // Python computes len(packed_payload) - 16, which can go negative
        // for fully empty messages; saturate instead.
        let content_size = packed_payload
            .len()
            .saturating_sub(TIMESTAMP_SIZE + STRUCT_OVERHEAD);

        // If no desired delivery method has been defined,
        // one will be chosen according to these rules:
        if self.desired_method.is_none() {
            self.desired_method = Some(DIRECT);
        }

        // If opportunistic delivery was requested, check that the message
        // will fit within packet size limits. LXMF delivery destinations
        // are always SINGLE type.
        if self.desired_method == Some(OPPORTUNISTIC) && content_size > ENCRYPTED_PACKET_MAX_CONTENT
        {
            log::debug!(
                "Opportunistic delivery was requested for {}, but content of length {} exceeds packet size limit. Falling back to link-based delivery.",
                self,
                content_size
            );
            self.desired_method = Some(DIRECT);
        }

        // Set delivery parameters according to delivery method
        match self.desired_method {
            Some(OPPORTUNISTIC) => {
                let single_packet_content_limit = ENCRYPTED_PACKET_MAX_CONTENT;
                if content_size > single_packet_content_limit {
                    return Err(LxmfError::ContentTooLarge(format!(
                        "opportunistic content of length {content_size} exceeds single-packet content limit of {single_packet_content_limit}"
                    )));
                }
                self.method = OPPORTUNISTIC;
                self.representation = PACKET;
            }
            Some(DIRECT) => {
                self.method = DIRECT;
                if content_size <= LINK_PACKET_MAX_CONTENT {
                    self.representation = PACKET;
                } else {
                    // Sequenced resource transfer required
                    self.representation = RESOURCE;
                }
            }
            _ => return Err(LxmfError::UnsupportedMethod),
        }

        Ok(())
    }

    /// Pack for PROPAGATED delivery: encrypt the message for the destination
    /// identity and wrap it in the propagation transfer container.
    ///
    /// Mirrors the `PROPAGATED` branch of the Python `pack()`. A propagation
    /// stamp, if already generated, is appended to the transport data.
    pub fn pack_propagation(
        &mut self,
        source: &PrivateIdentity,
        rng: impl CryptoRngCore + Copy,
    ) -> Result<(), LxmfError> {
        self.desired_method = Some(PROPAGATED);
        self.pack_core(source)?;

        let destination_identity = self.destination_identity.ok_or(LxmfError::PathUnknown)?;
        let packed = self.packed.as_ref().ok_or(LxmfError::NotPacked)?;

        // self.__pn_encrypted_data = self.__destination.encrypt(
        //     self.packed[LXMessage.DESTINATION_LENGTH:])
        let encrypted =
            encrypt_for_identity(rng, &destination_identity, &packed[DESTINATION_LENGTH..])?;

        let mut lxmf_data = Vec::with_capacity(DESTINATION_LENGTH + encrypted.len());
        lxmf_data.extend_from_slice(&packed[..DESTINATION_LENGTH]);
        lxmf_data.extend_from_slice(&encrypted);
        self.transient_id = Some(full_hash(&lxmf_data));

        if let Some(stamp) = &self.propagation_stamp {
            lxmf_data.extend_from_slice(stamp);
        }

        // self.propagation_packed = msgpack.packb([time.time(), [lxmf_data]])
        let mut propagation_packed = Vec::with_capacity(lxmf_data.len() + 32);
        rmp::encode::write_array_len(&mut propagation_packed, 2).ok();
        rmp::encode::write_f64(&mut propagation_packed, now_as_f64()).ok();
        rmp::encode::write_array_len(&mut propagation_packed, 1).ok();
        rmp::encode::write_bin_len(&mut propagation_packed, lxmf_data.len() as u32).ok();
        propagation_packed.extend_from_slice(&lxmf_data);
        self.propagation_packed = Some(propagation_packed);

        let content_size = self.propagation_packed.as_ref().unwrap().len();
        self.method = PROPAGATED;
        if content_size <= LINK_PACKET_MAX_CONTENT {
            self.representation = PACKET;
        } else {
            self.representation = RESOURCE;
        }

        Ok(())
    }

    /// Generate the propagation stamp for this message at `target_cost`,
    /// mirroring `LXMessage.get_propagation_stamp`.
    pub fn get_propagation_stamp(
        &mut self,
        target_cost: u8,
        source: Option<&PrivateIdentity>,
    ) -> Result<Option<Vec<u8>>, LxmfError> {
        if let Some(stamp) = &self.propagation_stamp {
            return Ok(Some(stamp.clone()));
        }

        self.propagation_target_cost = Some(target_cost);

        if self.transient_id.is_none() {
            match source {
                Some(source) => self.pack_propagation(source, rand_core::OsRng)?,
                None => return Err(LxmfError::NotPacked),
            }
        }

        let transient_id = self.transient_id.ok_or(LxmfError::NotPacked)?;
        let (stamp, value) = stamper::generate_stamp_with_rounds(
            transient_id.as_slice(),
            target_cost as u32,
            stamper::WORKBLOCK_EXPAND_ROUNDS_PN,
            &mut rand_core::OsRng,
        );
        if let Some(stamp) = stamp {
            self.propagation_stamp = Some(stamp.to_vec());
            self.propagation_stamp_value = Some(value);
            self.propagation_stamp_valid = true;
            Ok(self.propagation_stamp.clone())
        } else {
            Ok(None)
        }
    }

    /// Pack for PAPER delivery: encrypt the message for the destination
    /// identity so it can be transferred out of band (QR code, URI).
    /// Mirrors the `PAPER` branch of the Python `pack()`.
    pub fn pack_paper(
        &mut self,
        source: &PrivateIdentity,
        rng: impl CryptoRngCore + Copy,
    ) -> Result<(), LxmfError> {
        self.desired_method = Some(PAPER);
        self.pack_core(source)?;

        let destination_identity = self.destination_identity.ok_or(LxmfError::PathUnknown)?;
        let packed = self.packed.as_ref().ok_or(LxmfError::NotPacked)?;

        let encrypted =
            encrypt_for_identity(rng, &destination_identity, &packed[DESTINATION_LENGTH..])?;

        let mut paper_packed = Vec::with_capacity(DESTINATION_LENGTH + encrypted.len());
        paper_packed.extend_from_slice(&packed[..DESTINATION_LENGTH]);
        paper_packed.extend_from_slice(&encrypted);
        self.paper_packed = Some(paper_packed.clone());

        if paper_packed.len() <= PAPER_MDU {
            self.method = PAPER;
            self.representation = PAPER;
            Ok(())
        } else {
            Err(LxmfError::ContentTooLarge(
                "paper content exceeds paper message maximum size".into(),
            ))
        }
    }

    /// Validate the inbound stamp on this message at `target_cost`,
    /// optionally accepting tickets generated by the local router.
    /// Mirrors `LXMessage.validate_stamp`.
    pub fn validate_stamp(
        &mut self,
        target_cost: Option<u8>,
        tickets: Option<&[[u8; TICKET_LENGTH]]>,
    ) -> bool {
        if let Some(tickets) = tickets {
            for ticket in tickets {
                if let Some(message_id) = self.message_id {
                    let mut material = Vec::with_capacity(TICKET_LENGTH + HASH_SIZE);
                    material.extend_from_slice(ticket);
                    material.extend_from_slice(message_id.as_slice());
                    let ticket_stamp = truncated_hash(&material);
                    if Some(ticket_stamp.as_slice()) == self.stamp.as_deref() {
                        log::debug!("Stamp on {} validated by inbound ticket", self);
                        self.stamp_value = Some(COST_TICKET);
                        return true;
                    }
                }
            }
        }

        let Some(stamp) = self.stamp.clone() else {
            return false;
        };

        let Some(target_cost) = target_cost else {
            return false;
        };

        let Some(message_id) = self.message_id else {
            return false;
        };

        let workblock = stamper::stamp_workblock(message_id.as_slice());
        if stamper::stamp_valid(&stamp, target_cost as u32, &workblock) {
            log::debug!("Stamp on {} validated", self);
            self.stamp_value = Some(stamper::stamp_value(&workblock, &stamp));
            true
        } else {
            false
        }
    }

    /// Determine the transport encryption description for the current
    /// delivery method and destination type, mirroring
    /// `LXMessage.determine_transport_encryption`:
    ///
    /// - `OPPORTUNISTIC`/`PROPAGATED`/`PAPER` to a `SINGLE` destination:
    ///   Curve25519; to a `GROUP` destination: AES-128; anything else
    ///   (e.g. `PLAIN`): unencrypted.
    /// - `DIRECT`: always Curve25519 (link or single-destination delivery).
    /// - anything else: unencrypted.
    ///
    /// An explicit override set via [`Self::set_transport_encryption`]
    /// always wins.
    pub fn determine_transport_encryption(&mut self) {
        if let Some(encryption) = self.transport_encryption_override.clone() {
            self.transport_encrypted = encryption != TransportEncryption::Unencrypted;
            self.transport_encryption = Some(encryption);
            return;
        }
        use reticulum_core::packet::DestinationType;
        match self.method {
            OPPORTUNISTIC | PROPAGATED | PAPER => match self.destination_type {
                DestinationType::Single => {
                    self.transport_encrypted = true;
                    self.transport_encryption = Some(TransportEncryption::Curve25519);
                }
                DestinationType::Group => {
                    self.transport_encrypted = true;
                    self.transport_encryption = Some(TransportEncryption::Aes128);
                }
                DestinationType::Plain | DestinationType::Link => {
                    self.transport_encrypted = false;
                    self.transport_encryption = Some(TransportEncryption::Unencrypted);
                }
            },
            DIRECT => {
                self.transport_encrypted = true;
                self.transport_encryption = Some(TransportEncryption::Curve25519);
            }
            _ => {
                self.transport_encrypted = false;
                self.transport_encryption = Some(TransportEncryption::Unencrypted);
            }
        }
    }

    /// Explicitly override the transport-encryption description, bypassing
    /// the automatic determination in
    /// [`Self::determine_transport_encryption`]. Use this when the delivery
    /// setup implies a different transport encryption than the destination
    /// type suggests.
    pub fn set_transport_encryption(&mut self, encryption: TransportEncryption) {
        self.transport_encrypted = encryption != TransportEncryption::Unencrypted;
        self.transport_encryption = Some(encryption.clone());
        self.transport_encryption_override = Some(encryption);
    }

    /// Clear an explicit transport-encryption override so the automatic
    /// determination applies again.
    pub fn clear_transport_encryption_override(&mut self) {
        self.transport_encryption_override = None;
    }

    /// The type of the target delivery destination
    /// (Python `LXMessage.__destination.type`).
    pub fn destination_type(&self) -> reticulum_core::packet::DestinationType {
        self.destination_type
    }

    /// Set the type of the target delivery destination used by
    /// [`Self::determine_transport_encryption`].
    pub fn set_destination_type(
        &mut self,
        destination_type: reticulum_core::packet::DestinationType,
    ) {
        self.destination_type = destination_type;
    }

    /// Pack the persistence container produced by the Python
    /// `LXMessage.packed_container()`.
    pub fn packed_container(&mut self) -> Result<Vec<u8>, LxmfError> {
        if self.packed.is_none() {
            return Err(LxmfError::NotPacked);
        }

        let mut out = Vec::with_capacity(64 + self.packed.as_ref().unwrap().len());
        rmp::encode::write_map_len(&mut out, 5).ok();
        rmp::encode::write_str(&mut out, "state").ok();
        rmp::encode::write_uint(&mut out, self.state as u64).ok();
        rmp::encode::write_str(&mut out, "lxmf_bytes").ok();
        rmp::encode::write_bin_len(&mut out, self.packed.as_ref().unwrap().len() as u32).ok();
        out.extend_from_slice(self.packed.as_ref().unwrap());
        rmp::encode::write_str(&mut out, "transport_encrypted").ok();
        rmp::encode::write_bool(&mut out, self.transport_encrypted).ok();
        rmp::encode::write_str(&mut out, "transport_encryption").ok();
        match &self.transport_encryption {
            Some(description) => {
                rmp::encode::write_str(&mut out, description.as_str()).ok();
            }
            None => {
                rmp::encode::write_nil(&mut out).ok();
            }
        }
        rmp::encode::write_str(&mut out, "method").ok();
        rmp::encode::write_uint(&mut out, self.method as u64).ok();

        Ok(out)
    }

    /// Write the packed message to `directory`, using an atomic
    /// rename as the Python `write_to_directory` does.
    pub fn write_to_directory(
        &mut self,
        directory: &std::path::Path,
    ) -> Result<std::path::PathBuf, LxmfError> {
        let hash = self.hash.ok_or(LxmfError::NotPacked)?;
        let file_name = crate::to_hex(hash.as_slice());
        let file_path = directory.join(&file_name);

        let mut random_bytes = [0u8; 8];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut random_bytes);
        let tmp_name = format!("{}.tmp.{}", file_name, crate::to_hex(&random_bytes));
        let tmp_path = directory.join(&tmp_name);

        let container = self.packed_container()?;

        std::fs::create_dir_all(directory)?;
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(&container)?;
            file.sync_all().ok();
        }

        std::fs::rename(&tmp_path, &file_path)?;

        Ok(file_path)
    }

    /// Represent this message as an `lxm://` URI, mirroring
    /// `LXMessage.as_uri`. Requires the message to have been packed for
    /// PAPER delivery.
    pub fn as_uri(&mut self) -> Result<String, LxmfError> {
        if self.packed.is_none() {
            return Err(LxmfError::NotPacked);
        }

        if self.desired_method == Some(PAPER) && self.paper_packed.is_some() {
            let paper_packed = self.paper_packed.as_ref().unwrap();
            let encoded = base64_urlsafe_nopad(paper_packed);
            self.determine_transport_encryption();
            self.state = PAPER;
            self.progress = 1.0;
            Ok(format!("{URI_SCHEMA}://{encoded}"))
        } else {
            Err(LxmfError::UnsupportedMethod)
        }
    }

    /// Unpack an LXMF message from its packed bytes.
    ///
    /// Since no identity store is available in this context, the signature
    /// cannot be validated and `unverified_reason` will be set to
    /// [`SOURCE_UNKNOWN`].
    pub fn unpack_from_bytes(lxmf_bytes: &[u8]) -> Result<Self, LxmfError> {
        Self::unpack_from_bytes_with(lxmf_bytes, &|_| None)
    }

    /// Unpack an LXMF message from its packed bytes, resolving the source
    /// and destination identities through `resolver` (the equivalent of
    /// `RNS.Identity.recall`). If the source identity is known, the message
    /// signature is validated.
    pub fn unpack_from_bytes_with(
        lxmf_bytes: &[u8],
        resolver: &dyn Fn(&AddressHash) -> Option<Identity>,
    ) -> Result<Self, LxmfError> {
        if lxmf_bytes.len() < 2 * DESTINATION_LENGTH + SIGNATURE_LENGTH {
            return Err(LxmfError::InvalidFormat);
        }

        let destination_hash =
            AddressHash::new(lxmf_bytes[..DESTINATION_LENGTH].try_into().unwrap());
        let source_hash = AddressHash::new(
            lxmf_bytes[DESTINATION_LENGTH..2 * DESTINATION_LENGTH]
                .try_into()
                .unwrap(),
        );
        let signature: [u8; SIGNATURE_LENGTH] = lxmf_bytes
            [2 * DESTINATION_LENGTH..2 * DESTINATION_LENGTH + SIGNATURE_LENGTH]
            .try_into()
            .unwrap();
        let mut packed_payload = &lxmf_bytes[2 * DESTINATION_LENGTH + SIGNATURE_LENGTH..];

        // Unpack the payload array: [timestamp, title, content, fields
        // (, stamp)]
        let payload = FieldValue::unpack(&mut packed_payload)?;
        let mut elements = match payload {
            FieldValue::Array(items) if items.len() >= 4 => items,
            _ => return Err(LxmfError::InvalidFormat),
        };

        // Extract stamp from payload if included. The stamp can be either a
        // 32 byte hashcash stamp or a 16 byte ticket-derived stamp.
        let stamp = if elements.len() > 4 {
            match elements.pop() {
                Some(FieldValue::Bin(stamp)) => Some(stamp),
                _ => return Err(LxmfError::InvalidFormat),
            }
        } else {
            None
        };

        let timestamp = match elements[0] {
            FieldValue::F64(timestamp) => timestamp,
            _ => return Err(LxmfError::InvalidFormat),
        };
        let title_bytes = match &elements[1] {
            FieldValue::Bin(title) => title.clone(),
            _ => return Err(LxmfError::InvalidFormat),
        };
        let content_bytes = match &elements[2] {
            FieldValue::Bin(content) => content.clone(),
            _ => return Err(LxmfError::InvalidFormat),
        };
        let fields = match &elements[3] {
            FieldValue::Map(_) => Fields::from_value(&elements[3])?,
            _ => return Err(LxmfError::InvalidFormat),
        };

        // Re-pack the four-element payload to compute the message hash,
        // exactly as `unpack_from_bytes` does in the Python implementation.
        let mut repacked = Vec::with_capacity(lxmf_bytes.len());
        rmp::encode::write_array_len(&mut repacked, 4).ok();
        elements[0].pack(&mut repacked);
        elements[1].pack(&mut repacked);
        elements[2].pack(&mut repacked);
        elements[3].pack(&mut repacked);

        let mut hashed_part = Vec::with_capacity(2 * DESTINATION_LENGTH + repacked.len());
        hashed_part.extend_from_slice(destination_hash.as_slice());
        hashed_part.extend_from_slice(source_hash.as_slice());
        hashed_part.extend_from_slice(&repacked);
        let message_hash = full_hash(&hashed_part);

        let mut signed_part = Vec::with_capacity(hashed_part.len() + HASH_SIZE);
        signed_part.extend_from_slice(&hashed_part);
        signed_part.extend_from_slice(message_hash.as_slice());

        let destination_identity = resolver(&destination_hash);
        let source_identity = resolver(&source_hash);

        let mut message = Self::new(destination_hash, source_hash, &title_bytes, &content_bytes);
        message.fields = fields;
        message.hash = Some(message_hash);
        message.message_id = message.hash;
        message.signature = Some(signature);
        message.stamp = stamp;
        message.incoming = true;
        message.timestamp = Some(timestamp);
        message.packed = Some(lxmf_bytes.to_vec());
        message.packed_size = Some(lxmf_bytes.len());
        message.packed_payload = Some(repacked);
        message.destination_identity = destination_identity;
        message.source_identity = source_identity;

        // Validate the signature against the recalled source identity
        if let Some(source_identity) = &source_identity {
            let signature = Signature::from_bytes(&signature);
            match source_identity.verify(&signed_part, &signature) {
                Ok(()) => {
                    message.signature_validated = true;
                }
                Err(_) => {
                    message.signature_validated = false;
                    message.unverified_reason = Some(SIGNATURE_INVALID);
                }
            }
        } else {
            message.signature_validated = false;
            message.unverified_reason = Some(SOURCE_UNKNOWN);
            log::debug!(
                "Unpacked LXMF message signature could not be validated, \
                 since source identity is unknown"
            );
        }

        Ok(message)
    }

    /// Ingest a paper message URI, decrypting with the private identity of
    /// the message destination (mirrors `LXMRouter.ingest_lxm_uri` data
    /// preparation, plus the transport-decrypt step performed by
    /// `lxmf_propagation` for locally destined messages).
    pub fn unpack_from_uri(
        uri: &str,
        destination_identity: &PrivateIdentity,
        resolver: &dyn Fn(&AddressHash) -> Option<Identity>,
    ) -> Result<(Self, Hash), LxmfError> {
        let prefix = format!("{URI_SCHEMA}://");
        if !uri.to_ascii_lowercase().starts_with(&prefix) {
            return Err(LxmfError::InvalidFormat);
        }

        let encoded = uri[prefix.len()..].replace('/', "");
        let lxmf_data = base64_urlsafe_decode(&encoded)?;
        let transient_id = full_hash(&lxmf_data);

        if lxmf_data.len() < DESTINATION_LENGTH + LXMF_OVERHEAD {
            return Err(LxmfError::InvalidFormat);
        }

        let destination_hash =
            AddressHash::new(lxmf_data[..DESTINATION_LENGTH].try_into().unwrap());
        let encrypted = &lxmf_data[DESTINATION_LENGTH..];
        let decrypted = decrypt_for_identity(destination_identity, encrypted)?;

        let mut delivery_data = Vec::with_capacity(DESTINATION_LENGTH + decrypted.len());
        delivery_data.extend_from_slice(destination_hash.as_slice());
        delivery_data.extend_from_slice(&decrypted);

        let message = Self::unpack_from_bytes_with(&delivery_data, resolver)?;
        Ok((message, transient_id))
    }

    /// Unpack a message persisted by [`LXMessage::write_to_directory`],
    /// mirroring `LXMessage.unpack_from_file`.
    pub fn unpack_from_file(
        path: &std::path::Path,
        resolver: &dyn Fn(&AddressHash) -> Option<Identity>,
    ) -> Result<Self, LxmfError> {
        let raw = std::fs::read(path)?;
        let mut rd: &[u8] = &raw;
        let container = FieldValue::unpack(&mut rd)?;

        let FieldValue::Map(entries) = container else {
            return Err(LxmfError::InvalidFormat);
        };

        let mut lxmf_bytes: Option<Vec<u8>> = None;
        let mut state: Option<u8> = None;
        let mut transport_encrypted: Option<bool> = None;
        let mut transport_encryption: Option<TransportEncryption> = None;
        let mut method: Option<u8> = None;

        for (key, value) in entries {
            let Some(key) = key.as_str() else { continue };
            match key {
                "lxmf_bytes" => match value {
                    FieldValue::Bin(bytes) => lxmf_bytes = Some(bytes),
                    _ => return Err(LxmfError::InvalidFormat),
                },
                "state" => state = value.as_int().map(|v| v as u8),
                "transport_encrypted" => {
                    transport_encrypted = match value {
                        FieldValue::Bool(b) => Some(b),
                        _ => None,
                    }
                }
                "transport_encryption" => {
                    transport_encryption = match value.as_str() {
                        Some(ENCRYPTION_DESCRIPTION_AES) => Some(TransportEncryption::Aes128),
                        Some(ENCRYPTION_DESCRIPTION_EC) => Some(TransportEncryption::Curve25519),
                        Some(ENCRYPTION_DESCRIPTION_UNENCRYPTED) => {
                            Some(TransportEncryption::Unencrypted)
                        }
                        _ => None,
                    }
                }
                "method" => method = value.as_int().map(|v| v as u8),
                _ => {}
            }
        }

        let lxmf_bytes = lxmf_bytes.ok_or(LxmfError::InvalidFormat)?;
        let mut message = Self::unpack_from_bytes_with(&lxmf_bytes, resolver)?;
        if let Some(state) = state {
            message.state = state;
        }
        if let Some(transport_encrypted) = transport_encrypted {
            message.transport_encrypted = transport_encrypted;
        }
        message.transport_encryption = transport_encryption;
        if let Some(method) = method {
            message.method = method;
        }

        Ok(message)
    }
}

#[cfg(test)]
mod transport_encryption_tests {
    use super::*;
    use reticulum_core::packet::DestinationType;

    fn message_with(method: u8, destination_type: DestinationType) -> LXMessage {
        let mut message = LXMessage::new(
            AddressHash::new_empty(),
            AddressHash::new_empty(),
            b"title",
            b"content",
        );
        message.method = method;
        message.destination_type = destination_type;
        message
    }

    #[test]
    fn single_destinations_use_curve25519() {
        // Python: OPPORTUNISTIC/PROPAGATED/PAPER to SINGLE -> EC.
        for method in [OPPORTUNISTIC, PROPAGATED, PAPER] {
            let mut message = message_with(method, DestinationType::Single);
            message.determine_transport_encryption();
            assert!(message.transport_encrypted);
            assert_eq!(
                message.transport_encryption,
                Some(TransportEncryption::Curve25519),
                "method {method}"
            );
        }
    }

    #[test]
    fn group_destinations_use_aes128() {
        // Python: GROUP -> AES-128 for the packet-carried methods.
        for method in [OPPORTUNISTIC, PROPAGATED, PAPER] {
            let mut message = message_with(method, DestinationType::Group);
            message.determine_transport_encryption();
            assert!(message.transport_encrypted);
            assert_eq!(
                message.transport_encryption,
                Some(TransportEncryption::Aes128),
                "method {method}"
            );
        }
    }

    #[test]
    fn plain_destinations_are_unencrypted() {
        // Python: everything but SINGLE/GROUP (PLAIN, LINK) is reported
        // unencrypted for opportunistic/propagated/paper delivery.
        for method in [OPPORTUNISTIC, PROPAGATED, PAPER] {
            let mut message = message_with(method, DestinationType::Plain);
            message.determine_transport_encryption();
            assert!(!message.transport_encrypted);
            assert_eq!(
                message.transport_encryption,
                Some(TransportEncryption::Unencrypted),
                "method {method}"
            );
        }
    }

    #[test]
    fn direct_delivery_is_always_curve25519() {
        // Python: DIRECT is always EC regardless of destination type.
        for destination_type in [
            DestinationType::Single,
            DestinationType::Group,
            DestinationType::Plain,
            DestinationType::Link,
        ] {
            let mut message = message_with(DIRECT, destination_type);
            message.determine_transport_encryption();
            assert!(message.transport_encrypted, "{destination_type:?}");
            assert_eq!(
                message.transport_encryption,
                Some(TransportEncryption::Curve25519)
            );
        }
    }

    #[test]
    fn unknown_methods_are_unencrypted() {
        let mut message = message_with(0x00, DestinationType::Single);
        message.determine_transport_encryption();
        assert!(!message.transport_encrypted);
        assert_eq!(
            message.transport_encryption,
            Some(TransportEncryption::Unencrypted)
        );
    }

    #[test]
    fn explicit_override_wins_over_determination() {
        let mut message = message_with(OPPORTUNISTIC, DestinationType::Single);
        message.set_transport_encryption(TransportEncryption::Aes128);
        assert_eq!(
            message.transport_encryption,
            Some(TransportEncryption::Aes128)
        );
        assert!(message.transport_encrypted);

        // Re-running the determination keeps the override.
        message.determine_transport_encryption();
        assert_eq!(
            message.transport_encryption,
            Some(TransportEncryption::Aes128)
        );

        // Clearing it restores the automatic result.
        message.clear_transport_encryption_override();
        message.determine_transport_encryption();
        assert_eq!(
            message.transport_encryption,
            Some(TransportEncryption::Curve25519)
        );
    }

    #[test]
    fn unencrypted_override_marks_transport_unencrypted() {
        let mut message = message_with(DIRECT, DestinationType::Single);
        message.set_transport_encryption(TransportEncryption::Unencrypted);
        assert!(!message.transport_encrypted);
    }

    #[test]
    fn destination_type_defaults_to_single() {
        // LXMF delivery destinations are SINGLE type.
        let message = LXMessage::new(AddressHash::new_empty(), AddressHash::new_empty(), b"", b"");
        assert_eq!(message.destination_type, DestinationType::Single);
        assert_eq!(message.destination_type(), DestinationType::Single);
    }
}
