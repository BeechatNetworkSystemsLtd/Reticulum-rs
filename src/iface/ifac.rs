//! Interface Access Codes — Python `RNS.Transport` IFAC support
//! (Phase 5.1).
//!
//! Interfaces configured with a `networkname` and/or `passphrase` derive a
//! shared 64-byte access key (HKDF-SHA256 over the salted origin hash with
//! the fixed `IFAC_SALT`). Every packet on the wire is then wrapped:
//!
//! * transmit (`Transport.transmit`): compute `ifac =
//!   ifac_identity.sign(raw)[-ifac_size:]`, derive an HKDF mask keyed by
//!   the IFAC itself, set the IFAC flag in the header, insert the IFAC
//!   after the two header bytes and mask header + payload (leaving the
//!   IFAC itself unmasked)
//! * receive (`Transport.inbound`): check the IFAC flag, extract and
//!   un-mask, verify the truncated signature over the reassembled packet
//!   and drop on mismatch
//!
//! Packets without a valid access code are dropped, so IFAC-protected
//! interfaces only accept traffic from peers sharing the network name
//! and/or passphrase.

use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::RnsError;
use crate::hash::Hash;
use crate::identity::SigningKey;
use reticulum_core::identity::Signer;

/// Fixed HKDF salt for IFAC key derivation
/// (Python `Reticulum.IFAC_SALT`).
pub const IFAC_SALT: [u8; 32] = [
    0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4, 0x99, 0x5d, 0x70, 0x2d, 0x4a,
    0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0, 0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
];

/// Minimum IFAC size in bytes (Python `Reticulum.IFAC_MIN_SIZE`).
pub const IFAC_MIN_SIZE: usize = 1;
/// Maximum IFAC signature truncation length (one Ed25519 signature).
pub const IFAC_MAX_SIZE: usize = 64;

/// Default IFAC size in bytes when none is configured
/// (Python `Interface.DEFAULT_IFAC_SIZE`).
pub const DEFAULT_IFAC_SIZE: usize = 16;

/// Default IFAC size in bytes for the serial family when none is
/// configured (Python `DEFAULT_IFAC_SIZE` on `SerialInterface`,
/// `KISSInterface`, `AX25KISSInterface`, `RNodeInterface`,
/// `RNodeMultiInterface`, and `PipeInterface`).
pub const SERIAL_FAMILY_IFAC_SIZE: usize = 8;

/// HKDF-SHA256 with an empty context (Python `RNS.Cryptography.hkdf`
/// with `context=None`).
fn hkdf(derive_from: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), derive_from);
    let mut okm = vec![0u8; length];
    hk.expand(&[], &mut okm).expect("hkdf expand");
    okm
}

/// A derived interface access-code key set
/// (Python `interface.ifac_key` / `ifac_identity` / `ifac_size`).
pub struct IfacKey {
    /// The 64-byte HKDF-derived access key (`x25519 || ed25519` private
    /// halves, Python `Identity.from_bytes(ifac_key)`).
    key: [u8; 64],
    /// Signing half of the access identity.
    sign_key: SigningKey,
    /// Access code length in bytes (Python `interface.ifac_size`).
    pub size: usize,
}

impl IfacKey {
    /// Derive the access key set from an optional network name and/or
    /// passphrase (Python `Reticulum._add_interface`):
    /// `origin = full_hash(netname)? [+ full_hash(netkey)?]`,
    /// `key = HKDF(64, origin_hash, IFAC_SALT)`.
    pub fn derive(
        netname: Option<&str>,
        netkey: Option<&str>,
        size: usize,
    ) -> Result<Self, RnsError> {
        if size > IFAC_MAX_SIZE {
            return Err(RnsError::InvalidArgument);
        }
        let mut origin = Vec::new();

        if let Some(netname) = netname {
            origin.extend_from_slice(Hash::new_from_slice(netname.as_bytes()).as_bytes());
        }

        if let Some(netkey) = netkey {
            origin.extend_from_slice(Hash::new_from_slice(netkey.as_bytes()).as_bytes());
        }

        let origin_hash = Hash::new_from_slice(&origin);
        let key = hkdf(origin_hash.as_bytes(), &IFAC_SALT, 64);

        let mut key_bytes = [0u8; 64];
        key_bytes.copy_from_slice(&key);

        // Python `Identity.from_bytes(ifac_key)`: the second half is the
        // ed25519 signing key.
        let mut sign_seed = [0u8; 32];
        sign_seed.copy_from_slice(&key_bytes[32..]);

        Ok(Self {
            key: key_bytes,
            sign_key: SigningKey::from_bytes(&sign_seed),
            size: size.max(IFAC_MIN_SIZE),
        })
    }

    /// Truncated access-code signature: the last `size` bytes of the
    /// signature over `raw` (Python `identity.sign(raw)[-ifac_size:]`).
    fn ifac_for(&self, raw: &[u8]) -> Vec<u8> {
        let signature = self.sign_key.sign(raw);
        signature.to_bytes()[64 - self.size..].to_vec()
    }

    /// Wrap a serialized packet for transmission
    /// (Python `Transport.transmit` IFAC branch). Returns the wire bytes.
    pub fn apply(&self, raw: &[u8]) -> Vec<u8> {
        let ifac = self.ifac_for(raw);

        // mask = hkdf(len(raw)+size, ifac, ifac_key)
        let mask = hkdf(&ifac, &self.key, raw.len() + self.size);

        // new payload with the IFAC inserted after the two header bytes
        // and the IFAC flag set.
        let mut new_raw = Vec::with_capacity(raw.len() + self.size);
        new_raw.push(raw[0] | 0x80);
        new_raw.push(raw[1]);
        new_raw.extend_from_slice(&ifac);
        new_raw.extend_from_slice(&raw[2..]);

        // Mask the first header byte (keeping the IFAC flag), the second
        // header byte and the payload; the IFAC itself stays unmasked.
        let mut masked = Vec::with_capacity(new_raw.len());
        for (i, byte) in new_raw.iter().enumerate() {
            if i == 0 {
                masked.push((byte ^ mask[i]) | 0x80);
            } else if i == 1 || i > self.size + 1 {
                masked.push(byte ^ mask[i]);
            } else {
                masked.push(*byte);
            }
        }

        masked
    }

    /// Validate and unwrap a received IFAC packet
    /// (Python `Transport.inbound` IFAC branch). Returns the plain wire
    /// bytes, or `None` when the access code is missing or invalid.
    pub fn strip(&self, raw: &[u8]) -> Option<Vec<u8>> {
        // The IFAC flag must be set.
        if raw.first()? & 0x80 == 0 {
            return None;
        }

        if raw.len() <= 2 + self.size {
            return None;
        }

        let ifac = &raw[2..2 + self.size];

        // mask = hkdf(len(raw), ifac, ifac_key)
        let mask = hkdf(ifac, &self.key, raw.len());

        // Unmask header bytes and payload; the IFAC itself stays unmasked.
        let mut unmasked = Vec::with_capacity(raw.len());
        for (i, byte) in raw.iter().enumerate() {
            if i <= 1 || i > self.size + 1 {
                unmasked.push(byte ^ mask[i]);
            } else {
                unmasked.push(*byte);
            }
        }

        // Re-assemble the packet without the IFAC and unset the flag.
        let mut new_raw = Vec::with_capacity(unmasked.len() - self.size);
        new_raw.push(unmasked[0] & 0x7f);
        new_raw.push(unmasked[1]);
        new_raw.extend_from_slice(&unmasked[2 + self.size..]);

        let expected = self.ifac_for(&new_raw);
        if expected == ifac {
            Some(new_raw)
        } else {
            None
        }
    }
}

/// Encode a serialized packet for an interface IFAC, when one is
/// configured (worker transmit helper).
pub fn encode(raw: &[u8], ifac: Option<&IfacKey>) -> Vec<u8> {
    match ifac {
        Some(ifac) => ifac.apply(raw),
        None => raw.to_vec(),
    }
}

/// Decode received wire bytes for an interface IFAC, when one is
/// configured (worker receive helper). Returns `None` when the packet
/// must be dropped.
pub fn decode(raw: &[u8], ifac: Option<&IfacKey>) -> Option<Vec<u8>> {
    decode_inbound(raw, ifac, None)
}

/// [`decode`] that counts a bad access code or a truncated frame on
/// `stats` (Python `Interface.ifac_violation` / `protocol_violation`).
///
/// `None` stats keeps the historical two-argument behaviour so existing
/// callers stay source-compatible.
pub fn decode_inbound(
    raw: &[u8],
    ifac: Option<&IfacKey>,
    stats: Option<&crate::iface::InterfaceCounters>,
) -> Option<Vec<u8>> {
    if raw.len() <= 2 {
        if let Some(stats) = stats {
            stats.count_protocol_violation();
            return None;
        }
    }

    match ifac {
        Some(ifac) => match ifac.strip(raw) {
            Some(plain) => Some(plain),
            None => {
                if let Some(stats) = stats {
                    stats.count_ifac_violation();
                }
                None
            }
        },
        None => {
            // IFAC flag set on an interface that has no access code.
            if stats.is_some() && raw.first().is_some_and(|byte| byte & 0x80 == 0x80) {
                if let Some(stats) = stats {
                    stats.count_ifac_violation();
                }
                return None;
            }
            Some(raw.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejection() {
        let key = IfacKey::derive(Some("ifac-test-network"), Some("correct horse"), 8)
            .expect("valid IFAC");

        let raw: Vec<u8> = (0..128u8).collect();

        let wrapped = key.apply(&raw);
        assert_eq!(wrapped.len(), raw.len() + key.size);
        // IFAC flag set in the wrapped header.
        assert_eq!(wrapped[0] & 0x80, 0x80);

        let unwrapped = key.strip(&wrapped).expect("valid ifac");
        assert_eq!(unwrapped, raw);

        // Tampering with the payload breaks the access code.
        let mut tampered = wrapped.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(key.strip(&tampered).is_none());

        // A different network name cannot unwrap.
        let other =
            IfacKey::derive(Some("other-network"), Some("correct horse"), 8).expect("valid IFAC");
        assert!(other.strip(&wrapped).is_none());

        // Packets without the IFAC flag are rejected.
        let mut unflagged = wrapped.clone();
        unflagged[0] &= 0x7f;
        assert!(key.strip(&unflagged).is_none());
    }

    #[test]
    fn deterministic_derivation() {
        let a = IfacKey::derive(Some("net"), Some("pass"), 8).expect("valid IFAC");
        let b = IfacKey::derive(Some("net"), Some("pass"), 8).expect("valid IFAC");
        let c = IfacKey::derive(None, Some("pass"), 8).expect("valid IFAC");

        let raw = [7u8; 64];
        assert_eq!(a.apply(&raw), b.apply(&raw));
        assert_ne!(a.apply(&raw), c.apply(&raw));

        // Default minimum size applies.
        let small = IfacKey::derive(Some("net"), None, 0).expect("valid IFAC");
        assert_eq!(small.size, IFAC_MIN_SIZE);
    }

    #[test]
    fn defaults_match_python() {
        assert_eq!(IFAC_MIN_SIZE, 1);
        // Omitted `ifac_size` is 16 bytes on the base interface.
        assert_eq!(DEFAULT_IFAC_SIZE, 16);
        // Serial, KISS, AX.25, RNode, RNodeMulti, and Pipe omit to 8 bytes.
        assert_eq!(SERIAL_FAMILY_IFAC_SIZE, 8);

        let base = IfacKey::derive(Some("net"), None, DEFAULT_IFAC_SIZE).expect("valid IFAC");
        assert_eq!(base.size, 16);
        let serial =
            IfacKey::derive(Some("net"), None, SERIAL_FAMILY_IFAC_SIZE).expect("valid IFAC");
        assert_eq!(serial.size, 8);

        let raw = [1u8, 2, 3, 4];
        let wrapped = base.apply(&raw);
        assert_eq!(wrapped.len(), raw.len() + DEFAULT_IFAC_SIZE);
        assert_eq!(base.strip(&wrapped).as_deref(), Some(raw.as_slice()));
    }

    #[test]
    fn derivation_enforces_signature_size_bounds() {
        assert_eq!(
            IfacKey::derive(Some("net"), None, 1)
                .expect("one-byte IFAC")
                .size,
            1
        );
        assert_eq!(
            IfacKey::derive(Some("net"), None, IFAC_MAX_SIZE)
                .expect("full signature IFAC")
                .size,
            IFAC_MAX_SIZE
        );
        assert!(matches!(
            IfacKey::derive(Some("net"), None, IFAC_MAX_SIZE + 1),
            Err(RnsError::InvalidArgument)
        ));
    }

    #[test]
    fn matches_python_reference() {
        // Golden vector produced with the Python reference implementation:
        //   origin = full_hash(b"net") + full_hash(b"pass")
        //   key    = RNS.Cryptography.hkdf(64, full_hash(origin), IFAC_SALT)
        //   ident  = RNS.Identity.from_bytes(key)
        //   ifac   = ident.sign(raw)[-8:]
        //   mask   = hkdf(len(raw)+8, ifac, salt=key)
        let key = IfacKey::derive(Some("net"), Some("pass"), 8).expect("valid IFAC");

        let raw: Vec<u8> = (0..64u8).collect();
        let wrapped = key.apply(&raw);

        let expected = hex_literal_vec(
            "b94fbf92d8e36218fc0d178bd37991243588d582da13d7bb61b78afbd82b852d\
             1c365683eaaa4583cb20d65a4aa39ac8fe3c008fa3ee0ee2506a9aa46cdce860\
             74a17d45e6248626",
        );
        assert_eq!(wrapped, expected);

        // and the reference implementation's wrapped packet unwraps here.
        assert_eq!(key.strip(&expected), Some(raw));
    }

    fn hex_literal_vec(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len() / 2)
            .map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
}
