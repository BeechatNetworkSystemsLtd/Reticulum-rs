//! LXStamper - hashcash-style stamps for LXMF.
//!
//! Port of `LXMF/LXMF/LXStamper.py`. The stamp work-block construction and
//! the leading-zero-bit validity rule are byte-for-byte compatible with the
//! Python implementation:
//!
//! * `workblock = concat(hkdf_sha256(256 bytes, ikm = material,
//!   salt = sha256(material || msgpack(n))))` for `n` in `0..expand_rounds`
//! * a stamp is valid at `target_cost` when `sha256(workblock || stamp)`
//!   has at least `target_cost` leading zero bits (big-endian).

use std::vec::Vec;

use rand_core::CryptoRngCore;
use reticulum_core::hash::Hash;

use crate::message::full_hash;

/// HKDF expansion rounds of a standard message stamp work block.
pub const WORKBLOCK_EXPAND_ROUNDS: usize = 3000;
/// HKDF expansion rounds of a propagation node stamp work block.
pub const WORKBLOCK_EXPAND_ROUNDS_PN: usize = 1000;
/// HKDF expansion rounds of a peering key work block.
pub const WORKBLOCK_EXPAND_ROUNDS_PEERING: usize = 25;
/// Size of a hashcash stamp in bytes (`RNS.Identity.HASHLENGTH // 8`).
pub const STAMP_SIZE: usize = 32;
/// Minimum batch size for which the Python implementation uses a process pool.
pub const PN_VALIDATION_POOL_MIN_SIZE: usize = 256;

/// The length of a work block for a given number of expand rounds
/// (256 bytes are appended per round).
pub fn workblock_len(expand_rounds: usize) -> usize {
    expand_rounds * 256
}

/// Expand `material` into a stamp work block, exactly as the Python
/// `LXStamper.stamp_workblock` does.
/// Expand `material` into a stamp work block with the default number of
/// expansion rounds (`LXStamper.stamp_workblock`).
pub fn stamp_workblock(material: &[u8]) -> Vec<u8> {
    stamp_workblock_with_rounds(material, WORKBLOCK_EXPAND_ROUNDS)
}

/// Expand `material` into a stamp work block using a custom number of
/// HKDF expand rounds.
pub fn stamp_workblock_with_rounds(material: &[u8], expand_rounds: usize) -> Vec<u8> {
    let mut workblock = Vec::with_capacity(workblock_len(expand_rounds));

    for n in 0..expand_rounds {
        // salt = RNS.Identity.full_hash(material + msgpack.packb(n))
        let mut salt_material = Vec::with_capacity(material.len() + 5);
        salt_material.extend_from_slice(material);
        // msgpack.packb(n) for the small round counters used here is a
        // single positive fixint byte; use the full minimal encoding
        // anyway for parity with umsgpack.
        rmp::encode::write_uint(&mut salt_material, n as u64).ok();
        let salt = full_hash(&salt_material);

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt.as_slice()), material);
        let mut derived = [0u8; 256];
        // HKDF-SHA256 with 256 bytes of output; the error case cannot
        // happen since the output buffer has a valid length.
        hk.expand(&[], &mut derived).expect("valid hkdf length");
        workblock.extend_from_slice(&derived);
    }

    workblock
}

/// Number of leading zero bits in `data`, interpreted as a big-endian
/// integer. Mirrors the bit-shift loop of `LXStamper.stamp_value`.
pub fn leading_zero_bits(data: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for byte in data {
        if *byte == 0 {
            value += 8;
        } else {
            value += byte.leading_zeros() as u64;
            break;
        }
    }
    value
}

/// Calculate the work value of `stamp` against `workblock`.
pub fn stamp_value(workblock: &[u8], stamp: &[u8]) -> u64 {
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    let hash = Hash::new_from_slice(&material);
    leading_zero_bits(hash.as_slice())
}

/// Check whether `stamp` is valid at `target_cost` against `workblock`.
///
/// The Python implementation compares the big-endian integer of the hash
/// against `1 << (256 - target_cost)`; that condition is equivalent to
/// requiring at least `target_cost` leading zero bits.
pub fn stamp_valid(stamp: &[u8], target_cost: u32, workblock: &[u8]) -> bool {
    if target_cost == 0 {
        return true;
    }
    if target_cost > 256 {
        return false;
    }
    let mut material = Vec::with_capacity(workblock.len() + stamp.len());
    material.extend_from_slice(workblock);
    material.extend_from_slice(stamp);
    let hash = Hash::new_from_slice(&material);
    leading_zero_bits(hash.as_slice()) >= target_cost as u64
}

/// Find a stamp for `material` at `stamp_cost`, using the default number of
/// work block expand rounds. Returns the stamp and its work value.
///
/// This is a single-process, single-core generator (the equivalent of the
/// Python `job_simple` fallback path).
pub fn generate_stamp(material: &[u8], stamp_cost: u32) -> (Option<[u8; STAMP_SIZE]>, u64) {
    generate_stamp_with_rounds(
        material,
        stamp_cost,
        WORKBLOCK_EXPAND_ROUNDS,
        &mut rand_core::OsRng,
    )
}

/// Find a stamp for `material` at `stamp_cost` with a custom work block
/// expansion and RNG.
pub fn generate_stamp_with_rounds<R: CryptoRngCore>(
    material: &[u8],
    stamp_cost: u32,
    expand_rounds: usize,
    rng: &mut R,
) -> (Option<[u8; STAMP_SIZE]>, u64) {
    let workblock = stamp_workblock_with_rounds(material, expand_rounds);
    generate_stamp_against_workblock(&workblock, stamp_cost, rng)
}

/// Find a stamp against an already-expanded work block.
pub fn generate_stamp_against_workblock<R: CryptoRngCore>(
    workblock: &[u8],
    stamp_cost: u32,
    rng: &mut R,
) -> (Option<[u8; STAMP_SIZE]>, u64) {
    let mut stamp = [0u8; STAMP_SIZE];
    let mut rounds: u64 = 0;
    loop {
        rng.fill_bytes(&mut stamp);
        rounds += 1;
        if stamp_valid(&stamp, stamp_cost, workblock) {
            let value = stamp_value(workblock, &stamp);
            log::debug!("Stamp with value {value} generated in {rounds} rounds");
            return (Some(stamp), value);
        }
    }
}

/// Validate a peering key (`LXStamper.validate_peering_key`).
pub fn validate_peering_key(peering_id: &[u8], peering_key: &[u8], target_cost: u32) -> bool {
    let workblock = stamp_workblock_with_rounds(peering_id, WORKBLOCK_EXPAND_ROUNDS_PEERING);
    stamp_valid(peering_key, target_cost, &workblock)
}

/// A propagation-node message stamp validation result, mirroring the tuple
/// returned by `LXStamper.validate_pn_stamp`.
#[derive(Clone, Debug)]
pub struct ValidatedPnStamp {
    /// Full hash of the message data without the trailing stamp.
    pub transient_id: Hash,
    /// The message data (destination hash || encrypted payload).
    pub lxm_data: Vec<u8>,
    /// The work value of the validated stamp.
    pub value: u64,
    /// The stamp bytes themselves.
    pub stamp: [u8; STAMP_SIZE],
}

/// Validate a single propagated message transport entry against
/// `target_cost` (`LXStamper.validate_pn_stamp`). The input is
/// `lxm_data || stamp`.
pub fn validate_pn_stamp(transient_data: &[u8], target_cost: u32) -> Option<ValidatedPnStamp> {
    // The LXMF overhead plus one stamp does not leave room for an
    // actual message.
    if transient_data.len() <= crate::message::LXMF_OVERHEAD + STAMP_SIZE {
        return None;
    }

    let lxm_data = &transient_data[..transient_data.len() - STAMP_SIZE];
    let mut stamp = [0u8; STAMP_SIZE];
    stamp.copy_from_slice(&transient_data[transient_data.len() - STAMP_SIZE..]);

    let transient_id = full_hash(lxm_data);
    let workblock =
        stamp_workblock_with_rounds(transient_id.as_slice(), WORKBLOCK_EXPAND_ROUNDS_PN);

    if !stamp_valid(&stamp, target_cost, &workblock) {
        return None;
    }

    let value = stamp_value(&workblock, &stamp);
    Some(ValidatedPnStamp {
        transient_id,
        lxm_data: lxm_data.to_vec(),
        value,
        stamp,
    })
}

/// Validate a batch of propagated message entries (`LXStamper.validate_pn_stamps`).
pub fn validate_pn_stamps(transient_list: &[Vec<u8>], target_cost: u32) -> Vec<ValidatedPnStamp> {
    transient_list
        .iter()
        .filter_map(|transient_data| validate_pn_stamp(transient_data, target_cost))
        .collect()
}
