use alloc::fmt::Write;
use core::cmp;
use core::fmt;

use crypto_common::typenum::Unsigned;
use crypto_common::OutputSizeUser;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

use crate::error::RnsError;

pub const HASH_SIZE: usize = <<Sha256 as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
pub const ADDRESS_HASH_SIZE: usize = 16;

pub fn create_hash(data: &[u8], out: &mut [u8]) {
    out.copy_from_slice(
        &Sha256::new().chain_update(data).finalize().as_slice()[..cmp::min(out.len(), HASH_SIZE)],
    );
}

pub fn lxmf_address_hash(hash: &Hash) -> AddressHash {
    AddressHash::new_from_hash(hash)
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Hash([u8; HASH_SIZE]);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Hash)]
pub struct AddressHash([u8; ADDRESS_HASH_SIZE]);

impl Hash {
    pub fn generator() -> Sha256 {
        Sha256::new()
    }

    pub const fn new(hash: [u8; HASH_SIZE]) -> Self {
        Self { 0: hash }
    }

    pub const fn new_empty() -> Self {
        Self {
            0: [0u8; HASH_SIZE],
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        create_hash(data, &mut hash);
        Self { 0: hash }
    }

    pub fn new_from_rand<R: CryptoRngCore>(mut rng: R) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        let mut data = [0u8; HASH_SIZE];

        rng.fill_bytes(&mut data[..]);

        create_hash(&data, &mut hash);
        Self { 0: hash }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; HASH_SIZE] {
        self.0
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AddressHash {
    pub const fn new(hash: [u8; ADDRESS_HASH_SIZE]) -> Self {
        Self { 0: hash }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut hash = [0u8; ADDRESS_HASH_SIZE];
        create_hash(data, &mut hash);
        Self { 0: hash }
    }

    pub fn new_from_hash(hash: &Hash) -> Self {
        let mut address_hash = [0u8; ADDRESS_HASH_SIZE];
        address_hash.copy_from_slice(&hash.0[0..ADDRESS_HASH_SIZE]);
        Self { 0: address_hash }
    }

    pub fn new_from_rand<R: CryptoRngCore>(rng: R) -> Self {
        Self::new_from_hash(&Hash::new_from_rand(rng))
    }

    pub fn new_from_hex_string(hex_string: &str) -> Result<Self, RnsError> {
        if hex_string.len() < ADDRESS_HASH_SIZE * 2 {
            return Err(RnsError::IncorrectHash);
        }

        let mut bytes = [0u8; ADDRESS_HASH_SIZE];

        for i in 0..ADDRESS_HASH_SIZE {
            bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16).unwrap();
        }

        Ok(Self { 0: bytes })
    }

    pub const fn new_empty() -> Self {
        Self {
            0: [0u8; ADDRESS_HASH_SIZE],
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }

    pub fn to_hex_string(&self) -> String {
        let mut hex_string = String::with_capacity(ADDRESS_HASH_SIZE * 2);

        for byte in self.0 {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        hex_string
    }
}

impl From<Hash> for AddressHash {
    fn from(hash: Hash) -> Self {
        Self::new_from_hash(&hash)
    }
}

impl fmt::Display for AddressHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/")?;
        for data in self.0.iter() {
            write!(f, "{:0>2x}", data)?;
        }
        write!(f, "/")?;

        Ok(())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for data in self.0.iter() {
            write!(f, "{:0>2x}", data)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use rand_core::OsRng;

    use crate::hash::AddressHash;

    #[test]
    fn address_hex_string() {
        let original_address_hash = AddressHash::new_from_rand(OsRng);

        let address_hash_hex = original_address_hash.to_hex_string();

        let actual_address_hash =
            AddressHash::new_from_hex_string(&address_hash_hex).expect("valid hash");

        assert_eq!(
            actual_address_hash.as_slice(),
            original_address_hash.as_slice()
        );
    }
}
