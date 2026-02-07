use oqs;
use crate::hash::Hash;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum PostQuantumCapability {
    /// Bit 0 (LSB): PQC key exchange supported (ML-KEM)
    KeyExchangeSupported = 0b001,
    /// Bit 1: PQC signature supported (ML-DSA)
    SignatureSupported = 0b010,
    /// Bit 2: PQC-only mode
    PqcOnlyMode = 0b100,
}

#[derive(Clone)]
pub struct PostQuantumKeys {
    /// ML-KEM-768 public key
    pubkey: oqs::kem::PublicKey,
    /// ML-KEM-768 secret key
    privkey: oqs::kem::SecretKey,
    /// ML-DSA-65 public key
    verifykey: oqs::sig::PublicKey,
    /// ML-DSA-65 secret key
    signkey: oqs::sig::SecretKey,
    /// Hash of ML-DSA-65 public key (used for announces)
    verifykey_hash: Hash,
    /// Disallow ECC-only links
    pqc_only: bool
}

impl PostQuantumKeys {
  pub fn new(
      pubkey: oqs::kem::PublicKey,
      privkey: oqs::kem::SecretKey,
      verifykey: oqs::sig::PublicKey,
      signkey: oqs::sig::SecretKey,
      pqc_only: bool
  ) -> Self {
      let verifykey_hash = Hash::new_from_slice (verifykey.as_ref());
      PostQuantumKeys { pubkey, privkey, verifykey, signkey, verifykey_hash, pqc_only }
  }

  pub fn pubkey(&self) -> &oqs::kem::PublicKey {
      &self.pubkey
  }
  pub fn privkey(&self) -> &oqs::kem::SecretKey {
      &self.privkey
  }
  pub fn verifykey(&self) -> &oqs::sig::PublicKey {
      &self.verifykey
  }
  pub fn signkey(&self) -> &oqs::sig::SecretKey {
      &self.signkey
  }
  pub fn verifykey_hash(&self) -> &Hash {
      &self.verifykey_hash
  }
  /// Returns capabilities bitflags
  ///
  /// Bit 0 (LSB): PQC key exchange supported (ML-KEM)
  /// Bit 1: PQC signature supported (ML-DSA)
  /// Bit 2: PQC-only mode
  pub fn capabilities_flags(&self) -> u8 {
    use PostQuantumCapability::*;
    // TODO: make key exchange support or signature support optional?
    KeyExchangeSupported as u8 | SignatureSupported as u8 | if self.pqc_only {
      PqcOnlyMode as u8
    } else {
      0b0
    }
  }
}
