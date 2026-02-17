use std::sync::LazyLock;
use oqs::kem::{self, Kem};
use oqs::sig::{self, Sig, Signature};
use crate::hash::Hash;

// NOTE: oqs::init() can only be called once if oqs `std` feature is not enabled. `std` is a default
// feature but if it needs to be disabled then this lazy lock means that we only call it once.
static OQS_INIT: LazyLock<()> = LazyLock::new(||{
    log::debug!("initializing liboqs");
    oqs::init()
});

pub static ALGORITHM_MLKEM768: LazyLock<Kem> = LazyLock::new(||{
    let _ = *OQS_INIT;
    Kem::new(kem::Algorithm::MlKem768)
        .unwrap_or_else(|err|{
            log::error!("error initializing MlKem768 algorithm: {err}");
            panic!("error initializing MlKem768 algorithm: {err}")
        })
});

pub static ALGORITHM_MLDSA65: LazyLock<Sig> = LazyLock::new(||{
    let _ = *OQS_INIT;
    Sig::new(sig::Algorithm::MlDsa65)
        .unwrap_or_else(|err|{
            log::error!("error initializing MlDsa65 algorithm: {err}");
            panic!("error initializing MlDsa65 algorithm: {err}")
        })
});

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
    verifykey_hash: Hash
}

#[derive(Clone)]
pub struct PostQuantumPublicKeys {
    /// ML-KEM-768 public key
    pubkey: oqs::kem::PublicKey,
    /// ML-DSA-65 public key
    verifykey: oqs::sig::PublicKey
}

impl PostQuantumKeys {
    pub fn new(
        pubkey: oqs::kem::PublicKey,
        privkey: oqs::kem::SecretKey,
        verifykey: oqs::sig::PublicKey,
        signkey: oqs::sig::SecretKey,
    ) -> Self {
        let verifykey_hash = Hash::new_from_slice(verifykey.as_ref());
        PostQuantumKeys { pubkey, privkey, verifykey, signkey, verifykey_hash }
    }

    pub fn generate() -> oqs::Result<Self> {
        let (pubkey, privkey) = ALGORITHM_MLKEM768.keypair()?;
        let (verifykey, signkey) = ALGORITHM_MLDSA65.keypair()?;
        let verifykey_hash = Hash::new_from_slice(verifykey.as_ref());
        Ok(PostQuantumKeys { pubkey, privkey, verifykey, signkey, verifykey_hash })
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
    pub fn capabilities_flags(&self, pqc_only: bool) -> u8 {
    use PostQuantumCapability::*;
        // TODO: make key exchange support or signature support optional?
        KeyExchangeSupported as u8 | SignatureSupported as u8 | if pqc_only {
            PqcOnlyMode as u8
        } else {
            0b0
        }
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        ALGORITHM_MLDSA65.sign(data, &self.signkey).expect("signature")
    }

}

impl PostQuantumPublicKeys {
    pub fn new(pubkey: oqs::kem::PublicKey, verifykey: oqs::sig::PublicKey) -> Self {
        PostQuantumPublicKeys { pubkey, verifykey }
    }

    pub fn pubkey(&self) -> &oqs::kem::PublicKey {
        &self.pubkey
    }
    pub fn verifykey(&self) -> &oqs::sig::PublicKey {
        &self.verifykey
    }
}
