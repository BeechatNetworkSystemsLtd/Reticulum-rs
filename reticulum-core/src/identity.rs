use alloc::{fmt::Write, string::String, vec::Vec};
use hkdf::Hkdf;
use rand_core::CryptoRngCore;

/// Entropy source for operations that generate keys non-deterministically
/// on hosted targets. Bare-metal users bring their own RNG and pass it via
/// the `_with_rng` / generic-RNG APIs.
#[cfg(feature = "std")]
pub use rand_core::OsRng;

use ed25519_dalek::{SIGNATURE_LENGTH, VerifyingKey};

pub use ed25519_dalek::ed25519::signature::Signer;
pub use ed25519_dalek::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, SharedSecret};

pub use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    crypt::{
        fernet::{Fernet, PlainText, Token},
        group::GroupKey,
    },
    error::RnsError,
    hash::{AddressHash, HASH_SIZE, Hash},
};

/// X.25519 ratchet key size in bytes (Python `Identity.RATCHETSIZE // 8`).
pub const RATCHET_KEY_LENGTH: usize = 256 / 8;

/// Expiry time for received ratchets in seconds (Python
/// `Identity.RATCHET_EXPIRY`, 30 days).
pub const RATCHET_EXPIRY_SECS: u64 = 60 * 60 * 24 * 30;

/// Length of a ratchet id in bytes (Python `Identity.NAME_HASH_LENGTH // 8`).
pub const RATCHET_ID_LENGTH: usize = 80 / 8;

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

#[cfg(feature = "fernet-aes128")]
pub const DERIVED_KEY_LENGTH: usize = 256 / 8;

#[cfg(not(feature = "fernet-aes128"))]
pub const DERIVED_KEY_LENGTH: usize = 512 / 8;

pub trait EncryptIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError>;
}

pub trait DecryptIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError>;
}

pub trait HashIdentity {
    fn as_address_hash_slice(&self) -> &[u8];
}

#[derive(Copy, Clone, Debug)]
pub struct Identity {
    pub public_key: PublicKey,
    pub verifying_key: VerifyingKey,
    pub address_hash: AddressHash,
}

impl Identity {
    pub fn new(public_key: PublicKey, verifying_key: VerifyingKey) -> Self {
        let hash = Hash::new(
            Hash::generator()
                .chain_update(public_key.as_bytes())
                .chain_update(verifying_key.as_bytes())
                .finalize()
                .into(),
        );

        let address_hash = AddressHash::new_from_hash(&hash);

        Self {
            public_key,
            verifying_key,
            address_hash,
        }
    }

    pub fn new_from_slices(public_key: &[u8], verifying_key: &[u8]) -> Self {
        let public_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(public_key);
            PublicKey::from(key_data)
        };

        let verifying_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(verifying_key);
            VerifyingKey::from_bytes(&key_data).unwrap_or_default()
        };

        Self::new(public_key, verifying_key)
    }

    pub fn new_from_hex_string(hex_string: &str) -> Result<Self, RnsError> {
        if hex_string.len() < PUBLIC_KEY_LENGTH * 2 * 2 {
            return Err(RnsError::IncorrectHash);
        }

        let mut public_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        let mut verifying_key_bytes = [0u8; PUBLIC_KEY_LENGTH];

        for i in 0..PUBLIC_KEY_LENGTH {
            public_key_bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16).unwrap();
            verifying_key_bytes[i] = u8::from_str_radix(
                &hex_string[PUBLIC_KEY_LENGTH * 2 + (i * 2)..PUBLIC_KEY_LENGTH * 2 + (i * 2) + 2],
                16,
            )
            .unwrap();
        }

        Ok(Self::new_from_slices(
            &public_key_bytes[..],
            &verifying_key_bytes[..],
        ))
    }

    pub fn to_hex_string(&self) -> String {
        let mut hex_string = String::with_capacity((PUBLIC_KEY_LENGTH * 2) * 2);

        for byte in self.public_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        for byte in self.verifying_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        hex_string
    }

    pub fn public_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.public_key.as_bytes()
    }

    pub fn verifying_key_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.verifying_key.as_bytes()
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), RnsError> {
        self.verifying_key
            .verify_strict(data, signature)
            .map_err(|_| RnsError::IncorrectSignature)
    }

    pub fn derive_key<R: CryptoRngCore + Copy>(&self, rng: R, salt: Option<&[u8]>) -> DerivedKey {
        DerivedKey::new_from_ephemeral_key(rng, &self.public_key, salt)
    }

    /// Raw public key bytes: `x25519 public || ed25519 public`
    /// (Python `Identity.get_public_key`).
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH * 2] {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH * 2];
        bytes[..PUBLIC_KEY_LENGTH].copy_from_slice(self.public_key.as_bytes());
        bytes[PUBLIC_KEY_LENGTH..].copy_from_slice(self.verifying_key.as_bytes());
        bytes
    }

    /// Encrypt `text` for this identity (Python `Identity.encrypt`).
    ///
    /// If a `ratchet` public key is supplied the ephemeral key exchange is
    /// performed against the ratchet key instead of the static identity
    /// key. The HKDF salt is the identity hash and the context is `None`,
    /// exactly as in the Python reference implementation.
    ///
    /// The result is `ephemeral_pub || fernet_token` written to `out_buf`.
    pub fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        ratchet: Option<&PublicKey>,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let ephemeral = StaticSecret::random_from_rng(rng);
        self.encrypt_with_ephemeral(rng, &ephemeral, text, ratchet, out_buf)
    }

    /// Deterministic variant of [`Identity::encrypt`] with a caller-supplied
    /// ephemeral key exchange secret.
    pub fn encrypt_with_ephemeral<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        ephemeral: &StaticSecret,
        text: &[u8],
        ratchet: Option<&PublicKey>,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if out_buf.len() <= RATCHET_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

        let target_public_key = ratchet.copied().unwrap_or(self.public_key);
        let shared_key = ephemeral.diffie_hellman(&target_public_key);

        // Python `Identity.encrypt`: hkdf(salt=self.get_salt() (= identity
        // hash), context=self.get_context() (= None)).
        let derived_key = DerivedKey::new(&shared_key, Some(self.address_hash.as_slice()));

        let ephemeral_public = PublicKey::from(ephemeral);
        out_buf[..RATCHET_KEY_LENGTH].copy_from_slice(ephemeral_public.as_bytes());

        let fernet = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        );

        let token_len = {
            let token =
                fernet.encrypt(PlainText::from(text), &mut out_buf[RATCHET_KEY_LENGTH..])?;
            token.len()
        };

        Ok(&out_buf[..RATCHET_KEY_LENGTH + token_len])
    }
}

impl Default for Identity {
    fn default() -> Self {
        let empty_key = [0u8; PUBLIC_KEY_LENGTH];
        Self::new(PublicKey::from(empty_key), VerifyingKey::default())
    }
}

impl HashIdentity for Identity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.address_hash.as_slice()
    }
}

impl EncryptIdentity for Identity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let mut out_offset = 0;
        let ephemeral_key = EphemeralSecret::random_from_rng(rng);
        {
            let ephemeral_public = PublicKey::from(&ephemeral_key);
            let ephemeral_public_bytes = ephemeral_public.as_bytes();

            if out_buf.len() >= ephemeral_public_bytes.len() {
                out_buf[..ephemeral_public_bytes.len()].copy_from_slice(ephemeral_public_bytes);
                out_offset += ephemeral_public_bytes.len();
            } else {
                return Err(RnsError::InvalidArgument);
            }
        }

        let token = Fernet::new_from_slices(
            &derived_key.as_bytes()[..16],
            &derived_key.as_bytes()[16..],
            rng,
        )
        .encrypt(PlainText::from(text), &mut out_buf[out_offset..])?;

        out_offset += token.as_bytes().len();

        Ok(&out_buf[..out_offset])
    }
}

pub struct EmptyIdentity;

impl HashIdentity for EmptyIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        &[]
    }
}

impl EncryptIdentity for EmptyIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        _rng: R,
        text: &[u8],
        _derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if text.len() > out_buf.len() {
            return Err(RnsError::OutOfMemory);
        }

        let result = &mut out_buf[..text.len()];
        result.copy_from_slice(text);
        Ok(result)
    }
}

impl DecryptIdentity for EmptyIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        _rng: R,
        data: &[u8],
        _derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if data.len() > out_buf.len() {
            return Err(RnsError::OutOfMemory);
        }

        let result = &mut out_buf[..data.len()];
        result.copy_from_slice(data);
        Ok(result)
    }
}

#[derive(Clone)]
pub struct PrivateIdentity {
    identity: Identity,
    private_key: StaticSecret,
    sign_key: SigningKey,
}

impl PrivateIdentity {
    pub fn new(private_key: StaticSecret, sign_key: SigningKey) -> Self {
        Self {
            identity: Identity::new((&private_key).into(), sign_key.verifying_key()),
            private_key,
            sign_key,
        }
    }

    pub fn new_from_rand<R: CryptoRngCore>(mut rng: R) -> Self {
        let sign_key = SigningKey::generate(&mut rng);
        let private_key = StaticSecret::random_from_rng(rng);

        Self::new(private_key, sign_key)
    }

    pub fn new_from_name(name: &str) -> Self {
        let hash = Hash::new_from_slice(name.as_bytes());
        let private_key = StaticSecret::from(hash.to_bytes());

        let hash = Hash::new_from_slice(hash.as_bytes());
        let sign_key = SigningKey::from_bytes(hash.as_bytes());

        Self::new(private_key, sign_key)
    }

    pub fn new_from_hex_string(hex_string: &str) -> Result<Self, RnsError> {
        if hex_string.len() < PUBLIC_KEY_LENGTH * 2 * 2 {
            return Err(RnsError::IncorrectHash);
        }

        let mut private_key_bytes = [0u8; PUBLIC_KEY_LENGTH];
        let mut sign_key_bytes = [0u8; PUBLIC_KEY_LENGTH];

        for i in 0..PUBLIC_KEY_LENGTH {
            private_key_bytes[i] = u8::from_str_radix(&hex_string[i * 2..(i * 2) + 2], 16).unwrap();
            sign_key_bytes[i] = u8::from_str_radix(
                &hex_string[PUBLIC_KEY_LENGTH * 2 + (i * 2)..PUBLIC_KEY_LENGTH * 2 + (i * 2) + 2],
                16,
            )
            .unwrap();
        }

        Ok(Self::new(
            StaticSecret::from(private_key_bytes),
            SigningKey::from_bytes(&sign_key_bytes),
        ))
    }

    pub fn sign_key(&self) -> &SigningKey {
        &self.sign_key
    }

    pub fn into(&self) -> &Identity {
        &self.identity
    }

    pub fn as_identity(&self) -> &Identity {
        &self.identity
    }

    pub fn address_hash(&self) -> &AddressHash {
        &self.identity.address_hash
    }

    pub fn to_hex_string(&self) -> String {
        let mut hex_string = String::with_capacity((PUBLIC_KEY_LENGTH * 2) * 2);

        for byte in self.private_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        for byte in self.sign_key.as_bytes() {
            write!(&mut hex_string, "{:02x}", byte).unwrap();
        }

        hex_string
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), RnsError> {
        self.identity.verify(data, signature)
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.sign_key.try_sign(data).expect("signature")
    }

    pub fn exchange(&self, public_key: &PublicKey) -> SharedSecret {
        self.private_key.diffie_hellman(public_key)
    }

    pub fn derive_key(&self, public_key: &PublicKey, salt: Option<&[u8]>) -> DerivedKey {
        DerivedKey::new_from_private_key(&self.private_key, public_key, salt)
    }

    /// Raw private key bytes: `x25519 private || ed25519 signing private`
    /// (Python `Identity.get_private_key` / `Identity.from_bytes`).
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH * 2] {
        let mut bytes = [0u8; PUBLIC_KEY_LENGTH * 2];
        bytes[..PUBLIC_KEY_LENGTH].copy_from_slice(self.private_key.as_bytes());
        bytes[PUBLIC_KEY_LENGTH..].copy_from_slice(self.sign_key.as_bytes());
        bytes
    }

    /// Create an identity from raw private key bytes
    /// (Python `Identity.from_bytes` / `load_private_key`).
    pub fn new_from_bytes(bytes: &[u8]) -> Result<Self, RnsError> {
        if bytes.len() != PUBLIC_KEY_LENGTH * 2 {
            return Err(RnsError::IncorrectHash);
        }

        let mut private_key = [0u8; PUBLIC_KEY_LENGTH];
        private_key.copy_from_slice(&bytes[..PUBLIC_KEY_LENGTH]);

        let mut sign_key = [0u8; PUBLIC_KEY_LENGTH];
        sign_key.copy_from_slice(&bytes[PUBLIC_KEY_LENGTH..]);

        Ok(Self::new(
            StaticSecret::from(private_key),
            SigningKey::from_bytes(&sign_key),
        ))
    }

    /// Decrypt a token produced by [`Identity::encrypt`]
    /// (Python `Identity.decrypt`).
    ///
    /// The supplied `ratchets` are private ratchet keys of this identity,
    /// tried in order before falling back to the static identity key.
    /// The HKDF salt is always the identity hash.
    pub fn decrypt<'a>(
        &self,
        data: &[u8],
        ratchets: &[[u8; RATCHET_KEY_LENGTH]],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        self.decrypt_ratchet(data, ratchets, false, out_buf)
            .map(|(plaintext, _ratchet_id)| plaintext)
    }

    /// Decrypt like [`PrivateIdentity::decrypt`] and report which ratchet
    /// worked.
    ///
    /// The ratchet id is the truncated hash of that ratchet's public key
    /// (Python `Identity._get_ratchet_id`). It is `None` when the static
    /// identity key was used. When `enforce_ratchets` is set, a token that
    /// no supplied ratchet can open is rejected instead of falling through
    /// to the static key (Python `enforce_ratchets=True`).
    pub fn decrypt_ratchet<'a>(
        &self,
        data: &[u8],
        ratchets: &[[u8; RATCHET_KEY_LENGTH]],
        enforce_ratchets: bool,
        out_buf: &'a mut [u8],
    ) -> Result<(&'a [u8], Option<[u8; RATCHET_ID_LENGTH]>), RnsError> {
        if data.len() <= RATCHET_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

        let mut peer_bytes = [0u8; RATCHET_KEY_LENGTH];
        peer_bytes.copy_from_slice(&data[..RATCHET_KEY_LENGTH]);
        let peer_public_key = PublicKey::from(peer_bytes);
        let ciphertext = &data[RATCHET_KEY_LENGTH..];

        for ratchet in ratchets {
            let ratchet_key = StaticSecret::from(*ratchet);
            let shared_key = ratchet_key.diffie_hellman(&peer_public_key);
            let derived_key =
                DerivedKey::new(&shared_key, Some(self.identity.address_hash.as_slice()));

            let len = self
                .decrypt_token(&derived_key, ciphertext, &mut *out_buf)
                .map(|plain| plain.len())
                .ok();
            if let Some(len) = len {
                let public = ratchet_public_from_private(ratchet);
                let id_hash = ratchet_id(&public);
                let mut id = [0u8; RATCHET_ID_LENGTH];
                id.copy_from_slice(&id_hash.as_slice()[..RATCHET_ID_LENGTH]);
                return Ok((&out_buf[..len], Some(id)));
            }
        }

        if enforce_ratchets {
            return Err(RnsError::CryptoError);
        }

        let shared_key = self.private_key.diffie_hellman(&peer_public_key);
        let derived_key = DerivedKey::new(&shared_key, Some(self.identity.address_hash.as_slice()));
        let len = self
            .decrypt_token(&derived_key, ciphertext, &mut *out_buf)?
            .len();
        Ok((&out_buf[..len], None))
    }

    fn decrypt_token<'a>(
        &self,
        derived_key: &DerivedKey,
        data: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let fernet = Fernet::<crate::crypt::fernet::ZeroRng>::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            crate::crypt::fernet::ZeroRng,
        );

        let token = fernet.verify(Token::from(data))?;
        let plain_text = fernet.decrypt(token, out_buf)?;

        Ok(plain_text.as_slice())
    }
}

impl HashIdentity for PrivateIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.identity.address_hash.as_slice()
    }
}

impl EncryptIdentity for PrivateIdentity {
    fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let mut out_offset = 0;

        let token = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        )
        .encrypt(PlainText::from(text), &mut out_buf[out_offset..])?;

        out_offset += token.len();

        Ok(&out_buf[..out_offset])
    }
}

impl DecryptIdentity for PrivateIdentity {
    fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        derived_key: &DerivedKey,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        if data.len() <= PUBLIC_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

        let fernet = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        );

        let token = Token::from(data);

        let token = fernet.verify(token)?;

        let plain_text = fernet.decrypt(token, out_buf)?;

        Ok(plain_text.as_slice())
    }
}

pub struct GroupIdentity {
    /// Used to derive destination address
    identity: Identity,
    /// Shared symmetric encryption key
    key: GroupKey,
}

impl GroupIdentity {
    pub fn new(identity: Identity, key: GroupKey) -> Self {
        Self { identity, key }
    }

    pub fn as_identity(&self) -> &Identity {
        &self.identity
    }

    pub fn key(&self) -> &GroupKey {
        &self.key
    }
}

impl HashIdentity for GroupIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.identity.address_hash.as_slice()
    }
}

pub struct DerivedKey {
    key: [u8; DERIVED_KEY_LENGTH],
}

impl DerivedKey {
    pub fn new(shared_key: &SharedSecret, salt: Option<&[u8]>) -> Self {
        let mut key = [0u8; DERIVED_KEY_LENGTH];

        let _ = Hkdf::<Sha256>::new(salt, shared_key.as_bytes()).expand(&[], &mut key[..]);

        Self { key }
    }

    pub fn new_empty() -> Self {
        Self {
            key: [0u8; DERIVED_KEY_LENGTH],
        }
    }

    pub fn new_from_private_key(
        priv_key: &StaticSecret,
        pub_key: &PublicKey,
        salt: Option<&[u8]>,
    ) -> Self {
        Self::new(&priv_key.diffie_hellman(pub_key), salt)
    }

    pub fn new_from_ephemeral_key<R: CryptoRngCore + Copy>(
        rng: R,
        pub_key: &PublicKey,
        salt: Option<&[u8]>,
    ) -> Self {
        let secret = EphemeralSecret::random_from_rng(rng);
        let shared_key = secret.diffie_hellman(pub_key);
        Self::new(&shared_key, salt)
    }

    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_LENGTH] {
        &self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
    }
}

//***************************************************************************/
// Ratchets (Python `Identity._generate_ratchet`, `_remember_ratchet`,
// `get_ratchet`, `current_ratchet_id`, `_get_ratchet_id`, `_clean_ratchets`)
//***************************************************************************/
/// Python `Identity._ratchet_public_bytes`: derive the public ratchet key
/// from a private ratchet key.
pub fn ratchet_public_from_private(
    private_key: &[u8; RATCHET_KEY_LENGTH],
) -> [u8; RATCHET_KEY_LENGTH] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

/// Python `Identity._get_ratchet_id`: SHA-256 of the ratchet public key,
/// truncated to `NAME_HASH_LENGTH // 8` (10) bytes.
pub fn ratchet_id(ratchet_public: &[u8; RATCHET_KEY_LENGTH]) -> Hash {
    let hash = Hash::new_from_slice(ratchet_public);
    let mut id = [0u8; HASH_SIZE];
    id[..RATCHET_ID_LENGTH].copy_from_slice(&hash.as_slice()[..RATCHET_ID_LENGTH]);
    Hash::new(id)
}

/// Generate a new private ratchet key (Python `Identity._generate_ratchet`).
pub fn generate_ratchet<R: CryptoRngCore + Copy>(rng: R) -> [u8; RATCHET_KEY_LENGTH] {
    StaticSecret::random_from_rng(rng).to_bytes()
}

/// Python `RNS.Cryptography.Token` overhead for reference: the ciphertext of
/// `Identity.encrypt` is `ephemeral_pub || fernet_token`.
pub const SINGLE_TOKEN_PUB_OVERHEAD: usize = RATCHET_KEY_LENGTH;

//***************************************************************************/
// Known-destination persistence (pure serialisation of Python
// `Identity.known_destinations` / `Identity._remember_ratchet` storage files;
// file access lives in the `reticulum` crate).
//***************************************************************************/
/// The `uses` field of a known-destination entry (Python list index 4).
/// `0` means never used, `-1` means data retained for the destination and
/// any other value is the unix timestamp of the last use.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DestinationUses {
    Never,
    Retained,
    LastUsed(f64),
}

impl DestinationUses {
    /// Seconds since the destination data was last used (`None` if never
    /// used or retained).
    pub fn unused_for(&self, now: f64) -> Option<f64> {
        match self {
            DestinationUses::LastUsed(last_use) => Some(now - *last_use),
            _ => None,
        }
    }

    pub fn is_retained(&self) -> bool {
        matches!(self, DestinationUses::Retained)
    }

    pub fn was_used(&self) -> bool {
        matches!(self, DestinationUses::LastUsed(_))
    }
}

/// One entry of Python `Identity.known_destinations`:
/// `[time, packet_hash, public_key, app_data, uses]`.
#[derive(Clone, Debug, PartialEq)]
pub struct KnownDestinationData {
    /// Unix timestamp of the last announce.
    pub time: f64,
    /// Full hash of the announce packet.
    pub packet_hash: [u8; HASH_SIZE],
    /// `x25519 public key || ed25519 public key` (64 bytes).
    pub public_key: [u8; PUBLIC_KEY_LENGTH * 2],
    /// Announce app data (`None` when the announce carried none).
    pub app_data: Option<Vec<u8>>,
    pub uses: DestinationUses,
}

/// Recall a known destination (Python `Identity.recall`).
///
/// `target_hash` is a destination hash unless `from_identity_hash` is set,
/// in which case it is an identity hash (truncated SHA-256 of the raw
/// `x25519 || ed25519` public key, the same value as
/// [`Identity::address_hash`]) and the first matching entry in iteration
/// order is returned.
pub fn recall<'a>(
    entries: &'a [(AddressHash, KnownDestinationData)],
    target_hash: &AddressHash,
    from_identity_hash: bool,
) -> Option<(&'a AddressHash, &'a KnownDestinationData)> {
    if from_identity_hash {
        return entries.iter().find_map(|(destination_hash, entry)| {
            (AddressHash::new_from_slice(&entry.public_key) == *target_hash)
                .then_some((destination_hash, entry))
        });
    }

    entries
        .iter()
        .find_map(|(hash, entry)| (hash == target_hash).then_some((hash, entry)))
}

/// Pack a known-destinations map exactly like Python
/// `Identity.save_known_destinations` (`umsgpack.dump`): a msgpack map of
/// `destination hash -> [time, packet_hash, public_key, app_data, uses]`
/// in insertion order.
pub fn pack_known_destinations(
    entries: &[(AddressHash, KnownDestinationData)],
) -> Result<Vec<u8>, RnsError> {
    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, entries.len() as u32)
        .map_err(|_| RnsError::OutOfMemory)?;

    for (hash, entry) in entries {
        rmp::encode::write_bin(&mut out, hash.as_slice()).map_err(|_| RnsError::OutOfMemory)?;
        rmp::encode::write_array_len(&mut out, 5).map_err(|_| RnsError::OutOfMemory)?;
        rmp::encode::write_f64(&mut out, entry.time).map_err(|_| RnsError::OutOfMemory)?;
        rmp::encode::write_bin(&mut out, &entry.packet_hash).map_err(|_| RnsError::OutOfMemory)?;
        rmp::encode::write_bin(&mut out, &entry.public_key).map_err(|_| RnsError::OutOfMemory)?;
        match &entry.app_data {
            Some(data) => {
                rmp::encode::write_bin(&mut out, data).map_err(|_| RnsError::OutOfMemory)?
            }
            None => rmp::encode::write_nil(&mut out).map_err(|_| RnsError::OutOfMemory)?,
        }

        match entry.uses {
            // Python `umsgpack` packs 0 and -1 as fixint markers.
            DestinationUses::Never => {
                let _ = rmp::encode::write_sint(&mut out, 0).map_err(|_| RnsError::OutOfMemory)?;
            }
            DestinationUses::Retained => {
                let _ = rmp::encode::write_sint(&mut out, -1).map_err(|_| RnsError::OutOfMemory)?;
            }
            DestinationUses::LastUsed(time) => {
                rmp::encode::write_f64(&mut out, time).map_err(|_| RnsError::OutOfMemory)?;
            }
        }
    }

    Ok(out)
}

/// Unpack a known-destinations file written by Python
/// (`Identity.load_known_destinations`).
pub fn unpack_known_destinations(
    bytes: &[u8],
) -> Result<Vec<(AddressHash, KnownDestinationData)>, RnsError> {
    let mut reader = MsgReader::new(bytes);
    let len = reader.read_map_len()?;

    let mut entries = Vec::new();
    for _ in 0..len {
        let hash_bytes = reader.read_bin()?;
        if hash_bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
            return Err(RnsError::IncorrectHash);
        }
        let mut hash = AddressHash::new_empty();
        hash.as_mut_slice().copy_from_slice(hash_bytes);

        let array_len = reader.read_array_len()?;
        if array_len < 4 {
            return Err(RnsError::PacketError);
        }

        let time = reader.read_f64()?;
        let packet_hash = reader.read_fixed_bin::<HASH_SIZE>()?;
        let public_key = reader.read_fixed_bin::<{ PUBLIC_KEY_LENGTH * 2 }>()?;
        let app_data = reader.read_opt_bin()?;
        // Python `load_known_destinations` backfills a missing `uses`
        // entry with 0 (= never used).
        let uses = if array_len >= 5 {
            reader.read_uses()?
        } else {
            DestinationUses::Never
        };

        entries.push((
            hash,
            KnownDestinationData {
                time,
                packet_hash,
                public_key,
                app_data,
                uses,
            },
        ));
    }

    reader.expect_end()?;

    Ok(entries)
}

/// Python `Identity._remember_ratchet` file layout: msgpack map
/// `{"ratchet": <32 bytes public key>, "received": <unix time f64>}`.
#[derive(Clone, Debug, PartialEq)]
pub struct RatchetFileData {
    pub ratchet: [u8; RATCHET_KEY_LENGTH],
    pub received: f64,
}

pub fn pack_ratchet(data: &RatchetFileData) -> Result<Vec<u8>, RnsError> {
    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, 2).map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_str(&mut out, "ratchet").map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_bin(&mut out, &data.ratchet).map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_str(&mut out, "received").map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_f64(&mut out, data.received).map_err(|_| RnsError::OutOfMemory)?;
    Ok(out)
}

pub fn unpack_ratchet(bytes: &[u8]) -> Result<RatchetFileData, RnsError> {
    let mut reader = MsgReader::new(bytes);
    let len = reader.read_map_len()?;
    if len < 2 {
        return Err(RnsError::PacketError);
    }

    let mut data = RatchetFileData {
        ratchet: [0u8; RATCHET_KEY_LENGTH],
        received: 0.0,
    };

    for _ in 0..len {
        let key = reader.read_key()?;
        match key.as_slice() {
            b"ratchet" => data.ratchet = reader.read_fixed_bin::<RATCHET_KEY_LENGTH>()?,
            b"received" => data.received = reader.read_f64()?,
            _ => reader.skip_value()?,
        }
    }

    reader.expect_end()?;

    Ok(data)
}

/// Python `Destination._persist_ratchets`: the value of the `"ratchets"` map
/// entry is the packed msgpack list of private ratchet keys.
pub fn pack_ratchet_list(keys: &[[u8; RATCHET_KEY_LENGTH]]) -> Result<Vec<u8>, RnsError> {
    let mut out = Vec::new();
    rmp::encode::write_array_len(&mut out, keys.len() as u32).map_err(|_| RnsError::OutOfMemory)?;
    for key in keys {
        rmp::encode::write_bin(&mut out, key).map_err(|_| RnsError::OutOfMemory)?;
    }
    Ok(out)
}

pub fn unpack_ratchet_list(bytes: &[u8]) -> Result<Vec<[u8; RATCHET_KEY_LENGTH]>, RnsError> {
    let mut reader = MsgReader::new(bytes);
    let len = reader.read_array_len()?;
    let mut keys = Vec::new();
    for _ in 0..len {
        keys.push(reader.read_fixed_bin::<RATCHET_KEY_LENGTH>()?);
    }
    reader.expect_end()?;
    Ok(keys)
}

/// Python `Destination._persist_ratchets` file layout: msgpack map
/// `{"signature": <64 bytes>, "ratchets": <packed ratchet list>}`.
pub fn pack_destination_ratchets(
    keys: &[[u8; RATCHET_KEY_LENGTH]],
    signature: &Signature,
) -> Result<Vec<u8>, RnsError> {
    let packed_ratchets = pack_ratchet_list(keys)?;

    let mut out = Vec::new();
    rmp::encode::write_map_len(&mut out, 2).map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_str(&mut out, "signature").map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_bin(&mut out, &signature.to_bytes()).map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_str(&mut out, "ratchets").map_err(|_| RnsError::OutOfMemory)?;
    rmp::encode::write_bin(&mut out, &packed_ratchets).map_err(|_| RnsError::OutOfMemory)?;

    Ok(out)
}

pub fn unpack_destination_ratchets(
    bytes: &[u8],
) -> Result<(Vec<[u8; RATCHET_KEY_LENGTH]>, Signature), RnsError> {
    let mut reader = MsgReader::new(bytes);
    let len = reader.read_map_len()?;
    if len < 2 {
        return Err(RnsError::PacketError);
    }

    let mut signature = None;
    let mut ratchets = None;

    for _ in 0..len {
        let key = reader.read_key()?;
        match key.as_slice() {
            b"signature" => {
                let bytes = reader.read_fixed_bin::<SIGNATURE_LENGTH>()?;
                signature = Some(Signature::from_bytes(&bytes));
            }
            b"ratchets" => {
                let packed = reader.read_bin()?;
                ratchets = Some(unpack_ratchet_list(packed)?);
            }
            _ => reader.skip_value()?,
        }
    }

    reader.expect_end()?;

    match (ratchets, signature) {
        (Some(ratchets), Some(signature)) => Ok((ratchets, signature)),
        _ => Err(RnsError::PacketError),
    }
}

//***************************************************************************/
// Minimal msgpack reader matching Python `umsgpack` output shapes.
//***************************************************************************/
struct MsgReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MsgReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, RnsError> {
        let byte = *self.data.get(self.pos).ok_or(RnsError::PacketError)?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RnsError> {
        if self.pos + len > self.data.len() {
            return Err(RnsError::PacketError);
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, RnsError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, RnsError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, RnsError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_map_len(&mut self) -> Result<u32, RnsError> {
        let marker = self.byte()?;
        match marker {
            0x80..=0x8f => Ok((marker & 0x0f) as u32),
            0xde => Ok(self.read_u16()? as u32),
            0xdf => Ok(self.read_u32()?),
            _ => Err(RnsError::PacketError),
        }
    }

    fn read_array_len(&mut self) -> Result<u32, RnsError> {
        let marker = self.byte()?;
        match marker {
            0x90..=0x9f => Ok((marker & 0x0f) as u32),
            0xdc => Ok(self.read_u16()? as u32),
            0xdd => self.read_u32(),
            _ => Err(RnsError::PacketError),
        }
    }

    fn read_bin_len(&mut self) -> Result<usize, RnsError> {
        let marker = self.byte()?;
        match marker {
            0xc4 => Ok(self.byte()? as usize),
            0xc5 => Ok(self.read_u16()? as usize),
            0xc6 => Ok(self.read_u32()? as usize),
            // Old-spec "raw" strings are accepted as binary data, since the
            // key material is byte-identical.
            0xa0..=0xbf => Ok((marker & 0x1f) as usize),
            0xd9 => Ok(self.byte()? as usize),
            0xda => Ok(self.read_u16()? as usize),
            0xdb => Ok(self.read_u32()? as usize),
            _ => Err(RnsError::PacketError),
        }
    }

    fn read_bin(&mut self) -> Result<&'a [u8], RnsError> {
        let len = self.read_bin_len()?;
        self.take(len)
    }

    fn read_fixed_bin<const N: usize>(&mut self) -> Result<[u8; N], RnsError> {
        let len = self.read_bin_len()?;
        if len != N {
            // Corrupt or truncated persistence files must fail cleanly,
            // not panic.
            return Err(RnsError::PacketError);
        }
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn read_opt_bin(&mut self) -> Result<Option<Vec<u8>>, RnsError> {
        let marker = *self.data.get(self.pos).ok_or(RnsError::PacketError)?;
        if marker == 0xc0 {
            self.pos += 1;
            return Ok(None);
        }

        Ok(Some(self.read_bin()?.to_vec()))
    }

    fn read_key(&mut self) -> Result<Vec<u8>, RnsError> {
        self.read_bin().map(|slice| slice.to_vec())
    }

    fn read_f64(&mut self) -> Result<f64, RnsError> {
        let marker = self.byte()?;
        match marker {
            0xcb => Ok(f64::from_bits(self.read_u64()?)),
            0xca => {
                let bits = self.read_u32()?;
                Ok(f64::from(f32::from_bits(bits)))
            }
            _ => {
                self.pos -= 1;
                let value = self.read_number()?;
                match value {
                    Num::F64(value) => Ok(value),
                    Num::Int(value) => Ok(value as f64),
                }
            }
        }
    }

    fn read_number(&mut self) -> Result<Num, RnsError> {
        let marker = self.byte()?;
        match marker {
            0x00..=0x7f => Ok(Num::Int(marker as i64)),
            0xe0..=0xff => Ok(Num::Int(marker as i8 as i64)),
            0xcc => Ok(Num::Int(self.byte()? as i64)),
            0xcd => Ok(Num::Int(self.read_u16()? as i64)),
            0xce => Ok(Num::Int(self.read_u32()? as i64)),
            0xcf => Ok(Num::Int(self.read_u64()? as i64)),
            0xd0 => {
                let byte = self.byte()?;
                Ok(Num::Int(byte as i8 as i64))
            }
            0xd1 => {
                let bytes = self.take(2)?;
                Ok(Num::Int(i16::from_be_bytes([bytes[0], bytes[1]]) as i64))
            }
            0xd2 => {
                let bytes = self.take(4)?;
                Ok(Num::Int(
                    i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64,
                ))
            }
            0xd3 => {
                let bytes = self.take(8)?;
                Ok(Num::Int(i64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])))
            }
            0xcb => {
                self.pos -= 1;
                Ok(Num::F64(self.read_f64()?))
            }
            _ => Err(RnsError::PacketError),
        }
    }

    fn read_uses(&mut self) -> Result<DestinationUses, RnsError> {
        match self.read_number()? {
            Num::Int(0) => Ok(DestinationUses::Never),
            Num::Int(-1) => Ok(DestinationUses::Retained),
            Num::Int(value) => Ok(DestinationUses::LastUsed(value as f64)),
            Num::F64(value) => Ok(DestinationUses::LastUsed(value)),
        }
    }

    fn skip_value(&mut self) -> Result<(), RnsError> {
        let marker = self.byte()?;

        match marker {
            0xc0 | 0xc2 | 0xc3 => Ok(()),
            0x00..=0x7f | 0xe0..=0xff => Ok(()),
            0xcc | 0xd0 => self.take(1).map(|_| ()),
            0xcd | 0xd1 => self.take(2).map(|_| ()),
            0xce | 0xd2 | 0xca => self.take(4).map(|_| ()),
            0xcf | 0xd3 | 0xcb => self.take(8).map(|_| ()),
            0xa0..=0xbf => {
                let len = (marker & 0x1f) as usize;
                self.take(len).map(|_| ())
            }
            0xd9 => {
                let len = self.byte()? as usize;
                self.take(len).map(|_| ())
            }
            0xda => {
                let len = self.read_u16()? as usize;
                self.take(len).map(|_| ())
            }
            0xdb => {
                let len = self.read_u32()? as usize;
                self.take(len).map(|_| ())
            }
            0xc4 => {
                let len = self.byte()? as usize;
                self.take(len).map(|_| ())
            }
            0xc5 => {
                let len = self.read_u16()? as usize;
                self.take(len).map(|_| ())
            }
            0xc6 => {
                let len = self.read_u32()? as usize;
                self.take(len).map(|_| ())
            }
            0x90..=0x9f => {
                let len = (marker & 0x0f) as u32;
                self.skip_n_values(len)
            }
            0xdc => {
                let len = self.read_u16()? as u32;
                self.skip_n_values(len)
            }
            0xdd => {
                let len = self.read_u32()?;
                self.skip_n_values(len)
            }
            0x80..=0x8f => {
                let len = (marker & 0x0f) as u32;
                self.skip_n_values(len * 2)
            }
            0xde => {
                let len = self.read_u16()? as u32;
                self.skip_n_values(len * 2)
            }
            0xdf => {
                let len = self.read_u32()?;
                self.skip_n_values(len * 2)
            }
            _ => Err(RnsError::PacketError),
        }
    }

    fn skip_n_values(&mut self, count: u32) -> Result<(), RnsError> {
        for _ in 0..count {
            self.skip_value()?;
        }
        Ok(())
    }

    fn expect_end(&mut self) -> Result<(), RnsError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(RnsError::PacketError)
        }
    }
}

enum Num {
    Int(i64),
    F64(f64),
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use rand_core::OsRng;

    use super::PrivateIdentity;

    #[test]
    #[cfg(feature = "std")]
    fn private_identity_hex_string() {
        let original_id = PrivateIdentity::new_from_rand(OsRng);
        let original_hex = original_id.to_hex_string();

        let actual_id =
            PrivateIdentity::new_from_hex_string(&original_hex).expect("valid identity");

        assert_eq!(
            actual_id.private_key.as_bytes(),
            original_id.private_key.as_bytes()
        );

        assert_eq!(
            actual_id.sign_key.as_bytes(),
            original_id.sign_key.as_bytes()
        );
    }

    #[test]
    fn recall_from_identity_hash_matches_public_key() {
        use crate::hash::{AddressHash, HASH_SIZE};

        use super::{DestinationUses, KnownDestinationData, recall};

        let identity = PrivateIdentity::new_from_name("recall-by-identity");
        let other = PrivateIdentity::new_from_name("recall-other");
        let destination_hash = AddressHash::new_from_slice(b"destination-not-identity");
        let entries = [(
            destination_hash,
            KnownDestinationData {
                time: 1.0,
                packet_hash: [7u8; HASH_SIZE],
                public_key: identity.as_identity().to_bytes(),
                app_data: Some(alloc::vec![1, 2, 3]),
                uses: DestinationUses::Never,
            },
        )];

        let (found_hash, found) =
            recall(&entries, identity.address_hash(), true).expect("identity hash");
        assert_eq!(found_hash, &destination_hash);
        assert_eq!(found.public_key, identity.as_identity().to_bytes());

        assert!(recall(&entries, other.address_hash(), true).is_none());
        assert!(recall(&entries, identity.address_hash(), false).is_none());
        assert!(recall(&entries, &destination_hash, false).is_some());
    }

    #[test]
    #[cfg(feature = "std")]
    fn enforced_ratchets_reject_static_key_and_report_id() {
        use super::{RATCHET_ID_LENGTH, generate_ratchet, ratchet_id, ratchet_public_from_private};

        let identity = PrivateIdentity::new_from_name("ratchet-enforce");
        let public = *identity.as_identity();
        let ratchet = generate_ratchet(rand_core::OsRng);
        let ratchet_public = ratchet_public_from_private(&ratchet);
        let expected_id = {
            let hash = ratchet_id(&ratchet_public);
            let mut id = [0u8; RATCHET_ID_LENGTH];
            id.copy_from_slice(&hash.as_slice()[..RATCHET_ID_LENGTH]);
            id
        };

        let plaintext = b"ratchet or static";
        let mut token_buf = [0u8; 512];
        let static_token = public
            .encrypt(rand_core::OsRng, plaintext, None, &mut token_buf)
            .expect("static encrypt")
            .to_vec();

        let mut ratchet_buf = [0u8; 512];
        let ratchet_token = public
            .encrypt(
                rand_core::OsRng,
                plaintext,
                Some(&super::PublicKey::from(ratchet_public)),
                &mut ratchet_buf,
            )
            .expect("ratchet encrypt")
            .to_vec();

        let mut out = [0u8; 512];
        let (plain, id) = identity
            .decrypt_ratchet(&static_token, &[], false, &mut out)
            .expect("static key");
        assert_eq!(plain, plaintext);
        assert!(id.is_none());

        let (plain, id) = identity
            .decrypt_ratchet(&ratchet_token, &[ratchet], false, &mut out)
            .expect("ratchet key");
        assert_eq!(plain, plaintext);
        assert_eq!(id, Some(expected_id));

        assert!(
            identity
                .decrypt_ratchet(&static_token, &[ratchet], true, &mut out)
                .is_err()
        );
        assert!(
            identity
                .decrypt_ratchet(&static_token, &[], true, &mut out)
                .is_err()
        );
    }
}
