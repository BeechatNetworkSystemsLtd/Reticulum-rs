use alloc::fmt::Write;
use hkdf::Hkdf;
use rand_core::CryptoRngCore;

mod ratchet_store;
pub use ratchet_store::{global_ratchet_store, CachedRatchet, RatchetStore};

use ed25519_dalek::{ed25519::signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::{
    crypt::fernet::{Fernet, PlainText, Token},
    error::RnsError,
    hash::{AddressHash, Hash},
    utils::deterministic,
};

pub const PUBLIC_KEY_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

#[cfg(feature = "fernet-aes128")]
pub const DERIVED_KEY_LENGTH: usize = 256 / 8;

#[cfg(not(feature = "fernet-aes128"))]
pub const DERIVED_KEY_LENGTH: usize = 512 / 8;

pub const RATCHET_ID_LENGTH: usize = 10;

pub type RatchetId = [u8; RATCHET_ID_LENGTH];

pub fn ratchet_pub_from_priv(priv_key_bytes: &[u8]) -> Result<[u8; PUBLIC_KEY_LENGTH], RnsError> {
    if priv_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(RnsError::InvalidArgument);
    }

    let mut secret_bytes = [0u8; PUBLIC_KEY_LENGTH];
    secret_bytes.copy_from_slice(&priv_key_bytes[..PUBLIC_KEY_LENGTH]);
    let secret = StaticSecret::from(secret_bytes);

    Ok(ratchet_pub_from_secret(&secret))
}

pub fn ratchet_id_from_pub(pub_key_bytes: &[u8]) -> Result<RatchetId, RnsError> {
    if pub_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(RnsError::InvalidArgument);
    }

    let mut pub_bytes = [0u8; PUBLIC_KEY_LENGTH];
    pub_bytes.copy_from_slice(&pub_key_bytes[..PUBLIC_KEY_LENGTH]);
    Ok(ratchet_id_from_pub_bytes(&pub_bytes))
}

fn ratchet_pub_from_secret(secret: &StaticSecret) -> [u8; PUBLIC_KEY_LENGTH] {
    PublicKey::from(secret).to_bytes()
}

fn ratchet_id_from_pub_bytes(pub_bytes: &[u8; PUBLIC_KEY_LENGTH]) -> RatchetId {
    let digest = Sha256::new().chain_update(pub_bytes).finalize();
    let mut id = [0u8; RATCHET_ID_LENGTH];
    id.copy_from_slice(&digest[..RATCHET_ID_LENGTH]);
    id
}

pub fn ratchet_id_from_secret(secret: &StaticSecret) -> RatchetId {
    let pub_bytes = ratchet_pub_from_secret(secret);
    ratchet_id_from_pub_bytes(&pub_bytes)
}

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

#[derive(Copy, Clone)]
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
            key_data.copy_from_slice(&public_key);
            PublicKey::from(key_data)
        };

        let verifying_key = {
            let mut key_data = [0u8; PUBLIC_KEY_LENGTH];
            key_data.copy_from_slice(&verifying_key);
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

    pub fn derive_key<R: CryptoRngCore + Copy>(&self, rng: R) -> DerivedKey {
        DerivedKey::new_from_ephemeral_key(rng, &self.public_key, Some(self.address_hash.as_slice()))
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
        let ephemeral_public_bytes = derived_key
            .ephemeral_public()
            .ok_or(RnsError::InvalidArgument)?;

        if out_buf.len() >= ephemeral_public_bytes.len() {
            out_buf[..ephemeral_public_bytes.len()].copy_from_slice(ephemeral_public_bytes);
            out_offset += ephemeral_public_bytes.len();
        } else {
            return Err(RnsError::InvalidArgument);
        }

        let token = Fernet::new_from_slices(
            &derived_key.as_bytes()[..DERIVED_KEY_LENGTH / 2],
            &derived_key.as_bytes()[DERIVED_KEY_LENGTH / 2..],
            rng,
        )
        .encrypt(PlainText::from(text), &mut out_buf[out_offset..])?;

        out_offset += token.as_bytes().len();

        Ok(&out_buf[..out_offset])
    }
}

pub struct EmptyIdentity;

impl EmptyIdentity {
    pub fn new() -> Self {
        Self {}
    }
}

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
        result.copy_from_slice(&text);
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
        result.copy_from_slice(&data);
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

    pub fn decrypt_token<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        ciphertext_token: &[u8],
        salt: Option<&[u8]>,
        ratchets: &[StaticSecret],
        enforce_ratchets: bool,
        ratchet_id: &mut Option<RatchetId>,
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        *ratchet_id = None;

        if ciphertext_token.len() <= PUBLIC_KEY_LENGTH {
            return Err(RnsError::InvalidArgument);
        }

        let (peer_pub_bytes, ciphertext) = ciphertext_token.split_at(PUBLIC_KEY_LENGTH);

        let mut peer_pub_arr = [0u8; PUBLIC_KEY_LENGTH];
        peer_pub_arr.copy_from_slice(peer_pub_bytes);
        let peer_pub = PublicKey::from(peer_pub_arr);

        let default_salt = self.address_hash().as_slice();
        let ratchet_salt = salt.unwrap_or(default_salt);

        for ratchet in ratchets {
            let shared = ratchet.diffie_hellman(&peer_pub);
            let derived = DerivedKey::new(&shared, Some(ratchet_salt));
            match self.decrypt(rng, ciphertext, &derived, out_buf) {
                Ok(plain_text) => {
                    let len = plain_text.len();
                    *ratchet_id = Some(ratchet_id_from_secret(ratchet));
                    return Ok(&out_buf[..len]);
                }
                Err(RnsError::IncorrectSignature) | Err(RnsError::CryptoError) => {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }

        if enforce_ratchets {
            return Err(RnsError::CryptoError);
        }

        let derived = self.derive_key(&peer_pub, Some(default_salt));
        match self.decrypt(rng, ciphertext, &derived, out_buf) {
            Ok(plain_text) => {
                let len = plain_text.len();
                Ok(&out_buf[..len])
            }
            Err(err) => Err(err),
        }
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

        let token = Token::from(&data[..]);

        let token = fernet.verify(token)?;

        let plain_text = fernet.decrypt(token, out_buf)?;

        Ok(plain_text.as_slice())
    }
}

pub struct GroupIdentity {}

pub struct DerivedKey {
    key: [u8; DERIVED_KEY_LENGTH],
    ephemeral_public: Option<[u8; PUBLIC_KEY_LENGTH]>,
}

impl DerivedKey {
    pub fn new(shared_key: &SharedSecret, salt: Option<&[u8]>) -> Self {
        let mut key = [0u8; DERIVED_KEY_LENGTH];

        let _ = Hkdf::<Sha256>::new(salt, shared_key.as_bytes()).expand(&[], &mut key[..]);

        Self {
            key,
            ephemeral_public: None,
        }
    }

    pub fn new_empty() -> Self {
        Self {
            key: [0u8; DERIVED_KEY_LENGTH],
            ephemeral_public: None,
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
        let secret = deterministic::take_next_ephemeral_secret()
            .map(StaticSecret::from)
            .unwrap_or_else(|| StaticSecret::random_from_rng(rng));
        let ephemeral_public = PublicKey::from(&secret);
        let shared_key = secret.diffie_hellman(pub_key);
        let mut derived = Self::new(&shared_key, salt);
        derived.ephemeral_public = Some(*ephemeral_public.as_bytes());
        derived
    }

    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_LENGTH] {
        &self.key
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.key[..]
    }

    pub fn ephemeral_public(&self) -> Option<&[u8; PUBLIC_KEY_LENGTH]> {
        self.ephemeral_public.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{CryptoRng, OsRng, RngCore};
    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::error::RnsError;

    use super::{
        ratchet_id_from_pub, ratchet_pub_from_priv, DerivedKey, EncryptIdentity, PrivateIdentity,
        PUBLIC_KEY_LENGTH, RATCHET_ID_LENGTH,
    };

    #[test]
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
    fn identity_ephemeral_header_matches_derived_key() {
        let recipient = PrivateIdentity::new_from_name("python-compat");
        let identity = recipient.as_identity().clone();
        let derived = identity.derive_key(TestRng::new(0x0102030405060708));

        let mut out_buf = [0u8; 256];
        let cipher = identity
            .encrypt(TestRng::new(0x0f1e2d3c4b5a6978), b"header-test", &derived, &mut out_buf)
            .expect("ciphertext");

        let header = derived
            .ephemeral_public()
            .expect("ephemeral header present");

        assert_eq!(header.as_slice(), &cipher[..PUBLIC_KEY_LENGTH]);
    }

    #[test]
    fn identity_encryption_matches_reference_vector() {
        let recipient = PrivateIdentity::new_from_name("python-compat");
        let identity = recipient.as_identity().clone();
        let derived = identity.derive_key(TestRng::new(0x1122334455667788));

        let mut out_buf = [0u8; 256];
        let cipher = identity
            .encrypt(
                TestRng::new(0x8877665544332211),
                b"reticulum-python-compat",
                &derived,
                &mut out_buf,
            )
            .expect("ciphertext");

        assert_eq!(cipher, EXPECTED_CIPHERTEXT);
    }

    const EXPECTED_CIPHERTEXT: &[u8] = &[
        81, 172, 219, 20, 46, 94, 54, 160, 80, 146, 221, 64, 47, 55, 114, 184, 220, 241, 63, 41,
        253, 82, 16, 225, 124, 198, 110, 7, 108, 183, 92, 0, 140, 141, 197, 163, 30, 187, 20, 47,
        219, 97, 81, 254, 176, 6, 234, 188, 228, 209, 199, 36, 236, 175, 21, 97, 71, 5, 40, 156,
        157, 222, 133, 237, 135, 180, 172, 1, 165, 52, 76, 136, 255, 64, 25, 78, 66, 223, 156, 9,
        121, 200, 70, 141, 198, 128, 87, 75, 147, 161, 209, 205, 131, 181, 109, 41, 228, 161, 41,
        86, 44, 75, 95, 158, 43, 180, 113, 78, 129, 131, 76, 103,
    ];

    #[test]
    fn ratchet_helper_roundtrip() {
        let secret = StaticSecret::random_from_rng(TestRng::new(0x0102030405060708));
        let secret_bytes = secret.to_bytes();
        let pub_from_helper =
            ratchet_pub_from_priv(&secret_bytes[..]).expect("ratchet public from private");
        let expected_pub = PublicKey::from(&secret).to_bytes();
        assert_eq!(pub_from_helper, expected_pub);

        let ratchet_id = ratchet_id_from_pub(&expected_pub[..]).expect("ratchet id");
        let digest = Sha256::new().chain_update(expected_pub).finalize();
        assert_eq!(&ratchet_id[..], &digest[..RATCHET_ID_LENGTH]);
    }

    #[test]
    fn decrypt_token_prefers_ratchet_keys() {
        let recipient = PrivateIdentity::new_from_name("ratchet-pref");
        let ratchet_secret = StaticSecret::random_from_rng(TestRng::new(0x1122334455667788));
        let ratchet_public = PublicKey::from(&ratchet_secret);
        let ratchet_pub_bytes = ratchet_public.to_bytes();
        let expected_id = ratchet_id_from_pub(&ratchet_pub_bytes[..]).expect("ratchet id");

        let derived = DerivedKey::new_from_ephemeral_key(
            TestRng::new(0x0f1e2d3c4b5a6978),
            &ratchet_public,
            Some(recipient.address_hash().as_slice()),
        );

        let mut cipher_buf = [0u8; 512];
        let cipher = recipient
            .as_identity()
            .encrypt(
                TestRng::new(0x8877665544332211),
                b"ratchet-msg",
                &derived,
                &mut cipher_buf,
            )
            .expect("cipher");

        let mut plain_buf = [0u8; 512];
        let mut ratchet_id = None;
        let ratchets = vec![ratchet_secret];
        let plaintext = recipient
            .decrypt_token(
                TestRng::new(0x13579bdf2468ace0),
                cipher,
                None,
                ratchets.as_slice(),
                false,
                &mut ratchet_id,
                &mut plain_buf,
            )
            .expect("ratchet decrypt");

        assert_eq!(plaintext, b"ratchet-msg");
        assert_eq!(ratchet_id, Some(expected_id));
    }

    #[test]
    fn decrypt_token_enforces_ratchets() {
        let recipient = PrivateIdentity::new_from_name("ratchet-enforce");
        let derived = recipient
            .as_identity()
            .derive_key(TestRng::new(0x1122aabbccddeeff));

        let mut cipher_buf = [0u8; 256];
        let cipher = recipient
            .as_identity()
            .encrypt(
                TestRng::new(0xffeeddccbbaa2211),
                b"enforce",
                &derived,
                &mut cipher_buf,
            )
            .expect("cipher");

        let mut plain_buf = [0u8; 256];
        let mut ratchet_id = None;
        let result = recipient.decrypt_token(
            TestRng::new(0x0101010101010101),
            cipher,
            None,
            &[],
            true,
            &mut ratchet_id,
            &mut plain_buf,
        );

        assert!(matches!(result, Err(RnsError::CryptoError)));
        assert!(ratchet_id.is_none());
    }

    #[test]
    fn decrypt_token_falls_back_without_enforcement() {
        let recipient = PrivateIdentity::new_from_name("ratchet-fallback");
        let derived = recipient
            .as_identity()
            .derive_key(TestRng::new(0x99aabbccddeeff00));

        let mut cipher_buf = [0u8; 256];
        let cipher = recipient
            .as_identity()
            .encrypt(
                TestRng::new(0x0011223344556677),
                b"fallback",
                &derived,
                &mut cipher_buf,
            )
            .expect("cipher");

        let mut plain_buf = [0u8; 256];
        let mut ratchet_id = Some([0u8; RATCHET_ID_LENGTH]);
        let random_ratchet = StaticSecret::random_from_rng(TestRng::new(0xabcdef0123456789));
        let ratchets = vec![random_ratchet];
        let plaintext = recipient
            .decrypt_token(
                TestRng::new(0x89abcdef01234567),
                cipher,
                None,
                ratchets.as_slice(),
                false,
                &mut ratchet_id,
                &mut plain_buf,
            )
            .expect("fallback decrypt");

        assert_eq!(plaintext, b"fallback");
        assert!(ratchet_id.is_none());
    }

    #[derive(Clone, Copy)]
    struct TestRng {
        state: u128,
    }

    impl TestRng {
        const fn new(seed: u128) -> Self {
            Self { state: seed }
        }

        fn next_u64_inner(&mut self) -> u64 {
            const MUL: u128 = 6364136223846793005;
            const INC: u128 = 1442695040888963407;
            self.state = self.state.wrapping_mul(MUL).wrapping_add(INC);
            (self.state >> 64) as u64
        }
    }

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64_inner() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.next_u64_inner()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let value = self.next_u64_inner();
                let bytes = value.to_le_bytes();
                let len = chunk.len();
                chunk.copy_from_slice(&bytes[..len]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}
}
