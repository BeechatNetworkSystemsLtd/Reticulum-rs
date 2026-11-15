use core::cmp;
use core::convert::From;

use aes::cipher::BlockCipher;
use aes::cipher::BlockDecrypt;
use aes::cipher::BlockDecryptMut;
use aes::cipher::BlockEncrypt;
use aes::cipher::BlockEncryptMut;
use aes::cipher::Key;
use aes::cipher::KeyInit;
use aes::cipher::KeySizeUser;
use aes::cipher::Unsigned;
use cbc::cipher::KeyIvInit;
use cipher::block_padding::Pkcs7;
use crypto_common::IvSizeUser;
use crypto_common::OutputSizeUser;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::Sha256;

use crate::error::RnsError;

// `Fernet::new` / `new_rand` keep the historical compile-time size so
// existing call sites still type-check. Token construction from key bytes
// selects AES-128 or AES-256 at runtime (Python `Token.__init__`).
#[cfg(feature = "fernet-aes128")]
type AesAlgo = aes::Aes128;
#[cfg(not(feature = "fernet-aes128"))]
type AesAlgo = aes::Aes256;

type AesCbcEnc = cbc::Encryptor<AesAlgo>;
type AesKey = Key<AesAlgo>;

type HmacSha256 = Hmac<Sha256>;

const HMAC_OUT_SIZE: usize = <<HmacSha256 as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
const AES_KEY_SIZE: usize = <<AesAlgo as KeySizeUser>::KeySize as Unsigned>::USIZE;
const IV_KEY_SIZE: usize = 16;
const FERNET_OVERHEAD_SIZE: usize = IV_KEY_SIZE + HMAC_OUT_SIZE;
const AES128_KEY_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;

pub struct PlainText<'a>(pub &'a [u8]);
pub struct VerifiedToken<'a>(&'a [u8]);
pub struct Token<'a>(&'a [u8]);

// This class provides a slightly modified implementation of the Fernet spec
// found at: https://github.com/fernet/spec/blob/master/Spec.md
//
// According to the spec, a Fernet token includes a one byte VERSION and
// eight byte TIMESTAMP field at the start of each token. These fields are
// not relevant to Reticulum. They are therefore stripped from this
// implementation, since they incur overhead and leak initiator metadata.
pub struct Fernet<R: CryptoRngCore> {
    rng: R,
    cipher: TokenCipher,
}

enum TokenCipher {
    Aes128 {
        sign_key: [u8; AES128_KEY_SIZE],
        enc_key: Key<aes::Aes128>,
    },
    Aes256 {
        sign_key: [u8; AES256_KEY_SIZE],
        enc_key: Key<aes::Aes256>,
    },
}

impl<'a> PlainText<'a> {
    pub fn as_slice(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> From<&'a str> for PlainText<'a> {
    fn from(item: &'a str) -> Self {
        Self(item.as_bytes())
    }
}

impl<'a> From<&'a [u8]> for PlainText<'a> {
    fn from(item: &'a [u8]) -> Self {
        Self(item)
    }
}

impl<'a> Token<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }
}

impl<'a> From<&'a [u8]> for Token<'a> {
    fn from(item: &'a [u8]) -> Self {
        Self(item)
    }
}

impl<R: CryptoRngCore + Copy> Fernet<R> {
    pub fn new(sign_key: [u8; AES_KEY_SIZE], enc_key: AesKey, rng: R) -> Self {
        Self::new_from_slices(&sign_key, enc_key.as_slice(), rng)
    }

    /// Python `Token(key)`: a 32-byte key is AES-128, a 64-byte key is AES-256.
    pub fn new_from_key(key: &[u8], rng: R) -> Result<Self, RnsError> {
        match key.len() {
            32 => Ok(Self::new_from_slices(&key[..16], &key[16..], rng)),
            64 => Ok(Self::new_from_slices(&key[..32], &key[32..], rng)),
            _ => Err(RnsError::InvalidArgument),
        }
    }

    pub fn new_from_slices(sign_key: &[u8], enc_key: &[u8], rng: R) -> Self {
        // Python `Token` uses AES-128 when each half is 16 bytes and
        // AES-256 when each half is 32 bytes. Longer halves are truncated
        // the way the fixed-size constructor used to.
        let cipher = if sign_key.len() <= AES128_KEY_SIZE && enc_key.len() <= AES128_KEY_SIZE {
            let mut sign = [0u8; AES128_KEY_SIZE];
            let mut enc = [0u8; AES128_KEY_SIZE];
            sign[..sign_key.len()].copy_from_slice(sign_key);
            enc[..enc_key.len()].copy_from_slice(enc_key);
            TokenCipher::Aes128 {
                sign_key: sign,
                enc_key: enc.into(),
            }
        } else {
            let sign_len = cmp::min(AES256_KEY_SIZE, sign_key.len());
            let enc_len = cmp::min(AES256_KEY_SIZE, enc_key.len());
            let mut sign = [0u8; AES256_KEY_SIZE];
            let mut enc = [0u8; AES256_KEY_SIZE];
            sign[..sign_len].copy_from_slice(&sign_key[..sign_len]);
            enc[..enc_len].copy_from_slice(&enc_key[..enc_len]);
            TokenCipher::Aes256 {
                sign_key: sign,
                enc_key: enc.into(),
            }
        };

        Self { rng, cipher }
    }

    /// A no-op RNG for decrypt-only usage: the decrypt/verify paths never
    /// consume randomness (only IV generation does), so constructions used
    /// solely for decryption can avoid supplying real entropy.
    pub fn new_decrypt_only(sign_key: &[u8], enc_key: &[u8]) -> Fernet<ZeroRng> {
        Fernet::<ZeroRng>::new_from_slices(sign_key, enc_key, ZeroRng)
    }

    pub fn new_rand(mut rng: R) -> Self {
        let mut sign_key = [0u8; AES_KEY_SIZE];
        rng.fill_bytes(&mut sign_key);
        let enc_key = AesCbcEnc::generate_key(&mut rng);

        Self::new(sign_key, enc_key, rng)
    }

    pub fn encrypt<'a>(
        &self,
        text: PlainText,
        out_buf: &'a mut [u8],
    ) -> Result<Token<'a>, RnsError> {
        // Required size: IV + padded ciphertext + HMAC. Checking only
        // against the fixed overhead let Channel-sized payloads expand
        // past the buffer and panic in the padding/slicing.
        let padded_len = text.0.len().div_ceil(crate::packet::AES128_BLOCKSIZE)
            * crate::packet::AES128_BLOCKSIZE
            + IV_KEY_SIZE;
        let required = padded_len + HMAC_OUT_SIZE;
        if out_buf.len() < required {
            return Err(RnsError::InvalidArgument);
        }

        match &self.cipher {
            TokenCipher::Aes128 { sign_key, enc_key } => {
                encrypt::<aes::Aes128>(enc_key, sign_key, self.rng, text.0, out_buf)
            }
            TokenCipher::Aes256 { sign_key, enc_key } => {
                encrypt::<aes::Aes256>(enc_key, sign_key, self.rng, text.0, out_buf)
            }
        }
    }

    pub fn verify<'a>(&self, token: Token<'a>) -> Result<VerifiedToken<'a>, RnsError> {
        let token_data = token.0;

        if token_data.len() <= FERNET_OVERHEAD_SIZE {
            return Err(RnsError::InvalidArgument);
        }

        let expected_tag = &token_data[token_data.len() - HMAC_OUT_SIZE..];
        let sign_key = match &self.cipher {
            TokenCipher::Aes128 { sign_key, .. } => sign_key.as_slice(),
            TokenCipher::Aes256 { sign_key, .. } => sign_key.as_slice(),
        };

        let mut hmac =
            <HmacSha256 as Mac>::new_from_slice(sign_key).map_err(|_| RnsError::InvalidArgument)?;

        hmac.update(&token_data[..token_data.len() - HMAC_OUT_SIZE]);

        let actual_tag = hmac.finalize().into_bytes();

        let valid = expected_tag
            .iter()
            .zip(actual_tag.as_slice())
            .map(|(x, y)| x.cmp(y))
            .find(|&ord| ord != cmp::Ordering::Equal)
            .unwrap_or(actual_tag.len().cmp(&expected_tag.len()))
            == cmp::Ordering::Equal;

        if valid {
            Ok(VerifiedToken(token_data))
        } else {
            Err(RnsError::IncorrectSignature)
        }
    }

    pub fn decrypt<'a, 'b>(
        &self,
        token: VerifiedToken<'a>,
        out_buf: &'b mut [u8],
    ) -> Result<PlainText<'b>, RnsError> {
        let token_data = token.0;

        if token_data.len() <= FERNET_OVERHEAD_SIZE {
            return Err(RnsError::InvalidArgument);
        }

        let tag_start_index = token_data.len() - HMAC_OUT_SIZE;

        let iv: [u8; IV_KEY_SIZE] = token_data[..IV_KEY_SIZE].try_into().unwrap();

        let ciphertext = &token_data[IV_KEY_SIZE..tag_start_index];

        let msg = match &self.cipher {
            TokenCipher::Aes128 { enc_key, .. } => {
                decrypt::<aes::Aes128>(enc_key, &iv, ciphertext, out_buf)?
            }
            TokenCipher::Aes256 { enc_key, .. } => {
                decrypt::<aes::Aes256>(enc_key, &iv, ciphertext, out_buf)?
            }
        };

        Ok(PlainText(msg))
    }
}

fn encrypt<'a, A>(
    enc_key: &Key<A>,
    sign_key: &[u8],
    rng: impl CryptoRngCore,
    text: &[u8],
    out_buf: &'a mut [u8],
) -> Result<Token<'a>, RnsError>
where
    A: BlockEncrypt + BlockCipher + KeyInit + KeySizeUser,
    cbc::Encryptor<A>: BlockEncryptMut + KeyIvInit + IvSizeUser,
{
    let iv = cbc::Encryptor::<A>::generate_iv(rng);
    let mut out_len = iv.len();
    out_buf[..out_len].copy_from_slice(iv.as_slice());

    let cipher_len = cbc::Encryptor::<A>::new_from_slices(enc_key, iv.as_slice())
        .map_err(|_| RnsError::InvalidArgument)?
        .encrypt_padded_b2b_mut::<Pkcs7>(text, &mut out_buf[out_len..])
        .map_err(|_| RnsError::InvalidArgument)?
        .len();
    out_len += cipher_len;

    let mut hmac =
        <HmacSha256 as Mac>::new_from_slice(sign_key).map_err(|_| RnsError::InvalidArgument)?;
    hmac.update(&out_buf[..out_len]);
    let tag = hmac.finalize().into_bytes();
    out_buf[out_len..out_len + tag.len()].copy_from_slice(tag.as_slice());
    out_len += tag.len();

    Ok(Token(&out_buf[..out_len]))
}

fn decrypt<'a, A>(
    enc_key: &Key<A>,
    iv: &[u8; IV_KEY_SIZE],
    ciphertext: &[u8],
    out_buf: &'a mut [u8],
) -> Result<&'a [u8], RnsError>
where
    A: BlockDecrypt + BlockCipher + KeyInit + KeySizeUser,
    cbc::Decryptor<A>: BlockDecryptMut + KeyIvInit,
{
    cbc::Decryptor::<A>::new_from_slices(enc_key, iv)
        .map_err(|_| RnsError::CryptoError)?
        .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, out_buf)
        .map_err(|_| RnsError::CryptoError)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::crypt::fernet::Fernet;
    use core::str;
    use rand_core::OsRng;

    #[test]
    fn encrypt_then_decrypt() {
        const BUF_SIZE: usize = 4096;

        let fernet = Fernet::new_rand(OsRng);

        let out_msg: &str = "#FERNET_TEST_MESSAGE#";

        let mut out_buf = [0u8; BUF_SIZE];

        let token = fernet
            .encrypt(out_msg.into(), &mut out_buf[..])
            .expect("cipher token");

        let token = fernet.verify(token).expect("verified token");

        let mut in_buf = [0u8; BUF_SIZE];
        let in_msg = str::from_utf8(fernet.decrypt(token, &mut in_buf).expect("decoded token").0)
            .expect("valid string");

        assert_eq!(in_msg, out_msg);
    }

    #[test]
    fn small_buffer() {
        let fernet = Fernet::new_rand(OsRng);

        let test_msg: &str = "#FERNET_TEST_MESSAGE#";

        let mut out_buf = [0u8; 12];
        assert!(fernet.encrypt(test_msg.into(), &mut out_buf[..]).is_err());
    }

    #[test]
    fn key_length_selects_cipher() {
        let message = b"token size selects the cipher";
        let mut key128 = [0u8; 32];
        let mut key256 = [0u8; 64];
        for (i, byte) in key128.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        for (i, byte) in key256.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(5).wrapping_add(9);
        }

        let aes128 = Fernet::new_from_key(&key128, OsRng).expect("aes-128 key");
        let aes256 = Fernet::new_from_key(&key256, OsRng).expect("aes-256 key");

        let mut buf128 = [0u8; 256];
        let mut buf256 = [0u8; 256];
        let raw128 = aes128
            .encrypt(message.as_slice().into(), &mut buf128)
            .expect("aes-128 token")
            .as_bytes()
            .to_vec();
        let raw256 = aes256
            .encrypt(message.as_slice().into(), &mut buf256)
            .expect("aes-256 token")
            .as_bytes()
            .to_vec();

        let mut out = [0u8; 256];
        let plain = aes128
            .decrypt(aes128.verify(raw128.as_slice().into()).unwrap(), &mut out)
            .expect("aes-128 decrypts its token");
        assert_eq!(plain.as_slice(), message);
        assert!(aes128.verify(raw256.as_slice().into()).is_err());

        let plain = aes256
            .decrypt(aes256.verify(raw256.as_slice().into()).unwrap(), &mut out)
            .expect("aes-256 decrypts its token");
        assert_eq!(plain.as_slice(), message);
        assert!(aes256.verify(raw128.as_slice().into()).is_err());

        assert!(hmac_matches(&key128[..16], &raw128));
        assert!(hmac_matches(&key256[..32], &raw256));
        // The 64-byte key's signing half is 32 bytes; the first 16 alone
        // must not verify it.
        assert!(!hmac_matches(&key256[..16], &raw256));

        // Ciphertext itself is AES-128 for a 32-byte key and AES-256 for a
        // 64-byte key, not the other mode with a zero-padded key.
        let mut padded = [0u8; 32];
        padded[..16].copy_from_slice(&key128[16..]);
        assert_eq!(
            aes128_plain(&key128[16..], &raw128).as_deref(),
            Some(message.as_slice())
        );
        assert!(aes256_plain(&padded, &raw128).is_none());
        assert_eq!(
            aes256_plain(&key256[32..], &raw256).as_deref(),
            Some(message.as_slice())
        );
        assert!(aes128_plain(&key256[32..48], &raw256).is_none());
    }

    fn hmac_matches(sign_key: &[u8], token: &[u8]) -> bool {
        use hmac::Mac;
        use sha2::Sha256;

        let mut hmac = hmac::Hmac::<Sha256>::new_from_slice(sign_key).unwrap();
        hmac.update(&token[..token.len() - 32]);
        hmac.verify_slice(&token[token.len() - 32..]).is_ok()
    }

    fn aes128_plain(enc_key: &[u8], token: &[u8]) -> Option<Vec<u8>> {
        use aes::cipher::BlockDecryptMut;
        use cbc::cipher::KeyIvInit;
        use cipher::block_padding::Pkcs7;

        let key: [u8; 16] = enc_key.try_into().ok()?;
        let iv: [u8; 16] = token[..16].try_into().ok()?;
        let ciphertext = &token[16..token.len() - 32];
        let mut out = vec![0u8; ciphertext.len()];
        cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut out)
            .ok()
            .map(|plain| plain.to_vec())
    }

    fn aes256_plain(enc_key: &[u8], token: &[u8]) -> Option<Vec<u8>> {
        use aes::cipher::BlockDecryptMut;
        use cbc::cipher::KeyIvInit;
        use cipher::block_padding::Pkcs7;

        let key: [u8; 32] = enc_key.try_into().ok()?;
        let iv: [u8; 16] = token[..16].try_into().ok()?;
        let ciphertext = &token[16..token.len() - 32];
        let mut out = vec![0u8; ciphertext.len()];
        cbc::Decryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut out)
            .ok()
            .map(|plain| plain.to_vec())
    }
}

/// Deterministic no-op RNG: fills with zeroes. Only valid where no
/// randomness is actually consumed (decrypt/verify paths).
#[derive(Clone, Copy, Default)]
pub struct ZeroRng;

impl rand_core::RngCore for ZeroRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for ZeroRng {}
