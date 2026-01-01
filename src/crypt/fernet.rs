use core::cmp;
use core::convert::From;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::BlockDecryptMut;
use aes::cipher::Key;
use aes::cipher::Unsigned;
use cbc::cipher::generic_array::GenericArray;
use cbc::cipher::BlockEncryptMut;
use cbc::cipher::KeyIvInit;
use crypto_common::{IvSizeUser, KeySizeUser, OutputSizeUser};
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::Sha256;

use crate::error::RnsError;

#[cfg(feature = "fernet-aes128")]
type AesAlgo = aes::Aes128;
#[cfg(not(feature = "fernet-aes128"))]
type AesAlgo = aes::Aes256;

type AesCbcEnc = cbc::Encryptor<AesAlgo>;
type AesCbcDec = cbc::Decryptor<AesAlgo>;
type AesKey = Key<AesAlgo>;

type HmacSha256 = Hmac<Sha256>;

const HMAC_OUT_SIZE: usize = <<HmacSha256 as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
const AES_KEY_SIZE: usize = <<AesAlgo as KeySizeUser>::KeySize as Unsigned>::USIZE;
const IV_KEY_SIZE: usize = <<AesCbcEnc as IvSizeUser>::IvSize as Unsigned>::USIZE;
// Token layout: IV (IV_KEY_SIZE bytes) || ciphertext || HMAC (HMAC_OUT_SIZE bytes)
const FERNET_OVERHEAD_SIZE: usize = IV_KEY_SIZE + HMAC_OUT_SIZE;
pub const FERNET_IV_LENGTH: usize = IV_KEY_SIZE;

pub struct PlainText<'a>(&'a [u8]);
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
    sign_key: [u8; AES_KEY_SIZE],
    enc_key: AesKey,
}

impl<'a> PlainText<'a> {
    pub fn as_slice(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> From<&'a str> for PlainText<'a> {
    fn from(item: &'a str) -> Self {
        Self { 0: item.as_bytes() }
    }
}

impl<'a> From<&'a [u8]> for PlainText<'a> {
    fn from(item: &'a [u8]) -> Self {
        Self { 0: item }
    }
}

impl<'a> Token<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> From<&'a [u8]> for Token<'a> {
    fn from(item: &'a [u8]) -> Self {
        Self { 0: item }
    }
}

impl<R: CryptoRngCore + Copy> Fernet<R> {
    pub fn new(sign_key: [u8; AES_KEY_SIZE], enc_key: AesKey, rng: R) -> Self {
        Self {
            rng,
            sign_key,
            enc_key,
        }
    }

    pub fn new_from_slices(sign_key: &[u8], enc_key: &[u8], rng: R) -> Self {
        let mut sign_key_bytes = [0u8; AES_KEY_SIZE];
        sign_key_bytes[..cmp::min(AES_KEY_SIZE, sign_key.len())].copy_from_slice(sign_key);

        let mut enc_key_bytes = [0u8; AES_KEY_SIZE];
        enc_key_bytes[..cmp::min(AES_KEY_SIZE, enc_key.len())].copy_from_slice(enc_key);

        Self {
            rng,
            sign_key: sign_key_bytes.into(),
            enc_key: enc_key_bytes.into(),
        }
    }

    pub fn new_rand(mut rng: R) -> Self {
        let mut sign_key = [0u8; AES_KEY_SIZE];
        rng.fill_bytes(&mut sign_key);
        let enc_key = AesCbcEnc::generate_key(&mut rng);

        Self {
            rng,
            sign_key,
            enc_key,
        }
    }

    pub fn encrypt<'a>(
        &self,
        text: PlainText,
        out_buf: &'a mut [u8],
    ) -> Result<Token<'a>, RnsError> {
        if out_buf.len() <= FERNET_OVERHEAD_SIZE {
            return Err(RnsError::InvalidArgument);
        }

        let mut out_len = 0;

        // Generate IV (deterministic hooks override randomness when set)
        let iv = if let Some(bytes) = crate::utils::deterministic::take_next_fernet_iv() {
            GenericArray::from(bytes)
        } else {
            AesCbcEnc::generate_iv(self.rng)
        };
        out_buf[..iv.len()].copy_from_slice(iv.as_slice());

        out_len += iv.len();

        let chiper_len = AesCbcEnc::new(&self.enc_key, &iv)
            .encrypt_padded_b2b_mut::<Pkcs7>(text.0, &mut out_buf[out_len..])
            .unwrap()
            .len();

        out_len += chiper_len;

        let mut hmac = <HmacSha256 as Mac>::new_from_slice(&self.sign_key)
            .map_err(|_| RnsError::InvalidArgument)?;

        hmac.update(&out_buf[..out_len]);

        let tag = hmac.finalize().into_bytes();

        out_buf[out_len..out_len + tag.len()].copy_from_slice(tag.as_slice());
        out_len += tag.len();

        Ok(Token {
            0: &out_buf[..out_len],
        })
    }

    pub fn verify<'a>(&self, token: Token<'a>) -> Result<VerifiedToken<'a>, RnsError> {
        let token_data = token.0;

        if token_data.len() <= FERNET_OVERHEAD_SIZE {
            return Err(RnsError::InvalidArgument);
        }

        let (data, expected_tag) = token_data.split_at(token_data.len() - HMAC_OUT_SIZE);

        let mut hmac = <HmacSha256 as Mac>::new_from_slice(&self.sign_key)
            .map_err(|_| RnsError::InvalidArgument)?;

        hmac.update(data);

        hmac.verify_slice(expected_tag)
            .map_err(|_| RnsError::IncorrectSignature)?;

        Ok(VerifiedToken { 0: token_data })
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

        let msg = AesCbcDec::new(&self.enc_key, &iv.into())
            .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, out_buf)
            .map_err(|_| RnsError::CryptoError)?;

        return Ok(PlainText { 0: msg });
    }
}

#[cfg(test)]
mod tests {
    use super::{Fernet, Token, IV_KEY_SIZE};
    use crate::error::RnsError;
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
    fn tamper_detection_fails_verification() {
        const BUF_SIZE: usize = 4096;
        let fernet = Fernet::new_rand(OsRng);
        let out_msg: &str = "#FERNET_TEST_MESSAGE#";

        let mut out_buf = [0u8; BUF_SIZE];
        let token = fernet
            .encrypt(out_msg.into(), &mut out_buf[..])
            .expect("cipher token");

        let tamper_indices = [0usize, IV_KEY_SIZE, token.len() - 1];

        for idx in tamper_indices {
            let mut tampered = token.as_bytes().to_vec();
            tampered[idx] ^= 0xFF;

            let verification = fernet.verify(Token::from(tampered.as_slice()));
            assert!(matches!(verification, Err(RnsError::IncorrectSignature)));
        }
    }
}
