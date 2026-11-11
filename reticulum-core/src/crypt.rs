use rand_core::CryptoRngCore;

use crate::error::RnsError;
use crate::identity::DERIVED_KEY_LENGTH;

pub mod fernet;

use self::fernet::{Fernet, PlainText, Token};

pub const GROUP_KEY_LENGTH: usize = DERIVED_KEY_LENGTH;

/// An HMAC signing key followed by an encryption key of the same length
#[derive(Clone)]
pub struct GroupKey {
    key: [u8; GROUP_KEY_LENGTH],
}

impl GroupKey {
    pub fn new_rand<R: CryptoRngCore>(mut rng: R) -> Self {
        let mut key = [0u8; GROUP_KEY_LENGTH];
        rng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn new_from_slice(key: &[u8]) -> Result<Self, RnsError> {
        let key: [u8; GROUP_KEY_LENGTH] = key.try_into().map_err(|_| RnsError::InvalidArgument)?;
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8; GROUP_KEY_LENGTH] {
        &self.key
    }

    pub fn encrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let token = self.fernet(rng).encrypt(PlainText::from(text), out_buf)?;
        Ok(token.as_bytes())
    }

    pub fn decrypt<'a, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        out_buf: &'a mut [u8],
    ) -> Result<&'a [u8], RnsError> {
        let fernet = self.fernet(rng);
        let token = fernet.verify(Token::from(data))?;
        let plain_text = fernet.decrypt(token, out_buf)?;
        Ok(plain_text.as_slice())
    }

    fn fernet<R: CryptoRngCore + Copy>(&self, rng: R) -> Fernet<R> {
        Fernet::new_from_slices(
            &self.key[..GROUP_KEY_LENGTH / 2],
            &self.key[GROUP_KEY_LENGTH / 2..],
            rng,
        )
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use rand_core::OsRng;

    use super::GroupKey;
    use crate::error::RnsError;

    #[test]
    fn group_key_encrypt_decrypt() {
        let key = GroupKey::new_rand(OsRng);
        let other_key = GroupKey::new_rand(OsRng);

        let mut token_buf = [0u8; 128];
        let token = key.encrypt(OsRng, b"group message", &mut token_buf).expect("token");

        let mut out_buf = [0u8; 128];
        assert_eq!(
            key.decrypt(OsRng, token, &mut out_buf).expect("plain text"),
            b"group message"
        );

        assert_eq!(
            other_key.decrypt(OsRng, token, &mut out_buf),
            Err(RnsError::IncorrectSignature)
        );
    }

    // Token encrypted by the Python reference implementation:
    // Token(bytes(range(64, 128))).encrypt(b"hello from python")
    #[cfg(not(feature = "fernet-aes128"))]
    #[test]
    fn group_key_decrypt_python_token() {
        let key: [u8; 64] = std::array::from_fn(|i| 64 + i as u8);
        let key = GroupKey::new_from_slice(&key).expect("group key");

        let token = "3fc69a2565ba07eb02a46b20bb8333240103dfcb42fc6745d9135d86c8f31a53\
                     5fc8520e043df4c532ad2b70bdaa9a6fbf601a865b805376cd2c1c24b06d507a\
                     db1341152b1d1f8f39145972fc1714ab";
        let token: Vec<u8> = (0..token.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&token[i..i + 2], 16).unwrap())
            .collect();

        let mut out_buf = [0u8; 128];
        assert_eq!(
            key.decrypt(OsRng, &token, &mut out_buf).expect("plain text"),
            b"hello from python"
        );
    }
}
