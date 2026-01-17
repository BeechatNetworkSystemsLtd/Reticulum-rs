pub mod deterministic {
    use crate::crypt::fernet::FERNET_IV_LENGTH;
    use crate::identity::PUBLIC_KEY_LENGTH;

    /// Forces the next derived key to use the provided ephemeral secret bytes.
    /// Subsequent invocations fall back to RNG unless another secret is queued.
    pub fn set_next_ephemeral_secret(secret: [u8; PUBLIC_KEY_LENGTH]) {
        crate::utils::deterministic::set_next_ephemeral_secret(secret);
    }

    /// Forces the next Fernet encryption to use the provided IV bytes.
    pub fn set_next_fernet_iv(iv: [u8; FERNET_IV_LENGTH]) {
        crate::utils::deterministic::set_next_fernet_iv(iv);
    }

    /// Resets any queued deterministic hooks so future operations use RNG.
    pub fn clear() {
        crate::utils::deterministic::clear_hooks();
    }
}
