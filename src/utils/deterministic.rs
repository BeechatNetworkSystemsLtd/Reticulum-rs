use std::sync::{Mutex, OnceLock};

use crate::crypt::fernet::FERNET_IV_LENGTH;
use crate::identity::PUBLIC_KEY_LENGTH;

#[derive(Default)]
struct Hooks {
    ephemeral_secret: Option<[u8; PUBLIC_KEY_LENGTH]>,
    fernet_iv: Option<[u8; FERNET_IV_LENGTH]>,
}

fn hooks() -> &'static Mutex<Hooks> {
    static HOOKS: OnceLock<Mutex<Hooks>> = OnceLock::new();
    HOOKS.get_or_init(|| Mutex::new(Hooks::default()))
}

pub(crate) fn set_next_ephemeral_secret(secret: [u8; PUBLIC_KEY_LENGTH]) {
    hooks().lock().unwrap().ephemeral_secret = Some(secret);
}

pub(crate) fn take_next_ephemeral_secret() -> Option<[u8; PUBLIC_KEY_LENGTH]> {
    hooks().lock().unwrap().ephemeral_secret.take()
}

pub(crate) fn set_next_fernet_iv(iv: [u8; FERNET_IV_LENGTH]) {
    hooks().lock().unwrap().fernet_iv = Some(iv);
}

pub(crate) fn take_next_fernet_iv() -> Option<[u8; FERNET_IV_LENGTH]> {
    hooks().lock().unwrap().fernet_iv.take()
}

pub(crate) fn clear_hooks() {
    let mut guard = hooks().lock().unwrap();
    guard.ephemeral_secret = None;
    guard.fernet_iv = None;
}
