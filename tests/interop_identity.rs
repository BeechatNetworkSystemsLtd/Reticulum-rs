#![cfg(feature = "python-interop")]

use rand_core::OsRng;
use reticulum::identity::{DecryptIdentity, EncryptIdentity, Identity, PrivateIdentity, PUBLIC_KEY_LENGTH};

mod python_support;
use python_support::{python_available, run_python};

#[cfg(feature = "python-interop")]
#[test]
fn rust_encrypt_python_decrypt() {
    if !python_available() {
        eprintln!("python RNS not available; skipping interop test");
        return;
    }

    // You must provide these from your Rust Identity implementation:
    // pubkey: 64 bytes (x25519 pub + ed25519 pub)
    // privkey: 64 bytes (x25519 priv + ed25519 priv)
    let (pub_hex, priv_hex) = rust_test_identity_keys_hex();

    let plaintext = b"hello";
    let ciphertext = rust_encrypt_hex(plaintext, &pub_hex); // hex string

    let (code, pt_hex, err) = run_python(&["tests/python/decrypt.py", &priv_hex, &ciphertext]);
    assert_eq!(code, 0, "python decrypt failed: {err}");
    assert_eq!(hex::decode(pt_hex).unwrap(), plaintext);
}

#[cfg(feature = "python-interop")]
#[test]
fn python_encrypt_rust_decrypt() {
    if !python_available() {
        eprintln!("python RNS not available; skipping interop test");
        return;
    }

    let (pub_hex, priv_hex) = rust_test_identity_keys_hex();
    let plaintext = b"hello";

    let (code, ct_hex, err) =
        run_python(&["tests/python/encrypt.py", &pub_hex, &hex::encode(plaintext)]);
    assert_eq!(code, 0, "python encrypt failed: {err}");

    let decrypted = rust_decrypt_hex(&ct_hex, &priv_hex);
    assert_eq!(decrypted, plaintext);
}

fn rust_test_identity_keys_hex() -> (String, String) {
    let identity = PrivateIdentity::new_from_name("rust-python-interop");
    (
        identity.as_identity().to_hex_string(),
        identity.to_hex_string(),
    )
}

fn rust_encrypt_hex(pt: &[u8], recipient_pub_hex: &str) -> String {
    let recipient =
        Identity::new_from_hex_string(recipient_pub_hex).expect("invalid recipient public hex");
    let derived = recipient.derive_key(OsRng);

    let mut out_buf = vec![0u8; PUBLIC_KEY_LENGTH + pt.len() + 128];
    let cipher = recipient
        .encrypt(OsRng, pt, &derived, &mut out_buf)
        .expect("encryption should succeed");

    hex::encode(cipher)
}

fn rust_decrypt_hex(ct_hex: &str, recipient_priv_hex: &str) -> Vec<u8> {
    let cipher = hex::decode(ct_hex).expect("ciphertext hex");
    let recipient =
        PrivateIdentity::new_from_hex_string(recipient_priv_hex).expect("invalid recipient hex");
    let mut out_buf = vec![0u8; cipher.len()];
    let mut ratchet_id = None;
    let plaintext = recipient
        .decrypt_token(OsRng, &cipher, None, &[], false, &mut ratchet_id, &mut out_buf)
        .expect("decrypt");

    assert!(ratchet_id.is_none());
    plaintext.to_vec()
}
