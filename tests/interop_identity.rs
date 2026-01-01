use std::{env, path::PathBuf, process::Command};

use rand_core::OsRng;
use reticulum::identity::{DecryptIdentity, EncryptIdentity, Identity, PrivateIdentity, PUBLIC_KEY_LENGTH};
use x25519_dalek::PublicKey;

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn python_path_env() -> String {
    let reference = PathBuf::from(manifest_dir()).join("reference").join("Reticulum");
    match env::var("PYTHONPATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{}", reference.display(), existing),
        _ => reference.display().to_string(),
    }
}

fn python_command() -> Command {
    let mut cmd = Command::new("python3");
    cmd.env("PYTHONPATH", python_path_env());
    cmd.current_dir(manifest_dir());
    cmd
}

fn python_available() -> bool {
    python_command()
        .arg("-c")
        .arg("import RNS")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_python(args: &[&str]) -> (i32, String, String) {
    let mut cmd = python_command();

    if let Some((script, rest)) = args.split_first() {
        let script_path = PathBuf::from(manifest_dir()).join(script);
        cmd.arg(script_path);
        cmd.args(rest);
    }

    let out = cmd.output().expect("failed to run python3");

    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

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
    let mut cipher = hex::decode(ct_hex).expect("ciphertext hex");
    assert!(cipher.len() > PUBLIC_KEY_LENGTH, "ciphertext too short");

    let token = cipher.split_off(PUBLIC_KEY_LENGTH);
    let ephemeral_bytes: [u8; PUBLIC_KEY_LENGTH] = cipher[..PUBLIC_KEY_LENGTH]
        .try_into()
        .expect("header length");
    let ephemeral_pub = PublicKey::from(ephemeral_bytes);

    let recipient =
        PrivateIdentity::new_from_hex_string(recipient_priv_hex).expect("invalid recipient hex");
    let salt = recipient.address_hash().as_slice();
    let derived = recipient.derive_key(&ephemeral_pub, Some(salt));

    let mut out_buf = vec![0u8; token.len()];
    recipient
        .decrypt(OsRng, &token, &derived, &mut out_buf)
        .expect("decrypt")
        .to_vec()
}
