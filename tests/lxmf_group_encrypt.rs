use reticulum::destination::{group_decrypt, group_encrypt};

#[test]
fn group_encrypt_roundtrip() {
    let key = [7u8; 16];
    let plaintext = b"hello";
    let ciphertext = group_encrypt(&key, plaintext).unwrap();
    let decoded = group_decrypt(&key, &ciphertext).unwrap();
    assert_eq!(decoded, plaintext);
}
