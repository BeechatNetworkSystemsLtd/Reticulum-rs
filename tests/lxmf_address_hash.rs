use reticulum::hash::Hash;

#[test]
fn lxmf_address_hash_uses_first_16_bytes() {
    let hash = Hash::new_from_slice(b"hello");
    let addr = reticulum::hash::lxmf_address_hash(&hash);
    assert_eq!(addr.as_slice().len(), 16);
    assert_eq!(addr.as_slice(), &hash.as_slice()[0..16]);
}
