use reticulum::{
    group_decrypt, group_encrypt, lxmf_address_hash, lxmf_sign, lxmf_verify, DeliveryReceipt,
    LXMF_MAX_PAYLOAD, Packet, ReceiptHandler,
};
use reticulum::identity::{Identity, PrivateIdentity};

struct NoopReceipt;

impl ReceiptHandler for NoopReceipt {
    fn on_receipt(&self, _receipt: &DeliveryReceipt) {}
}

#[test]
fn lxmf_reexports_are_available() {
    let signer = PrivateIdentity::new_from_name("lxmf-export");
    let identity: &Identity = signer.as_identity();
    let data = b"data";
    let signature = lxmf_sign(&signer, data);
    assert!(lxmf_verify(identity, data, &signature));

    let hash = reticulum::hash::Hash::new_from_slice(b"hello");
    let _addr = lxmf_address_hash(&hash);

    let key = [1u8; 16];
    let ciphertext = group_encrypt(&key, data).expect("encrypt");
    let plaintext = group_decrypt(&key, &ciphertext).expect("decrypt");
    assert_eq!(plaintext, data);

    let packets = Packet::fragment_for_lxmf(&vec![0u8; LXMF_MAX_PAYLOAD + 1]).expect("fragment");
    assert_eq!(packets.len(), 2);

    let _handler: Box<dyn ReceiptHandler> = Box::new(NoopReceipt);
}
