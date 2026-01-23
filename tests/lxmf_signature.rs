use reticulum::identity::{Identity, PrivateIdentity};

#[test]
fn lxmf_sign_and_verify_helpers() {
    let signer = PrivateIdentity::new_from_name("lxmf-sign");
    let identity: &Identity = signer.as_identity();
    let data = b"lxmf-data";

    let signature = reticulum::identity::lxmf_sign(&signer, data);
    assert!(reticulum::identity::lxmf_verify(identity, data, &signature));
}
