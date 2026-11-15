#![no_main]
use libfuzzer_sys::fuzz_target;
use reticulum::iface::ifac::IfacKey;

fuzz_target!(|data: &[u8]| {
    let key = IfacKey::derive(Some("fuzz"), Some("net"), 8).expect("valid IFAC");
    // IFAC unwrap of arbitrary bytes must never panic; short inputs are
    // rejected by the length checks.
    let _ = key.strip(data);
});
