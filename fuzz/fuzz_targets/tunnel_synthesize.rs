#![no_main]
use libfuzzer_sys::fuzz_target;
use reticulum::transport::decode_tunnel_synthesis;

fuzz_target!(|data: &[u8]| {
    // Tunnel synthesize decoding (signature verification) must never
    // panic on arbitrary input.
    let _ = decode_tunnel_synthesis(data);
});
