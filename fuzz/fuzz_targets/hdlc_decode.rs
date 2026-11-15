#![no_main]
use libfuzzer_sys::fuzz_target;
use reticulum::iface::hdlc::HdlcDecoder;

fuzz_target!(|data: &[u8]| {
    // HDLC decoding of arbitrary byte streams must never panic.
    let mut decoder = HdlcDecoder::new(2048);
    decoder.feed(data, |_frame| {});
});
