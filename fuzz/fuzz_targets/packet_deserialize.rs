#![no_main]
use libfuzzer_sys::fuzz_target;
use reticulum::buffer::InputBuffer;
use reticulum::packet::Packet;

fuzz_target!(|data: &[u8]| {
    // Packet deserialization must never panic on arbitrary input.
    let mut input = InputBuffer::new(data);
    let _ = Packet::deserialize(&mut input);
});
