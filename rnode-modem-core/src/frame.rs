//! KISS framing: build and incrementally parse FEND/FESC frames.
//!
//! Mirrors `reticulum::iface::rnode::{kiss_frame, FEND, FESC, TFEND,
//! TFESC}` and the upstream RNode firmware framing byte-for-byte; the
//! parity is asserted in `tests/host_parity.rs`.

use alloc::vec::Vec;

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

/// Build a command frame: `FEND cmd escaped-payload FEND`.
pub fn kiss_frame(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 6);
    frame.push(FEND);
    frame.push(command);
    for &byte in payload {
        match byte {
            FEND => {
                frame.push(FESC);
                frame.push(TFEND);
            }
            FESC => {
                frame.push(FESC);
                frame.push(TFESC);
            }
            _ => frame.push(byte),
        }
    }
    frame.push(FEND);
    frame
}

/// Incremental frame parser: feed arbitrary chunks, get complete
/// `(command, payload)` frames out. One parser per link.
///
/// Equivalent to the batch `split_frames` in `rnode_sim.rs`, but streaming
/// and alloc-light (one payload buffer reused per frame).
#[derive(Default)]
pub struct FrameParser {
    command: u8,
    payload: Vec<u8>,
    active: bool,
    escaped: bool,
}

pub const MAX_PAYLOAD: usize = 512;

impl FrameParser {
    pub fn new() -> Self {
        Self {
            command: 0xFE,
            payload: Vec::new(),
            active: false,
            escaped: false,
        }
    }

    /// Feed bytes; returns the frames completed by this chunk.
    pub fn feed(&mut self, bytes: &[u8], mut on_frame: impl FnMut(u8, &[u8])) {
        for &byte in bytes {
            if byte == FEND {
                if self.active {
                    let command = self.command;
                    let payload = core::mem::take(&mut self.payload);
                    on_frame(command, &payload);
                    self.payload = Vec::new();
                }
                self.active = false;
                self.escaped = false;
                continue;
            }

            if !self.active {
                self.active = true;
                self.command = byte;
                self.payload.clear();
                self.escaped = false;
                continue;
            }

            if self.escaped {
                self.escaped = false;
                let decoded = match byte {
                    TFEND => FEND,
                    TFESC => FESC,
                    other => other,
                };
                if self.payload.len() < MAX_PAYLOAD {
                    self.payload.push(decoded);
                }
            } else if byte == FESC {
                self.escaped = true;
            } else if self.payload.len() < MAX_PAYLOAD {
                self.payload.push(byte);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_escapes() {
        let payload = [0x00, FEND, FESC, 0x42, TFEND];
        let frame = kiss_frame(0x00, &payload);
        assert_eq!(frame.first(), Some(&FEND));

        let mut parser = FrameParser::new();
        let mut out = Vec::new();
        // Feed one byte at a time to exercise streaming.
        for &byte in &frame {
            parser.feed(&[byte], |cmd, pl| out.push((cmd, pl.to_vec())));
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 0x00);
        assert_eq!(out[0].1, payload.to_vec());
    }

    #[test]
    fn multiple_frames_in_one_chunk() {
        let stream = [kiss_frame(0x01, &[1, 2]), kiss_frame(0x02, &[3])].concat();
        let mut parser = FrameParser::new();
        let mut out = Vec::new();
        parser.feed(&stream, |cmd, pl| out.push((cmd, pl.to_vec())));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (0x01, vec![1, 2]));
        assert_eq!(out[1], (0x02, vec![3]));
    }
}
