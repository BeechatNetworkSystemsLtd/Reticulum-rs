use crate::{buffer::OutputBuffer, error::RnsError};

const HDLC_FRAME_FLAG: u8 = 0x7e;
const HDLC_ESCAPE_BYTE: u8 = 0x7d;
const HDLC_ESCAPE_MASK: u8 = 0b00100000;

pub struct Hdlc {}

impl Hdlc {
    pub fn encode(data: &[u8], buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write_byte(HDLC_FRAME_FLAG)?;

        for &byte in data {
            match byte {
                HDLC_FRAME_FLAG | HDLC_ESCAPE_BYTE => {
                    buffer.write(&[HDLC_ESCAPE_BYTE, byte ^ HDLC_ESCAPE_MASK])?;
                }
                _ => {
                    buffer.write_byte(byte)?;
                }
            }
        }

        buffer.write_byte(HDLC_FRAME_FLAG)?;

        Ok(buffer.offset())
    }

    /// Returns start and end index of HDLC frame or None
    pub fn find(data: &[u8]) -> Option<(usize, usize)> {
        let mut start = false;
        let mut end = false;

        let mut start_index: usize = 0;
        let mut end_index: usize = 0;

        for (i, byte) in data.iter().enumerate() {
            // Search for HDLC frame flags only
            if *byte != HDLC_FRAME_FLAG {
                continue;
            }

            // Find start of HDLC frame
            if !start {
                start_index = i;
                start = true;
            }
            // Find end of HDLC frame
            else if !end {
                end_index = i;
                end = true;
            }

            if start && end {
                return Option::Some((start_index, end_index));
            }
        }

        Option::None
    }

    /// Byte-for-byte port of the `escape` HDLC helper shared by
    /// `SerialInterface`, `PipeInterface` and `LocalInterface`.
    pub fn escape(data: &[u8], buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        for &byte in data {
            match byte {
                HDLC_FRAME_FLAG | HDLC_ESCAPE_BYTE => {
                    buffer.write(&[HDLC_ESCAPE_BYTE, byte ^ HDLC_ESCAPE_MASK])?;
                }
                _ => {
                    buffer.write_byte(byte)?;
                }
            }
        }

        Ok(buffer.offset())
    }

    /// Frame `data` with HDLC flags: `FLAG + escape(data) + FLAG`
    pub fn encode_frame(data: &[u8], buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write_byte(HDLC_FRAME_FLAG)?;
        Hdlc::escape(data, buffer)?;
        buffer.write_byte(HDLC_FRAME_FLAG)?;

        Ok(buffer.offset())
    }

    /// Frame `data` into an owned buffer: `FLAG + escape(data) + FLAG`.
    pub fn encode_frame_vec(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 16);
        out.push(HDLC_FRAME_FLAG);
        for &byte in data {
            match byte {
                HDLC_FRAME_FLAG | HDLC_ESCAPE_BYTE => {
                    out.push(HDLC_ESCAPE_BYTE);
                    out.push(byte ^ HDLC_ESCAPE_MASK);
                }
                _ => out.push(byte),
            }
        }
        out.push(HDLC_FRAME_FLAG);
        out
    }

    pub fn decode(data: &[u8], output: &mut OutputBuffer) -> Result<usize, RnsError> {
        let mut started = false;
        let mut finished = false;
        let mut escape = false;

        for &byte in data {
            if escape {
                escape = false;
                output.write_byte(byte ^ HDLC_ESCAPE_MASK)?;
            } else {
                match byte {
                    HDLC_FRAME_FLAG => {
                        if started {
                            finished = true;
                            break;
                        }

                        started = true;
                    }
                    HDLC_ESCAPE_BYTE => {
                        escape = true;
                    }
                    _ => {
                        output.write_byte(byte)?;
                    }
                }
            }
        }

        if !finished {
            return Err(RnsError::OutOfMemory);
        }

        Ok(output.offset())
    }
}

/// Incremental HDLC frame decoder for byte streams, a byte-for-byte port of
/// the `readLoop` state machine in `SerialInterface.py` / `PipeInterface.py` /
/// `LocalInterface.py`:
///
/// * a `FLAG` starts a frame, the next `FLAG` completes it,
/// * `ESC` escapes the following byte (`byte ^ ESC_MASK`),
/// * frames longer than `mtu` are truncated like the Python `HW_MTU` check,
/// * empty frames (e.g. `FLAG FLAG` keepalives) are delivered as empty slices
///   and must be ignored by the caller, matching
///   `if len(frame) > RNS.Reticulum.HEADER_MINSIZE`.
#[derive(Debug)]
pub struct HdlcDecoder {
    frame: Vec<u8>,
    in_frame: bool,
    escape: bool,
    mtu: usize,
}

impl HdlcDecoder {
    pub fn new(mtu: usize) -> Self {
        Self {
            frame: Vec::new(),
            in_frame: false,
            escape: false,
            mtu,
        }
    }

    /// Feed raw stream bytes and invoke `on_frame` with every completed
    /// (unescaped) frame payload.
    pub fn feed<F: FnMut(&[u8])>(&mut self, data: &[u8], mut on_frame: F) {
        for &byte in data {
            if self.in_frame && byte == HDLC_FRAME_FLAG {
                self.in_frame = false;
                self.escape = false;
                on_frame(&self.frame);
                self.frame.clear();
            } else if byte == HDLC_FRAME_FLAG {
                self.in_frame = true;
                self.escape = false;
                self.frame.clear();
            } else if self.in_frame && self.frame.len() < self.mtu {
                if byte == HDLC_ESCAPE_BYTE {
                    self.escape = true;
                } else {
                    let mut byte = byte;
                    if self.escape {
                        if byte == HDLC_FRAME_FLAG ^ HDLC_ESCAPE_MASK {
                            byte = HDLC_FRAME_FLAG;
                        }
                        if byte == HDLC_ESCAPE_BYTE ^ HDLC_ESCAPE_MASK {
                            byte = HDLC_ESCAPE_BYTE;
                        }
                        self.escape = false;
                    }
                    self.frame.push(byte);
                }
            }
        }
    }

    /// Drop any partial frame state (Python resets the buffer after a
    /// read timeout).
    pub fn reset(&mut self) {
        self.frame.clear();
        self.in_frame = false;
        self.escape = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_matches_python_reference() {
        // Python: HDLC.escape(bytes([0x7e, 0x7d, 0x01]))
        //       = 7d 5e 7d 5d 01
        let mut buffer = [0u8; 8];
        let mut output = OutputBuffer::new(&mut buffer[..]);
        Hdlc::escape(&[0x7e, 0x7d, 0x01], &mut output).unwrap();
        assert_eq!(output.as_slice(), [0x7d, 0x5e, 0x7d, 0x5d, 0x01]);
    }

    #[test]
    fn frame_vec_matches_python_reference() {
        // Python: bytes([0x7e])+HDLC.escape(bytes([0x7e,0x7d,0x01]))+bytes([0x7e])
        assert_eq!(
            Hdlc::encode_frame_vec(&[0x7e, 0x7d, 0x01]),
            vec![0x7e, 0x7d, 0x5e, 0x7d, 0x5d, 0x01, 0x7e]
        );
    }

    #[test]
    fn decoder_round_trip() {
        let frame = Hdlc::encode_frame_vec(&[0x7e, 0x7d, 0xc0, 0xdb, 0x00, 0xff]);
        let mut decoder = HdlcDecoder::new(564);

        // feed in chunks to exercise partial-frame handling
        let mut frames = Vec::new();
        for chunk in frame.chunks(3) {
            decoder.feed(chunk, |frame| frames.push(frame.to_vec()));
        }

        assert_eq!(frames, vec![vec![0x7e, 0x7d, 0xc0, 0xdb, 0x00, 0xff]]);
    }

    #[test]
    fn decoder_ignores_garbage_and_empty_frames() {
        let mut decoder = HdlcDecoder::new(564);
        let mut frames = Vec::new();
        // noise before frame, empty keepalive frame, then real frame
        let stream = [
            &[0x00u8, 0x11, 0x22][..],
            &[0x7e, 0x7e], // keepalive
            &Hdlc::encode_frame_vec(&[1, 2, 3])[..],
        ]
        .concat();

        decoder.feed(&stream, |frame| frames.push(frame.to_vec()));

        assert_eq!(frames, vec![Vec::<u8>::new(), vec![1, 2, 3]]);
    }
}
