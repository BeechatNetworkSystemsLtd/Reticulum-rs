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

        for i in 0..data.len() {
            // Search for HDLC frame flags only
            if data[i] != HDLC_FRAME_FLAG {
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

        return Option::None;
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
