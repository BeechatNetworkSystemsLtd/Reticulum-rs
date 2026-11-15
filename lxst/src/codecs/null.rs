//! The `Null` codec (Python `LXST/Codecs/Codec.py::Null`): a pass-through
//! that neither transforms nor frames data.

use crate::codecs::{Codec, CodecError, CodecType};
use crate::common::AudioFrame;

#[derive(Clone, Debug, Default)]
pub struct Null;

impl Null {
    pub fn new() -> Self {
        Self
    }
}

impl Codec for Null {
    fn codec_type(&self) -> CodecType {
        CodecType::Null
    }

    /// Pass-through encode: samples are serialised as little-endian `f32`
    /// bytes (Python returns the frame unchanged, i.e. the numpy array
    /// buffer).
    fn encode(&mut self, frame: &AudioFrame) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(frame.samples.len() * 4);
        for s in &frame.samples {
            out.extend_from_slice(&s.to_le_bytes());
        }
        Ok(out)
    }

    /// Pass-through decode (Python returns the frame unchanged).
    fn decode(&mut self, data: &[u8]) -> Result<AudioFrame, CodecError> {
        if !data.len().is_multiple_of(4) {
            return Err(CodecError::new(
                "null codec payload is not a multiple of the 4-byte sample width",
            ));
        }
        let samples = data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| f32::from_le_bytes(*c))
            .collect();
        Ok(AudioFrame {
            samples,
            channels: 1,
        })
    }

    fn channels(&self) -> Option<usize> {
        Some(1)
    }

    fn set_channels(&mut self, _channels: Option<usize>) {}

    fn reset(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough() {
        let mut n = Null::new();
        let f = AudioFrame::from_interleaved(vec![0.5, -0.5], 2);
        let e = n.encode(&f).unwrap();
        assert_eq!(&e[..4], &0.5f32.to_le_bytes());
        let d = n.decode(&e).unwrap();
        assert_eq!(d.samples, vec![0.5, -0.5]);
        assert_eq!(d.channels, 1);
    }
}
