//! The `Codec2` codec (Python `LXST/Codecs/Codec2.py`), behind the `codec2`
//! cargo feature (pure-Rust `codec2` crate).
//!
//! Wire format: one **mode header byte** followed by one or more packed
//! Codec2 frames. Mode header mapping (Python `Codec2.MODE_HEADERS`):
//!
//! | mode  | header |
//! |-------|--------|
//! | 700C  | 0x00   |
//! | 1200  | 0x01   |
//! | 1300  | 0x02   |
//! | 1400  | 0x03   |
//! | 1600  | 0x04   |
//! | 2400  | 0x05   |
//! | 3200  | 0x06   |
//!
//! Codec2 runs at 8 kHz with 40 ms frames, mono. The upstream Rust `codec2`
//! crate only implements the 2400 and 3200 bit/s modes; other modes fail at
//! construction with [`CodecError::Unsupported`].

use crate::codecs::{Codec, CodecError, CodecType};
use crate::common::AudioFrame;

/// Input/output samplerate (Python `Codec2.INPUT_RATE` / `OUTPUT_RATE`).
pub const INPUT_RATE: u32 = 8000;
/// Output samplerate.
pub const OUTPUT_RATE: u32 = 8000;
/// Frame duration (Python `Codec2.FRAME_QUANTA_MS`).
pub const FRAME_QUANTA_MS: f64 = 40.0;
/// int16 scaling factor (Python `TYPE_MAP_FACTOR`).
pub const TYPE_MAP_FACTOR: f32 = 32767.0;

pub const CODEC2_700C: u32 = 700;
pub const CODEC2_1200: u32 = 1200;
pub const CODEC2_1300: u32 = 1300;
pub const CODEC2_1400: u32 = 1400;
pub const CODEC2_1600: u32 = 1600;
pub const CODEC2_2400: u32 = 2400;
pub const CODEC2_3200: u32 = 3200;

fn mode_header(mode: u32) -> u8 {
    match mode {
        CODEC2_700C => 0x00,
        CODEC2_1200 => 0x01,
        CODEC2_1300 => 0x02,
        CODEC2_1400 => 0x03,
        CODEC2_1600 => 0x04,
        CODEC2_2400 => 0x05,
        CODEC2_3200 => 0x06,
        _ => 0x05,
    }
}

fn header_mode(header: u8) -> Option<u32> {
    match header {
        0x00 => Some(CODEC2_700C),
        0x01 => Some(CODEC2_1200),
        0x02 => Some(CODEC2_1300),
        0x03 => Some(CODEC2_1400),
        0x04 => Some(CODEC2_1600),
        0x05 => Some(CODEC2_2400),
        0x06 => Some(CODEC2_3200),
        _ => None,
    }
}

fn codec2_mode(mode: u32) -> Result<::codec2::Codec2Mode, CodecError> {
    use ::codec2::Codec2Mode;
    match mode {
        CODEC2_2400 => Ok(Codec2Mode::MODE_2400),
        CODEC2_3200 => Ok(Codec2Mode::MODE_3200),
        other => Err(CodecError::Unsupported(format!(
            "the `codec2` crate only implements modes 2400 and 3200, not {other}"
        ))),
    }
}

/// Codec2 codec (Python `LXST.Codecs.Codec2`).
pub struct Codec2 {
    pub mode: u32,
    pub channels: usize,
    pub bitdepth: usize,
    pub source_samplerate: Option<u32>,
    pub sink_samplerate: Option<u32>,

    c2: ::codec2::Codec2,
}

impl Codec2 {
    pub fn new() -> Self {
        Self::with_mode(CODEC2_2400)
    }

    pub fn with_mode(mode: u32) -> Self {
        let c2 = ::codec2::Codec2::new(codec2_mode(mode).expect("valid mode"));
        Self {
            mode,
            channels: 1,
            bitdepth: 16,
            source_samplerate: None,
            sink_samplerate: None,
            c2,
        }
    }

    pub fn set_mode(&mut self, mode: u32) -> Result<(), CodecError> {
        self.mode = mode;
        self.c2 = ::codec2::Codec2::new(codec2_mode(mode)?);
        Ok(())
    }

    fn samples_per_frame(&self) -> usize {
        self.c2.samples_per_frame()
    }

    fn bytes_per_frame(&self) -> usize {
        (self.c2.bits_per_frame() as usize + 7) / 8
    }
}

impl Default for Codec2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Codec for Codec2 {
    fn codec_type(&self) -> CodecType {
        CodecType::Codec2
    }

    fn encode(&mut self, frame: &AudioFrame) -> Result<Vec<u8>, CodecError> {
        if frame.channels == 0 {
            return Err(CodecError::new("Cannot encode frame with 0 channels"));
        }
        // Python takes frame[:, 1] when too many channels are present,
        // i.e. drops the first channel and keeps channel index 1.
        let mono = if frame.channels > 1 {
            (0..frame.frames())
                .map(|i| frame.sample(i, 1))
                .collect::<Vec<_>>()
        } else {
            frame.samples.clone()
        };

        let input: Vec<i16> = mono.iter().map(|&s| (s * TYPE_MAP_FACTOR) as i16).collect();

        let spf = self.samples_per_frame();
        let bpf = self.bytes_per_frame();
        let n_frames = input.len() / spf;

        let mut out = Vec::with_capacity(1 + n_frames * bpf);
        out.push(mode_header(self.mode));
        let mut packed = vec![0u8; bpf];
        for f in 0..n_frames {
            self.c2.encode(&mut packed, &input[f * spf..(f + 1) * spf]);
            out.extend_from_slice(&packed);
        }
        Ok(out)
    }

    fn decode(&mut self, data: &[u8]) -> Result<AudioFrame, CodecError> {
        if data.is_empty() {
            return Err(CodecError::new("codec2 frame shorter than its mode header"));
        }
        let header = data[0];
        let frame_mode = header_mode(header).unwrap_or(self.mode);
        if self.mode != frame_mode {
            self.set_mode(frame_mode)?;
        }

        let spf = self.samples_per_frame();
        let bpf = self.bytes_per_frame();
        let body = &data[1..];
        let n_frames = body.len() / bpf;

        let mut samples = Vec::with_capacity(n_frames * spf);
        let mut pcm = vec![0i16; spf];
        for f in 0..n_frames {
            self.c2.decode(&mut pcm, &body[f * bpf..(f + 1) * bpf]);
            samples.extend(pcm.iter().map(|&s| s as f32 / TYPE_MAP_FACTOR));
        }

        Ok(AudioFrame {
            samples,
            channels: 1,
        })
    }

    fn channels(&self) -> Option<usize> {
        Some(self.channels)
    }

    fn set_channels(&mut self, _channels: Option<usize>) {
        // Codec2 is mono only.
    }

    fn bitdepth(&self) -> usize {
        self.bitdepth
    }

    fn preferred_samplerate(&self) -> Option<u32> {
        Some(INPUT_RATE)
    }

    fn output_samplerate(&self) -> Option<u32> {
        Some(OUTPUT_RATE)
    }

    fn frame_quanta_ms(&self) -> Option<f64> {
        Some(FRAME_QUANTA_MS)
    }

    fn frame_max_ms(&self) -> Option<f64> {
        Some(FRAME_QUANTA_MS)
    }

    fn valid_frame_ms(&self) -> Option<Vec<f64>> {
        Some(vec![FRAME_QUANTA_MS])
    }

    fn set_sink_params(&mut self, samplerate: Option<u32>, _channels: Option<usize>) {
        self.sink_samplerate = samplerate;
    }

    fn set_source_samplerate(&mut self, samplerate: u32) {
        self.source_samplerate = Some(samplerate);
    }

    fn reset(&mut self) {
        // Codec2 objects are stateless across frames in this binding.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_headers() {
        assert_eq!(mode_header(CODEC2_700C), 0x00);
        assert_eq!(mode_header(CODEC2_2400), 0x05);
        assert_eq!(mode_header(CODEC2_3200), 0x06);
        assert_eq!(header_mode(0x05), Some(CODEC2_2400));
        assert_eq!(header_mode(0xff), None);
    }

    #[test]
    fn roundtrip() {
        let mut input = Vec::new();
        for i in 0..320 {
            input.push(((i as f32) * 0.08).sin() * 0.6);
        }
        let frame = AudioFrame::from_interleaved(input, 1);
        let mut enc = Codec2::with_mode(CODEC2_2400);
        let data = enc.encode(&frame).unwrap();
        assert_eq!(data[0], 0x05);
        assert_eq!(data.len(), 1 + 2 * 6); // 2 frames of 6 bytes
        let mut dec = Codec2::with_mode(CODEC2_2400);
        let out = dec.decode(&data).unwrap();
        assert_eq!(out.channels, 1);
        assert_eq!(out.frames(), 320);
    }
}
