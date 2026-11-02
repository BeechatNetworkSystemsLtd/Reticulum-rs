//! The `Raw` codec (Python `LXST/Codecs/Raw.py`).
//!
//! Encodes normalised `float` samples directly, one header byte followed by
//! the raw little-endian samples:
//!
//! ```text
//! header = bitdepth_index << 6 | (channels - 1)
//! ```
//!
//! `bitdepth_index` selects the sample format:
//!
//! | index | nominal bits | numpy dtype | Rust            | bytes/sample |
//! |-------|--------------|-------------|-----------------|--------------|
//! | 0     | 16           | float16     | `half::f16`     | 2            |
//! | 1     | 32           | float32     | `f32`           | 4            |
//! | 2     | 64           | float64     | `f64`           | 8            |
//! | 3     | 128          | float128    | x87 80-bit (see below) | 16     |
//!
//! ## float128
//!
//! numpy `float128` on x86-64 is the x87 80-bit extended precision format
//! stored in a 16-byte container. The upper 10 bytes hold the value
//! (64-bit significand with explicit integer bit, 15-bit exponent) and the
//! trailing 6 bytes are **padding** which numpy leaves uninitialised (the
//! Python reference output contains garbage there). This implementation
//! writes the exact same 10 value bytes and zeroes the padding; receivers
//! must ignore the padding bytes, so the encodings interoperate.
//!
//! Bit-depth selection mirrors the Python constructor thresholds: any
//! `bitdepth >= 128` selects float128, `>= 64` float64, `>= 32` float32 and
//! anything below 32 float16 (note this means *the nominal default of 16
//! bits is float16*, not integer PCM).

use half::f16;

use crate::codecs::{Codec, CodecError, CodecType};
use crate::common::AudioFrame;

/// float16 sample format header value (Python `Raw.BITDEPTH_16`).
pub const BITDEPTH_16: u8 = 0x00;
/// float32 sample format header value (Python `Raw.BITDEPTH_32`).
pub const BITDEPTH_32: u8 = 0x01;
/// float64 sample format header value (Python `Raw.BITDEPTH_64`).
pub const BITDEPTH_64: u8 = 0x02;
/// float128 (x87 80-bit) sample format header value (Python `Raw.BITDEPTH_128`).
pub const BITDEPTH_128: u8 = 0x03;

/// Bytes per sample for a header bit-depth index.
pub const SAMPLE_WIDTH: [usize; 4] = [2, 4, 8, 16];

/// Convert one `f32` into the x87 80-bit extended format used by numpy's
/// `float128` (little-endian value bytes followed by zero padding).
///
/// The returned array is the full 16-byte container.
pub fn f32_to_f128_le(value: f32) -> [u8; 16] {
    let bits = value.to_bits();
    let sign = ((bits >> 31) & 1) as u16;
    let exp = ((bits >> 23) & 0xff) as i32;
    let frac = bits & 0x007f_ffff;

    let (significand, biased) = if exp == 0 {
        if frac == 0 {
            // (signed) zero
            (0u64, 0i32)
        } else {
            // subnormal float32: value = frac * 2^-149, frac is a 23-bit
            // integer. Normalise to significand * 2^(e-63): shift the
            // highest set bit into position 63.
            let k = 31 - frac.leading_zeros() as i32; // highest set bit index (0..22)
            ((frac as u64) << (63 - k), k - 149 + 16383)
        }
    } else if exp == 0xff {
        // Inf / NaN: exponent all-ones, integer bit set, payload preserved
        let significand = if frac == 0 {
            1u64 << 63
        } else {
            (1u64 << 63) | ((frac as u64) << 40)
        };
        (significand, 0x7fff)
    } else {
        // normal: the implicit integer bit becomes explicit bit 63, and the
        // 23-bit float32 mantissa is left-aligned in the remaining 63 bits
        // (shifted by 63 - 23 = 40).
        let significand = (1u64 << 63) | ((frac as u64) << 40);
        (significand, exp - 127 + 16383)
    };

    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&significand.to_le_bytes());
    let se = (sign << 15) | (biased as u16);
    out[8..10].copy_from_slice(&se.to_le_bytes());
    out
}

/// Parse one x87 80-bit extended sample (from a 16-byte container) back into
/// `f32`. The 6 padding bytes are ignored. The conversion goes through
/// `f64`, which is exact for values that originated from `f32` (and close
/// enough to numpy's direct conversion for arbitrary inputs).
pub fn f128_le_to_f32(bytes: &[u8]) -> Result<f32, CodecError> {
    if bytes.len() < 10 {
        return Err(CodecError::new("truncated float128 sample"));
    }
    let significand = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let se = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let sign: f64 = if (se >> 15) & 1 == 1 { -1.0 } else { 1.0 };
    let biased = (se & 0x7fff) as i32;

    let value = if biased == 0x7fff {
        if significand & !(1u64 << 63) == 0 {
            f64::INFINITY
        } else {
            f64::NAN
        }
    } else if significand == 0 {
        0.0
    } else {
        let e = biased - 16383;
        // value = (significand / 2^63) * 2^e with significand / 2^63 in
        // [1, 2); scaling the fraction first keeps the powers in range.
        let fraction = significand as f64 / 2f64.powi(63);
        fraction * 2f64.powi(e)
    };

    Ok((sign * value) as f32)
}

/// Uncompressed float codec (Python `LXST.Codecs.Raw`).
#[derive(Clone, Debug)]
pub struct Raw {
    /// Nominal bit depth as configured. Selects the actual dtype via the
    /// thresholds `>=128`, `>=64`, `>=32`, else float16.
    pub bitdepth: u32,
    /// Configured channel count, discovered from the first encoded frame if
    /// `None` (Python leaves `channels` as `None` until the first frame).
    pub channels: Option<usize>,
    /// The header bit-depth index actually used (`header_bitdpeth` in Python).
    header_bitdepth: u8,
}

impl Raw {
    /// Create a Raw codec.
    ///
    /// * `channels` - optional fixed channel count; like Python it is
    ///   clamped to `1..=32`. `None` adopts the channel count of the first
    ///   encoded frame.
    /// * `bitdepth` - nominal bits per sample (16 selects float16!).
    pub fn new(channels: Option<usize>, bitdepth: u32) -> Self {
        // Python only clamps when `channels` is truthy: `if channels:
        // channels = min(max(channels, 1), 32)` - so channels=0 stays 0
        // (and encoding then fails, matching the Python OverflowError from
        // `(channels-1).to_bytes()`).
        let channels = channels.map(|c| if c == 0 { 0 } else { c.clamp(1, 32) });

        let (header_bitdepth, _) = if bitdepth >= 128 {
            (BITDEPTH_128, "float128")
        } else if bitdepth >= 64 {
            (BITDEPTH_64, "float64")
        } else if bitdepth >= 32 {
            (BITDEPTH_32, "float32")
        } else {
            (BITDEPTH_16, "float16")
        };

        Self {
            bitdepth,
            channels,
            header_bitdepth,
        }
    }

    /// The header byte this codec writes into its encoded frames.
    ///
    /// Note there is no mask on the channel bits: 32 channels produce
    /// `bitdepth << 6 | 31`, exactly like Python.
    pub fn frame_header(&self) -> u8 {
        let channels = self.channels.unwrap_or(1).max(1);
        (self.header_bitdepth << 6) | (channels as u8 - 1)
    }

    fn write_sample(&self, sample: f32, out: &mut Vec<u8>) {
        match self.header_bitdepth {
            BITDEPTH_16 => out.extend_from_slice(&f16::from_f32(sample).to_le_bytes()),
            BITDEPTH_32 => out.extend_from_slice(&sample.to_le_bytes()),
            BITDEPTH_64 => out.extend_from_slice(&(sample as f64).to_le_bytes()),
            _ => out.extend_from_slice(&f32_to_f128_le(sample)),
        }
    }

    fn read_samples(&self, data: &[u8], channels: usize) -> Result<Vec<f32>, CodecError> {
        let width = SAMPLE_WIDTH[self.header_bitdepth as usize];
        if !data.len().is_multiple_of(width) {
            return Err(CodecError::new(format!(
                "raw frame payload of {} bytes is not a multiple of the {}-byte sample width",
                data.len(),
                width
            )));
        }

        let mut samples = Vec::with_capacity(data.len() / width);
        match self.header_bitdepth {
            BITDEPTH_16 => {
                for c in data.as_chunks::<2>().0 {
                    samples.push(f16::from_le_bytes(*c).to_f32());
                }
            }
            BITDEPTH_32 => {
                for c in data.as_chunks::<4>().0 {
                    samples.push(f32::from_le_bytes(*c));
                }
            }
            BITDEPTH_64 => {
                for c in data.as_chunks::<8>().0 {
                    samples.push(f64::from_le_bytes(*c) as f32);
                }
            }
            _ => {
                for c in data.as_chunks::<16>().0 {
                    samples.push(f128_le_to_f32(c)?);
                }
            }
        }

        // Python reshape(len(samples) // channels, channels) silently drops
        // a partial trailing sample-row.
        samples.truncate((samples.len() / channels) * channels);
        Ok(samples)
    }
}

impl Codec for Raw {
    fn codec_type(&self) -> CodecType {
        CodecType::Raw
    }

    fn encode(&mut self, frame: &AudioFrame) -> Result<Vec<u8>, CodecError> {
        if self.channels.is_none() {
            self.channels = Some(frame.channels.max(1));
        }
        if self.channels == Some(0) {
            // Python: (channels-1).to_bytes() raises OverflowError
            return Err(CodecError::new("Raw codec configured with 0 channels"));
        }

        let channels = self.channels.unwrap();
        let adapted = frame.adapt_channels(channels);

        let mut out = Vec::with_capacity(
            1 + adapted.samples.len() * SAMPLE_WIDTH[self.header_bitdepth as usize],
        );
        out.push(self.frame_header());
        for &s in &adapted.samples {
            self.write_sample(s, &mut out);
        }
        Ok(out)
    }

    fn decode(&mut self, data: &[u8]) -> Result<AudioFrame, CodecError> {
        if data.is_empty() {
            return Err(CodecError::new("raw frame shorter than its header byte"));
        }
        let header = data[0];
        let channels = ((header & 0b0011_1111) + 1) as usize;
        let bitdepth_index = header >> 6;
        if bitdepth_index as usize >= SAMPLE_WIDTH.len() {
            return Err(CodecError::new(format!(
                "invalid raw frame bit depth index {bitdepth_index}"
            )));
        }

        // Decoding uses the header of the incoming frame, not the local
        // configuration (Python reads BITDEPTHS[frame_bitdepth]).
        let mut decodable = self.clone();
        decodable.header_bitdepth = bitdepth_index;
        let samples = decodable.read_samples(&data[1..], channels)?;

        if self.channels.is_none() {
            self.channels = Some(channels);
        }

        Ok(AudioFrame { samples, channels })
    }

    fn channels(&self) -> Option<usize> {
        self.channels
    }

    fn set_channels(&mut self, channels: Option<usize>) {
        self.channels = channels.map(|c| if c == 0 { 0 } else { c.clamp(1, 32) });
    }

    fn bitdepth(&self) -> usize {
        self.bitdepth as usize
    }

    fn reset(&mut self) {
        // Channels stay configured; no other state.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn frame(values: &[f32], channels: usize) -> AudioFrame {
        AudioFrame::from_interleaved(values.to_vec(), channels)
    }

    #[test]
    fn header_bits() {
        assert_eq!(Raw::new(Some(1), 32).frame_header(), 0x40);
        assert_eq!(Raw::new(Some(2), 32).frame_header(), 0x41);
        // 32 channels: (2 << 6) | 31 = 0x9f (no mask, like Python)
        assert_eq!(Raw::new(Some(32), 64).frame_header(), 0x9f);
        assert_eq!(Raw::new(Some(1), 16).frame_header(), 0x00);
        assert_eq!(Raw::new(Some(1), 128).frame_header(), 0xc0);
        // Python only clamps truthy channel counts: 0 stays 0 (and encoding
        // then fails), 99 clamps to 32
        assert_eq!(Raw::new(Some(0), 32).channels, Some(0));
        assert_eq!(Raw::new(Some(99), 32).channels, Some(32));
        // encoding with 0 channels errors, like the Python OverflowError
        let mut c = Raw::new(Some(0), 32);
        assert!(c
            .encode(&AudioFrame::from_interleaved(vec![0.5], 1))
            .is_err());
    }

    #[test]
    fn bitdepth_thresholds() {
        assert_eq!(Raw::new(Some(1), 0).frame_header() >> 6, BITDEPTH_16);
        assert_eq!(Raw::new(Some(1), 31).frame_header() >> 6, BITDEPTH_16);
        assert_eq!(Raw::new(Some(1), 32).frame_header() >> 6, BITDEPTH_32);
        assert_eq!(Raw::new(Some(1), 63).frame_header() >> 6, BITDEPTH_32);
        assert_eq!(Raw::new(Some(1), 64).frame_header() >> 6, BITDEPTH_64);
        assert_eq!(Raw::new(Some(1), 127).frame_header() >> 6, BITDEPTH_64);
        assert_eq!(Raw::new(Some(1), 128).frame_header() >> 6, BITDEPTH_128);
        assert_eq!(Raw::new(Some(1), 256).frame_header() >> 6, BITDEPTH_128);
    }

    #[test]
    fn roundtrip_all_bitdepths() {
        let values: Vec<f32> = (-32..32).map(|i| i as f32 / 33.0).collect();
        for bd in [16u32, 32, 64, 128] {
            for ch in [1usize, 2, 3] {
                let input = frame(&values, 1).adapt_channels(ch);
                let mut enc = Raw::new(Some(ch), bd);
                let data = enc.encode(&input).unwrap();
                let mut dec = Raw::new(None, 16);
                let out = dec.decode(&data).unwrap();
                assert_eq!(out.channels, ch);
                assert_eq!(out.frames(), input.frames());
                let tolerance = match bd {
                    16 => 6e-4, // float16 mantissa
                    _ => 1e-7,  // exact for 32/64/128 (values came from f32)
                };
                for (a, b) in out.samples.iter().zip(input.samples.iter()) {
                    assert!((a - b).abs() <= tolerance, "bd={bd} ch={ch}: {a} vs {b}");
                }
            }
        }
    }

    #[test]
    fn channel_adaptation() {
        // More channels than configured -> truncate
        let mut c = Raw::new(Some(2), 32);
        let data = c.encode(&frame(&[0.5, -0.5, 0.25], 3)).unwrap();
        assert_eq!(
            &data[1..],
            &[
                0x00, 0x00, 0x00, 0x3f, //  0.5
                0x00, 0x00, 0x00, 0xbf, // -0.5
            ]
        );

        // Fewer channels than configured -> pad with last original channel
        let mut c = Raw::new(Some(3), 32);
        let data = c.encode(&frame(&[0.5], 1)).unwrap();
        assert_eq!(
            &data[1..],
            &[
                0x00, 0x00, 0x00, 0x3f, //
                0x00, 0x00, 0x00, 0x3f, //
                0x00, 0x00, 0x00, 0x3f, //
            ]
        );
    }

    #[test]
    fn adopts_channels_on_first_frame() {
        let mut c = Raw::new(None, 32);
        assert_eq!(c.channels(), None);
        c.encode(&frame(&[0.5, 0.25], 2)).unwrap();
        assert_eq!(c.channels(), Some(2));

        // Decode also adopts channels when unset
        let mut d = Raw::new(None, 32);
        d.decode(&[0x41, 0, 0, 0, 0]).unwrap();
        assert_eq!(d.channels(), Some(2));
    }

    #[test]
    fn f128_roundtrips_assorted_values() {
        let vals: Vec<f32> = (-32..32).map(|i| i as f32 / 33.0).collect();
        for (idx, &v) in vals.iter().enumerate().take(4) {
            let b = f32_to_f128_le(v);
            let back = f128_le_to_f32(&b).unwrap();
            println!("{idx}: {v} -> {} -> {back}", hex_of(&b));
            assert_eq!(back.to_bits(), v.to_bits(), "{idx}: {v}");
        }
    }

    #[test]
    fn f128_layout() {
        // 0.5 -> significand 1<<63, exponent 16382 (0x3ffe), sign 0
        let b = f32_to_f128_le(0.5);
        assert_eq!(&b[..8], &[0, 0, 0, 0, 0, 0, 0, 0x80]);
        assert_eq!(&b[8..10], &[0xfe, 0x3f]);
        assert_eq!(&b[10..], &[0u8; 6]);
        // -0.25
        let b = f32_to_f128_le(-0.25);
        assert_eq!(&b[..8], &[0, 0, 0, 0, 0, 0, 0, 0x80]);
        assert_eq!(&b[8..10], &[0xfd, 0xbf]);
        // zero
        assert_eq!(f32_to_f128_le(0.0), [0u8; 16]);
        // subnormal f32 (1.4e-45)
        let tiny = f32::from_bits(1);
        let b = f32_to_f128_le(tiny);
        assert_eq!(&b[..8], &[0, 0, 0, 0, 0, 0, 0, 0x80]);
        let se = u16::from_le_bytes([b[8], b[9]]);
        // exponent = 16383 - 149 = 16234 = 0x3f6a
        assert_eq!(se, 0x3f6a);
        assert_eq!(f128_le_to_f32(&b).unwrap().to_bits(), tiny.to_bits());
        // roundtrip of assorted values
        for v in [0.0f32, -0.0, 1.0, -1.0, 0.5, 1e-30, 3.4e38, -2.5e-9] {
            let b = f32_to_f128_le(v);
            assert_eq!(f128_le_to_f32(&b).unwrap().to_bits(), v.to_bits(), "{v}");
        }
    }
}
