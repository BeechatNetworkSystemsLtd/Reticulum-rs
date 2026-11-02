//! Audio processing blocks (Python `LXST/Processing.py`).
//!
//! The Python module is currently an empty placeholder file upstream, so
//! this module holds the processing utilities that the codecs and pipelines
//! need, ported from `LXST/Codecs/Codec.py` and the equivalent numpy
//! operations used throughout the package:
//!
//! * [`resample`] / [`resample_bytes`] - linear resampling of interleaved
//!   i16 audio (Python uses pydub; here a straightforward linear
//!   interpolator, which is what pydub's `set_frame_rate` performs for
//!   non-integer ratios via its sample-count based path)
//! * [`normalise`] - peak normalisation (Python `apply_gain(-max_dBFS)`)
//! * [`to_i16`] / [`from_i16`] - the int16 type mapping every codec uses
//!   (`TYPE_MAP_FACTOR = np.iinfo("int16").max`)
//! * [`Denoiser`] - a simple spectral-gate denoiser standing in for the
//!   noise suppression the Python pipeline performs through AGC/BandPass

use crate::common::AudioFrame;

/// int16 full-scale factor (Python `TYPE_MAP_FACTOR`).
pub const TYPE_MAP_FACTOR: f32 = 32767.0;

/// Map normalised f32 samples to i16 the way numpy does
/// (`(frame * np.iinfo("int16").max).astype(np.int16)`), i.e. with
/// truncation towards zero and saturation at the type bounds.
pub fn to_i16(samples: &[f32]) -> Vec<i16> {
    samples
        .iter()
        .map(|&s| {
            let v = s * TYPE_MAP_FACTOR;
            if v.is_nan() {
                0
            } else {
                v as i16 // Rust float->int casts saturate
            }
        })
        .collect()
}

/// Map i16 samples back to normalised f32.
pub fn from_i16(samples: &[i16]) -> Vec<f32> {
    samples
        .iter()
        .map(|&s| s as f32 / TYPE_MAP_FACTOR)
        .collect()
}

/// Convert interleaved normalised samples to interleaved i16 little-endian
/// bytes (Python `input_samples.tobytes()`).
pub fn to_i16_bytes(samples: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(samples.len() * 2);
    for s in to_i16(samples) {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

/// Convert interleaved i16 little-endian bytes to normalised samples.
pub fn from_i16_bytes(bytes: &[u8], channels: usize) -> AudioFrame {
    let samples: Vec<f32> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes(*c) as f32 / TYPE_MAP_FACTOR)
        .collect();
    AudioFrame::from_interleaved(samples, channels.max(1))
}

/// Resample interleaved i16 audio linearly (Python
/// `Codecs.Codec.resample_bytes`).
///
/// `input_rate -> output_rate`, optionally peak-normalising first. Returns
/// interleaved i16 bytes with (approximately) `input_len * output_rate /
/// input_rate` frames.
pub fn resample_bytes(
    sample_bytes: &[u8],
    channels: usize,
    input_rate: u32,
    output_rate: u32,
    normalise: bool,
) -> Vec<u8> {
    if channels == 0 || input_rate == output_rate {
        return sample_bytes.to_vec();
    }

    let mut samples: Vec<i16> = sample_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| i16::from_le_bytes(*c))
        .collect();
    let input_frames = samples.len() / channels;

    if normalise {
        let peak = samples.iter().map(|s| s.abs()).max().unwrap_or(0);
        if peak > 0 {
            for s in samples.iter_mut() {
                *s = (*s as i32 * i16::MAX as i32 / peak as i32) as i16;
            }
        }
    }

    let output_frames =
        ((input_frames as f64) * (output_rate as f64) / (input_rate as f64)).round() as usize;
    let mut out = Vec::with_capacity(output_frames * channels * 2);

    for f in 0..output_frames {
        let src_pos = f as f64 * (input_rate as f64 / output_rate as f64);
        let i0 = src_pos.floor() as usize;
        let i1 = (i0 + 1).min(input_frames.saturating_sub(1));
        let t = (src_pos - i0 as f64) as f32;
        for ch in 0..channels {
            let a = samples[i0 * channels + ch] as f32;
            let b = samples[i1 * channels + ch] as f32;
            let v = a + (b - a) * t;
            out.extend_from_slice(&(v.round() as i16).to_le_bytes());
        }
    }

    out
}

/// Resample a decoded frame (Python `Codecs.Codec.resample`).
pub fn resample(frame: &AudioFrame, input_rate: u32, output_rate: u32) -> AudioFrame {
    if input_rate == output_rate || frame.is_empty() {
        return frame.clone();
    }

    let channels = frame.channels;
    let input_frames = frame.frames();
    let output_frames =
        ((input_frames as f64) * (output_rate as f64) / (input_rate as f64)).round() as usize;

    let mut samples = Vec::with_capacity(output_frames * channels);
    for f in 0..output_frames {
        let src_pos = f as f64 * (input_rate as f64 / output_rate as f64);
        let i0 = src_pos.floor() as usize;
        let i1 = (i0 + 1).min(input_frames.saturating_sub(1));
        let t = (src_pos - i0 as f64) as f32;
        for ch in 0..channels {
            let a = frame.sample(i0, ch);
            let b = frame.sample(i1, ch);
            samples.push(a + (b - a) * t);
        }
    }

    AudioFrame::from_interleaved(samples, channels)
}

/// Peak-normalise a frame to full scale (Python `apply_gain(-max_dBFS)`).
pub fn normalise(frame: &mut AudioFrame) {
    let peak = frame.samples.iter().fold(0.0f32, |m, s| m.max(s.abs()));
    if peak > 0.0 && peak != 1.0 {
        for s in frame.samples.iter_mut() {
            *s /= peak;
        }
    }
}

/// Noise gate / denoiser: attenuates blocks whose RMS falls below the
/// threshold, with soft attack/release to avoid gating artefacts.
///
/// This is a Rust-native stand-in for the denoising the Python call
/// pipeline achieves with `BandPass(250, 8500) + AGC`; it is exposed here
/// because `Processing.py` is an empty placeholder upstream and callers may
/// want explicit denoising.
pub struct Denoiser {
    /// RMS threshold below which blocks are attenuated.
    pub threshold: f32,
    /// Attenuation applied to sub-threshold blocks (linear).
    pub attenuation: f32,
    /// Block size in samples (per channel).
    pub block_size: usize,
    smoothed: f32,
}

impl Denoiser {
    pub fn new() -> Self {
        Self {
            threshold: 0.005,
            attenuation: 0.1,
            block_size: 160,
            smoothed: 1.0,
        }
    }

    pub fn process(&mut self, frame: &AudioFrame) -> AudioFrame {
        if frame.is_empty() {
            return frame.clone();
        }
        let mut out = frame.clone();
        let channels = frame.channels;
        let frames = frame.frames();

        let mut start = 0;
        while start < frames {
            let end = (start + self.block_size).min(frames);
            let n = end - start;

            let mut sum = 0.0f32;
            for i in start..end {
                for ch in 0..channels {
                    let v = frame.sample(i, ch);
                    sum += v * v;
                }
            }
            let rms = (sum / (n * channels) as f32).sqrt();

            let target = if rms < self.threshold {
                self.attenuation
            } else {
                1.0
            };
            // smooth toward the target to avoid clicks
            self.smoothed += (target - self.smoothed) * 0.25;
            let gain = self.smoothed;

            for i in start..end {
                for ch in 0..channels {
                    *out.sample_mut(i, ch) *= gain;
                }
            }
            start = end;
        }

        out
    }
}

impl Default for Denoiser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i16_mapping_matches_numpy() {
        // numpy: (0.5*32767).astype(int16) == 16383
        assert_eq!(to_i16(&[0.5]), vec![16383]);
        assert_eq!(to_i16(&[-0.5]), vec![-16383]);
        assert_eq!(to_i16(&[0.0]), vec![0]);
        // truncation towards zero
        assert_eq!(to_i16(&[0.99999]), vec![32766]);
        // saturation rather than numpy's wraparound
        assert_eq!(to_i16(&[2.0]), vec![32767]);
        assert_eq!(to_i16(&[-2.0]), vec![-32768]);
    }

    #[test]
    fn i16_bytes_roundtrip() {
        let samples = vec![0.5, -0.25, 0.125];
        let bytes = to_i16_bytes(&samples);
        let frame = from_i16_bytes(&bytes, 1);
        for (a, b) in frame.samples.iter().zip(samples.iter()) {
            assert!((a - b).abs() < 1e-4);
        }
    }

    #[test]
    fn resample_changes_length() {
        let f = AudioFrame::from_interleaved(vec![0.5; 4800], 1);
        let out = resample(&f, 48_000, 24_000);
        assert_eq!(out.frames(), 2400);
        let out = resample(&f, 48_000, 16_000);
        assert_eq!(out.frames(), 1600);
        let out = resample(&f, 48_000, 48_000);
        assert_eq!(out.frames(), 4800);
        // multichannel
        let f = AudioFrame::from_interleaved(vec![0.5; 4800 * 2], 2);
        let out = resample(&f, 48_000, 12_000);
        assert_eq!(out.frames(), 1200);
        assert_eq!(out.channels, 2);
    }

    #[test]
    fn resample_preserves_dc() {
        let f = AudioFrame::from_interleaved(vec![0.25; 1000], 1);
        let out = resample(&f, 8000, 4000);
        assert!(out.samples.iter().all(|s| (*s - 0.25).abs() < 1e-6));
    }

    #[test]
    fn normalise_peaks() {
        let mut f = AudioFrame::from_interleaved(vec![0.1, -0.5, 0.25], 1);
        normalise(&mut f);
        assert!((f.samples.iter().fold(0.0f32, |m, s| m.max(s.abs())) - 1.0).abs() < 1e-6);
        assert!((f.samples[2] - 0.5).abs() < 1e-6);
    }

    #[test]
    fn denoiser_gates_silence() {
        let mut d = Denoiser::new();
        let loud = AudioFrame::from_interleaved(vec![0.5; 320], 1);
        let quiet = AudioFrame::from_interleaved(vec![0.0001; 320], 1);

        let loud_out = d.process(&loud);
        assert!(loud_out.samples.iter().all(|s| *s > 0.4));

        let quiet_out = d.process(&quiet);
        assert!(quiet_out.samples.iter().all(|s| *s < 0.01));
    }
}
