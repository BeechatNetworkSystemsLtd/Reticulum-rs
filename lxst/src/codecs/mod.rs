//! Codecs (Python `LXST/Codecs`).
//!
//! Wire registry (Python `LXST/Codecs/__init__.py`):
//!
//! | codec   | header byte |
//! |---------|-------------|
//! | `Raw`   | `0x00`      |
//! | `Opus`  | `0x01`      |
//! | `Codec2`| `0x02`      |
//! | `Null`  | `0xFF` (no packet mapping - see [`codec_header_byte`]) |
//!
//! Every encoded frame carried on the network is prefixed with one codec
//! header byte by [`crate::network::Packetizer`]. Some codecs additionally
//! carry their own per-frame header *inside* the payload:
//!
//! * [`Raw`] - one byte, `bitdepth << 6 | (channels - 1)`
//! * [`Codec2`] - one byte mode header
//! * [`Opus`] - no inner header
//!
//! Feature flags: [`Opus`](codecs::Opus) is only available with the `opus`
//! cargo feature (libopus), [`Codec2`](codecs::Codec2) with the `codec2`
//! cargo feature. The default build has no native/C dependencies and still
//! provides [`Raw`] and [`Null`].

use crate::common::AudioFrame;

mod null;
mod raw;

#[cfg(feature = "codec2")]
mod codec2_impl;
#[cfg(feature = "opus")]
mod opus;

pub use null::Null;
pub use raw::Raw;

#[cfg(feature = "codec2")]
pub use codec2_impl::Codec2;
#[cfg(feature = "opus")]
pub use opus::Opus;

/// Codec registry header bytes (Python `LXST.Codecs.RAW/OPUS/CODEC2/NULL`).
pub const RAW: u8 = 0x00;
/// Opus header byte.
pub const OPUS: u8 = 0x01;
/// Codec2 header byte.
pub const CODEC2: u8 = 0x02;
/// `Null` pseudo header byte. Python defines the constant but has **no**
/// packet mapping for it: `codec_header_byte(Null)` raises `TypeError`.
pub const NULL: u8 = 0xFF;

/// Codec selector, one value per registered codec (Python: the codec classes).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum CodecType {
    Raw,
    Opus,
    Codec2,
    Null,
}

impl CodecType {
    /// Human readable name, matching the Python class names.
    pub fn name(&self) -> &'static str {
        match self {
            CodecType::Raw => "Raw",
            CodecType::Opus => "Opus",
            CodecType::Codec2 => "Codec2",
            CodecType::Null => "Null",
        }
    }
}

/// Header byte for a codec type (Python `codec_header_byte`).
///
/// Mirrors the Python behaviour exactly: `Raw`, `Opus` and `Codec2` have
/// header bytes, `Null` has **no mapping** - Python raises `TypeError`
/// there, so this returns `None`.
pub fn codec_header_byte(codec: CodecType) -> Option<u8> {
    match codec {
        CodecType::Raw => Some(RAW),
        CodecType::Opus => Some(OPUS),
        CodecType::Codec2 => Some(CODEC2),
        CodecType::Null => None,
    }
}

/// Codec type for a header byte (Python `codec_type`).
///
/// Returns `None` for unknown bytes - Python returns `None` for `NULL`
/// (`0xff`) and any unmapped value.
pub fn codec_type(header_byte: u8) -> Option<CodecType> {
    match header_byte {
        RAW => Some(CodecType::Raw),
        OPUS => Some(CodecType::Opus),
        CODEC2 => Some(CodecType::Codec2),
        _ => None,
    }
}

/// Errors produced by codecs (Python `LXST.Codecs.CodecError`).
#[derive(Debug)]
pub enum CodecError {
    /// Human readable codec failure.
    Error(String),
    /// A parameter was out of range for the codec.
    InvalidParameter(String),
    /// The codec is compiled out of this build.
    Unsupported(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Error(e) => write!(f, "{e}"),
            CodecError::InvalidParameter(e) => write!(f, "invalid parameter: {e}"),
            CodecError::Unsupported(e) => write!(f, "unsupported: {e}"),
        }
    }
}

impl std::error::Error for CodecError {}

impl CodecError {
    fn new<S: Into<String>>(s: S) -> Self {
        CodecError::Error(s.into())
    }
}

/// An encoded audio frame together with the codec that produced it.
///
/// `data` is the raw codec output **including** any codec-internal frame
/// header, but **excluding** the network codec header byte which
/// [`crate::network::Packetizer`] prepends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedFrame {
    pub codec: CodecType,
    pub data: Vec<u8>,
}

/// Codec interface, mirroring the Python `LXST.Codecs.Codec` base class.
///
/// Python codecs are stateful stream processors: `encode` takes decoded
/// samples and returns bytes, `decode` takes bytes and returns decoded
/// samples. Channel counts are frequently discovered lazily from the first
/// frame, which is preserved here.
pub trait Codec: Send {
    /// The codec registry type of this codec.
    fn codec_type(&self) -> CodecType;

    /// Encode one frame of normalised interleaved samples.
    fn encode(&mut self, frame: &AudioFrame) -> Result<Vec<u8>, CodecError>;

    /// Decode one encoded frame.
    fn decode(&mut self, data: &[u8]) -> Result<AudioFrame, CodecError>;

    /// The channel count configured/discovered by this codec.
    fn channels(&self) -> Option<usize>;

    /// Configure the channel count (clamped by the codec where applicable).
    fn set_channels(&mut self, channels: Option<usize>);

    /// Nominal bit depth of the encoded representation.
    fn bitdepth(&self) -> usize {
        16
    }

    /// Samplerate the codec would prefer its input at, if any.
    fn preferred_samplerate(&self) -> Option<u32> {
        None
    }

    /// Samplerate the codec emits/produces (Python `output_samplerate`).
    fn output_samplerate(&self) -> Option<u32> {
        None
    }

    /// Frame duration quantisation, if the codec requires it.
    fn frame_quanta_ms(&self) -> Option<f64> {
        None
    }

    /// Maximum frame duration the codec accepts.
    fn frame_max_ms(&self) -> Option<f64> {
        None
    }

    /// The only valid frame durations, if restricted.
    fn valid_frame_ms(&self) -> Option<Vec<f64>> {
        None
    }

    /// Provide the properties of the sink that frames are decoded into.
    ///
    /// Python codecs read `self.sink.samplerate` / `self.sink.channels`
    /// inside `decode`. Since codecs here are decoupled from sinks, the
    /// pipeline informs them through this hook.
    fn set_sink_params(&mut self, _samplerate: Option<u32>, _channels: Option<usize>) {}

    /// Provide the samplerate of the source feeding the encoder.
    fn set_source_samplerate(&mut self, _samplerate: u32) {}

    /// Internal state reset for tests.
    fn reset(&mut self);
}

/// Create a default codec instance for a registry type (used e.g. when a
/// receiver detects that the remote switched codecs).
///
/// Fails with [`CodecError::Unsupported`] for codecs compiled out of this
/// build. The Python registry would raise `TypeError` when calling the
/// resulting `None`.
pub fn new_codec(t: CodecType) -> Result<Box<dyn Codec>, CodecError> {
    match t {
        CodecType::Raw => Ok(Box::new(Raw::new(None, 16))),
        CodecType::Null => Ok(Box::new(Null::new())),
        #[cfg(feature = "opus")]
        CodecType::Opus => Ok(Box::new(Opus::new())),
        #[cfg(not(feature = "opus"))]
        CodecType::Opus => Err(CodecError::Unsupported(
            "Opus codec requires the `opus` cargo feature".into(),
        )),
        #[cfg(feature = "codec2")]
        CodecType::Codec2 => Ok(Box::new(Codec2::new())),
        #[cfg(not(feature = "codec2"))]
        CodecType::Codec2 => Err(CodecError::Unsupported(
            "Codec2 codec requires the `codec2` cargo feature".into(),
        )),
    }
}

/// Clamp a target frame duration to codec restrictions, mirroring the
/// repeated quantisation/clamping logic found in the Python `codec` setters
/// of `LineSource`, `OpusFileSource`, `ToneSource` and `Mixer`.
///
/// 1. if the codec has a frame quanta, round the target up to a multiple
/// 2. if the codec has a frame maximum, clamp to it
/// 3. if the codec has a list of valid durations, snap to the closest one
pub fn clamp_frame_ms(codec: &dyn Codec, target_frame_ms: f64) -> f64 {
    let mut t = target_frame_ms;
    if let Some(q) = codec.frame_quanta_ms() {
        if q > 0.0 && (t % q) != 0.0 {
            t = (t / q).ceil() * q;
        }
    }
    if let Some(m) = codec.frame_max_ms() {
        if t > m {
            t = m;
        }
    }
    if let Some(valid) = codec.valid_frame_ms() {
        if !valid.is_empty() && !valid.contains(&t) {
            let mut best = valid[0];
            for &v in &valid {
                if (v - t).abs() < (best - t).abs() {
                    best = v;
                }
            }
            t = best;
        }
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_python() {
        assert_eq!(codec_header_byte(CodecType::Raw), Some(0x00));
        assert_eq!(codec_header_byte(CodecType::Opus), Some(0x01));
        assert_eq!(codec_header_byte(CodecType::Codec2), Some(0x02));
        // Python raises TypeError for Null - no mapping exists.
        assert_eq!(codec_header_byte(CodecType::Null), None);

        assert_eq!(codec_type(0x00), Some(CodecType::Raw));
        assert_eq!(codec_type(0x01), Some(CodecType::Opus));
        assert_eq!(codec_type(0x02), Some(CodecType::Codec2));
        assert_eq!(codec_type(0xff), None);
        assert_eq!(codec_type(0x7f), None);
    }

    #[test]
    fn frame_ms_clamping() {
        // Opus-like clamping (values only meaningful with the feature, so
        // emulate with Raw which clamps nothing).
        let raw = Raw::new(None, 16);
        assert_eq!(clamp_frame_ms(&raw, 42.0), 42.0);
    }
}
