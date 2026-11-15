//! # LXST for Reticulum-rs
//!
//! A Rust port of the [LXST](https://github.com/markqvist/LXST) Python package:
//! low-latency audio streaming, calls and telephony over
//! [Reticulum](https://reticulum.network).
//!
//! ## Module map (mirrors the Python package layout)
//!
//! | Python module        | Rust module                    |
//! |----------------------|--------------------------------|
//! | `LXST/__init__.py`   | [`APP_NAME`] here              |
//! | `Common.py`          | [`common`] (`nop`, `AudioFrame`)|
//! | `Codecs/`            | [`codecs`]                     |
//! | `Network.py`         | [`network`]                    |
//! | `Pipeline.py`        | [`pipeline`]                   |
//! | `Sources.py`         | [`sources`]                    |
//! | `Sinks.py`           | [`sinks`]                      |
//! | `Mixer.py`           | [`mixer`]                      |
//! | `Filters.py`         | [`filters`]                    |
//! | `Processing.py`      | [`processing`]                 |
//! | `Generators.py`      | [`generators`]                 |
//! | `Call.py`            | [`call`]                       |
//! | `Primitives/`        | not ported (OS audio/hardware) |
//! | `Platforms/`         | not ported (OS audio/hardware) |
//!
//! ## Frame data model
//!
//! The Python package passes `numpy` arrays of shape `(samples, channels)`
//! holding normalised `float32` samples in `[-1.0, 1.0]` between pipeline
//! stages, and opaque `bytes` between a codec and a remote sink. This port
//! uses:
//!
//! * [`common::AudioFrame`] - interleaved `Vec<f32>` samples plus a channel
//!   count, for all decoded audio.
//! * [`codecs::EncodedFrame`] - opaque codec bytes plus the
//!   [`codecs::CodecType`] that produced them, for all encoded audio.
//!
//! Everything audio/DSP related is decoupled from the transport; only
//! [`network`], and the transport plumbing of [`call`], depend on the
//! `reticulum` crate.
//!
//! ## Async structure
//!
//! The Python package is threaded (ingest/digest/mixer jobs). This port is
//! async on tokio: [`pipeline::Pipeline`] pulls frames from a
//! [`sources::Source`] and pushes them into a [`sinks::Sink`], and network
//! endpoints bridge reticulum link events into tokio channels.

pub mod call;
pub mod codecs;
pub mod common;
pub mod filters;
pub mod generators;
pub mod mixer;
pub mod network;
pub mod pipeline;
pub mod processing;
pub mod sinks;
pub mod sources;

/// The LXST application name, used to derive destination names
/// (Python `LXST.APP_NAME`).
pub const APP_NAME: &str = "lxst";

pub use codecs::{Codec, CodecError, CodecType, EncodedFrame};
pub use common::{AudioFrame, SourceId};

/// Error type shared by the pipeline, network and call layers.
#[derive(Debug)]
pub enum LxstError {
    /// A codec failed to encode or decode a frame.
    Codec(CodecError),
    /// A codec type was requested that is not available in this build
    /// (feature not enabled).
    UnsupportedCodec(CodecType),
    /// The wire format was violated (bad msgpack, bad frame header, ...).
    WireFormat(String),
    /// A network endpoint was used in the wrong state.
    InvalidState(String),
    /// No active link was available for the operation.
    NoLink,
    /// Transport-level failure.
    Transport(String),
    /// An I/O failure (files, audio devices).
    Io(std::io::Error),
}

impl std::fmt::Display for LxstError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LxstError::Codec(e) => write!(f, "codec error: {e}"),
            LxstError::UnsupportedCodec(t) => write!(
                f,
                "codec {t:?} is not available (enable the corresponding cargo feature)"
            ),
            LxstError::WireFormat(e) => write!(f, "wire format error: {e}"),
            LxstError::InvalidState(e) => write!(f, "invalid state: {e}"),
            LxstError::NoLink => write!(f, "no active link for the operation"),
            LxstError::Transport(e) => write!(f, "transport error: {e}"),
            LxstError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for LxstError {}

impl From<CodecError> for LxstError {
    fn from(e: CodecError) -> Self {
        LxstError::Codec(e)
    }
}

impl From<std::io::Error> for LxstError {
    fn from(e: std::io::Error) -> Self {
        LxstError::Io(e)
    }
}

impl From<hound::Error> for LxstError {
    fn from(e: hound::Error) -> Self {
        LxstError::Io(std::io::Error::other(format!("wav error: {e}")))
    }
}
