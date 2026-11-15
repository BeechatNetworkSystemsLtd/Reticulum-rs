//! LXMF error type.

use std::string::String;

/// Errors produced while creating, packing, unpacking or routing
/// LXMF messages.
#[derive(Debug)]
pub enum LxmfError {
    /// The packed representation was malformed and could not be parsed.
    InvalidFormat,
    /// A msgpack encoding or decoding error.
    Msgpack(String),
    /// A field dictionary key was not a one-byte integer identifier.
    UnsupportedFieldKey,
    /// A msgpack type that LXMF does not model was encountered.
    UnsupportedValue,
    /// Attempted to pack an already-packed message.
    AlreadyPacked,
    /// Attempted to access packing results before packing.
    NotPacked,
    /// The desired delivery method is not supported here.
    UnsupportedMethod,
    /// Message content exceeds the size limit of the desired delivery method.
    ContentTooLarge(String),
    /// A cryptographic operation failed (encryption or decryption).
    Crypto(String),
    /// The destination identity is unknown, so a path or link cannot be
    /// established yet.
    PathUnknown,
    /// An RNS-level error surfaced by the underlying transport.
    Reticulum(reticulum_core::error::RnsError),
    /// An I/O error from the message store.
    Io(std::io::Error),
}

impl core::fmt::Display for LxmfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LxmfError::InvalidFormat => write!(f, "invalid LXMF data format"),
            LxmfError::Msgpack(e) => write!(f, "msgpack error: {e}"),
            LxmfError::UnsupportedFieldKey => {
                write!(f, "unsupported field key (must be a one-byte integer)")
            }
            LxmfError::UnsupportedValue => write!(f, "unsupported msgpack value type"),
            LxmfError::AlreadyPacked => write!(f, "LXMessage is already packed"),
            LxmfError::NotPacked => write!(f, "LXMessage is not packed yet"),
            LxmfError::UnsupportedMethod => write!(f, "unsupported LXMF delivery method"),
            LxmfError::ContentTooLarge(what) => write!(f, "content too large: {what}"),
            LxmfError::Crypto(e) => write!(f, "cryptographic error: {e}"),
            LxmfError::PathUnknown => write!(f, "path to destination is unknown"),
            LxmfError::Reticulum(e) => write!(f, "reticulum error: {e:?}"),
            LxmfError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for LxmfError {}

impl From<std::io::Error> for LxmfError {
    fn from(e: std::io::Error) -> Self {
        LxmfError::Io(e)
    }
}

impl From<reticulum_core::error::RnsError> for LxmfError {
    fn from(e: reticulum_core::error::RnsError) -> Self {
        LxmfError::Reticulum(e)
    }
}
