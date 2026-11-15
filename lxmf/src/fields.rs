//! LXMF core fields and field-specific specifiers.
//!
//! This module is a byte-for-byte port of the constant definitions and the
//! `fields` dictionary concept found in `LXMF/LXMF/LXMF.py` from the Python
//! LXMF distribution. Since the Python `fields` value is a plain `dict` with
//! insertion-ordered integer keys, the Rust equivalent is [`Fields`], an
//! insertion-ordered map keyed by the one-byte field identifiers defined
//! below. Values are [`FieldValue`]s, a lossless representation of the
//! msgpack types LXMF carries in field values.

use std::{string::String, vec::Vec};

use crate::error::LxmfError;

//////////////////////////////////////////////////////////
// The following core fields are provided to facilitate   //
// interoperability in data exchange between various LXMF //
// clients and systems.                                   //
//////////////////////////////////////////////////////////

/// Embedded LXMF messages.
pub const FIELD_EMBEDDED_LXMS: u8 = 0x01;
/// Telemetry data.
pub const FIELD_TELEMETRY: u8 = 0x02;
/// Telemetry stream data.
pub const FIELD_TELEMETRY_STREAM: u8 = 0x03;
/// Icon appearance data.
pub const FIELD_ICON_APPEARANCE: u8 = 0x04;
/// File attachments.
pub const FIELD_FILE_ATTACHMENTS: u8 = 0x05;
/// Image data.
pub const FIELD_IMAGE: u8 = 0x06;
/// Audio data.
pub const FIELD_AUDIO: u8 = 0x07;
/// Bytes, full thread ID hash
pub const FIELD_THREAD: u8 = 0x08;
/// Commands.
pub const FIELD_COMMANDS: u8 = 0x09;
/// Results.
pub const FIELD_RESULTS: u8 = 0x0A;
/// Group data.
pub const FIELD_GROUP: u8 = 0x0B;
/// Reply ticket `[expires, ticket]`.
pub const FIELD_TICKET: u8 = 0x0C;
/// Event data.
pub const FIELD_EVENT: u8 = 0x0D;
/// RNR references.
pub const FIELD_RNR_REFS: u8 = 0x0E;
/// Renderer specification (see the `RENDERER_*` constants).
pub const FIELD_RENDERER: u8 = 0x0F;
/// Bytes, full LXMessage.hash
/// Bytes, full thread ID hash.
pub const FIELD_REPLY_TO: u8 = 0x30;
/// Bytes, quoted content in UTF-8 encoding
/// Bytes, quoted content in UTF-8 encoding.
pub const FIELD_REPLY_QUOTE: u8 = 0x31;
/// Dict, see "Reaction dict indices" below
/// Dict, see "Reaction dict indices" below.
pub const FIELD_REACTION: u8 = 0x40;
/// Dict, see "Comment dict indices" below
/// Dict, see "Comment dict indices" below.
pub const FIELD_COMMENT: u8 = 0x41;
/// Dict, see "Continuation dict indices" below
/// Dict, see "Continuation dict indices" below.
pub const FIELD_CONTINUATION: u8 = 0x42;

// Unallocated fields between 0x00 and 0x80, both included,
// should be considered reserved for future extensibility
// For experimental and unstable features, it is recommended
// to use fields above 0xFF.

/// Custom embedded data type identifier.
pub const FIELD_CUSTOM_TYPE: u8 = 0xFB;
/// Custom embedded data payload.
pub const FIELD_CUSTOM_DATA: u8 = 0xFC;
/// Custom embedded metadata.
pub const FIELD_CUSTOM_META: u8 = 0xFD;

/// Non-specific, development and testing data.
pub const FIELD_NON_SPECIFIC: u8 = 0xFE;
/// Debug data.
pub const FIELD_DEBUG: u8 = 0xFF;

//////////////////////////////////////////////////////////
// The following section lists field-specific specifiers, //
// modes and identifiers that are native to LXMF.         //
//////////////////////////////////////////////////////////

// Audio modes for the data structure in FIELD_AUDIO

// Codec2 Audio Modes
/// Codec2 audio mode 450PWB.
pub const AM_CODEC2_450PWB: u8 = 0x01;
/// Codec2 audio mode 450.
pub const AM_CODEC2_450: u8 = 0x02;
/// Codec2 audio mode 700C.
pub const AM_CODEC2_700C: u8 = 0x03;
/// Codec2 audio mode 1200.
pub const AM_CODEC2_1200: u8 = 0x04;
/// Codec2 audio mode 1300.
pub const AM_CODEC2_1300: u8 = 0x05;
/// Codec2 audio mode 1400.
pub const AM_CODEC2_1400: u8 = 0x06;
/// Codec2 audio mode 1600.
pub const AM_CODEC2_1600: u8 = 0x07;
/// Codec2 audio mode 2400.
pub const AM_CODEC2_2400: u8 = 0x08;
/// Codec2 audio mode 3200.
pub const AM_CODEC2_3200: u8 = 0x09;

// Opus Audio Modes
/// Opus audio mode, OGG container.
pub const AM_OPUS_OGG: u8 = 0x10;
/// Opus audio mode, low bandwidth.
pub const AM_OPUS_LBW: u8 = 0x11;
/// Opus audio mode, medium bandwidth.
pub const AM_OPUS_MBW: u8 = 0x12;
/// Opus audio mode, push to talk.
pub const AM_OPUS_PTT: u8 = 0x13;
/// Opus audio mode, real-time half duplex.
pub const AM_OPUS_RT_HDX: u8 = 0x14;
/// Opus audio mode, real-time full duplex.
pub const AM_OPUS_RT_FDX: u8 = 0x15;
/// Opus audio mode, standard.
pub const AM_OPUS_STANDARD: u8 = 0x16;
/// Opus audio mode, high quality.
pub const AM_OPUS_HQ: u8 = 0x17;
/// Opus audio mode, broadcast.
pub const AM_OPUS_BROADCAST: u8 = 0x18;
/// Opus audio mode, lossless.
pub const AM_OPUS_LOSSLESS: u8 = 0x19;

/// Custom, unspecified audio mode, the client must
/// determine it itself based on the included data.
pub const AM_CUSTOM: u8 = 0xFF;

// Message renderer specifications for FIELD_RENDERER.
/// Plain text renderer.
pub const RENDERER_PLAIN: u8 = 0x00;
/// Micron renderer.
pub const RENDERER_MICRON: u8 = 0x01;
/// Markdown renderer.
pub const RENDERER_MARKDOWN: u8 = 0x02;
/// BBCode renderer.
pub const RENDERER_BBCODE: u8 = 0x03;

// When using the FIELD_REACTION field, the contents is a dict
// with the following keys:
/// Bytes, full LXMessage.hash
/// Bytes, full LXMessage.hash the reaction refers to.
pub const REACTION_TO: u8 = 0x00;
/// Bytes, the reaction content in UTF-8 encoding
/// Bytes, the reaction content in UTF-8 encoding.
pub const REACTION_CONTENT: u8 = 0x01;

// When using the FIELD_COMMENT field, the contents is a dict
// with the following keys:
/// Bytes, full LXMessage.hash
/// Bytes, full LXMessage.hash the comment refers to.
pub const COMMENT_FOR: u8 = 0x00;

// When using the FIELD_CONTINUATION field, the contents is a
// dict with the following keys:
/// Bytes, full LXMessage.hash
/// Bytes, full LXMessage.hash the message continues.
pub const CONTINUATION_OF: u8 = 0x00;

// Optional propagation node metadata fields.
/// Propagation node metadata: version.
pub const PN_META_VERSION: u8 = 0x00;
/// Propagation node metadata: node name.
pub const PN_META_NAME: u8 = 0x01;
/// Propagation node metadata: sync stratum.
pub const PN_META_SYNC_STRATUM: u8 = 0x02;
/// Propagation node metadata: sync throttling.
pub const PN_META_SYNC_THROTTLE: u8 = 0x03;
/// Propagation node metadata: authorisation band.
pub const PN_META_AUTH_BAND: u8 = 0x04;
/// Propagation node metadata: utilisation pressure.
pub const PN_META_UTIL_PRESSURE: u8 = 0x05;
/// Propagation node metadata: custom entries.
pub const PN_META_CUSTOM: u8 = 0xFF;

// Supported functionality codes for signalling
// feature and capability support.
/// Supported functionality code: resource compression.
pub const SF_COMPRESSION: u8 = 0x00;

/// A single msgpack-compatible value as carried inside LXMF
/// message fields.
///
/// The variants map one-to-one onto the msgpack types produced
/// by the Python reference implementation (RNS' vendored
/// umsgpack) for the data structures LXMF places in fields:
/// nil, booleans, integers, doubles, strings, binaries, arrays
/// and maps.
#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    /// msgpack nil (Python `None`).
    Nil,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Double-precision float (the only float type the Python
    /// implementation produces).
    F64(f64),
    /// UTF-8 string (msgpack `str` family).
    Str(String),
    /// Byte string (msgpack `bin` family).
    Bin(Vec<u8>),
    /// Array.
    Array(Vec<FieldValue>),
    /// Map, with insertion order preserved.
    Map(Vec<(FieldValue, FieldValue)>),
}

impl FieldValue {
    /// Construct a binary value.
    pub fn bin(data: impl Into<Vec<u8>>) -> Self {
        FieldValue::Bin(data.into())
    }

    /// Pack the value into `out` using the exact same msgpack
    /// encoding rules as `RNS.vendor.umsgpack.packb`.
    pub fn pack(&self, out: &mut Vec<u8>) {
        match self {
            FieldValue::Nil => {
                rmp::encode::write_nil(out).ok();
            }
            FieldValue::Bool(b) => {
                rmp::encode::write_bool(out, *b).ok();
            }
            FieldValue::Int(v) => {
                // Python packs with the same minimal encoding rules
                if *v < 0 {
                    rmp::encode::write_sint(out, *v).ok();
                } else {
                    rmp::encode::write_uint(out, *v as u64).ok();
                }
            }
            // The Python reference implementation always packs
            // floating point values as IEEE-754 double precision.
            FieldValue::F64(v) => {
                rmp::encode::write_f64(out, *v).ok();
            }
            FieldValue::Str(s) => {
                rmp::encode::write_str(out, s).ok();
            }
            FieldValue::Bin(b) => {
                rmp::encode::write_bin_len(out, b.len() as u32).ok();
                out.extend_from_slice(b);
            }
            FieldValue::Array(items) => {
                rmp::encode::write_array_len(out, items.len() as u32).ok();
                for item in items {
                    item.pack(out);
                }
            }
            FieldValue::Map(entries) => {
                rmp::encode::write_map_len(out, entries.len() as u32).ok();
                for (key, value) in entries {
                    key.pack(out);
                    value.pack(out);
                }
            }
        }
    }

    /// Unpack a single value from a msgpack byte stream.
    ///
    /// Mirrors `RNS.vendor.umsgpack.unpackb`: 32-bit floats are widened
    /// to doubles (the Python implementation re-packs them as doubles
    /// too), and both `str` and `bin` marker families are preserved as
    /// distinct variants.
    pub fn unpack(rd: &mut &[u8]) -> Result<Self, LxmfError> {
        use rmp::Marker;

        // Peek at the marker without consuming it, then dispatch to the
        // typed rmp reader which validates the marker itself.
        let marker = {
            let mut peek: &[u8] = rd;
            rmp::decode::read_marker(&mut peek).map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?
        };

        match marker {
            // These markers carry no payload bytes; consume the marker
            // itself from the stream (it was only peeked at above).
            Marker::Null => {
                *rd = &rd[1..];
                Ok(FieldValue::Nil)
            }
            Marker::True => {
                *rd = &rd[1..];
                Ok(FieldValue::Bool(true))
            }
            Marker::False => {
                *rd = &rd[1..];
                Ok(FieldValue::Bool(false))
            }
            Marker::F64 => {
                let value =
                    rmp::decode::read_f64(rd).map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?;
                Ok(FieldValue::F64(value))
            }
            Marker::F32 => {
                let value =
                    rmp::decode::read_f32(rd).map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?;
                Ok(FieldValue::F64(value as f64))
            }
            Marker::FixPos(_)
            | Marker::U8
            | Marker::U16
            | Marker::U32
            | Marker::U64
            | Marker::FixNeg(_)
            | Marker::I8
            | Marker::I16
            | Marker::I32
            | Marker::I64 => {
                // read_int accepts any integer marker, mirroring umsgpack
                let value = rmp::decode::read_int::<i64, _>(rd)
                    .map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?;
                Ok(FieldValue::Int(value))
            }
            Marker::FixStr(_) | Marker::Str8 | Marker::Str16 | Marker::Str32 => {
                let len = rmp::decode::read_str_len(rd)
                    .map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?
                    as usize;
                if rd.len() < len {
                    return Err(LxmfError::InvalidFormat);
                }
                let s =
                    String::from_utf8(rd[..len].to_vec()).map_err(|_| LxmfError::InvalidFormat)?;
                *rd = &rd[len..];
                Ok(FieldValue::Str(s))
            }
            Marker::Bin8 | Marker::Bin16 | Marker::Bin32 => {
                let len = rmp::decode::read_bin_len(rd)
                    .map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?
                    as usize;
                if rd.len() < len {
                    return Err(LxmfError::InvalidFormat);
                }
                let b = rd[..len].to_vec();
                *rd = &rd[len..];
                Ok(FieldValue::Bin(b))
            }
            Marker::FixArray(_) | Marker::Array16 | Marker::Array32 => {
                let len = rmp::decode::read_array_len(rd)
                    .map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?
                    as usize;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(FieldValue::unpack(rd)?);
                }
                Ok(FieldValue::Array(items))
            }
            Marker::FixMap(_) | Marker::Map16 | Marker::Map32 => {
                let len = rmp::decode::read_map_len(rd)
                    .map_err(|e| LxmfError::Msgpack(format!("{e:?}")))?
                    as usize;
                // Same bound as arrays: each entry needs at least two
                // input bytes (key + value markers).
                if len.saturating_mul(2) > rd.len() {
                    return Err(LxmfError::InvalidFormat);
                }
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = FieldValue::unpack(rd)?;
                    let value = FieldValue::unpack(rd)?;
                    entries.push((key, value));
                }
                Ok(FieldValue::Map(entries))
            }
            _ => Err(LxmfError::UnsupportedValue),
        }
    }

    /// Borrow the value as binary data, if it is one.
    pub fn as_bin(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Bin(b) => Some(b),
            _ => None,
        }
    }

    /// Borrow the value as an integer, if it is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            FieldValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Borrow the value as a float, if it is one.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            FieldValue::F64(v) => Some(*v),
            _ => None,
        }
    }

    /// Borrow the value as a string, if it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// Insertion-ordered map of LXMF field identifiers to values,
/// the Rust equivalent of the Python `LXMessage.fields` dict.
///
/// Order is significant: it is preserved on the wire, so two
/// implementations that insert the same fields in the same
/// order produce byte-identical packed messages.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Fields {
    entries: Vec<(u8, FieldValue)>,
}

impl Fields {
    /// Create an empty fields map.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a field. As with the Python dict, re-inserting an
    /// existing key replaces the value but keeps the original
    /// insertion position.
    pub fn insert(&mut self, key: u8, value: FieldValue) {
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            entry.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }

    /// Get the value of a field.
    pub fn get(&self, key: u8) -> Option<&FieldValue> {
        self.entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// Remove a field, returning its value.
    pub fn remove(&mut self, key: u8) -> Option<FieldValue> {
        let index = self.entries.iter().position(|(k, _)| *k == key)?;
        Some(self.entries.remove(index).1)
    }

    /// Whether the field is present.
    pub fn contains_key(&self, key: u8) -> bool {
        self.entries.iter().any(|(k, _)| *k == key)
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no fields.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over the fields in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &(u8, FieldValue)> {
        self.entries.iter()
    }

    /// Pack the fields as a msgpack map, in insertion order.
    pub fn pack(&self, out: &mut Vec<u8>) {
        rmp::encode::write_map_len(out, self.entries.len() as u32).ok();
        for (key, value) in &self.entries {
            // Field identifiers are always positive one-byte
            // integers on the wire (msgpack positive fixint).
            rmp::encode::write_uint(out, *key as u64).ok();
            value.pack(out);
        }
    }

    /// Build a `Fields` map from an unpacked msgpack map value. All keys
    /// must be integers that fit into a single byte; anything else is
    /// rejected as an unsupported field identifier.
    pub fn from_value(value: &FieldValue) -> Result<Self, LxmfError> {
        match value {
            FieldValue::Map(entries) => {
                let mut fields = Fields::new();
                for (key, value) in entries {
                    let key = match key {
                        FieldValue::Int(k) if (0..=0xFF).contains(k) => *k as u8,
                        _ => return Err(LxmfError::UnsupportedFieldKey),
                    };
                    fields.insert(key, value.clone());
                }
                Ok(fields)
            }
            _ => Err(LxmfError::InvalidFormat),
        }
    }

    /// Unpack a fields map directly from a msgpack byte stream.
    pub fn unpack(rd: &mut &[u8]) -> Result<Self, LxmfError> {
        let value = FieldValue::unpack(rd)?;
        Self::from_value(&value)
    }
}

impl FromIterator<(u8, FieldValue)> for Fields {
    fn from_iter<T: IntoIterator<Item = (u8, FieldValue)>>(iter: T) -> Self {
        let mut fields = Fields::new();
        for (key, value) in iter {
            fields.insert(key, value);
        }
        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the msgpack marker dispatch: markers without
    /// payload bytes (nil/true/false) must be consumed, and integer
    /// markers of any width must decode through the lenient reader.
    #[test]
    fn decode_marker_families() {
        let cases: Vec<(&str, &str)> = vec![
            (
                "pn announce",
                "97c2ce67748580c3cd0100cd0400931003128101c40954657374204e6f6465",
            ),
            ("delivery announce", "93c40c446973706c6179204e616d650c9100"),
        ];

        for (name, hex) in cases {
            let bytes = crate::from_hex(hex).unwrap();
            match FieldValue::unpack(&mut bytes.as_slice()) {
                Ok(value) => println!("{name}: {value:?}"),
                Err(e) => panic!("{name}: {e:?}"),
            }
        }

        // Full helper round-trip on the propagation node fixture
        let pn = crate::from_hex("97c2ce67748580c3cd0100cd0400931003128101c40954657374204e6f6465")
            .unwrap();
        let info = crate::pn_announce_data_from_app_data(Some(&pn))
            .expect("pn announce data must be valid");
        assert_eq!(info.timebase, 1735689600);
        assert_eq!(
            crate::pn_name_from_app_data(Some(&pn)).as_deref(),
            Some("Test Node")
        );
    }
}
