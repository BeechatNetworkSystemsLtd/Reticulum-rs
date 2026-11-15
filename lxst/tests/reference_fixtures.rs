//! Byte-exactness tests against fixtures produced by the Python LXST
//! package.
//!
//! The fixtures are (re)generated with:
//!
//! ```text
//! PYTHONPATH=../Reticulum:../LXST python3 fixtures/gen_fixtures.py
//! ```
//!
//! and live in `fixtures/reference.json`.

use std::collections::HashMap;

use lxst::codecs::{codec_header_byte, codec_type, new_codec, Codec, CodecType, Null, Raw};
use lxst::common::AudioFrame;
use lxst::network::{
    pack_frame, pack_frames, pack_signalling, unpack_message, FIELD_FRAMES, FIELD_SIGNALLING,
};

/// Minimal JSON value type (avoids pulling serde_json into the crate deps;
/// it is only needed here, so it lives in dev-dependencies and is parsed by
/// hand for the handful of shapes the fixtures use).
#[derive(Debug, Clone)]
enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &str) -> Json {
        let mut chars = text.chars().peekable();
        parse_value(&mut chars)
    }

    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> &str {
        match self {
            Json::Str(s) => s,
            _ => panic!("expected string"),
        }
    }

    fn as_num(&self) -> f64 {
        match self {
            Json::Num(n) => *n,
            _ => panic!("expected number"),
        }
    }

    fn as_bool(&self) -> bool {
        match self {
            Json::Bool(b) => *b,
            _ => panic!("expected bool"),
        }
    }

    fn as_arr(&self) -> &[Json] {
        match self {
            Json::Arr(a) => a,
            _ => panic!("expected array"),
        }
    }

    fn as_obj(&self) -> &[(String, Json)] {
        match self {
            Json::Obj(o) => o,
            _ => panic!("expected object"),
        }
    }
}

fn parse_value(chars: &mut std::iter::Peekable<std::str::Chars>) -> Json {
    skip_ws(chars);
    match chars.peek().expect("value") {
        '{' => {
            chars.next();
            let mut entries = Vec::new();
            skip_ws(chars);
            if chars.peek() == Some(&'}') {
                chars.next();
                return Json::Obj(entries);
            }
            loop {
                skip_ws(chars);
                let key = parse_string(chars);
                skip_ws(chars);
                assert_eq!(chars.next(), Some(':'));
                let value = parse_value(chars);
                entries.push((key, value));
                skip_ws(chars);
                match chars.next() {
                    Some(',') => continue,
                    Some('}') => break,
                    other => panic!("unexpected {other:?} in object"),
                }
            }
            Json::Obj(entries)
        }
        '[' => {
            chars.next();
            let mut items = Vec::new();
            skip_ws(chars);
            if chars.peek() == Some(&']') {
                chars.next();
                return Json::Arr(items);
            }
            loop {
                let value = parse_value(chars);
                items.push(value);
                skip_ws(chars);
                match chars.next() {
                    Some(',') => continue,
                    Some(']') => break,
                    other => panic!("unexpected {other:?} in array"),
                }
            }
            Json::Arr(items)
        }
        '"' => Json::Str(parse_string(chars)),
        't' => {
            for c in "true".chars() {
                assert_eq!(chars.next(), Some(c));
            }
            Json::Bool(true)
        }
        'f' => {
            for c in "false".chars() {
                assert_eq!(chars.next(), Some(c));
            }
            Json::Bool(false)
        }
        'n' => {
            for c in "null".chars() {
                assert_eq!(chars.next(), Some(c));
            }
            Json::Null
        }
        _ => {
            let mut num = String::new();
            while let Some(c) = chars.peek() {
                if c.is_ascii_digit()
                    || *c == '-'
                    || *c == '+'
                    || *c == '.'
                    || *c == 'e'
                    || *c == 'E'
                {
                    num.push(*c);
                    chars.next();
                } else {
                    break;
                }
            }
            Json::Num(num.parse().expect("number"))
        }
    }
}

fn parse_string(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    assert_eq!(chars.next(), Some('"'));
    let mut out = String::new();
    loop {
        match chars.next().expect("string end") {
            '"' => break,
            '\\' => match chars.next().expect("escape") {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'u' => {
                    let mut code = String::new();
                    for _ in 0..4 {
                        code.push(chars.next().expect("hex"));
                    }
                    let v = u32::from_str_radix(&code, 16).expect("hex");
                    out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                }
                other => panic!("bad escape {other}"),
            },
            c => out.push(c),
        }
    }
    out
}

fn skip_ws(chars: &mut std::iter::Peekable<std::str::Chars>) {
    while let Some(c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else {
            break;
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex byte"))
        .collect()
}

/// Rebuild an input frame from its float32 bytes.
fn input_frame(fixture: &Json, name: &str) -> AudioFrame {
    let input = fixture.get("inputs").unwrap().get(name).unwrap();
    let bytes = unhex(input.get("float32_hex").unwrap().as_str());
    let samples: Vec<f32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| f32::from_le_bytes(*c))
        .collect();
    AudioFrame::from_interleaved(samples, input.get("channels").unwrap().as_num() as usize)
}

fn load_fixture() -> Json {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/reference.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    Json::parse(&text)
}

//***************************************************************************//

#[test]
fn codec_header_bytes_match_python() {
    let fixture = load_fixture();
    let headers = fixture.get("codec_headers").unwrap();

    assert_eq!(
        codec_header_byte(CodecType::Raw),
        Some(headers.get("raw").unwrap().as_num() as u8)
    );
    assert_eq!(
        codec_header_byte(CodecType::Opus),
        Some(headers.get("opus").unwrap().as_num() as u8)
    );
    assert_eq!(
        codec_header_byte(CodecType::Codec2),
        Some(headers.get("codec2").unwrap().as_num() as u8)
    );
    // Python defines NULL = 0xFF but has no packet mapping for it.
    assert_eq!(
        codec_header_byte(CodecType::Null),
        None,
        "Python codec_header_byte(Null) raises TypeError"
    );
}

#[test]
fn codec_type_lookup_matches_python() {
    let fixture = load_fixture();
    let map = fixture.get("codec_type_map").unwrap();

    let mut expected: HashMap<String, bool> = HashMap::new();
    for (k, v) in map.as_obj() {
        expected.insert(k.clone(), v.as_bool());
    }

    for (key, byte) in [
        ("0x00", 0x00u8),
        ("0x01", 0x01),
        ("0x02", 0x02),
        ("0xff", 0xff),
        ("0x7f", 0x7f),
    ] {
        let found = codec_type(byte).is_some();
        let want = *expected.get(key).unwrap();
        assert_eq!(
            found, want,
            "codec_type({key}) resolved={found}, python={want}"
        );
    }
}

#[test]
fn raw_encode_is_byte_exact() {
    let fixture = load_fixture();

    for entry in fixture.get("raw_encode").unwrap().as_arr() {
        let name = entry.get("frame").unwrap().as_str();
        let bitdepth = entry.get("bitdepth").unwrap().as_num() as u32;
        let channels = entry.get("channels").unwrap().as_num() as usize;
        let expected = unhex(entry.get("hex").unwrap().as_str());

        let input = input_frame(&fixture, name);
        // The Python codec was constructed with an explicit channel count,
        // so mirror that (except for the "default" entry which passes None).
        let note = entry.get("note").is_some();
        let mut codec = if note {
            Raw::new(None, bitdepth)
        } else {
            Raw::new(Some(channels), bitdepth)
        };

        let encoded = codec.encode(&input).expect("encode");
        if bitdepth >= 128 {
            // numpy float128 is the x87 80-bit format in a 16-byte
            // container: the 10 value bytes are deterministic, the 6
            // trailing padding bytes are UNINITIALISED in numpy, so only the
            // value bytes can be compared.
            assert_eq!(encoded.len(), expected.len(), "frame={name}");
            for (i, (a, b)) in encoded[1..]
                .as_chunks::<16>()
                .0
                .iter()
                .zip(expected[1..].as_chunks::<16>().0)
                .enumerate()
            {
                assert_eq!(&a[..10], &b[..10], "frame={name} sample {i}");
            }
        } else {
            assert_eq!(
                encoded, expected,
                "frame={name} bitdepth={bitdepth} channels={channels}"
            );
        }
    }
}

#[test]
fn raw_bitdepth_selection_matches_python() {
    let fixture = load_fixture();
    let map = fixture.get("bitdepth_map").unwrap();

    let expected_header: HashMap<u32, u8> = map
        .as_obj()
        .iter()
        .map(|(k, v)| {
            (
                k.parse::<u32>().unwrap(),
                v.get("header_bitdepth").unwrap().as_num() as u8,
            )
        })
        .collect();

    for bitdepth in [0u32, 15, 16, 31, 32, 63, 64, 127, 128, 256] {
        let codec = Raw::new(Some(1), bitdepth);
        assert_eq!(
            codec.frame_header() >> 6,
            *expected_header.get(&bitdepth).unwrap(),
            "bitdepth {bitdepth}"
        );
    }
}

#[test]
fn raw_channel_clamping_matches_python() {
    let fixture = load_fixture();
    let clamps = fixture.get("channel_clamp").unwrap();

    for (key, value) in clamps.as_obj() {
        let requested = key.parse::<usize>().unwrap();
        let expected = value.as_num() as usize;
        let codec = Raw::new(Some(requested), 32);
        assert_eq!(
            codec.channels(),
            Some(expected),
            "Raw(channels={requested})"
        );
    }
}

#[test]
fn raw_decode_roundtrip_matches_python_dtypes() {
    let fixture = load_fixture();

    for entry in fixture.get("raw_decode").unwrap().as_arr() {
        let bitdepth = entry.get("bitdepth").unwrap().as_num() as u32;
        let input = input_frame(&fixture, "2ch");

        let mut encoder = Raw::new(Some(2), bitdepth);
        let encoded = encoder.encode(&input).unwrap();

        let mut decoder = Raw::new(None, 16);
        let decoded = decoder.decode(&encoded).unwrap();

        assert_eq!(decoded.channels, 2);
        assert_eq!(decoded.frames(), input.frames());

        // decoded values round-trip within the precision of the format
        let tolerance = match bitdepth {
            16 => 6e-4,
            _ => 1e-7,
        };
        for (a, b) in decoded.samples.iter().zip(input.samples.iter()) {
            assert!(
                (a - b).abs() <= tolerance,
                "bitdepth {bitdepth}: {a} vs {b}"
            );
        }
    }
}

#[test]
fn null_codec_passthrough_bytes() {
    let fixture = load_fixture();
    let passthrough = fixture.get("null_passthrough").unwrap();
    let expected = unhex(passthrough.get("encode_hex").unwrap().as_str());

    let input = input_frame(&fixture, "1ch");
    let mut null = Null::new();
    let encoded = null.encode(&input).unwrap();

    // Python's Null returns the numpy float32 buffer unchanged, so the
    // Rust port must emit the same interleaved f32 bytes.
    assert_eq!(encoded, expected);
}

//***************************************************************************//
// msgpack wire format
//***************************************************************************//

#[test]
fn msgpack_frames_match_umsgpack() {
    let fixture = load_fixture();

    for entry in fixture.get("msgpack").unwrap().as_arr() {
        let name = entry.get("name").unwrap().as_str();
        let expected = unhex(entry.get("hex").unwrap().as_str());

        match name {
            "frame_single" => {
                let mut raw = Raw::new(Some(1), 32);
                let frame = raw.encode(&input_frame(&fixture, "1ch")).unwrap();
                let packed = pack_frame(&frame).unwrap();
                assert_eq!(packed, expected, "case {name}");
            }
            "signal_single" => {
                let packed = pack_signalling(&[2]).unwrap();
                assert_eq!(packed, expected, "case {name}");
            }
            "signal_multi" => {
                let packed = pack_signalling(&[0, 1, 2]).unwrap();
                assert_eq!(packed, expected, "case {name}");
            }
            "signal_not_list" => {
                // The encoder always emits a list; receivers must accept a
                // bare value too. Assert decode-side behaviour here.
                let msg = unpack_message(&expected).unwrap();
                assert_eq!(msg.signals, vec![2]);
                assert!(msg.frames.is_empty());
            }
            "frames_list" => {
                let mut raw = Raw::new(Some(1), 32);
                let frame = raw.encode(&input_frame(&fixture, "1ch")).unwrap();
                let packed = pack_frames(&[frame.clone(), frame]).unwrap();
                assert_eq!(packed, expected, "case {name}");
            }
            "bin_size_boundaries" => {
                let payload = vec![0x40u8; 255];
                let packed = pack_frame(&payload).unwrap();
                assert_eq!(&packed[..expected.len()], &expected[..]);
                // bin8 marker at 255 bytes
                assert_eq!(&packed[..4], &[0x81, FIELD_FRAMES, 0xc4, 0xff]);
            }
            "bin_size_boundary_256" => {
                let payload = vec![0x40u8; 256];
                let packed = pack_frame(&payload).unwrap();
                // bin16 marker at 256 bytes
                assert_eq!(&packed[..5], &[0x81, FIELD_FRAMES, 0xc5, 0x01, 0x00]);
            }
            "unknown_key_ignored" => {
                let msg = unpack_message(&expected).unwrap();
                assert_eq!(msg.frames.len(), 1);
                // the unknown key 0x05 is dropped
                assert!(msg.signals.is_empty());
            }
            "not_a_map" => {
                let msg = unpack_message(&expected).unwrap();
                assert!(msg.is_empty());
            }
            other => panic!("unhandled fixture case {other}"),
        }
    }
}

#[test]
fn msgpack_roundtrip_all_fields() {
    let mut raw = Raw::new(Some(2), 64);
    let frame = raw
        .encode(&AudioFrame::from_interleaved(vec![0.5, -0.5], 2))
        .unwrap();

    let packed = pack_frames(&[frame.clone(), frame]).unwrap();
    let msg = unpack_message(&packed).unwrap();
    assert_eq!(msg.frames.len(), 2);
    assert_eq!(msg.frames[0].as_slice(), msg.frames[1].as_slice());

    // Combined signalling and frames in one packet (the Python receiver
    // handles both fields of the same dict).
    let expected = msg.frames[0].clone();
    let frames = pack_frames(std::slice::from_ref(&expected)).unwrap();
    // rebuild manually: {0x00: [3], 0x01: [frame]}
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 2).unwrap();
    rmp::encode::write_pfix(&mut buf, FIELD_SIGNALLING).unwrap();
    rmp::encode::write_array_len(&mut buf, 1).unwrap();
    rmp::encode::write_pfix(&mut buf, 3).unwrap();
    rmp::encode::write_pfix(&mut buf, FIELD_FRAMES).unwrap();
    buf.extend_from_slice(&frames[3..]); // skip the map header of `frames`

    let msg = unpack_message(&buf).unwrap();
    assert_eq!(msg.signals, vec![3]);
    assert_eq!(msg.frames, vec![expected]);
}

#[test]
fn signals_above_fixint_range_are_rejected() {
    // Python's packer writes fixints; codes >= 0x80 are not representable
    // in the signalling array the Python receiver expects.
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 1).unwrap();
    rmp::encode::write_pfix(&mut buf, FIELD_SIGNALLING).unwrap();
    rmp::encode::write_array_len(&mut buf, 1).unwrap();
    rmp::encode::write_uint(&mut buf, 0xff).unwrap();
    assert!(unpack_message(&buf).is_err());
}

#[test]
fn truncated_and_garbage_payloads() {
    // empty payload decodes to an empty message
    assert!(unpack_message(&[]).unwrap().is_empty());
    // truncated bin
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 1).unwrap();
    rmp::encode::write_pfix(&mut buf, FIELD_FRAMES).unwrap();
    rmp::encode::write_bin(&mut buf, &[1, 2, 3, 4]).unwrap();
    buf.truncate(buf.len() - 2);
    assert!(unpack_message(&buf).is_err());
}

//***************************************************************************//
// registry behaviour
//***************************************************************************//

#[test]
fn registry_creates_available_codecs() {
    assert_eq!(
        new_codec(CodecType::Raw).unwrap().codec_type(),
        CodecType::Raw
    );
    assert_eq!(
        new_codec(CodecType::Null).unwrap().codec_type(),
        CodecType::Null
    );

    // Opus / Codec2 depend on cargo features
    match new_codec(CodecType::Opus) {
        Ok(c) => assert_eq!(c.codec_type(), CodecType::Opus),
        Err(e) => {
            assert!(format!("{e}").contains("feature"), "{e}");
        }
    }
}
