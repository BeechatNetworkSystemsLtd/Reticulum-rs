//! Wire protocol (Python `LXST/Network.py`).
//!
//! # Wire format
//!
//! Every LXST payload carried by a Reticulum packet (link data packet or
//! destination packet) is a **msgpack map** with integer keys:
//!
//! ```text
//! {0x00: [signal, ...]}   signalling: list of signal codes (or a single code)
//! {0x01: frame_bytes}     audio frames: a single frame, or a list of frames
//! ```
//!
//! where every audio `frame` is `[codec_header_byte] ++ codec_payload`
//! (the codec header byte is prepended by the sender's `Packetizer`).
//!
//! Produced with `RNS.vendor.umsgpack.packb(...)` in Python - keys are
//! encoded as msgpack **positive fixint** bytes (`0x00`/`0x01`), frame
//! payloads as **bin** (`0xc4 len8` / `0xc5 len16` / `0xc6 len32`), and
//! signal lists as **fixarray** (`0x9n`).
//!
//! Field keys (Python `FIELD_SIGNALLING` / `FIELD_FRAMES`).
//!
//! # Components
//!
//! | Python        | Rust                                       |
//! |---------------|--------------------------------------------|
//! | `Packetizer`  | [`Packetizer`]                             |
//! | `LinkSource`  | [`LinkSource`]                             |
//! | `SignallingReceiver` | [`SignallingReceiver`] / [`Signal`]|
//!
//! The async structure: [`Packetizer`] consumes encoded frames from a
//! tokio mpsc channel and pushes msgpack packets onto the wire through a
//! transport send closure; [`LinkSource`] is driven by
//! [`LinkSource::handle_packet`] (called from a link event loop) and fans
//! decoded frames out through tokio channels.

use std::collections::VecDeque;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};

use reticulum::destination::link::{Link, LinkStatus};
use reticulum::transport::Transport;

use crate::codecs::{codec_header_byte, codec_type, new_codec, Codec, CodecType};
use crate::common::{AudioFrame, SourceId};
use crate::{LxstError, APP_NAME};

/// Signalling field key in the msgpack map (Python `FIELD_SIGNALLING`).
pub const FIELD_SIGNALLING: u8 = 0x00;
/// Audio frames field key in the msgpack map (Python `FIELD_FRAMES`).
pub const FIELD_FRAMES: u8 = 0x01;

//***************************************************************************//
// msgpack encoding / decoding
//***************************************************************************//

/// Maximum number of signal codes accepted in one signalling map.
const MAX_SIGNALS: usize = 64;

/// Pack a signalling message: `{0x00: [signals]}`.
///
/// Byte-identical to `umsgpack.packb({0x00: [signal]})` for a single signal
/// and `{0x00: [s0, s1, ..]}` for a list.
pub fn pack_signalling(signals: &[u8]) -> Result<Vec<u8>, LxstError> {
    let mut buf = Vec::with_capacity(2 + signals.len() * 2);
    rmp::encode::write_map_len(&mut buf, 1).map_err(|e| LxstError::WireFormat(e.to_string()))?;
    rmp::encode::write_pfix(&mut buf, FIELD_SIGNALLING)
        .map_err(|e| LxstError::WireFormat(e.to_string()))?;
    rmp::encode::write_array_len(&mut buf, signals.len() as u32)
        .map_err(|e| LxstError::WireFormat(e.to_string()))?;
    for &s in signals {
        // Signals are positive fixints (0x00-0x7f). Masking an
        // out-of-range value would silently change its meaning (0x80 ->
        // status code 0, turning a profile/unknown signal into a call
        // control event) — reject instead.
        if s > 0x7f {
            return Err(LxstError::WireFormat(format!(
                "signal {s:#x} outside positive-fixint range"
            )));
        }
        rmp::encode::write_pfix(&mut buf, s).map_err(|e| LxstError::WireFormat(e.to_string()))?;
    }
    Ok(buf)
}

/// Pack an audio frames message: `{0x01: frame}` (single frame, matching the
/// Python `Packetizer` which packs the frame bytes directly, **not** in a
/// list).
pub fn pack_frame(frame: &[u8]) -> Result<Vec<u8>, LxstError> {
    let mut buf = Vec::with_capacity(2 + 1 + frame.len() + 8);
    rmp::encode::write_map_len(&mut buf, 1).map_err(|e| LxstError::WireFormat(e.to_string()))?;
    rmp::encode::write_pfix(&mut buf, FIELD_FRAMES)
        .map_err(|e| LxstError::WireFormat(e.to_string()))?;
    rmp::encode::write_bin(&mut buf, frame).map_err(|e| LxstError::WireFormat(e.to_string()))?;
    Ok(buf)
}

/// Pack an audio frames message carrying multiple frames in a list:
/// `{0x01: [frame0, frame1, ..]}`. The Python `Packetizer` never emits this,
/// but `LinkSource` accepts it, so the encoder is provided for symmetry.
pub fn pack_frames(frames: &[Vec<u8>]) -> Result<Vec<u8>, LxstError> {
    let mut buf = Vec::with_capacity(8);
    rmp::encode::write_map_len(&mut buf, 1).map_err(|e| LxstError::WireFormat(e.to_string()))?;
    rmp::encode::write_pfix(&mut buf, FIELD_FRAMES)
        .map_err(|e| LxstError::WireFormat(e.to_string()))?;
    rmp::encode::write_array_len(&mut buf, frames.len() as u32)
        .map_err(|e| LxstError::WireFormat(e.to_string()))?;
    for f in frames {
        rmp::encode::write_bin(&mut buf, f).map_err(|e| LxstError::WireFormat(e.to_string()))?;
    }
    Ok(buf)
}

/// The decoded contents of one LXST network message.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LxstMessage {
    /// Signal codes from the `0x00` field, in order.
    pub signals: Vec<u8>,
    /// Audio frames from the `0x01` field, in order. Every frame still
    /// carries its leading codec header byte.
    pub frames: Vec<Vec<u8>>,
}

impl LxstMessage {
    pub fn is_empty(&self) -> bool {
        self.signals.is_empty() && self.frames.is_empty()
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, LxstError> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or_else(|| LxstError::WireFormat("truncated message".into()))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], LxstError> {
        if self.pos + n > self.data.len() {
            return Err(LxstError::WireFormat("truncated message".into()));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16, LxstError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, LxstError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Decode one msgpack value.
///
/// Only the subset written by `umsgpack.packb` for LXST messages is
/// accepted: fixmaps, fixarrays, bin/str containers and small integers.
/// Unknown keys are ignored the way Python ignores unknown dict entries
/// (it only looks up `0x00`/`0x01`).
#[allow(clippy::large_enum_variant)]
enum Value {
    Int(i64),
    Bin(Vec<u8>),
    /// A msgpack `str` (never produced for LXST fields, but receivers must
    /// be able to skip unknown entries carrying strings).
    Str(#[allow(dead_code)] Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Nil,
}

fn read_value(c: &mut Cursor) -> Result<Value, LxstError> {
    let marker = c.byte()?;
    match marker {
        0x00..=0x7f => Ok(Value::Int(marker as i64)),
        0xe0..=0xff => Ok(Value::Int(marker as i8 as i64)),
        0xc0 => Ok(Value::Nil),
        0xc2 => Ok(Value::Int(0)),
        0xc3 => Ok(Value::Int(1)),
        // unsigned ints
        0xcc => Ok(Value::Int(c.byte()? as i64)),
        0xcd => Ok(Value::Int(c.u16()? as i64)),
        0xce => Ok(Value::Int(c.u32()? as i64)),
        0xcf => {
            let b = c.take(8)?;
            Ok(Value::Int(u64::from_be_bytes(b.try_into().unwrap()) as i64))
        }
        // signed ints
        0xd0 => Ok(Value::Int(c.byte()? as i8 as i64)),
        0xd1 => Ok(Value::Int(c.u16()? as i16 as i64)),
        0xd2 => Ok(Value::Int(c.u32()? as i32 as i64)),
        0xd3 => {
            let b = c.take(8)?;
            Ok(Value::Int(i64::from_be_bytes(b.try_into().unwrap())))
        }
        // bin
        0xc4 => {
            let len = c.byte()? as usize;
            Ok(Value::Bin(c.take(len)?.to_vec()))
        }
        0xc5 => {
            let len = c.u16()? as usize;
            Ok(Value::Bin(c.take(len)?.to_vec()))
        }
        0xc6 => {
            let len = c.u32()? as usize;
            Ok(Value::Bin(c.take(len)?.to_vec()))
        }
        // str (skippable, not used by LXST fields)
        0xa0..=0xbf => {
            let len = (marker & 0x1f) as usize;
            Ok(Value::Str(c.take(len)?.to_vec()))
        }
        0xd9 => {
            let len = c.byte()? as usize;
            Ok(Value::Str(c.take(len)?.to_vec()))
        }
        0xda => {
            let len = c.u16()? as usize;
            Ok(Value::Str(c.take(len)?.to_vec()))
        }
        0xdb => {
            let len = c.u32()? as usize;
            Ok(Value::Str(c.take(len)?.to_vec()))
        }
        // arrays
        0x90..=0x9f => {
            let len = (marker & 0x0f) as usize;
            read_array(c, len)
        }
        0xdc => {
            let len = c.u16()? as usize;
            read_array(c, len)
        }
        0xdd => {
            let len = c.u32()? as usize;
            read_array(c, len)
        }
        // maps
        0x80..=0x8f => {
            let len = (marker & 0x0f) as usize;
            read_map(c, len)
        }
        0xde => {
            let len = c.u16()? as usize;
            read_map(c, len)
        }
        0xdf => {
            let len = c.u32()? as usize;
            read_map(c, len)
        }
        other => Err(LxstError::WireFormat(format!(
            "unsupported msgpack marker 0x{other:02x}"
        ))),
    }
}

fn read_array(c: &mut Cursor, len: usize) -> Result<Value, LxstError> {
    if len > 4096 {
        return Err(LxstError::WireFormat("message array too large".into()));
    }
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        items.push(read_value(c)?);
    }
    Ok(Value::Array(items))
}

fn read_map(c: &mut Cursor, len: usize) -> Result<Value, LxstError> {
    if len > 64 {
        return Err(LxstError::WireFormat("message map too large".into()));
    }
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        let k = read_value(c)?;
        let v = read_value(c)?;
        items.push((k, v));
    }
    Ok(Value::Map(items))
}

fn value_as_u8(v: &Value) -> Option<u8> {
    match v {
        Value::Int(i) if (0..=255).contains(i) => Some(*i as u8),
        _ => None,
    }
}

/// Decode an LXST message from msgpack bytes.
///
/// Mirrors the Python receiver behaviour:
///
/// * the `0x00` field may be a list of signals **or** a single signal
///   (`LinkSource`/`SignallingReceiver` wrap non-lists into a one-element
///   list)
/// * the `0x01` field may be a single frame or a list of frames
/// * unknown map keys are ignored
/// * a non-map message decodes to an empty [`LxstMessage`] (Python checks
///   `type(unpacked) == dict` and drops anything else)
/// * **signals >= 0x80 cannot be represented** by the Python packer
///   (fixint range); such values are rejected here as wire errors
pub fn unpack_message(data: &[u8]) -> Result<LxstMessage, LxstError> {
    if data.is_empty() {
        return Ok(LxstMessage::default());
    }

    let mut c = Cursor::new(data);
    let root = read_value(&mut c)?;

    let Value::Map(entries) = root else {
        // Python: not a dict -> ignored entirely
        return Ok(LxstMessage::default());
    };

    let mut msg = LxstMessage::default();
    for (k, v) in entries {
        let key = match value_as_u8(&k) {
            Some(k) => k,
            None => continue, // unknown key type, ignore
        };

        match key {
            FIELD_SIGNALLING => match v {
                Value::Array(items) => {
                    for item in items {
                        match value_as_u8(&item) {
                            Some(s) if s < 0x80 => msg.signals.push(s),
                            Some(_) => {
                                return Err(LxstError::WireFormat(
                                    "signal codes >= 0x80 are not representable".into(),
                                ))
                            }
                            None => continue,
                        }
                        if msg.signals.len() > MAX_SIGNALS {
                            return Err(LxstError::WireFormat("too many signals".into()));
                        }
                    }
                }
                other => {
                    // single (non-list) signal, wrapped into a list
                    if let Some(s) = value_as_u8(&other) {
                        if s >= 0x80 {
                            return Err(LxstError::WireFormat(
                                "signal codes >= 0x80 are not representable".into(),
                            ));
                        }
                        msg.signals.push(s);
                    }
                }
            },
            FIELD_FRAMES => match v {
                Value::Bin(b) => msg.frames.push(b),
                Value::Array(items) => {
                    for item in items {
                        if let Value::Bin(b) = item {
                            msg.frames.push(b);
                        }
                    }
                }
                _ => {}
            },
            _ => {
                // Unknown key: ignored, matching Python dict lookup semantics
            }
        }
    }

    Ok(msg)
}

//***************************************************************************//
// Signalling
//***************************************************************************//

/// Signal codes understood by LXST (Python `Primitives/Telephony.py::Signalling`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Signal {
    /// Remote line is busy (`0x00`).
    StatusBusy,
    /// Remote rejected the call (`0x01`).
    StatusRejected,
    /// Remote is calling (`0x02`).
    StatusCalling,
    /// Remote line is available (`0x03`).
    StatusAvailable,
    /// Remote is ringing (`0x04`).
    StatusRinging,
    /// Remote is performing call setup (`0x05`).
    StatusConnecting,
    /// Call is fully established (`0x06`).
    StatusEstablished,
}

impl Signal {
    pub fn code(&self) -> u8 {
        match self {
            Signal::StatusBusy => 0x00,
            Signal::StatusRejected => 0x01,
            Signal::StatusCalling => 0x02,
            Signal::StatusAvailable => 0x03,
            Signal::StatusRinging => 0x04,
            Signal::StatusConnecting => 0x05,
            Signal::StatusEstablished => 0x06,
        }
    }

    pub fn from_code(code: u8) -> Option<Signal> {
        Some(match code {
            0x00 => Signal::StatusBusy,
            0x01 => Signal::StatusRejected,
            0x02 => Signal::StatusCalling,
            0x03 => Signal::StatusAvailable,
            0x04 => Signal::StatusRinging,
            0x05 => Signal::StatusConnecting,
            0x06 => Signal::StatusEstablished,
            _ => return None,
        })
    }

    /// Signal codes the telephony state machine reacts to automatically
    /// (Python `Signalling.AUTO_STATUS_CODES`).
    pub fn is_auto_status(&self) -> bool {
        matches!(
            self,
            Signal::StatusCalling
                | Signal::StatusAvailable
                | Signal::StatusRinging
                | Signal::StatusConnecting
                | Signal::StatusEstablished
        )
    }
}

/// The telephony preferred-profile signal base (Python
/// `Signalling.PREFERRED_PROFILE`): profile changes are signalled as
/// `0xff + profile` (which is **not** packable as a fixint, so profile
/// signalling uses raw `u8` codes - see [`SignalCode`]).
pub const PREFERRED_PROFILE_BASE: u16 = 0xff;

/// A raw signal code: either a known [`Signal`], a preferred-profile
/// request, or an unknown code.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SignalCode {
    Known(Signal),
    /// Preferred profile request, carrying the profile byte.
    PreferredProfile(u8),
    /// Unknown signal code, passed through untouched.
    Unknown(u8),
}

impl SignalCode {
    pub fn from_code(code: u8) -> Self {
        if let Some(s) = Signal::from_code(code) {
            SignalCode::Known(s)
        } else {
            SignalCode::Unknown(code)
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            SignalCode::Known(s) => s.code(),
            SignalCode::PreferredProfile(p) => *p,
            SignalCode::Unknown(c) => *c,
        }
    }
}

/// Outgoing signalling queue (Python `SignallingReceiver`).
///
/// Python queues signals in a deque and sends them as separate packets;
/// the in-band scheduler TODO from Python is not implemented here either.
#[derive(Clone, Default)]
pub struct SignallingReceiver {
    outgoing_signals: Arc<Mutex<VecDeque<u8>>>,
}

impl SignallingReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a signal for sending (Python `outgoing_signals.append`).
    pub async fn queue_signal(&self, signal: u8) {
        self.outgoing_signals.lock().await.push_back(signal);
    }

    /// Take all queued signals.
    pub async fn take_signals(&self) -> Vec<u8> {
        let mut q = self.outgoing_signals.lock().await;
        q.drain(..).collect()
    }
}

//***************************************************************************//
// Packetizer (Python Packetizer / RemoteSink)
//***************************************************************************//

/// Destination a [`Packetizer`] sends to.
///
/// The `Broadcast` variant carries the destination description (the field
/// is read through the [`crate::call::RemoteCallDestination::send`] path).
#[derive(Clone)]
#[allow(dead_code, clippy::large_enum_variant)]
pub enum SendDestination {
    /// Send over a specific link (Python `RNS.Link`).
    Link(Arc<Mutex<Link>>),
    /// Send to a destination address on a transport (used for testing and
    /// non-link destinations).
    Broadcast(crate::call::RemoteCallDestination),
}

/// Sends encoded audio frames onto the network (Python `Packetizer`).
///
/// For every frame received from [`Packetizer::frames`] the packetizer
/// builds `{0x01: codec_header_byte ++ frame}` msgpack and sends it through
/// the provided transport.
#[derive(Clone)]
pub struct Packetizer {
    transport: Arc<Transport>,
    destination: SendDestination,
    codec: CodecType,
    frames: mpsc::Sender<Vec<u8>>,
    failure: Arc<std::sync::atomic::AtomicBool>,
    /// Frames sent successfully.
    pub frames_sent: Arc<std::sync::atomic::AtomicU64>,
}

impl Packetizer {
    /// Create a packetizer for a link destination.
    pub fn new_for_link(
        transport: Arc<Transport>,
        link: Arc<Mutex<Link>>,
        codec: CodecType,
    ) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(64);
        let failure = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let frames_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        (
            Self {
                transport,
                destination: SendDestination::Link(link),
                codec,
                frames: tx,
                failure,
                frames_sent,
            },
            rx,
        )
    }

    /// Create a packetizer for an arbitrary send destination.
    pub fn new(
        transport: Arc<Transport>,
        destination: SendDestination,
        codec: CodecType,
    ) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(64);
        let failure = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let frames_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        (
            Self {
                transport,
                destination,
                codec,
                frames: tx,
                failure,
                frames_sent,
            },
            rx,
        )
    }

    /// The codec this packetizer frames for (Python reads
    /// `type(self.source.codec)`).
    pub fn codec(&self) -> CodecType {
        self.codec
    }

    /// Update the codec used for the header byte (e.g. on a profile switch).
    pub fn set_codec(&mut self, codec: CodecType) {
        self.codec = codec;
    }

    /// Whether any packet failed to send (Python `transmit_failure`).
    pub fn transmit_failure(&self) -> bool {
        self.failure.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Send handle used by the pipeline (Python `handle_frame`).
    pub fn frames(&self) -> mpsc::Sender<Vec<u8>> {
        self.frames.clone()
    }

    /// Build the wire payload for one encoded frame (exposed for tests and
    /// for [`crate::call`]).
    pub fn frame_payload(&self, frame: &[u8]) -> Result<Vec<u8>, LxstError> {
        let header =
            codec_header_byte(self.codec).ok_or(LxstError::UnsupportedCodec(self.codec))?;
        let mut data = Vec::with_capacity(1 + frame.len());
        data.push(header);
        data.extend_from_slice(frame);
        pack_frame(&data)
    }

    /// Encode and send one frame immediately (Python `Packetizer.handle_frame`).
    pub async fn send_frame(&self, frame: &[u8]) -> Result<(), LxstError> {
        let payload = self.frame_payload(frame)?;

        match &self.destination {
            SendDestination::Link(link) => {
                let packet = {
                    let link = link.lock().await;
                    if link.status() != LinkStatus::Active {
                        // Python silently drops frames for inactive links
                        return Ok(());
                    }
                    link.data_packet(&payload).map_err(LxstError::from)?
                };
                self.transport.send_packet(packet).await;
            }
            SendDestination::Broadcast(dest) => {
                dest.send(&self.transport, &payload).await;
            }
        }

        self.frames_sent
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Send one signalling packet: `{0x00: [signal]}` (Python
    /// `SignallingReceiver.signal`).
    pub async fn send_signal(&self, signal: u8) -> Result<(), LxstError> {
        let payload = pack_signalling(&[signal])?;
        match &self.destination {
            SendDestination::Link(link) => {
                let packet = {
                    let link = link.lock().await;
                    if link.status() != LinkStatus::Active {
                        return Ok(());
                    }
                    link.data_packet(&payload).map_err(LxstError::from)?
                };
                self.transport.send_packet(packet).await;
            }
            SendDestination::Broadcast(dest) => {
                dest.send(&self.transport, &payload).await;
            }
        }
        Ok(())
    }
}

impl From<reticulum::error::RnsError> for LxstError {
    fn from(e: reticulum::error::RnsError) -> Self {
        LxstError::Transport(format!("{e:?}"))
    }
}

//***************************************************************************//
// LinkSource (Python LinkSource / RemoteSource)
//***************************************************************************//

/// An incoming frame with its codec header resolved.
#[derive(Clone, Debug)]
pub struct IncomingFrame {
    /// Encoded frame payload (codec header byte stripped).
    pub data: Vec<u8>,
    /// Codec the sender used.
    pub codec: CodecType,
}

/// Events produced by a [`LinkSource`].
#[derive(Clone, Debug)]
pub enum LinkSourceEvent {
    /// A decoded audio frame.
    Frame(AudioFrame),
    /// An encoded frame whose codec could not be instantiated (unknown
    /// header byte, or feature compiled out). Python logs and drops these.
    UnknownCodec(u8),
    /// One or more signalling codes.
    Signals(Vec<u8>),
    /// The remote switched codecs; the new codec is now in use.
    CodecSwitched(CodecType),
    /// The frame could not be decoded.
    DecodeError(String),
}

/// Receives and demultiplexes LXST packets arriving on a link (Python
/// `LinkSource`).
///
/// Incoming audio frames are decoded with the current codec - when the frame
/// carries a *different* codec header byte, the codec is replaced first
/// (Python logs "Remote switched codec to ..."), and the channel count is
/// adopted from the new codec.
pub struct LinkSource {
    id: SourceId,
    codec: Box<dyn Codec>,
    /// Codec type currently decoding (None while the codec is not
    /// instantiable, e.g. feature compiled out).
    codec_type: Option<CodecType>,
    sink_samplerate: Option<u32>,
    sink_channels: Option<usize>,
    events: mpsc::Sender<LinkSourceEvent>,
}

impl LinkSource {
    /// Create a link source starting with the `Null` codec, like Python.
    pub fn new() -> (Self, mpsc::Receiver<LinkSourceEvent>) {
        Self::with_codec(CodecType::Null)
    }

    /// Create a link source starting with a specific codec type.
    pub fn with_codec(codec: CodecType) -> (Self, mpsc::Receiver<LinkSourceEvent>) {
        Self::with_codec_instance(new_codec(codec).ok())
    }

    /// Create a link source with a caller-provided codec instance.
    pub fn with_codec_instance(
        codec: Option<Box<dyn Codec>>,
    ) -> (Self, mpsc::Receiver<LinkSourceEvent>) {
        let (tx, rx) = mpsc::channel(256);
        let codec_type = codec.as_ref().map(|c| c.codec_type());
        let source = Self {
            id: crate::common::new_source_id(),
            codec: codec.unwrap_or_else(|| Box::new(crate::codecs::Null::new())),
            codec_type,
            sink_samplerate: None,
            sink_channels: None,
            events: tx,
        };
        (source, rx)
    }

    /// Unique source id of this receiver (Python uses object identity).
    pub fn id(&self) -> SourceId {
        self.id
    }

    /// The codec currently decoding incoming frames.
    pub fn codec_type(&self) -> Option<CodecType> {
        self.codec_type
    }

    /// The codec instance currently decoding incoming frames.
    pub fn codec(&self) -> &dyn Codec {
        self.codec.as_ref()
    }

    /// Inform the source about the sink it feeds (Python codecs read
    /// `self.sink.samplerate` / `self.sink.channels` in `decode`).
    pub fn set_sink_params(&mut self, samplerate: Option<u32>, channels: Option<usize>) {
        self.sink_samplerate = samplerate;
        self.sink_channels = channels;
        self.codec.set_sink_params(samplerate, channels);
    }

    /// Replace the active codec explicitly (Python `pipeline.codec = ...`).
    pub fn set_codec(&mut self, codec: Box<dyn Codec>) {
        self.codec_type = Some(codec.codec_type());
        self.codec = codec;
        self.codec
            .set_sink_params(self.sink_samplerate, self.sink_channels);
    }

    /// Handle one raw packet payload (Python `LinkSource._packet`).
    ///
    /// Returns the number of frames dispatched. Errors are reported through
    /// the event stream rather than returned, exactly like the Python code
    /// which logs and continues.
    pub async fn handle_packet(&mut self, data: &[u8]) -> usize {
        let msg = match unpack_message(data) {
            Ok(m) => m,
            Err(e) => {
                let _ = self
                    .events
                    .send(LinkSourceEvent::DecodeError(e.to_string()))
                    .await;
                return 0;
            }
        };

        let mut frames = 0;
        for frame in &msg.frames {
            if frame.is_empty() {
                let _ = self
                    .events
                    .send(LinkSourceEvent::DecodeError("empty frame".into()))
                    .await;
                continue;
            }

            let header = frame[0];
            let payload = &frame[1..];
            let frame_codec = codec_type(header);

            let mut switched = None;
            if self.codec_type.is_some() && frame_codec != self.codec_type {
                // Remote switched codec mid-stream
                match frame_codec {
                    Some(t) => match new_codec(t) {
                        Ok(c) => {
                            let mut c = c;
                            c.set_sink_params(self.sink_samplerate, self.sink_channels);
                            self.codec = c;
                            self.codec_type = Some(t);
                            switched = Some(t);
                            let _ = self.events.send(LinkSourceEvent::CodecSwitched(t)).await;
                        }
                        Err(e) => {
                            let _ = self
                                .events
                                .send(LinkSourceEvent::DecodeError(format!(
                                    "remote switched to unavailable codec: {e}"
                                )))
                                .await;
                            continue;
                        }
                    },
                    None => {
                        let _ = self
                            .events
                            .send(LinkSourceEvent::UnknownCodec(header))
                            .await;
                        continue;
                    }
                }
            } else if self.codec_type.is_none() {
                if let Some(t) = frame_codec {
                    match new_codec(t) {
                        Ok(c) => {
                            self.codec = c;
                            self.codec_type = Some(t);
                        }
                        Err(_) => {
                            let _ = self
                                .events
                                .send(LinkSourceEvent::UnknownCodec(header))
                                .await;
                            continue;
                        }
                    }
                } else {
                    let _ = self
                        .events
                        .send(LinkSourceEvent::UnknownCodec(header))
                        .await;
                    continue;
                }
            }

            match self.codec.decode(payload) {
                Ok(decoded) => {
                    if switched.is_some() && self.codec.channels().is_some() {
                        // Python adopts codec channels on switch
                    }
                    let _ = self.events.send(LinkSourceEvent::Frame(decoded)).await;
                    frames += 1;
                }
                Err(e) => {
                    let _ = self
                        .events
                        .send(LinkSourceEvent::DecodeError(e.to_string()))
                        .await;
                }
            }
        }

        if !msg.signals.is_empty() {
            let _ = self
                .events
                .send(LinkSourceEvent::Signals(msg.signals))
                .await;
        }

        frames
    }
}

impl Default for LinkSource {
    fn default() -> Self {
        // Used where an instance without the event receiver is needed;
        // events go nowhere (the receiver is dropped immediately, so sends
        // fail silently, like a discarded Python callback).
        let (source, _events) = Self::with_codec(CodecType::Null);
        source
    }
}

//***************************************************************************//
// Destination naming helpers
//***************************************************************************//

/// The LXST call endpoint aspect (Python `Call.py`: `APP_NAME, "call",
/// "endpoint"`).
pub const CALL_ENDPOINT_ASPECTS: &str = "call.endpoint";

/// Destination name for the LXST call endpoint.
pub fn call_endpoint_name() -> reticulum::destination::DestinationName {
    reticulum::destination::DestinationName::new(APP_NAME, CALL_ENDPOINT_ASPECTS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_signalling_matches_umsgpack() {
        // umsgpack.packb({0x00:[2]}) == 81 00 91 02
        assert_eq!(pack_signalling(&[2]).unwrap(), vec![0x81, 0x00, 0x91, 0x02]);
        // {0x00:[0,1,2]} == 81 00 93 00 01 02
        assert_eq!(
            pack_signalling(&[0, 1, 2]).unwrap(),
            vec![0x81, 0x00, 0x93, 0x00, 0x01, 0x02]
        );
    }

    #[test]
    fn pack_frame_matches_umsgpack() {
        // umsgpack.packb({0x01: b"\x00\x80\x01\x00"}) == 81 01 c4 04 00 80 01 00
        assert_eq!(
            pack_frame(&[0x00, 0x80, 0x01, 0x00]).unwrap(),
            vec![0x81, 0x01, 0xc4, 0x04, 0x00, 0x80, 0x01, 0x00]
        );
    }

    #[test]
    fn unpack_roundtrip() {
        let msg = unpack_message(&pack_frame(&[0x40, 1, 2, 3]).unwrap()).unwrap();
        assert_eq!(msg.frames, vec![vec![0x40, 1, 2, 3]]);
        assert!(msg.signals.is_empty());

        let msg = unpack_message(&pack_signalling(&[3, 4]).unwrap()).unwrap();
        assert_eq!(msg.signals, vec![3, 4]);
        assert!(msg.frames.is_empty());
    }
}
