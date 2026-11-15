//! Audio sinks (Python `LXST/Sinks.py`).
//!
//! Only the transport-independent sinks are ported:
//!
//! | Python         | Rust                                        |
//! |----------------|---------------------------------------------|
//! | `Sink`         | [`Sink`]                                    |
//! | `LocalSink`    | marker (`LineSink`, `WavFileSink`, ...)     |
//! | `RemoteSink`   | [`RemoteSink`] -> [`crate::network::Packetizer`] |
//! | `LineSink`     | [`LineSink`] (buffered, no OS audio)        |
//! | `OpusFileSink` | [`WavFileSink`] (WAV via `hound`)           |
//! | (new)          | [`BufferSink`] in-memory collector          |
//!
//! Python sinks are handed either encoded bytes (when the source encoded
//! them) or decoded frames (when the source passes them on, e.g. the
//! `Mixer`, which always decodes before inserting into its buffers and
//! calls the sink with `decoded=True`). [`SinkFrame`] models both cases.
//!
//! The OS audio device plumbing (speakers, Opus file writers) is **not**
//! ported; `LineSink` implements the same bounded-frame buffering,
//! autostart, underrun timeout and buffer-lag dropping logic in pure Rust,
//! and `WavFileSink` writes uncompressed WAV instead of Ogg Opus.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::common::{AudioFrame, SourceId};

/// A frame handed to a sink: either already decoded, or still encoded.
#[derive(Clone, Debug)]
pub enum SinkFrame {
    /// Decoded audio (Python passes a numpy frame, often with
    /// `decoded=True`).
    Decoded(AudioFrame),
    /// Encoded codec bytes, as produced by a `Codec::encode`
    /// (Python passes `bytes` here).
    Encoded(Vec<u8>),
}

impl SinkFrame {
    pub fn decoded(&self) -> bool {
        matches!(self, SinkFrame::Decoded(_))
    }
}

impl From<AudioFrame> for SinkFrame {
    fn from(f: AudioFrame) -> Self {
        SinkFrame::Decoded(f)
    }
}

/// A consumer of audio frames (Python `Sinks.Sink`).
#[async_trait::async_trait]
pub trait Sink: Send + Sync {
    /// Consume one frame (Python `handle_frame(frame, source, decoded)`).
    async fn handle_frame(&mut self, frame: SinkFrame, source: SourceId);

    /// Whether the sink can currently accept a frame from `source`
    /// (Python `can_receive`, used for backpressure).
    async fn can_receive(&self, _from_source: SourceId) -> bool {
        true
    }

    fn samplerate(&self) -> Option<u32> {
        None
    }

    fn channels(&self) -> Option<usize> {
        None
    }
}

/// Collects frames in memory (useful for tests and in-memory recording).
#[derive(Default)]
pub struct BufferSink {
    decoded: Vec<AudioFrame>,
    encoded: Vec<Vec<u8>>,
    backpressure_at: Option<usize>,
    stopped: bool,
}

impl BufferSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop accepting frames (Python `__recording_stopped`).
    pub fn stop(&mut self) {
        self.stopped = true;
    }

    /// Set a frame count after which `can_receive` reports false.
    pub fn set_backpressure(&mut self, at: Option<usize>) {
        self.backpressure_at = at;
    }

    pub fn decoded_frames(&self) -> &[AudioFrame] {
        &self.decoded
    }

    pub fn encoded_frames(&self) -> &[Vec<u8>] {
        &self.encoded
    }

    pub fn take_decoded(&mut self) -> Vec<AudioFrame> {
        std::mem::take(&mut self.decoded)
    }

    /// Flatten all decoded frames to interleaved samples.
    pub fn interleaved(&self) -> Vec<f32> {
        self.decoded
            .iter()
            .flat_map(|f| f.samples.iter().copied())
            .collect()
    }

    fn total(&self) -> usize {
        self.decoded.len() + self.encoded.len()
    }
}

#[async_trait::async_trait]
impl Sink for BufferSink {
    async fn handle_frame(&mut self, frame: SinkFrame, _source: SourceId) {
        match frame {
            SinkFrame::Decoded(f) => self.decoded.push(f),
            SinkFrame::Encoded(b) => self.encoded.push(b),
        }
    }

    async fn can_receive(&self, _from_source: SourceId) -> bool {
        if self.stopped {
            return false;
        }
        match self.backpressure_at {
            Some(limit) => self.total() < limit,
            None => true,
        }
    }
}

/// A buffered local sink drained on demand (Python `LineSink`, minus the
/// speaker).
///
/// Implements the Python buffering policy:
///
/// * `MAX_FRAMES` (6) bounded queue, `buffer_max_height = MAX_FRAMES - 3`
/// * `can_receive` returns false at/above the high-water mark
/// * [`LineSink::digest`] pops one frame per call and **drops an extra
///   frame** when the queue is still above the high-water mark (buffer lag)
/// * underrun tracking with a `FRAME_TIMEOUT` frame-times limit after which
///   playback stops
pub struct LineSink {
    queue: VecDeque<AudioFrame>,
    /// `MAX_FRAMES` (Python 6)
    pub max_frames: usize,
    /// High water mark (Python `buffer_max_height = MAX_FRAMES - 3`)
    pub buffer_max_height: usize,
    /// Frames that must be queued before autostart (Python `AUTOSTART_MIN`)
    pub autostart_min: usize,
    /// Underrun timeout in frame-times (Python `FRAME_TIMEOUT = 8`)
    pub frame_timeout: f64,
    autodigest: bool,
    running: bool,
    samples_per_frame: Option<usize>,
    channels: Option<usize>,
    underrun_since: Option<Instant>,
    output_latency: Duration,
    max_latency: Duration,
    frame_time: f64,
    frames_played: u64,
}

impl LineSink {
    pub fn new() -> Self {
        let max_frames = 6;
        Self {
            queue: VecDeque::new(),
            max_frames,
            buffer_max_height: max_frames.saturating_sub(3).max(1),
            autostart_min: 1,
            frame_timeout: 8.0,
            autodigest: true,
            running: false,
            samples_per_frame: None,
            channels: None,
            underrun_since: None,
            output_latency: Duration::ZERO,
            max_latency: Duration::ZERO,
            frame_time: 0.0,
            frames_played: 0,
        }
    }

    /// Frames waiting to be played (Python `len(self.frame_deque)`).
    pub fn frames_waiting(&self) -> usize {
        self.queue.len()
    }

    pub fn running(&self) -> bool {
        self.running
    }

    pub fn start(&mut self) {
        self.running = true;
    }

    pub fn stop(&mut self) {
        self.running = false;
        self.underrun_since = None;
    }

    pub fn output_latency(&self) -> Duration {
        self.output_latency
    }

    pub fn max_latency(&self) -> Duration {
        self.max_latency
    }

    pub fn samples_per_frame(&self) -> Option<usize> {
        self.samples_per_frame
    }

    pub fn frames_played(&self) -> u64 {
        self.frames_played
    }

    /// Pop one frame for playback (the body of Python `__digest_job`).
    ///
    /// When the queue remains above the high-water mark after popping, one
    /// extra frame is dropped (buffer lag). Returns `None` on underrun.
    pub fn digest(&mut self) -> Option<AudioFrame> {
        if !self.running {
            return None;
        }
        if let Some(frame) = self.queue.pop_front() {
            self.underrun_since = None;
            self.output_latency =
                Duration::from_secs_f64(self.queue.len() as f64 * self.frame_time);
            self.max_latency =
                Duration::from_secs_f64(self.buffer_max_height as f64 * self.frame_time);

            if self.queue.len() > self.buffer_max_height {
                log::debug!(
                    "Buffer lag on LineSink (height {}), dropping one frame",
                    self.queue.len()
                );
                self.queue.pop_front();
            }
            self.frames_played += 1;
            Some(frame)
        } else {
            self.underrun_since.get_or_insert_with(Instant::now);
            None
        }
    }

    /// Whether the underrun timeout has expired (Python stops playback).
    pub fn underrun_timed_out(&self) -> bool {
        match self.underrun_since {
            Some(since) => since.elapsed().as_secs_f64() > self.frame_time * self.frame_timeout,
            None => false,
        }
    }
}

impl Default for LineSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Sink for LineSink {
    async fn handle_frame(&mut self, frame: SinkFrame, _source: SourceId) {
        let frame = match frame {
            SinkFrame::Decoded(f) => f,
            SinkFrame::Encoded(_) => {
                log::warn!("LineSink received an encoded frame, expected decoded audio");
                return;
            }
        };

        // Python drops the oldest frame when the bounded deque overflows
        while self.queue.len() >= self.max_frames {
            self.queue.pop_front();
        }
        self.queue.push_back(frame.clone());

        if self.samples_per_frame.is_none() {
            self.samples_per_frame = Some(frame.frames());
            self.channels = Some(frame.channels);
            log::debug!(
                "LineSink starting at {} samples per frame, {} channels",
                frame.frames(),
                frame.channels
            );
        }

        if self.autodigest && !self.running && self.queue.len() >= self.autostart_min {
            self.running = true;
            // Python LineSink assumes the 48kHz backend samplerate
            let samplerate = 48_000.0;
            self.frame_time = self.samples_per_frame.unwrap_or(1) as f64 * (1.0 / samplerate);
        }
    }

    async fn can_receive(&self, _from_source: SourceId) -> bool {
        self.queue.len() < self.buffer_max_height
    }

    fn channels(&self) -> Option<usize> {
        self.channels
    }
}

/// A sink that forwards encoded frames to a network packetizer (Python
/// `RemoteSink` + `Packetizer.handle_frame`). Decoded frames are rejected
/// with a warning, exactly like the Python packetizer would choke on a
/// numpy array.
pub struct RemoteSink {
    codec: crate::codecs::CodecType,
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    frames_sent: u64,
    dropped: u64,
}

impl RemoteSink {
    pub fn new(
        codec: crate::codecs::CodecType,
        sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            codec,
            sender,
            frames_sent: 0,
            dropped: 0,
        }
    }

    pub fn frames_sent(&self) -> u64 {
        self.frames_sent
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn codec(&self) -> crate::codecs::CodecType {
        self.codec
    }
}

#[async_trait::async_trait]
impl Sink for RemoteSink {
    async fn handle_frame(&mut self, frame: SinkFrame, _source: SourceId) {
        let bytes = match frame {
            SinkFrame::Encoded(b) => b,
            SinkFrame::Decoded(_) => {
                log::warn!("RemoteSink received a decoded frame, expected encoded bytes");
                self.dropped += 1;
                return;
            }
        };
        if self.sender.send(bytes).await.is_ok() {
            self.frames_sent += 1;
        }
    }
}

/// A sink writing decoded audio to a WAV file (Python `OpusFileSink`, but
/// uncompressed WAV through `hound`).
pub struct WavFileSink {
    writer: Option<hound::WavWriter<std::io::BufWriter<std::fs::File>>>,
    spec: hound::WavSpec,
    samples_per_frame: Option<usize>,
    samplerate: Option<u32>,
    channels: Option<usize>,
    samples_written: usize,
    buffer: VecDeque<AudioFrame>,
    buffer_max_height: usize,
    stopped: bool,
    /// Frames that must be present before writing begins (Python pads short
    /// trailing frames with silence).
    pub final_silence_frames: usize,
}

impl WavFileSink {
    pub fn create(
        path: &std::path::Path,
        samplerate: u32,
        channels: usize,
    ) -> Result<Self, crate::LxstError> {
        let spec = hound::WavSpec {
            channels: channels as u16,
            sample_rate: samplerate,
            bits_per_sample: 32,
            sample_format: hound::SampleFormat::Float,
        };
        let writer = hound::WavWriter::create(path, spec)?;
        Ok(Self {
            writer: Some(writer),
            spec,
            samples_per_frame: None,
            samplerate: Some(samplerate),
            channels: Some(channels),
            samples_written: 0,
            buffer: VecDeque::new(),
            buffer_max_height: 64,
            stopped: false,
            final_silence_frames: 10,
        })
    }

    pub fn samples_written(&self) -> usize {
        self.samples_written
    }

    pub fn frames_waiting(&self) -> usize {
        self.buffer.len()
    }

    /// Flush everything and finalise the file (Python `OpusFileSink.stop`).
    pub fn stop(&mut self) {
        self.stopped = true;
        while let Some(frame) = self.buffer.pop_front() {
            self.write_frame(&frame);
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.finalize();
        }
    }

    fn write_frame(&mut self, frame: &AudioFrame) {
        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => return,
        };
        let channels = self.spec.channels as usize;
        let last = frame.channels.saturating_sub(1);
        for i in 0..frame.frames() {
            for ch in 0..channels {
                let sample = if ch < frame.channels {
                    frame.sample(i, ch)
                } else {
                    frame.sample(i, last)
                };
                let _ = writer.write_sample(sample.clamp(-1.0, 1.0));
            }
        }
        self.samples_written += frame.frames();
    }
}

#[async_trait::async_trait]
impl Sink for WavFileSink {
    async fn handle_frame(&mut self, frame: SinkFrame, _source: SourceId) {
        if self.stopped {
            return;
        }
        let frame = match frame {
            SinkFrame::Decoded(f) => f,
            SinkFrame::Encoded(_) => {
                log::warn!("WavFileSink received an encoded frame, expected decoded audio");
                return;
            }
        };

        if self.samples_per_frame.is_none() {
            self.samples_per_frame = Some(frame.frames());
            log::debug!(
                "WavFileSink starting at {} samples per frame, {} channels",
                frame.frames(),
                frame.channels
            );
        }
        self.buffer.push_back(frame);
        while self.buffer.len() > self.buffer_max_height {
            self.buffer.pop_front();
        }
        // drain eagerly so the file is always valid
        while let Some(frame) = self.buffer.pop_front() {
            self.write_frame(&frame);
        }
    }

    async fn can_receive(&self, _from_source: SourceId) -> bool {
        !self.stopped && self.buffer.len() < self.buffer_max_height
    }

    fn samplerate(&self) -> Option<u32> {
        self.samplerate
    }

    fn channels(&self) -> Option<usize> {
        self.channels
    }
}
