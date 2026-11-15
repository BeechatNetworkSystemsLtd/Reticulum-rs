//! Audio sources (Python `LXST/Sources.py`).
//!
//! Only the transport-independent sources are ported. The OS audio backends
//! (`LineSource`, which captures from a microphone via the `soundcard`
//! module) and the vendored `OpusFileSource`/`OpusFileSink` are **not**
//! ported; `LineSource` is provided as a source that reads interleaved f32
//! from a stream channel so that pipelines (and their gain / ease-in / skip
//! behaviour) can be exercised without OS audio hardware.
//!
//! | Python            | Rust                                              |
//! |-------------------|---------------------------------------------------|
//! | `Source`          | [`Source`]                                        |
//! | `LocalSource`     | [`LocalSource`] (marker type)                     |
//! | `RemoteSource`    | [`RemoteSource`] (marker type)                    |
//! | `LineSource`      | [`LineSource`] (stream-fed)                       |
//! | `OpusFileSource`  | [`WavFileSource`] (WAV via `hound`)               |
//! | `BufferSource`    | (new) in-memory frame source                      |
//! | `ToneSource`      | [`crate::generators::ToneSource`]                |

use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};

use crate::codecs::Codec;
use crate::common::{AudioFrame, SourceId};

/// A source of audio frames (Python `Sources.Source`).
#[async_trait::async_trait]
pub trait Source: Send {
    /// Unique identity of this source (Python: object identity).
    fn id(&self) -> SourceId;

    /// Samplerate this source produces, if known.
    fn samplerate(&self) -> Option<u32>;

    /// Channel count this source produces, if known.
    fn channels(&self) -> Option<usize>;

    /// Nominal bit depth.
    fn bitdepth(&self) -> Option<usize> {
        Some(32)
    }

    /// Number of samples per emitted frame.
    fn samples_per_frame(&self) -> Option<usize> {
        None
    }

    /// Pull the next frame. `None` ends the stream.
    async fn next_frame(&mut self) -> Option<AudioFrame>;

    /// Whether the source considers itself running (Python `should_run`).
    fn running(&self) -> bool {
        true
    }
}

/// Default frame duration for stream-fed sources (Python
/// `LineSource.DEFAULT_FRAME_MS`).
pub const DEFAULT_FRAME_MS: f64 = 80.0;
/// Maximum buffered frames (Python `LineSource.MAX_FRAMES`).
pub const MAX_FRAMES: usize = 128;

/// The `LineSource` shape, fed from a tokio channel instead of a microphone.
///
/// Preserves the Python gain / ease-in / skip semantics:
///
/// * `skip` - drop the first `skip` seconds of input
/// * `ease_in` - ramp the gain linearly from 0 to `gain` over `ease_in`
///   seconds
/// * `gain` - linear gain applied to every (non-skipped) frame, in dB
///   (Python `linear_gain(gain_db) = 10**(gain_db/10)`)
///
/// Feeding it: obtain a sender with [`LineSource::input`] and push interleaved
/// frames (Python would call `recorder.record`).
pub struct LineSource {
    id: SourceId,
    samplerate: Option<u32>,
    channels: Option<usize>,
    target_frame_ms: f64,
    gain_db: f32,
    ease_in: f32,
    skip: f32,
    input: mpsc::Sender<AudioFrame>,
    queue: Arc<Mutex<mpsc::Receiver<AudioFrame>>>,
    running: bool,
    skipped_samples: usize,
    elapsed_samples: usize,
    eased: bool,
    current_gain: f32,
}

impl LineSource {
    /// dB to linear gain (Python `LineSource.linear_gain`).
    pub fn linear_gain(gain_db: f32) -> f32 {
        10f32.powf(gain_db / 10.0)
    }

    pub fn new(target_frame_ms: f64, samplerate: Option<u32>, channels: Option<usize>) -> Self {
        let (tx, rx) = mpsc::channel(MAX_FRAMES);
        Self {
            id: crate::common::new_source_id(),
            samplerate,
            channels,
            target_frame_ms,
            gain_db: 0.0,
            ease_in: 0.0,
            skip: 0.0,
            input: tx,
            queue: Arc::new(Mutex::new(rx)),
            running: false,
            skipped_samples: 0,
            elapsed_samples: 0,
            eased: true,
            current_gain: 1.0,
        }
    }

    /// Sender side of the capture stream.
    pub fn input(&self) -> mpsc::Sender<AudioFrame> {
        self.input.clone()
    }

    /// Configure gain (dB), ease-in (seconds) and skip (seconds).
    pub fn configure(&mut self, gain_db: f32, ease_in: f32, skip: f32) {
        self.gain_db = gain_db;
        self.ease_in = ease_in;
        self.skip = skip;
        self.current_gain = if ease_in > 0.0 {
            0.0
        } else {
            Self::linear_gain(gain_db)
        };
        self.eased = ease_in <= 0.0;
        self.skipped_samples = 0;
        self.elapsed_samples = 0;
    }

    pub fn target_frame_ms(&self) -> f64 {
        self.target_frame_ms
    }

    fn samplerate_or(&self) -> u32 {
        self.samplerate.unwrap_or(48_000)
    }
}

#[async_trait::async_trait]
impl Source for LineSource {
    fn id(&self) -> SourceId {
        self.id
    }

    fn samplerate(&self) -> Option<u32> {
        self.samplerate
    }

    fn channels(&self) -> Option<usize> {
        self.channels
    }

    fn samples_per_frame(&self) -> Option<usize> {
        Some(((self.target_frame_ms / 1000.0) * self.samplerate_or() as f64).ceil() as usize)
    }

    async fn next_frame(&mut self) -> Option<AudioFrame> {
        let frame = {
            let mut queue = self.queue.lock().await;
            queue.recv().await
        }?;
        self.running = true;

        let mut frame = frame;
        if self.channels.is_none() {
            self.channels = Some(frame.channels);
        }
        self.elapsed_samples += frame.frames();

        // skip phase
        let sr = self.samplerate_or() as usize;
        if self.skip > 0.0 && self.skipped_samples < (self.skip * sr as f32) as usize {
            self.skipped_samples += frame.frames();
            return self.next_frame().await;
        }

        let target_gain = Self::linear_gain(self.gain_db);
        if self.current_gain != 1.0 || !self.eased {
            frame.apply_gain(self.current_gain);
        }

        if !self.eased {
            let d = self.elapsed_samples as f32 / sr as f32;
            self.current_gain = (d / self.ease_in) * target_gain;
            if self.current_gain >= target_gain {
                self.current_gain = target_gain;
                self.eased = true;
            }
        }

        Some(frame)
    }

    fn running(&self) -> bool {
        self.running
    }
}

/// An in-memory frame source (used for tests and for feeding prepared audio
/// into a pipeline).
pub struct BufferSource {
    id: SourceId,
    samplerate: Option<u32>,
    frames: std::collections::VecDeque<AudioFrame>,
}

impl BufferSource {
    pub fn new(samplerate: Option<u32>, frames: Vec<AudioFrame>) -> Self {
        Self {
            id: crate::common::new_source_id(),
            samplerate,
            frames: frames.into(),
        }
    }

    /// Split a flat interleaved sample buffer into fixed-size frames.
    pub fn from_interleaved(
        samplerate: u32,
        channels: usize,
        samples: Vec<f32>,
        frames_per_block: usize,
    ) -> Self {
        let mut frames = Vec::new();
        for chunk in samples.chunks(frames_per_block * channels) {
            frames.push(AudioFrame::from_interleaved(chunk.to_vec(), channels));
        }
        Self::new(Some(samplerate), frames)
    }
}

#[async_trait::async_trait]
impl Source for BufferSource {
    fn id(&self) -> SourceId {
        self.id
    }

    fn samplerate(&self) -> Option<u32> {
        self.samplerate
    }

    fn channels(&self) -> Option<usize> {
        self.frames.front().map(|f| f.channels)
    }

    async fn next_frame(&mut self) -> Option<AudioFrame> {
        self.frames.pop_front()
    }
}

/// A WAV file source (Python `OpusFileSource`, but for WAV files through the
/// `hound` crate).
///
/// Reads the whole file, converts to normalised interleaved `f32` and emits
/// fixed-duration frames, optionally looping.
pub struct WavFileSource {
    id: SourceId,
    samplerate: u32,
    channels: usize,
    samples: Vec<f32>,
    samples_per_frame: usize,
    next: usize,
    loop_playback: bool,
    done: bool,
}

impl WavFileSource {
    pub fn open(
        path: &std::path::Path,
        target_frame_ms: f64,
        loop_playback: bool,
    ) -> Result<Self, crate::LxstError> {
        let mut reader = hound::WavReader::open(path)?;
        let spec = reader.spec();
        let samplerate = spec.sample_rate;
        let channels = spec.channels as usize;

        let samples: Vec<f32> = match spec.sample_format {
            hound::SampleFormat::Float => {
                reader.samples::<f32>().map(|s| s.unwrap_or(0.0)).collect()
            }
            hound::SampleFormat::Int => {
                let max = (1i64 << (spec.bits_per_sample - 1)) as f32;
                reader
                    .samples::<i32>()
                    .map(|s| s.map(|v| v as f32 / max).unwrap_or(0.0))
                    .collect()
            }
        };

        let samples_per_frame = ((target_frame_ms / 1000.0) * samplerate as f64).ceil() as usize;

        Ok(Self {
            id: crate::common::new_source_id(),
            samplerate,
            channels,
            samples,
            samples_per_frame,
            next: 0,
            loop_playback,
            done: false,
        })
    }

    pub fn from_samples(
        samplerate: u32,
        channels: usize,
        samples: Vec<f32>,
        target_frame_ms: f64,
        loop_playback: bool,
    ) -> Self {
        let samples_per_frame = ((target_frame_ms / 1000.0) * samplerate as f64).ceil() as usize;
        Self {
            id: crate::common::new_source_id(),
            samplerate,
            channels,
            samples,
            samples_per_frame,
            next: 0,
            loop_playback,
            done: false,
        }
    }

    pub fn samplerate(&self) -> u32 {
        self.samplerate
    }

    pub fn channels(&self) -> usize {
        self.channels
    }

    /// Total length of the source in milliseconds (Python `length_ms`).
    pub fn length_ms(&self) -> f64 {
        (self.sample_count() as f64 / self.samplerate as f64) * 1000.0
    }

    pub fn sample_count(&self) -> usize {
        self.samples
            .len()
            .checked_div(self.channels.max(1))
            .unwrap_or(0)
    }
}

#[async_trait::async_trait]
impl Source for WavFileSource {
    fn id(&self) -> SourceId {
        self.id
    }

    fn samplerate(&self) -> Option<u32> {
        Some(self.samplerate)
    }

    fn channels(&self) -> Option<usize> {
        Some(self.channels)
    }

    fn samples_per_frame(&self) -> Option<usize> {
        Some(self.samples_per_frame)
    }

    async fn next_frame(&mut self) -> Option<AudioFrame> {
        if self.done {
            return None;
        }
        if self.next >= self.samples.len() {
            if self.loop_playback {
                self.next = 0;
            } else {
                self.done = true;
                return None;
            }
        }
        let end = (self.next + self.samples_per_frame * self.channels).min(self.samples.len());
        let chunk = self.samples[self.next..end].to_vec();
        self.next = end;
        Some(AudioFrame::from_interleaved(chunk, self.channels))
    }

    fn running(&self) -> bool {
        !self.done
    }
}

/// A remote (network) source: pulls frames that arrived from the network
/// (Python `RemoteSource`, e.g. `LinkSource`).
pub struct RemoteSource {
    id: SourceId,
    queue: Arc<Mutex<mpsc::Receiver<AudioFrame>>>,
    samplerate: Option<u32>,
    channels: Option<usize>,
}

impl RemoteSource {
    pub fn new(
        queue: Arc<Mutex<mpsc::Receiver<AudioFrame>>>,
        samplerate: Option<u32>,
        channels: Option<usize>,
    ) -> Self {
        Self {
            id: crate::common::new_source_id(),
            queue,
            samplerate,
            channels,
        }
    }
}

#[async_trait::async_trait]
impl Source for RemoteSource {
    fn id(&self) -> SourceId {
        self.id
    }

    fn samplerate(&self) -> Option<u32> {
        self.samplerate
    }

    fn channels(&self) -> Option<usize> {
        self.channels
    }

    async fn next_frame(&mut self) -> Option<AudioFrame> {
        let mut queue = self.queue.lock().await;
        let frame = queue.recv().await?;
        if self.channels.is_none() {
            self.channels = Some(frame.channels);
        }
        Some(frame)
    }
}

/// Wrap a codec in the frame-time constraints of a source, mirroring the
/// Python `codec` setters (quantise / clamp / snap the target frame time).
pub fn frame_ms_for_codec(codec: &dyn Codec, target_frame_ms: f64) -> f64 {
    crate::codecs::clamp_frame_ms(codec, target_frame_ms)
}
