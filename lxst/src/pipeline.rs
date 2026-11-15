//! Audio pipelines (Python `LXST/Pipeline.py`).
//!
//! A [`Pipeline`] connects a [`Source`] through an optional filter chain and
//! a [`Codec`] to a [`Sink`], and runs it as a tokio task.
//!
//! Two roles mirror how the Python package wires pipelines:
//!
//! * **encode** (local source): `source -> filters -> codec.encode ->
//!   sink(Encoded)` - used for transmit pipelines
//!   (`LineSource -> Packetizer`) and the Python `Pipeline` in general
//! * **decode** (remote source): frames arrive already decoded from the
//!   network (`LinkSource` decodes them), pass through the filters and reach
//!   the sink as `Decoded` - matching the Python receive pipelines where the
//!   *source* owns the codec
//!
//! Filters are applied to decoded samples only, exactly like Python where
//! `LineSource.__ingest_job` filters before `codec.encode`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::codecs::Codec;
use crate::filters::Filter;
use crate::sinks::{Sink, SinkFrame};
use crate::sources::Source;

/// Pipeline construction error (Python `PipelineError`).
#[derive(Debug)]
pub enum PipelineError {
    InvalidSource,
    InvalidSink,
    InvalidCodec,
}

impl std::fmt::Display for PipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineError::InvalidSource => {
                write!(f, "Audio pipeline initialised with invalid source")
            }
            PipelineError::InvalidSink => write!(f, "Audio pipeline initialised with invalid sink"),
            PipelineError::InvalidCodec => {
                write!(f, "Audio pipeline initialised with invalid codec")
            }
        }
    }
}

impl std::error::Error for PipelineError {}

/// Direction of audio flow through the codec.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CodecRole {
    /// Local source: frames are encoded before reaching the sink.
    Encode,
    /// Remote source: frames arrive decoded and are handed to the sink
    /// directly (the codec instance is available for late re-decoding).
    Decode,
}

/// Idle sleep while waiting for backpressure to clear.
const BACKPRESSURE_SLEEP: Duration = Duration::from_millis(5);

/// A running pipeline (Python `LXST.Pipeline`).
pub struct Pipeline<S: Source, K: Sink> {
    source: Arc<Mutex<S>>,
    sink: Arc<Mutex<K>>,
    codec: Arc<Mutex<Box<dyn Codec>>>,
    filters: Vec<Arc<Mutex<Box<dyn Filter>>>>,
    codec_role: CodecRole,
    cancel: CancellationToken,
    frames_processed: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    target_frame_ms: f64,
}

impl<S: Source + 'static, K: Sink + 'static> Pipeline<S, K> {
    fn build(
        source: S,
        filters: Vec<Box<dyn Filter>>,
        codec: Box<dyn Codec>,
        sink: K,
        codec_role: CodecRole,
        default_frame_ms: f64,
    ) -> Self {
        let target_frame_ms = crate::codecs::clamp_frame_ms(codec.as_ref(), default_frame_ms);
        let filters = filters
            .into_iter()
            .map(|f| Arc::new(Mutex::new(f)) as Arc<Mutex<Box<dyn Filter>>>)
            .collect();
        Self {
            source: Arc::new(Mutex::new(source)),
            sink: Arc::new(Mutex::new(sink)),
            codec: Arc::new(Mutex::new(codec)),
            filters,
            codec_role,
            cancel: CancellationToken::new(),
            frames_processed: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            target_frame_ms,
        }
    }

    /// Encoding pipeline: local source, optional filters, codec, sink.
    pub fn encode(
        source: S,
        filters: Vec<Box<dyn Filter>>,
        codec: Box<dyn Codec>,
        sink: K,
    ) -> Self {
        Self::build(source, filters, codec, sink, CodecRole::Encode, 80.0)
    }

    /// Decoding pipeline: remote source, optional filters, codec, sink.
    /// The sink receives decoded frames.
    pub fn decode(
        source: S,
        filters: Vec<Box<dyn Filter>>,
        codec: Box<dyn Codec>,
        sink: K,
    ) -> Self {
        Self::build(source, filters, codec, sink, CodecRole::Decode, 80.0)
    }

    /// Access the source.
    pub fn source(&self) -> Arc<Mutex<S>> {
        self.source.clone()
    }

    /// Access the sink.
    pub fn sink(&self) -> Arc<Mutex<K>> {
        self.sink.clone()
    }

    /// Access the codec.
    pub fn codec(&self) -> Arc<Mutex<Box<dyn Codec>>> {
        self.codec.clone()
    }

    /// Replace the codec (Python `pipeline.codec = ...`). The new codec is
    /// informed about the sink parameters, like the Python setter which
    /// assigns `codec.sink`.
    pub async fn set_codec(&self, mut codec: Box<dyn Codec>) {
        {
            let sink = self.sink.lock().await;
            codec.set_sink_params(sink.samplerate(), sink.channels());
        }
        *self.codec.lock().await = codec;
    }

    /// Frames processed so far.
    pub fn frames_processed(&self) -> u64 {
        self.frames_processed.load(Ordering::Relaxed)
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn target_frame_ms(&self) -> f64 {
        self.target_frame_ms
    }

    pub fn codec_role(&self) -> CodecRole {
        self.codec_role
    }

    /// Start the pipeline, returning the task handle (Python `start`).
    ///
    /// The task ends when [`Pipeline::stop`] is called or the source is
    /// exhausted.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        self.running.store(true, Ordering::Relaxed);

        let source = self.source.clone();
        let sink = self.sink.clone();
        let codec = self.codec.clone();
        let filters = self.filters.clone();
        let cancel = self.cancel.clone();
        let frames_processed = self.frames_processed.clone();
        let running = self.running.clone();
        let codec_role = self.codec_role;

        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                // Pull the next frame (source first, so id is fresh)
                let (source_id, samplerate, frame) = {
                    let mut source = source.lock().await;
                    let id = source.id();
                    let sr = source.samplerate();
                    match source.next_frame().await {
                        Some(f) => (id, sr, f),
                        None => break,
                    }
                };

                // Backpressure check against the sink
                if !sink.lock().await.can_receive(source_id).await {
                    tokio::time::sleep(BACKPRESSURE_SLEEP).await;
                    // park the frame for a moment and retry a bounded number
                    // of times before dropping it (Python simply skips the
                    // frame in the sources, or the deque drops the oldest)
                    let mut accepted = false;
                    for _ in 0..20 {
                        if cancel.is_cancelled() {
                            break;
                        }
                        if sink.lock().await.can_receive(source_id).await {
                            accepted = true;
                            break;
                        }
                        tokio::time::sleep(BACKPRESSURE_SLEEP).await;
                    }
                    if !accepted {
                        log::debug!("pipeline: dropping frame due to sink backpressure");
                        continue;
                    }
                }

                let samplerate = samplerate.unwrap_or(48_000);

                // Filter stage (on decoded samples)
                let mut frame = frame;
                for filter in &filters {
                    frame = filter.lock().await.handle_frame(&frame, samplerate);
                }

                // Codec stage
                let out_frame = match codec_role {
                    CodecRole::Encode => {
                        let mut codec = codec.lock().await;
                        codec.set_source_samplerate(samplerate);
                        match codec.encode(&frame) {
                            Ok(bytes) => SinkFrame::Encoded(bytes),
                            Err(e) => {
                                log::warn!("pipeline: encode failed: {e}");
                                continue;
                            }
                        }
                    }
                    CodecRole::Decode => {
                        // the source already decoded (e.g. LinkSource); the
                        // pipeline codec is the receive codec, kept for
                        // reference and late re-decoding
                        SinkFrame::Decoded(frame)
                    }
                };

                sink.lock().await.handle_frame(out_frame, source_id).await;
                frames_processed.fetch_add(1, Ordering::Relaxed);
            }

            running.store(false, Ordering::Relaxed);
        })
    }

    /// Stop the pipeline (Python `stop`).
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}
