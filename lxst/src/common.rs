//! Common types and helpers (Python `LXST/Common.py` plus the shared audio
//! frame representation).
//!
//! Python passes `numpy` arrays of shape `(samples, channels)` with
//! normalised `float32` samples in `[-1.0, 1.0]`. The Rust equivalent is
//! [`AudioFrame`] with **interleaved** samples.

use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque identifier for a pipeline source.
///
/// Python identifies sources by object identity (used e.g. by
/// [`crate::mixer::Mixer`] to keep per-source buffers). Here every source
/// gets a monotonically increasing id instead.
pub type SourceId = u64;

static NEXT_SOURCE_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate a new unique [`SourceId`].
pub fn new_source_id() -> SourceId {
    NEXT_SOURCE_ID.fetch_add(1, Ordering::Relaxed)
}

/// A block of decoded audio: interleaved `f32` samples for `channels`
/// channels (Python: a `numpy` array of shape `(samples, channels)`).
#[derive(Clone, Debug, PartialEq)]
pub struct AudioFrame {
    /// Interleaved samples, `samples.len() == frames() * channels`.
    pub samples: Vec<f32>,
    /// Number of interleaved channels.
    pub channels: usize,
}

impl AudioFrame {
    /// An all-zero frame of `frames` sample-rows and `channels` channels.
    pub fn silence(frames: usize, channels: usize) -> Self {
        Self {
            samples: vec![0.0; frames * channels],
            channels,
        }
    }

    /// Build a frame from interleaved samples.
    pub fn from_interleaved(samples: Vec<f32>, channels: usize) -> Self {
        Self { samples, channels }
    }

    /// Build a frame from planar (per-channel) sample buffers.
    pub fn from_planar(planar: &[&[f32]], frames: usize) -> Self {
        let channels = planar.len();
        let mut samples = Vec::with_capacity(frames * channels);
        for i in 0..frames {
            for ch in planar {
                samples.push(ch[i]);
            }
        }
        Self { samples, channels }
    }

    /// Number of sample-rows (the first dimension of the Python array).
    pub fn frames(&self) -> usize {
        self.samples
            .len()
            .checked_div(self.channels.max(1))
            .unwrap_or(0)
    }

    /// `true` when the frame contains no samples.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Interleaved sample accessor: sample-row `i`, channel `ch`.
    pub fn sample(&self, i: usize, ch: usize) -> f32 {
        self.samples[i * self.channels + ch]
    }

    /// Mutable interleaved sample accessor.
    pub fn sample_mut(&mut self, i: usize, ch: usize) -> &mut f32 {
        &mut self.samples[i * self.channels + ch]
    }

    /// Multiply every sample by `gain`.
    pub fn apply_gain(&mut self, gain: f32) {
        for s in self.samples.iter_mut() {
            *s *= gain;
        }
    }

    /// Clip every sample into `[-1.0, 1.0]` (Python `np.clip(mixed, -1, 1)`).
    pub fn clip(&mut self) {
        for s in self.samples.iter_mut() {
            *s = s.clamp(-1.0, 1.0);
        }
    }

    /// Adapt the channel count the way the Python codecs do:
    ///
    /// * more channels than requested -> keep only the first `channels`
    /// * fewer channels than requested -> replicate the **last original
    ///   channel** into every extra channel
    ///
    /// (Python `Raw.encode`: `new_frame[:, n] = frame[:, frame.shape[1]-1]`).
    pub fn adapt_channels(&self, channels: usize) -> AudioFrame {
        if channels == self.channels {
            return self.clone();
        }

        let frames = self.frames();
        if channels < self.channels {
            let mut samples = Vec::with_capacity(frames * channels);
            for i in 0..frames {
                for ch in 0..channels {
                    samples.push(self.sample(i, ch));
                }
            }
            Self { samples, channels }
        } else {
            let last = self.channels.saturating_sub(1);
            let mut samples = Vec::with_capacity(frames * channels);
            for i in 0..frames {
                for ch in 0..channels {
                    samples.push(if ch < self.channels {
                        self.sample(i, ch)
                    } else {
                        self.sample(i, last)
                    });
                }
            }
            Self { samples, channels }
        }
    }

    /// Element-wise sum of frames (must agree on layout), used by
    /// [`crate::mixer::Mixer`].
    pub fn sum(frames: &[&AudioFrame]) -> Option<AudioFrame> {
        let first = frames.first()?;
        let mut out = AudioFrame::silence(first.frames(), first.channels);
        for f in frames {
            if f.channels != out.channels || f.samples.len() != out.samples.len() {
                return None;
            }
            for (o, s) in out.samples.iter_mut().zip(f.samples.iter()) {
                *o += *s;
            }
        }
        Some(out)
    }
}

/// No-op, mirroring `LXST.Common.nop`.
pub fn nop() {}
