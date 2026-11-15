//! Signal generators (Python `LXST/Generators.py`).
//!
//! Ports `ToneSource`: a phase-continuous sine generator with per-channel
//! amplitude, gain easing in/out on stop, and codec-driven frame timing.

use std::f64::consts::TAU;

use crate::common::{AudioFrame, SourceId};
use crate::sources::Source;

/// Default frame duration (Python `ToneSource.DEFAULT_FRAME_MS`).
pub const DEFAULT_FRAME_MS: f64 = 80.0;
/// Default samplerate (Python `ToneSource.DEFAULT_SAMPLERATE`).
pub const DEFAULT_SAMPLERATE: u32 = 48_000;
/// Default frequency (Python `ToneSource.DEFAULT_FREQUENCY`).
pub const DEFAULT_FREQUENCY: f64 = 400.0;
/// Ease ramp length (Python `ToneSource.EASE_TIME_MS`).
pub const EASE_TIME_MS: f64 = 20.0;

/// Sine tone generator (Python `LXST.Generators.ToneSource`).
///
/// Behaviour notes ported from Python:
///
/// * `gain` can be changed at runtime; the actual amplitude ramps toward it
///   with `gain_step = 0.02 / (samplerate * ease_time)` per sample
/// * with easing enabled, output starts silent and ramps in over the ease
///   time; `stop()` ramps out before finishing (and `running` reports false
///   immediately while easing out)
/// * phase (`theta`) accumulates continuously across frames
pub struct ToneSource {
    id: SourceId,
    pub frequency: f64,
    /// Requested gain (Python `gain`).
    pub gain: f32,
    /// Applied gain (Python `_gain`), ramps toward `gain`.
    applied_gain: f32,
    pub ease: bool,
    pub ease_time_ms: f64,
    theta: f64,
    ease_gain: f32,
    easing_out: bool,
    should_run: bool,
    samplerate: u32,
    channels: usize,
    samples_per_frame: usize,
    target_frame_ms: f64,
}

impl ToneSource {
    pub fn new(frequency: f64, gain: f32) -> Self {
        Self::configured(
            frequency,
            gain,
            true,
            EASE_TIME_MS,
            DEFAULT_FRAME_MS,
            1,
            DEFAULT_SAMPLERATE,
        )
    }

    /// Full constructor mirroring the Python one
    /// (`frequency, gain, ease, ease_time_ms, target_frame_ms, codec=None,
    /// sink=None, channels=1`).
    pub fn configured(
        frequency: f64,
        gain: f32,
        ease: bool,
        ease_time_ms: f64,
        target_frame_ms: f64,
        channels: usize,
        samplerate: u32,
    ) -> Self {
        let samples_per_frame = ((target_frame_ms / 1000.0) * samplerate as f64).ceil() as usize;
        Self {
            id: crate::common::new_source_id(),
            frequency,
            gain,
            applied_gain: gain,
            ease,
            ease_time_ms,
            theta: 0.0,
            ease_gain: 0.0,
            easing_out: false,
            should_run: false,
            samplerate,
            channels,
            samples_per_frame,
            target_frame_ms,
        }
    }

    /// Frame time in seconds (Python `frame_time`).
    pub fn frame_time(&self) -> f64 {
        self.samples_per_frame as f64 / self.samplerate as f64
    }

    pub fn samples_per_frame(&self) -> usize {
        self.samples_per_frame
    }

    /// Apply codec frame-time restrictions (Python `codec` setter).
    pub fn apply_frame_constraints(&mut self, codec: &dyn crate::codecs::Codec) {
        let target = crate::codecs::clamp_frame_ms(codec, self.target_frame_ms);
        if let Some(sr) = codec.preferred_samplerate() {
            self.samplerate = sr;
        }
        self.target_frame_ms = target;
        self.samples_per_frame = ((target / 1000.0) * self.samplerate as f64).ceil() as usize;
    }

    pub fn start(&mut self) {
        self.ease_gain = if self.ease { 0.0 } else { 1.0 };
        self.should_run = true;
        self.easing_out = false;
    }

    /// Stop, easing out first when easing is enabled (Python `stop`).
    pub fn stop(&mut self) {
        if !self.ease {
            self.should_run = false;
        } else {
            self.easing_out = true;
        }
    }

    pub fn running(&self) -> bool {
        self.should_run && !self.easing_out
    }

    /// Generate one frame (Python `__generate`).
    pub fn generate(&mut self) -> AudioFrame {
        let mut frame = AudioFrame::silence(self.samples_per_frame, self.channels);
        let step = (self.frequency * TAU) / self.samplerate as f64;
        let ease_step = 1.0 / (self.samplerate as f64 * (self.ease_time_ms / 1000.0));
        let gain_step = 0.02 / (self.samplerate as f64 * (self.ease_time_ms / 1000.0));

        for n in 0..self.samples_per_frame {
            self.theta += step;
            let amplitude = (self.theta.sin() as f32) * self.applied_gain * self.ease_gain;
            for c in 0..self.channels {
                *frame.sample_mut(n, c) = amplitude;
            }

            // ramp the applied gain toward the requested gain
            if self.gain > self.applied_gain {
                self.applied_gain += gain_step as f32;
                if self.applied_gain > self.gain {
                    self.applied_gain = self.gain;
                }
            }
            if self.gain < self.applied_gain {
                self.applied_gain -= gain_step as f32;
                if self.applied_gain < self.gain {
                    self.applied_gain = self.gain;
                }
            }

            if self.ease {
                if self.ease_gain < 1.0 && !self.easing_out {
                    self.ease_gain += ease_step as f32;
                    if self.ease_gain > 1.0 {
                        self.ease_gain = 1.0;
                    }
                } else if self.easing_out && self.ease_gain > 0.0 {
                    self.ease_gain -= ease_step as f32;
                    if self.ease_gain <= 0.0 {
                        self.ease_gain = 0.0;
                        self.easing_out = false;
                        self.should_run = false;
                    }
                }
            }
        }

        frame
    }
}

#[async_trait::async_trait]
impl Source for ToneSource {
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
        if !self.should_run {
            self.start();
        }
        Some(self.generate())
    }

    fn running(&self) -> bool {
        self.running()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tone_frequency_and_amplitude() {
        let mut t = ToneSource::configured(1000.0, 0.5, false, 20.0, 20.0, 1, 48_000);
        t.start();
        let frame = t.generate();
        assert_eq!(frame.frames(), 960); // ceil(0.02 * 48000)

        // count zero crossings to verify the frequency
        let mut crossings: i32 = 0;
        for i in 1..frame.frames() {
            if frame.sample(i - 1, 0) <= 0.0 && frame.sample(i, 0) > 0.0 {
                crossings += 1;
            }
        }
        // 20ms of 1kHz should give ~20 cycles
        assert!((crossings - 20).abs() <= 1, "crossings {crossings}");

        // amplitude bounded by the gain
        let peak = (0..frame.frames())
            .map(|i| frame.sample(i, 0).abs())
            .fold(0.0f32, f32::max);
        assert!(peak <= 0.5 && peak > 0.49, "peak {peak}");
    }

    #[test]
    fn easing_ramps_in() {
        let mut t = ToneSource::configured(400.0, 1.0, true, 20.0, 20.0, 1, 48_000);
        t.start();
        let first = t.generate();
        // early samples must be near-silent with easing
        assert!(first.sample(0, 0).abs() < 0.01);
        // and reach full amplitude by the end of the ease window
        for _ in 0..3 {
            let _ = t.generate();
        }
        let later = t.generate();
        let peak = (0..later.frames())
            .map(|i| later.sample(i, 0).abs())
            .fold(0.0f32, f32::max);
        assert!(peak > 0.9, "peak {peak}");
    }

    #[test]
    fn easing_out_on_stop() {
        let mut t = ToneSource::configured(400.0, 1.0, true, 20.0, 20.0, 1, 48_000);
        t.start();
        let _ = t.generate();
        assert!(t.running());
        t.stop();
        // running reports false immediately while easing out
        assert!(!t.running());

        // generate until the source stops itself, mirroring the Python
        // __generate_job loop which exits on should_run == False
        let mut frames = 0;
        let mut last = t.generate();
        while t.should_run && frames < 8 {
            last = t.generate();
            frames += 1;
        }
        assert!(!t.should_run);
        // the final frame fades to (near) silence
        // the linear ease ramp reaches (near) zero at the very end of the
        // frame: the last few samples carry <= ease_step of amplitude
        let tail: Vec<f32> = last.samples[last.samples.len() - 8..].to_vec();
        assert!(
            tail.iter().all(|s| s.abs() < 0.01),
            "tail amplitude {}",
            tail.iter().fold(0.0f32, |m, s| m.max(s.abs()))
        );
    }

    #[test]
    fn phase_is_continuous() {
        // 700 Hz is not an integer number of cycles per 20 ms frame, so a
        // phase reset between frames would change the waveform
        // 717 Hz is not an integer number of cycles per 20 ms frame
        let mut t = ToneSource::configured(717.0, 1.0, false, 20.0, 20.0, 1, 48_000);
        t.start();
        let a = t.generate();
        let b = t.generate();
        // the first sample of the next frame is not the first sample of the
        // previous frame
        assert_ne!(a.sample(0, 0), b.sample(0, 0));
        // and amplitudes stay bounded
        let peak = b.samples.iter().fold(0.0f32, |m, s| m.max(s.abs()));
        assert!(peak <= 1.0);
    }

    #[test]
    fn multichannel() {
        let mut t = ToneSource::configured(400.0, 0.25, false, 20.0, 20.0, 2, 8000);
        t.start();
        let f = t.generate();
        assert_eq!(f.channels, 2);
        assert_eq!(f.frames(), 160);
        assert_eq!(f.sample(0, 0), f.sample(0, 1));
    }
}
