//! Audio filters (Python `LXST/Filters.py`).
//!
//! Ports the pure-DSP filters:
//!
//! * [`HighPass`] / [`LowPass`] - one-pole RC filters applied per channel
//!   with carried state, exactly the coefficients and recurrence used by
//!   both the Python fallback implementation and the C `filterlib`
//! * [`BandPass`] - high-pass then low-pass cascade
//! * [`AGC`] - block-wise automatic gain control with attack/release/hold
//!   and a 0.75 peak limiter (port of the C `agc_process`, which is the
//!   canonical implementation the Python falls back from)
//!
//! All filters are frame-oriented: `handle_frame(frame, samplerate)` takes
//! interleaved samples plus a channel count and keeps per-channel state
//! between calls.

use crate::common::AudioFrame;

/// A streaming audio filter (Python `Filters.Filter`).
pub trait Filter: Send {
    /// Process one frame of interleaved samples at `samplerate`.
    fn handle_frame(&mut self, frame: &AudioFrame, samplerate: u32) -> AudioFrame;
}

/// One-pole RC high-pass (Python `Filters.HighPass`).
///
/// `alpha = rc / (rc + dt)` with `rc = 1 / (2*pi*cut)`,
/// `y[n] = alpha * (y[n-1] + x[n] - x[n-1])`, computed with f32 state.
pub struct HighPass {
    pub cut: f64,
    samplerate: Option<u32>,
    channels: Option<usize>,
    filter_states: Vec<f32>,
    last_inputs: Vec<f32>,
    alpha: f32,
}

impl HighPass {
    pub fn new(cut: f64) -> Self {
        Self {
            cut,
            samplerate: None,
            channels: None,
            filter_states: Vec::new(),
            last_inputs: Vec::new(),
            alpha: 0.0,
        }
    }

    fn configure(&mut self, samplerate: u32) {
        if self.samplerate != Some(samplerate) {
            self.samplerate = Some(samplerate);
            let dt = 1.0 / samplerate as f64;
            let rc = 1.0 / (std::f64::consts::TAU * self.cut);
            self.alpha = (rc / (rc + dt)) as f32;
        }
    }
}

impl Filter for HighPass {
    fn handle_frame(&mut self, frame: &AudioFrame, samplerate: u32) -> AudioFrame {
        if frame.is_empty() {
            return frame.clone();
        }
        self.configure(samplerate);

        let channels = frame.channels;
        if self.channels != Some(channels) || self.filter_states.len() != channels {
            self.channels = Some(channels);
            self.filter_states = vec![0.0; channels];
            self.last_inputs = vec![0.0; channels];
        }

        let frames = frame.frames();
        let mut out = AudioFrame::silence(frames, channels);
        for ch in 0..channels {
            // first sample crosses the frame boundary using last frame's state
            let x0 = frame.sample(0, ch);
            let input_diff = x0 - self.last_inputs[ch];
            out.samples[ch] = self.alpha * (self.filter_states[ch] + input_diff);

            for i in 1..frames {
                let diff = frame.sample(i, ch) - frame.sample(i - 1, ch);
                out.samples[i * channels + ch] =
                    self.alpha * (out.samples[(i - 1) * channels + ch] + diff);
            }

            self.filter_states[ch] = out.sample(frames - 1, ch);
            self.last_inputs[ch] = frame.sample(frames - 1, ch);
        }
        out
    }
}

/// One-pole RC low-pass (Python `Filters.LowPass`).
///
/// `alpha = dt / (rc + dt)`, `y[n] = alpha * x[n] + (1 - alpha) * y[n-1]`.
pub struct LowPass {
    pub cut: f64,
    samplerate: Option<u32>,
    channels: Option<usize>,
    filter_states: Vec<f32>,
    alpha: f32,
}

impl LowPass {
    pub fn new(cut: f64) -> Self {
        Self {
            cut,
            samplerate: None,
            channels: None,
            filter_states: Vec::new(),
            alpha: 0.0,
        }
    }

    fn configure(&mut self, samplerate: u32) {
        if self.samplerate != Some(samplerate) {
            self.samplerate = Some(samplerate);
            let dt = 1.0 / samplerate as f64;
            let rc = 1.0 / (std::f64::consts::TAU * self.cut);
            self.alpha = (dt / (rc + dt)) as f32;
        }
    }
}

impl Filter for LowPass {
    fn handle_frame(&mut self, frame: &AudioFrame, samplerate: u32) -> AudioFrame {
        if frame.is_empty() {
            return frame.clone();
        }
        self.configure(samplerate);

        let channels = frame.channels;
        if self.channels != Some(channels) || self.filter_states.len() != channels {
            self.channels = Some(channels);
            self.filter_states = vec![0.0; channels];
        }

        let frames = frame.frames();
        let mut out = AudioFrame::silence(frames, channels);
        for ch in 0..channels {
            out.samples[ch] =
                self.alpha * frame.sample(0, ch) + (1.0 - self.alpha) * self.filter_states[ch];
            for i in 1..frames {
                out.samples[i * channels + ch] = self.alpha * frame.sample(i, ch)
                    + (1.0 - self.alpha) * out.samples[(i - 1) * channels + ch];
            }
            self.filter_states[ch] = out.sample(frames - 1, ch);
        }
        out
    }
}

/// High-pass + low-pass cascade (Python `Filters.BandPass`).
///
/// Panics at construction when `low_cut >= high_cut`, mirroring the Python
/// `ValueError`. Use [`BandPass::try_new`] for a fallible constructor.
pub struct BandPass {
    pub low_cut: f64,
    pub high_cut: f64,
    high_pass: HighPass,
    low_pass: LowPass,
}

impl BandPass {
    pub fn new(low_cut: f64, high_cut: f64) -> Self {
        if low_cut >= high_cut {
            panic!("Low-cut frequency must be less than high-cut frequency");
        }
        Self {
            low_cut,
            high_cut,
            high_pass: HighPass::new(low_cut),
            low_pass: LowPass::new(high_cut),
        }
    }

    pub fn try_new(low_cut: f64, high_cut: f64) -> Result<Self, String> {
        if low_cut >= high_cut {
            return Err("Low-cut frequency must be less than high-cut frequency".into());
        }
        Ok(Self::new(low_cut, high_cut))
    }
}

impl Filter for BandPass {
    fn handle_frame(&mut self, frame: &AudioFrame, samplerate: u32) -> AudioFrame {
        if frame.is_empty() {
            return frame.clone();
        }
        let high_passed = self.high_pass.handle_frame(frame, samplerate);
        self.low_pass.handle_frame(&high_passed, samplerate)
    }
}

/// Automatic gain control (Python `Filters.AGC`).
///
/// Defaults match Python: target `-12 dBFS`, max gain `12 dB`, attack
/// `100 us`, release `2 ms`, hold `1 ms`, trigger level `0.003`, block
/// target `10 ms`, peak limit `0.75`.
///
/// This is a port of the canonical C implementation (`Filters.c::
/// agc_process`), which the Python code uses whenever the native library is
/// available and falls back from. Notable details preserved:
///
/// * block RMS is measured **after** previous blocks have been amplified
///   (the C code measures `output`, i.e. progressively)
/// * the trigger level gates gain reduction only; quiet blocks keep the
///   current gain
/// * the attack path (gain decreasing) always resets the hold counter,
///   even mid-hold
/// * the release path only runs when the hold counter is exhausted
/// * a final per-channel peak limiter scales frames whose peak exceeds 0.75
pub struct Agc {
    pub trigger_level: f32,
    pub target_level_db: f32,
    pub max_gain_db: f32,
    pub attack_time: f64,
    pub release_time: f64,
    pub hold_time: f64,
    pub peak_limit: f32,

    target_linear: f32,
    max_gain_linear: f32,
    samplerate: Option<u32>,
    channels: Option<usize>,
    current_gain_lin: Vec<f32>,
    hold_counter: i32,
    block_target_s: f64,
    block_target: usize,
    attack_coeff: f32,
    release_coeff: f32,
    hold_samples: i32,
}

impl Agc {
    /// Python defaults.
    pub fn new() -> Self {
        Self::with_params(-12.0, 12.0, 0.0001, 0.002, 0.001)
    }

    pub fn with_params(
        target_level_db: f32,
        max_gain_db: f32,
        attack_time: f64,
        release_time: f64,
        hold_time: f64,
    ) -> Self {
        Self {
            trigger_level: 0.003,
            target_level_db,
            max_gain_db,
            attack_time,
            release_time,
            hold_time,
            peak_limit: 0.75,
            target_linear: 10f32.powf(target_level_db / 10.0),
            max_gain_linear: 10f32.powf(max_gain_db / 10.0),
            samplerate: None,
            channels: None,
            current_gain_lin: vec![1.0],
            hold_counter: 0,
            block_target_s: 0.01,
            block_target: 1,
            attack_coeff: 0.1,
            release_coeff: 0.01,
            hold_samples: 1000,
        }
    }

    fn calculate_coefficients(&mut self, samples: usize) {
        if let Some(sr) = self.samplerate {
            let sr = sr as f64;
            self.attack_coeff = (1.0 - (-1.0 / (self.attack_time * sr)).exp()) as f32;
            self.release_coeff = (1.0 - (-1.0 / (self.release_time * sr)).exp()) as f32;
            self.hold_samples = (self.hold_time * sr) as i32;
            // Python: self._block_target = int((samples/self._samplerate)/self._block_target_s)
            self.block_target = ((samples as f64 / sr) / self.block_target_s) as usize;
        }
    }
}

impl Default for Agc {
    fn default() -> Self {
        Self::new()
    }
}

impl Filter for Agc {
    fn handle_frame(&mut self, frame: &AudioFrame, samplerate: u32) -> AudioFrame {
        if frame.is_empty() {
            return frame.clone();
        }

        if self.samplerate != Some(samplerate) {
            self.samplerate = Some(samplerate);
            self.calculate_coefficients(frame.frames());
        }

        let channels = frame.channels;
        if self.channels != Some(channels) || self.current_gain_lin.len() != channels {
            self.channels = Some(channels);
            self.current_gain_lin = vec![1.0; channels];
            self.hold_counter = 0;
        }

        if self.block_target < 1 {
            self.block_target = 1;
        }

        let samples = frame.frames();
        let mut out = frame.clone();

        let num_blocks = self.block_target;
        let block_size = (samples / num_blocks).max(1);

        let mut block = 0usize;
        while block < num_blocks {
            let block_start = block * block_size;
            let mut block_end = (block + 1) * block_size;
            if block == num_blocks - 1 {
                block_end = samples;
            }
            if block_end > samples {
                block_end = samples;
            }
            let block_samples = block_end.saturating_sub(block_start);
            if block_samples == 0 {
                block += 1;
                continue;
            }

            for ch in 0..channels {
                let mut sum_squares = 0.0f32;
                for i in block_start..block_end {
                    let v = out.sample(i, ch);
                    sum_squares += v * v;
                }
                let rms = (sum_squares / block_samples as f32).sqrt();

                let target_gain = if rms > 1e-9 && rms > self.trigger_level {
                    let g = self.target_linear / rms;
                    if g > self.max_gain_linear {
                        self.max_gain_linear
                    } else {
                        g
                    }
                } else {
                    self.current_gain_lin[ch]
                };

                if target_gain < self.current_gain_lin[ch] {
                    self.current_gain_lin[ch] = self.attack_coeff * target_gain
                        + (1.0 - self.attack_coeff) * self.current_gain_lin[ch];
                    self.hold_counter = self.hold_samples;
                } else if self.hold_counter > 0 {
                    self.hold_counter -= block_samples as i32;
                } else {
                    self.current_gain_lin[ch] = self.release_coeff * target_gain
                        + (1.0 - self.release_coeff) * self.current_gain_lin[ch];
                }

                for i in block_start..block_end {
                    *out.sample_mut(i, ch) *= self.current_gain_lin[ch];
                }
            }
            block += 1;
        }

        // Peak limiter
        for ch in 0..channels {
            let mut peak = 0.0f32;
            for i in 0..samples {
                peak = peak.max(out.sample(i, ch).abs());
            }
            if peak > self.peak_limit {
                let scale = self.peak_limit / peak;
                for i in 0..samples {
                    *out.sample_mut(i, ch) *= scale;
                }
            }
        }

        out
    }
}

/// Python spelling kept as an alias.
pub type AGC = Agc;

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(freq: f32, samplerate: u32, frames: usize, channels: usize) -> AudioFrame {
        let mut samples = Vec::with_capacity(frames * channels);
        for i in 0..frames {
            let v = (std::f32::consts::TAU * freq * i as f32 / samplerate as f32).sin() * 0.8;
            for _ in 0..channels {
                samples.push(v);
            }
        }
        AudioFrame::from_interleaved(samples, channels)
    }

    fn energy(frame: &AudioFrame, ch: usize) -> f32 {
        let n = frame.frames();
        (0..n)
            .map(|i| frame.sample(i, ch) * frame.sample(i, ch))
            .sum::<f32>()
            / n as f32
    }

    #[test]
    fn lowpass_attenuates_highs() {
        let mut lp = LowPass::new(300.0);
        let low = tone(100.0, 48_000, 4800, 1);
        let high = tone(20_000.0, 48_000, 4800, 1);

        let low_out = lp.handle_frame(&low, 48_000);
        let high_out = lp.handle_frame(&high, 48_000);

        let low_ratio = energy(&low_out, 0) / energy(&low, 0);
        let high_ratio = energy(&high_out, 0) / energy(&high, 0);
        assert!(high_ratio < low_ratio, "high={high_ratio} low={low_ratio}");
        assert!(high_ratio < 0.01, "high ratio {high_ratio}");
        assert!(low_ratio > 0.8, "low ratio {low_ratio}");
    }

    #[test]
    fn highpass_attenuates_lows() {
        let mut hp = HighPass::new(3000.0);
        let low = tone(50.0, 48_000, 4800, 1);
        let high = tone(20_000.0, 48_000, 4800, 1);

        let low_out = hp.handle_frame(&low, 48_000);
        let high_out = hp.handle_frame(&high, 48_000);

        let low_ratio = energy(&low_out, 0) / energy(&low, 0);
        let high_ratio = energy(&high_out, 0) / energy(&high, 0);
        assert!(low_ratio < high_ratio);
        assert!(low_ratio < 0.01, "low ratio {low_ratio}");
    }

    #[test]
    fn filters_keep_state_between_frames() {
        let mut lp = LowPass::new(1000.0);
        let f = tone(1000.0, 8000, 800, 1);
        let a = lp.handle_frame(&f, 8000);
        let b = lp.handle_frame(&f, 8000);
        // second frame continues from the carried state, so differs
        assert_ne!(a.samples, b.samples);
        // and a steady tone converges: later energy >= earlier energy
        assert!(energy(&b, 0) >= energy(&a, 0) * 0.99);
    }

    #[test]
    fn multichannel_filters_are_independent() {
        let mut lp = LowPass::new(500.0);
        // channel 0 constant 1.0, channel 1 alternating +/-1
        let mut samples = Vec::new();
        for i in 0..1000 {
            samples.push(1.0);
            samples.push(if i % 2 == 0 { 1.0 } else { -1.0 });
        }
        let f = AudioFrame::from_interleaved(samples, 2);
        let out = lp.handle_frame(&f, 48_000);
        // channel 0 (DC) passes at cut 500Hz
        assert!(out.sample(999, 0) > 0.9);
        // channel 1 (24kHz Nyquist alternating) is strongly attenuated
        // (one-pole residual oscillation ~ alpha / (2 - alpha) ~ 0.03)
        assert!(out.sample(999, 1).abs() < 0.05);
    }

    #[test]
    fn bandpass_rejects_out_of_band() {
        let mut bp = BandPass::new(250.0, 8500.0);
        let low = tone(50.0, 48_000, 9600, 1);
        let high = tone(20_000.0, 48_000, 9600, 1);
        let mid = tone(1000.0, 48_000, 9600, 1);

        let lo = energy(&bp.handle_frame(&low, 48_000), 0) / energy(&low, 0);
        let hi = energy(&bp.handle_frame(&high, 48_000), 0) / energy(&high, 0);
        let mi = energy(&bp.handle_frame(&mid, 48_000), 0) / energy(&mid, 0);

        // one-pole skirts are gradual: compare against the pass band
        assert!(lo < 0.05, "low leakage {lo}");
        assert!(hi < mi, "high leakage {hi} vs mid {mi}");
        assert!(hi < 0.3, "high leakage {hi}");
        assert!(mi > 0.5, "mid attenuation {mi}");
    }

    #[test]
    fn agc_raises_quiet_signals() {
        let mut agc = Agc::new();
        let quiet = {
            let mut samples = Vec::new();
            for i in 0..4800 {
                samples.push((std::f32::consts::TAU * 1000.0 * i as f32 / 48000.0).sin() * 0.01);
            }
            AudioFrame::from_interleaved(samples, 1)
        };

        // gain accumulates across frames (attack/release smoothing)
        let mut last_gain = 0.0f32;
        let mut peak = 0.0f32;
        for _ in 0..5 {
            let out = agc.handle_frame(&quiet, 48_000);
            last_gain = energy(&out, 0) / energy(&quiet, 0);
            peak = (0..out.frames())
                .map(|i| out.sample(i, 0).abs())
                .fold(0.0f32, f32::max);
        }
        let gain = last_gain;
        assert!(gain > 2.0, "agc gain only {gain}");
        // and the peak limiter keeps the output bounded
        assert!(peak <= 0.76, "peak {peak}");
    }

    #[test]
    fn agc_limits_loud_signals() {
        let mut agc = Agc::new();
        let loud = tone(1000.0, 48_000, 4800, 1);
        let out = agc.handle_frame(&loud, 48_000);
        // attenuates toward the target level without exceeding the limit
        assert!(energy(&out, 0) < energy(&loud, 0));
        let peak = (0..out.frames())
            .map(|i| out.sample(i, 0).abs())
            .fold(0.0f32, f32::max);
        assert!(peak <= 0.76);
    }

    #[test]
    fn bandpass_validates_cuts() {
        assert!(BandPass::try_new(1000.0, 100.0).is_err());
        assert!(BandPass::try_new(100.0, 1000.0).is_ok());
    }
}
