//! The audio mixer (Python `LXST/Mixer.py`).
//!
//! Mixes decoded frames from multiple sources into a single output stream:
//!
//! * every source gets a bounded frame queue (default `MAX_FRAMES = 8`,
//!   configurable per source with [`Mixer::set_source_max_frames`])
//! * `handle_frame` decodes the incoming frame when it arrives still
//!   encoded (Python decodes via `source.codec.decode`) and buffers it
//! * `mix_next_frame` pops one frame per ready source, applies the mixing
//!   gain, sums them, clips to `[-1, 1]` and optionally re-encodes
//! * sources above their queue limit are refused by `can_receive`
//!   (backpressure)

use std::collections::HashMap;

use crate::codecs::Codec;
use crate::common::{AudioFrame, SourceId};
use crate::sinks::SinkFrame;

/// Maximum frames buffered per source (Python `Mixer.MAX_FRAMES`).
pub const MAX_FRAMES: usize = 8;

/// Multi-source summing mixer (Python `LXST.Mixer`).
pub struct Mixer {
    incoming_frames: HashMap<SourceId, std::collections::VecDeque<AudioFrame>>,
    max_frames: HashMap<SourceId, usize>,
    pub target_frame_ms: f64,
    pub gain: f32,
    pub muted: bool,
    pub samplerate: Option<u32>,
    pub channels: Option<usize>,
    pub samples_per_frame: Option<usize>,
    /// Frames the mixer has emitted.
    pub frames_mixed: u64,
}

impl Mixer {
    pub fn new(target_frame_ms: f64) -> Self {
        Self {
            incoming_frames: HashMap::new(),
            max_frames: HashMap::new(),
            target_frame_ms,
            gain: 0.0,
            muted: false,
            samplerate: None,
            channels: None,
            samples_per_frame: None,
            frames_mixed: 0,
        }
    }

    /// Mixer with an explicit samplerate (Python `Mixer(samplerate=...)`).
    pub fn with_samplerate(target_frame_ms: f64, samplerate: u32) -> Self {
        let mut m = Self::new(target_frame_ms);
        m.samplerate = Some(samplerate);
        m.samples_per_frame =
            Some(((target_frame_ms / 1000.0) * samplerate as f64).ceil() as usize);
        m
    }

    /// Set the mixer gain in dB (Python `set_gain`); `None` resets to 0.
    pub fn set_gain(&mut self, gain: Option<f32>) {
        self.gain = gain.unwrap_or(0.0);
    }

    pub fn mute(&mut self, mute: bool) {
        self.muted = mute;
    }

    /// Clear the mute.
    ///
    /// Note: the Python `Mixer.unmute` assigns `self.muted = unmute`, so
    /// calling `unmute()` there *keeps* the mixer muted - clearly a bug.
    /// This port implements the intended behaviour (`muted = !unmute`).
    pub fn unmute(&mut self, unmute: bool) {
        self.muted = !unmute;
    }

    /// The linear mixing gain applied to every source (Python
    /// `_mixing_gain`): 0 when muted, 1 at 0 dB gain, otherwise
    /// `10**(gain/10)`.
    pub fn mixing_gain(&self) -> f32 {
        if self.muted {
            0.0
        } else if self.gain == 0.0 {
            1.0
        } else {
            10f32.powf(self.gain / 10.0)
        }
    }

    /// Cap the buffer of one source (Python `set_source_max_frames`).
    pub fn set_source_max_frames(&mut self, source: SourceId, max_frames: usize) {
        let entry = self.incoming_frames.entry(source).or_default();
        while entry.len() > max_frames {
            entry.pop_front();
        }
        self.max_frames.insert(source, max_frames);
    }

    /// Frames buffered for a source.
    pub fn frames_waiting(&self, source: SourceId) -> usize {
        self.incoming_frames
            .get(&source)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Number of sources currently registered.
    pub fn source_count(&self) -> usize {
        self.incoming_frames.len()
    }

    /// Backpressure check (Python `can_receive`).
    ///
    /// Mirrors the Python quirk that this compares against the **class**
    /// `MAX_FRAMES` (8), not the per-source limit configured with
    /// [`Mixer::set_source_max_frames`]; the per-source limit only caps the
    /// queue itself (dropping the oldest frames).
    pub fn can_receive(&self, from_source: SourceId) -> bool {
        match self.incoming_frames.get(&from_source) {
            None => true,
            Some(q) => q.len() < MAX_FRAMES,
        }
    }

    /// Buffer one frame from `source` (Python `handle_frame`).
    ///
    /// The frame may still be encoded; in that case `codec` decodes it
    /// first (Python does `source.codec.decode(frame)` when
    /// `decoded == False`). The first source to register fixes the mixer's
    /// channel count, samplerate and frame size.
    pub fn handle_frame(
        &mut self,
        frame: SinkFrame,
        source: SourceId,
        source_samplerate: Option<u32>,
        source_channels: Option<usize>,
        codec: &mut dyn Codec,
    ) -> Result<(), crate::LxstError> {
        let decoded = match frame {
            SinkFrame::Decoded(f) => f,
            SinkFrame::Encoded(b) => codec.decode(&b)?,
        };

        if let std::collections::hash_map::Entry::Vacant(e) = self.incoming_frames.entry(source) {
            e.insert(Default::default());
            if self.channels.is_none() {
                self.channels = source_channels.or(Some(decoded.channels));
            }
            if self.samplerate.is_none() {
                if let Some(sr) = source_samplerate {
                    self.samplerate = Some(sr);
                    self.samples_per_frame =
                        Some(((self.target_frame_ms / 1000.0) * sr as f64).ceil() as usize);
                }
            }
        }

        let limit = *self.max_frames.get(&source).unwrap_or(&MAX_FRAMES);
        let Some(queue) = self.incoming_frames.get_mut(&source) else {
            return Ok(());
        };
        while queue.len() >= limit {
            queue.pop_front();
        }
        queue.push_back(decoded);
        Ok(())
    }

    /// Mix and return the next output frame, if any source has data
    /// (one iteration of the Python `_mixer_job` loop body).
    pub fn mix_next_frame(&mut self) -> Option<AudioFrame> {
        let gain = self.mixing_gain();

        let mut mixed: Option<AudioFrame> = None;
        let mut source_count = 0;

        for queue in self.incoming_frames.values_mut() {
            if let Some(frame) = queue.pop_front() {
                let scaled = {
                    let mut f = frame;
                    f.apply_gain(gain);
                    f
                };
                mixed = Some(match mixed {
                    None => scaled,
                    Some(mut acc) => {
                        // Python mixes element-wise; layouts are expected to
                        // agree, mismatched frames are truncated to the
                        // shorter one.
                        let n = acc.samples.len().min(scaled.samples.len());
                        acc.samples.truncate(n);
                        for i in 0..n {
                            acc.samples[i] += scaled.samples[i];
                        }
                        if scaled.channels > acc.channels {
                            acc.channels = scaled.channels;
                        }
                        acc
                    }
                });
                source_count += 1;
            }
        }

        if source_count == 0 {
            return None;
        }

        let mut mixed = mixed.expect("at least one source contributed");
        mixed.clip();
        self.frames_mixed += 1;
        Some(mixed)
    }

    /// Mix and encode the next frame with `codec` (Python encodes when a
    /// codec is configured on the mixer).
    pub fn mix_next_encoded(
        &mut self,
        codec: &mut dyn Codec,
    ) -> Result<Option<Vec<u8>>, crate::LxstError> {
        match self.mix_next_frame() {
            Some(frame) => Ok(Some(codec.encode(&frame)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codecs::{CodecType, Null, Raw};

    #[tokio::test]
    async fn mixes_two_sources() {
        let mut mixer = Mixer::new(20.0);
        let a = crate::common::new_source_id();
        let b = crate::common::new_source_id();
        let mut null = Null::new();

        mixer
            .handle_frame(
                SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.5; 100], 1)),
                a,
                Some(48_000),
                Some(1),
                &mut null,
            )
            .unwrap();
        mixer
            .handle_frame(
                SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.25; 100], 1)),
                b,
                Some(48_000),
                Some(1),
                &mut null,
            )
            .unwrap();

        let mixed = mixer.mix_next_frame().unwrap();
        assert_eq!(mixed.frames(), 100);
        assert!((mixed.sample(0, 0) - 0.75).abs() < 1e-6);
        // no more data
        assert!(mixer.mix_next_frame().is_none());
    }

    #[tokio::test]
    async fn clips_on_overflow() {
        let mut mixer = Mixer::new(20.0);
        let a = crate::common::new_source_id();
        let b = crate::common::new_source_id();
        let mut null = Null::new();
        mixer
            .handle_frame(
                SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.9; 10], 1)),
                a,
                None,
                None,
                &mut null,
            )
            .unwrap();
        mixer
            .handle_frame(
                SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.9; 10], 1)),
                b,
                None,
                None,
                &mut null,
            )
            .unwrap();
        let mixed = mixer.mix_next_frame().unwrap();
        assert_eq!(mixed.sample(0, 0), 1.0); // np.clip(1.8, -1, 1)
    }

    #[tokio::test]
    async fn gain_and_mute() {
        let mut mixer = Mixer::new(20.0);
        let a = crate::common::new_source_id();
        let mut null = Null::new();
        assert_eq!(mixer.mixing_gain(), 1.0);

        mixer.set_gain(Some(10.0)); // +10 dB -> 10x
        assert!((mixer.mixing_gain() - 10.0).abs() < 1e-4);

        mixer.mute(true);
        assert_eq!(mixer.mixing_gain(), 0.0);
        mixer
            .handle_frame(
                SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.5; 10], 1)),
                a,
                None,
                None,
                &mut null,
            )
            .unwrap();
        let mixed = mixer.mix_next_frame().unwrap();
        assert!(mixed.samples.iter().all(|s| *s == 0.0));

        mixer.unmute(true);
        assert_eq!(mixer.mixing_gain(), 10.0);
    }

    #[tokio::test]
    async fn decodes_encoded_input() {
        let mut mixer = Mixer::new(20.0);
        let a = crate::common::new_source_id();
        let mut raw = Raw::new(Some(1), 32);
        let encoded = raw
            .encode(&AudioFrame::from_interleaved(vec![0.5, -0.5], 1))
            .unwrap();

        mixer
            .handle_frame(
                SinkFrame::Encoded(encoded),
                a,
                Some(48_000),
                Some(1),
                &mut raw,
            )
            .unwrap();
        let mixed = mixer.mix_next_frame().unwrap();
        assert_eq!(mixed.samples, vec![0.5, -0.5]);
    }

    #[tokio::test]
    async fn backpressure_per_source() {
        let mut mixer = Mixer::new(20.0);
        let a = crate::common::new_source_id();
        let mut null = Null::new();
        assert!(mixer.can_receive(a));
        for _ in 0..MAX_FRAMES {
            mixer
                .handle_frame(
                    SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.1; 10], 1)),
                    a,
                    None,
                    None,
                    &mut null,
                )
                .unwrap();
        }
        assert!(!mixer.can_receive(a));
        assert!(mixer.can_receive(crate::common::new_source_id()));

        mixer.set_source_max_frames(a, 2);
        assert_eq!(mixer.frames_waiting(a), 2);
        // Python's can_receive compares against MAX_FRAMES (8), not the
        // per-source limit
        assert!(mixer.can_receive(a));
    }

    #[tokio::test]
    async fn encodes_output() {
        let mut mixer = Mixer::with_samplerate(20.0, 8000);
        let a = crate::common::new_source_id();
        let mut null = Null::new();
        mixer
            .handle_frame(
                SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.5; 160], 1)),
                a,
                None,
                None,
                &mut null,
            )
            .unwrap();
        assert_eq!(mixer.samples_per_frame, Some(160));
        let mut raw = Raw::new(Some(1), 32);
        let encoded = mixer.mix_next_encoded(&mut raw).unwrap().unwrap();
        assert_eq!(encoded[0], 0x40);
    }

    #[tokio::test]
    async fn codec_type_marker() {
        let _sink_frame = SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.0], 1));
        let _ = CodecType::Null;
    }
}
