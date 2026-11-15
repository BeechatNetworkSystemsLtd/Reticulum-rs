//! The `Opus` codec (Python `LXST/Codecs/Opus.py`), behind the `opus`
//! cargo feature (libopus via the `audiopus` crate).
//!
//! Wire format: an Opus packet **without any inner header byte** - the codec
//! header byte on the network packet identifies the codec.
//!
//! The Python implementation maps the codec profiles onto (application,
//! samplerate, channels, bitrate-ceiling) tuples. Resampling to the codec
//! samplerate is the responsibility of the pipeline here (see
//! [`crate::processing::resample`]), mirroring the Python behaviour where
//! codecs call `resample_bytes` when `source.samplerate` differs.

use audiopus::{
    coder::{Decoder, Encoder},
    Application, Channels, ErrorCode, SampleRate, TryFrom,
};

use crate::codecs::{Codec, CodecError, CodecType};
use crate::common::AudioFrame;

/// Frame duration quantisation (Python `Opus.FRAME_QUANTA_MS`).
pub const FRAME_QUANTA_MS: f64 = 2.5;
/// Maximum frame duration (Python `Opus.FRAME_MAX_MS`).
pub const FRAME_MAX_MS: f64 = 60.0;
/// Valid frame durations (Python `Opus.VALID_FRAME_MS`).
pub const VALID_FRAME_MS: [f64; 6] = [2.5, 5.0, 10.0, 20.0, 40.0, 60.0];

/// int16 scaling factor (Python `Opus.TYPE_MAP_FACTOR = np.iinfo("int16").max`).
pub const TYPE_MAP_FACTOR: f32 = 32767.0;

pub const PROFILE_VOICE_LOW: u8 = 0x00;
pub const PROFILE_VOICE_MEDIUM: u8 = 0x01;
pub const PROFILE_VOICE_HIGH: u8 = 0x02;
pub const PROFILE_VOICE_MAX: u8 = 0x03;
pub const PROFILE_AUDIO_MIN: u8 = 0x04;
pub const PROFILE_AUDIO_LOW: u8 = 0x05;
pub const PROFILE_AUDIO_MEDIUM: u8 = 0x06;
pub const PROFILE_AUDIO_HIGH: u8 = 0x07;
pub const PROFILE_AUDIO_MAX: u8 = 0x08;

/// Opus codec (Python `LXST.Codecs.Opus`).
pub struct Opus {
    /// Currently selected profile.
    pub profile: u8,
    /// Encoded channel count (from the profile, or the sink).
    pub channels: usize,
    /// Samplerate the encoder consumes / decoder emits at.
    pub output_samplerate: u32,
    /// Samplerate of the source feeding the encoder, if informed.
    pub source_samplerate: Option<u32>,
    /// Samplerate the decoder should emit at (Python reads `sink.samplerate`).
    pub sink_samplerate: Option<u32>,
    /// Channel count the decoder should emit at (Python reads `sink.channels`).
    pub sink_channels: Option<usize>,
    pub bitrate_ceiling: u32,
    pub output_bytes: usize,
    pub output_ms: f64,
    pub output_bitrate: f64,

    encoder: Option<Encoder>,
    decoder: Option<Decoder>,
    decoder_channels: Option<usize>,
}

fn return_samples(pcm: Vec<i16>, channels: usize) -> AudioFrame {
    AudioFrame::from_interleaved(
        pcm.iter().map(|&s| s as f32 / TYPE_MAP_FACTOR).collect(),
        channels,
    )
}

fn map_err(e: audiopus::Error) -> CodecError {
    CodecError::new(format!("opus error: {e:?}"))
}

impl Opus {
    pub fn new() -> Self {
        Self::with_profile(PROFILE_VOICE_LOW)
    }

    pub fn with_profile(profile: u8) -> Self {
        let mut c = Self {
            profile,
            channels: 1,
            output_samplerate: 8000,
            source_samplerate: None,
            sink_samplerate: None,
            sink_channels: None,
            bitrate_ceiling: 6000,
            output_bytes: 0,
            output_ms: 0.0,
            output_bitrate: 0.0,
            encoder: None,
            decoder: None,
            decoder_channels: None,
        };
        c.set_profile(profile);
        c
    }

    pub fn set_profile(&mut self, profile: u8) {
        self.profile = profile;
        self.channels = Self::profile_channels(profile);
        self.output_samplerate = Self::profile_samplerate(profile);
        self.bitrate_ceiling = Self::profile_bitrate_ceiling(profile);
        // encoder is (re)created lazily with the new settings
        self.encoder = None;
    }

    pub fn profile_channels(profile: u8) -> usize {
        match profile {
            PROFILE_VOICE_MAX | PROFILE_AUDIO_MEDIUM | PROFILE_AUDIO_HIGH | PROFILE_AUDIO_MAX => 2,
            _ => 1,
        }
    }

    pub fn profile_samplerate(profile: u8) -> u32 {
        match profile {
            PROFILE_VOICE_LOW => 8000,
            PROFILE_VOICE_MEDIUM => 24000,
            PROFILE_VOICE_HIGH | PROFILE_VOICE_MAX => 48000,
            PROFILE_AUDIO_MIN => 8000,
            PROFILE_AUDIO_LOW => 12000,
            PROFILE_AUDIO_MEDIUM => 24000,
            PROFILE_AUDIO_HIGH | PROFILE_AUDIO_MAX => 48000,
            _ => 8000,
        }
    }

    pub fn profile_application(profile: u8) -> Application {
        match profile {
            PROFILE_AUDIO_MIN..=PROFILE_AUDIO_MAX => Application::Audio,
            _ => Application::Voip,
        }
    }

    pub fn profile_bitrate_ceiling(profile: u8) -> u32 {
        match profile {
            PROFILE_VOICE_LOW => 6000,
            PROFILE_VOICE_MEDIUM => 8000,
            PROFILE_VOICE_HIGH => 16000,
            PROFILE_VOICE_MAX => 32000,
            PROFILE_AUDIO_MIN => 8000,
            PROFILE_AUDIO_LOW => 14000,
            PROFILE_AUDIO_MEDIUM => 28000,
            PROFILE_AUDIO_HIGH => 56000,
            PROFILE_AUDIO_MAX => 128000,
            _ => 6000,
        }
    }

    pub fn max_bytes_per_frame(bitrate_ceiling: u32, frame_duration_ms: f64) -> usize {
        ((bitrate_ceiling as f64 / 8.0) * (frame_duration_ms / 1000.0)).ceil() as usize
    }

    fn channels_enum(channels: usize) -> Channels {
        if channels >= 2 {
            Channels::Stereo
        } else {
            Channels::Mono
        }
    }

    fn sample_rate_enum(rate: u32) -> SampleRate {
        match rate {
            8000 => SampleRate::Hz8000,
            12000 => SampleRate::Hz12000,
            16000 => SampleRate::Hz16000,
            24000 => SampleRate::Hz24000,
            48000 => SampleRate::Hz48000,
            _ => SampleRate::Hz48000,
        }
    }

    fn ensure_encoder(&mut self) -> Result<&mut Encoder, CodecError> {
        if self.encoder.is_none() {
            let encoder = Encoder::new(
                Self::sample_rate_enum(self.output_samplerate),
                Self::channels_enum(self.channels),
                Self::profile_application(self.profile),
            )
            .map_err(map_err)?;
            self.encoder = Some(encoder);
        }
        Ok(self.encoder.as_mut().unwrap())
    }

    fn ensure_decoder(&mut self) -> Result<&mut Decoder, CodecError> {
        if self.decoder.is_none() {
            let channels = self.sink_channels.unwrap_or(2).max(self.channels);
            self.decoder_channels = Some(channels);
            let rate = self.sink_samplerate.unwrap_or(48000);
            let decoder = Decoder::new(Self::sample_rate_enum(rate), Self::channels_enum(channels))
                .map_err(map_err)?;
            self.decoder = Some(decoder);
        }
        Ok(self.decoder.as_mut().unwrap())
    }
}

impl Codec for Opus {
    fn codec_type(&self) -> CodecType {
        CodecType::Opus
    }

    fn encode(&mut self, frame: &AudioFrame) -> Result<Vec<u8>, CodecError> {
        if frame.channels == 0 {
            return Err(CodecError::new("Cannot encode frame with 0 channels"));
        }

        let adapted = frame.adapt_channels(self.channels);
        let input: Vec<i16> = adapted
            .samples
            .iter()
            .map(|&s| (s * TYPE_MAP_FACTOR) as i16)
            .collect();

        let frame_duration_ms = (adapted.frames() as f64 / self.output_samplerate as f64) * 1000.0;
        let max_bytes = Self::max_bytes_per_frame(self.bitrate_ceiling, frame_duration_ms).max(1);

        let encoder = self.ensure_encoder()?;
        let mut out = vec![0u8; max_bytes];
        let len = encoder.encode(&input, &mut out).map_err(map_err)?;
        out.truncate(len);

        self.output_bytes += len;
        self.output_ms += frame_duration_ms;
        if self.output_ms > 0.0 {
            self.output_bitrate = (self.output_bytes as f64 * 8.0) / (self.output_ms / 1000.0);
        }

        Ok(out)
    }

    fn decode(&mut self, data: &[u8]) -> Result<AudioFrame, CodecError> {
        if data.is_empty() {
            return Err(CodecError::new("opus packet is empty"));
        }
        // read the configuration before mutably borrowing the decoder
        let channels = {
            self.ensure_decoder()?;
            self.decoder_channels.unwrap_or(self.channels).max(1)
        };
        // 60 ms at 48 kHz is the largest Opus frame per channel
        let mut pcm = vec![0i16; 5760 * channels];
        let len = self
            .ensure_decoder()?
            .decode(Some(data), &mut pcm, false)
            .map_err(map_err)?;
        pcm.truncate(len * channels);

        Ok(return_samples(pcm, channels))
    }

    fn channels(&self) -> Option<usize> {
        Some(self.channels)
    }

    fn set_channels(&mut self, channels: Option<usize>) {
        if let Some(channels) = channels {
            self.channels = channels.clamp(1, 2);
            self.encoder = None;
        }
    }

    fn bitdepth(&self) -> usize {
        16
    }

    fn preferred_samplerate(&self) -> Option<u32> {
        Some(self.output_samplerate)
    }

    fn output_samplerate(&self) -> Option<u32> {
        Some(self.output_samplerate)
    }

    fn frame_quanta_ms(&self) -> Option<f64> {
        Some(FRAME_QUANTA_MS)
    }

    fn frame_max_ms(&self) -> Option<f64> {
        Some(FRAME_MAX_MS)
    }

    fn valid_frame_ms(&self) -> Option<Vec<f64>> {
        Some(VALID_FRAME_MS.to_vec())
    }

    fn set_sink_params(&mut self, samplerate: Option<u32>, channels: Option<usize>) {
        self.sink_samplerate = samplerate;
        self.sink_channels = channels;
        // decoder is rebuilt with the new sink parameters
        self.decoder = None;
    }

    fn set_source_samplerate(&mut self, samplerate: u32) {
        self.source_samplerate = Some(samplerate);
    }

    fn reset(&mut self) {
        self.encoder = None;
        self.decoder = None;
        self.decoder_channels = None;
    }
}

impl Default for Opus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tone(frames: usize, channels: usize) -> AudioFrame {
        let mut samples = Vec::with_capacity(frames * channels);
        for i in 0..frames {
            let v = ((i as f32) * 0.05).sin() * 0.5;
            for _ in 0..channels {
                samples.push(v);
            }
        }
        AudioFrame::from_interleaved(samples, channels)
    }

    #[test]
    fn roundtrip() {
        let input = tone(960, 1); // 20ms @ 48kHz
        let mut enc = Opus::with_profile(PROFILE_VOICE_HIGH);
        enc.set_source_samplerate(48000);
        let mut data = None;
        for _ in 0..4 {
            data = Some(enc.encode(&input).unwrap());
        }
        let mut dec = Opus::with_profile(PROFILE_VOICE_HIGH);
        dec.set_sink_params(Some(48000), Some(1));
        let out = dec.decode(&data.unwrap()).unwrap();
        assert_eq!(out.channels, 1);
        assert_eq!(out.frames(), 960);
    }

    #[test]
    fn frame_constraints() {
        let c = Opus::new();
        assert_eq!(c.frame_quanta_ms(), Some(2.5));
        assert_eq!(c.frame_max_ms(), Some(60.0));
        assert_eq!(c.valid_frame_ms().unwrap().len(), 6);
        // 70ms target must clamp to 60, and 61 -> 60
        assert_eq!(crate::codecs::clamp_frame_ms(&c, 70.0), 60.0);
        // 12ms snaps to 10 (closest of the valid list)
        assert_eq!(crate::codecs::clamp_frame_ms(&c, 12.0), 10.0);
    }
}
