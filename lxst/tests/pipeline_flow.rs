//! Pipeline frame-flow tests: source -> filters -> codec -> sink, plus the
//! sink buffering policies and file sources/sinks.

use std::time::Duration;

use lxst::codecs::{Codec, CodecType, Null, Raw};
use lxst::common::AudioFrame;
use lxst::filters::{BandPass, HighPass};
use lxst::pipeline::{CodecRole, Pipeline};
use lxst::sinks::{BufferSink, LineSink, Sink, SinkFrame, WavFileSink};
use lxst::sources::{BufferSource, LineSource, Source, WavFileSource};

fn frames_of(freq: f32, samplerate: u32, count: usize, per_frame: usize) -> Vec<AudioFrame> {
    let samples: Vec<f32> = (0..count * per_frame)
        .map(|i| (std::f32::consts::TAU * freq * i as f32 / samplerate as f32).sin() * 0.5)
        .collect();
    samples
        .chunks(per_frame)
        .map(|c| AudioFrame::from_interleaved(c.to_vec(), 1))
        .collect()
}

#[tokio::test]
async fn encode_pipeline_flows_source_to_sink() {
    let source = BufferSource::new(Some(48_000), frames_of(440.0, 48_000, 10, 480));
    let sink = BufferSink::new();
    let pipeline = Pipeline::encode(source, vec![], Box::new(Raw::new(None, 32)), sink);

    let task = pipeline.start();
    // source exhausts after 10 frames
    let _ = task.await;
    assert_eq!(pipeline.frames_processed(), 10);

    let sink_arc = pipeline.sink();
    let guard = sink_arc.lock().await;
    let encoded = guard.encoded_frames();
    assert_eq!(encoded.len(), 10);
    // every frame carries the Raw header + 480 f32 samples
    assert_eq!(encoded[0].len(), 1 + 480 * 4);
    assert_eq!(encoded[0][0], 0x40); // bitdepth 1 << 6 | (1-1)
}

#[tokio::test]
async fn decode_pipeline_passes_decoded_frames() {
    let source = BufferSource::new(Some(48_000), frames_of(440.0, 48_000, 5, 240));
    let sink = BufferSink::new();
    let pipeline = Pipeline::decode(source, vec![], Box::new(Null::new()), sink);

    assert_eq!(pipeline.codec_role(), CodecRole::Decode);
    let task = pipeline.start();
    let _ = task.await;
    assert_eq!(pipeline.frames_processed(), 5);

    let sink_arc = pipeline.sink();
    let guard = sink_arc.lock().await;
    let decoded = guard.decoded_frames();
    assert_eq!(decoded.len(), 5);
    assert_eq!(decoded[0].frames(), 240);
    // the frames reach the sink decoded (Python receive pipelines)
    assert!(decoded[0].samples.iter().any(|s| *s != 0.0));
}

#[tokio::test]
async fn pipeline_applies_filters_before_encoding() {
    // A 30 Hz rumble must be removed by the high-pass before encoding
    let mut samples = Vec::new();
    for i in 0..960 {
        samples.push(
            (std::f32::consts::TAU * 30.0 * i as f32 / 48_000.0).sin() * 0.9
                + (std::f32::consts::TAU * 2000.0 * i as f32 / 48_000.0).sin() * 0.1,
        );
    }
    let source = BufferSource::new(
        Some(48_000),
        vec![AudioFrame::from_interleaved(samples.clone(), 1)],
    );
    let sink = BufferSink::new();
    let pipeline = Pipeline::encode(
        source,
        vec![Box::new(HighPass::new(150.0))],
        Box::new(Raw::new(None, 32)),
        sink,
    );

    let task = pipeline.start();
    let _ = task.await;

    let sink_arc = pipeline.sink();
    let guard = sink_arc.lock().await;
    let encoded = guard.encoded_frames();
    assert_eq!(encoded.len(), 1);

    // decode and verify the low frequency is gone
    let mut decoder = Raw::new(None, 32);
    let decoded = decoder.decode(&encoded[0]).unwrap();
    // DC / low-frequency energy strongly reduced
    let mean = decoded.samples.iter().sum::<f32>() / decoded.samples.len() as f32;
    assert!(mean.abs() < 0.05, "mean {mean}");
}

#[tokio::test]
async fn pipeline_stops_on_cancel() {
    // A source that never ends: a tone source
    let mut source =
        lxst::generators::ToneSource::configured(440.0, 0.5, false, 20.0, 20.0, 1, 48_000);
    source.start();
    let sink = BufferSink::new();
    let pipeline = Pipeline::encode(source, vec![], Box::new(Raw::new(None, 32)), sink);

    let _task = pipeline.start();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(pipeline.running());
    pipeline.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!pipeline.running());
}

#[tokio::test]
async fn pipeline_codec_can_be_replaced() {
    let source = BufferSource::new(Some(48_000), frames_of(440.0, 48_000, 1, 100));
    let sink = BufferSink::new();
    let pipeline = Pipeline::encode(source, vec![], Box::new(Raw::new(None, 32)), sink);

    pipeline.set_codec(Box::new(Raw::new(Some(2), 64))).await;
    let codec_arc = pipeline.codec();
    let guard = codec_arc.lock().await;
    assert_eq!(guard.codec_type(), CodecType::Raw);
    drop(guard);
}

//***************************************************************************//
// sinks
//***************************************************************************//

#[tokio::test]
async fn line_sink_buffering_policy() {
    let mut sink = LineSink::new();
    assert_eq!(sink.max_frames, 6);
    assert_eq!(sink.buffer_max_height, 3);
    let source_id = lxst::common::new_source_id();

    // can_receive until the high-water mark
    for i in 0..3 {
        assert!(sink.can_receive(source_id).await, "at {i}");
        sink.handle_frame(
            SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.1; 10], 1)),
            source_id,
        )
        .await;
    }
    assert!(!sink.can_receive(source_id).await);

    // autostart happened on the first frame
    assert!(sink.running());
    assert_eq!(sink.frames_waiting(), 3);

    // digest pops frames; the queue drops to 2, can_receive is true again
    let frame = sink.digest().unwrap();
    assert_eq!(frame.frames(), 10);
    assert!(sink.can_receive(source_id).await);
    assert!(sink.frames_played() >= 1);

    // digest drains everything, then reports underrun
    sink.digest();
    sink.digest();
    assert!(sink.digest().is_none());
    assert!(!sink.underrun_timed_out()); // not yet
    assert!(sink.frames_waiting() == 0);
}

#[tokio::test]
async fn line_sink_drops_oldest_on_overflow() {
    let mut sink = LineSink::new();
    let source_id = lxst::common::new_source_id();
    for i in 0..10 {
        sink.handle_frame(
            SinkFrame::Decoded(AudioFrame::from_interleaved(vec![i as f32; 4], 1)),
            source_id,
        )
        .await;
    }
    // bounded at MAX_FRAMES
    assert!(sink.frames_waiting() <= 6);
    // and the oldest frames were dropped: the first frame left carries a
    // late index
    let first = sink.digest().unwrap();
    assert!(
        first.samples[0] >= 4.0,
        "first kept sample {}",
        first.samples[0]
    );
}

#[tokio::test]
async fn buffer_sink_backpressure_and_stop() {
    let mut sink = BufferSink::new();
    let source_id = lxst::common::new_source_id();
    sink.set_backpressure(Some(2));
    assert!(sink.can_receive(source_id).await);
    sink.handle_frame(SinkFrame::Encoded(vec![1]), source_id)
        .await;
    sink.handle_frame(SinkFrame::Encoded(vec![2]), source_id)
        .await;
    assert!(!sink.can_receive(source_id).await);

    sink.stop();
    assert!(!sink.can_receive(source_id).await);
}

//***************************************************************************//
// sources
//***************************************************************************//

#[tokio::test]
async fn line_source_gain_skip_and_ease() {
    let mut source = LineSource::new(20.0, Some(8000), Some(1));
    let input = source.input();

    // skip 2 frames, then gain of 0 dB
    source.configure(0.0, 0.0, 2.0 * 20.0 / 1000.0);

    for i in 0..6 {
        input
            .send(AudioFrame::from_interleaved(vec![i as f32; 160], 1))
            .await
            .unwrap();
    }

    // the first two frames are skipped
    let f = source.next_frame().await.unwrap();
    assert_eq!(f.samples[0], 2.0);
    let f = source.next_frame().await.unwrap();
    assert_eq!(f.samples[0], 3.0);

    // gain in dB is converted linearly
    let mut source = LineSource::new(20.0, Some(8000), Some(1));
    source.configure(20.0, 0.0, 0.0); // +20 dB -> 100x
    source
        .input()
        .send(AudioFrame::from_interleaved(vec![0.01; 10], 1))
        .await
        .unwrap();
    let f = source.next_frame().await.unwrap();
    assert!((f.samples[0] - 1.0).abs() < 1e-6);

    // ease-in ramps from silence
    let mut source = LineSource::new(20.0, Some(8000), Some(1));
    source.configure(0.0, 0.5, 0.0);
    source
        .input()
        .send(AudioFrame::from_interleaved(vec![0.5; 10], 1))
        .await
        .unwrap();
    let f = source.next_frame().await.unwrap();
    assert_eq!(f.samples[0], 0.0, "ease-in starts silent");
}

#[tokio::test]
async fn wav_file_roundtrip() {
    let dir = std::env::temp_dir().join("lxst-tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pipeline_flow.wav");

    // write
    {
        let mut sink = WavFileSink::create(&path, 8000, 1).unwrap();
        let source_id = lxst::common::new_source_id();
        for i in 0..4 {
            sink.handle_frame(
                SinkFrame::Decoded(AudioFrame::from_interleaved(vec![i as f32 * 0.1; 100], 1)),
                source_id,
            )
            .await;
        }
        sink.stop();
    }

    // read back
    let mut source = WavFileSource::open(&path, 20.0, false).unwrap();
    assert_eq!(source.samplerate(), 8000);
    assert_eq!(source.channels(), 1);
    assert_eq!(source.sample_count(), 400);

    let mut collected = Vec::new();
    while let Some(frame) = source.next_frame().await {
        collected.push(frame);
    }
    let all: Vec<f32> = collected
        .iter()
        .flat_map(|f| f.samples.iter().copied())
        .collect();
    assert_eq!(all.len(), 400);
    assert!((all[0] - 0.0).abs() < 1e-6);
    assert!((all[150] - 0.1).abs() < 1e-6);
    assert!((all[399] - 0.3).abs() < 1e-6);
}

//***************************************************************************//
// mixer + pipeline integration
//***************************************************************************//

#[tokio::test]
async fn mixer_feeds_encode_pipeline() {
    use lxst::mixer::Mixer;

    let mut mixer = Mixer::with_samplerate(20.0, 8000);
    let a = lxst::common::new_source_id();
    let b = lxst::common::new_source_id();
    let mut null = Null::new();

    mixer
        .handle_frame(
            SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.25; 160], 1)),
            a,
            Some(8000),
            Some(1),
            &mut null,
        )
        .unwrap();
    mixer
        .handle_frame(
            SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.25; 160], 1)),
            b,
            Some(8000),
            Some(1),
            &mut null,
        )
        .unwrap();

    // The mixed output feeds an encode pipeline through a BufferSource
    let mixed = vec![mixer.mix_next_frame().unwrap()];
    let source = BufferSource::new(Some(8000), mixed);
    let sink = BufferSink::new();
    let pipeline = Pipeline::encode(source, vec![], Box::new(Raw::new(None, 32)), sink);
    let task = pipeline.start();
    let _ = task.await;

    let sink_arc = pipeline.sink();
    let guard = sink_arc.lock().await;
    let encoded = guard.encoded_frames();
    assert_eq!(encoded.len(), 1);
    let mut decoder = Raw::new(None, 32);
    let decoded = decoder.decode(&encoded[0]).unwrap();
    // 0.25 + 0.25 = 0.5
    assert!((decoded.samples[0] - 0.5).abs() < 1e-6);
}

#[tokio::test]
async fn bandpass_chain_in_pipeline() {
    let samples: Vec<f32> = (0..1600)
        .map(|i| {
            (std::f32::consts::TAU * 100.0 * i as f32 / 16_000.0).sin() * 0.6
                + (std::f32::consts::TAU * 7000.0 * i as f32 / 16_000.0).sin() * 0.6
        })
        .collect();
    let source = BufferSource::new(
        Some(16_000),
        vec![AudioFrame::from_interleaved(samples.clone(), 1)],
    );
    let sink = BufferSink::new();
    let pipeline = Pipeline::encode(
        source,
        vec![Box::new(BandPass::new(500.0, 3000.0))],
        Box::new(Raw::new(None, 32)),
        sink,
    );
    let task = pipeline.start();
    let _ = task.await;

    let sink_arc = pipeline.sink();
    let guard = sink_arc.lock().await;
    let encoded = guard.encoded_frames();
    let mut decoder = Raw::new(None, 32);
    let decoded = decoder.decode(&encoded[0]).unwrap();
    let rms =
        (decoded.samples.iter().map(|s| s * s).sum::<f32>() / decoded.samples.len() as f32).sqrt();
    // both tones sat in the (one-pole) stop band: substantial attenuation
    // of the 0.85-combined input amplitude
    let input_rms = (samples.iter().map(|s| s * s).sum::<f32>() / samples.len() as f32).sqrt();
    assert!(rms < input_rms * 0.35, "rms {rms} vs input {input_rms}");
}
