//! Network framing tests: pack/unpack msgpack dicts, unknown-signal
//! handling and codec-switch detection through [`lxst::network::LinkSource`].

use lxst::codecs::{codec_header_byte, Codec, CodecType, Raw};
use lxst::common::AudioFrame;
use lxst::network::{
    pack_frame, pack_signalling, unpack_message, LinkSource, LinkSourceEvent, Signal, SignalCode,
    FIELD_FRAMES, FIELD_SIGNALLING,
};

fn raw_frame(values: &[f32], channels: usize, bitdepth: u32) -> Vec<u8> {
    let mut codec = Raw::new(Some(channels), bitdepth);
    codec
        .encode(&AudioFrame::from_interleaved(values.to_vec(), channels))
        .unwrap()
}

/// Wrap an encoded frame in the network framing: `[codec_header] ++ payload`.
fn wire_frame(codec: CodecType, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![codec_header_byte(codec).unwrap()];
    v.extend_from_slice(payload);
    v
}

#[tokio::test]
async fn link_source_decodes_frames_and_signals() {
    let (mut source, mut events) = LinkSource::with_codec(CodecType::Raw);

    let payload = raw_frame(&[0.5, -0.5, 0.25], 1, 32);
    let frame = wire_frame(CodecType::Raw, &payload);

    // A packet carrying both a frame and signalling
    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 2).unwrap();
    rmp::encode::write_pfix(&mut buf, FIELD_FRAMES).unwrap();
    rmp::encode::write_bin(&mut buf, &frame).unwrap();
    rmp::encode::write_pfix(&mut buf, FIELD_SIGNALLING).unwrap();
    rmp::encode::write_array_len(&mut buf, 1).unwrap();
    rmp::encode::write_pfix(&mut buf, Signal::StatusRinging.code()).unwrap();

    let frames = source.handle_packet(&buf).await;
    assert_eq!(frames, 1);

    // signalling is delivered after the frame
    let mut saw_frame = false;
    let mut saw_signals = false;
    while let Ok(event) = events.try_recv() {
        match event {
            LinkSourceEvent::Frame(f) => {
                saw_frame = true;
                assert_eq!(f.channels, 1);
                assert_eq!(f.samples, vec![0.5, -0.5, 0.25]);
            }
            LinkSourceEvent::Signals(s) => {
                saw_signals = true;
                assert_eq!(s, vec![Signal::StatusRinging.code()]);
            }
            other => panic!("unexpected event {other:?}"),
        }
    }
    assert!(saw_frame && saw_signals);
}

#[tokio::test]
async fn link_source_detects_codec_switch() {
    let (mut source, mut events) = LinkSource::with_codec(CodecType::Null);
    assert_eq!(source.codec_type(), Some(CodecType::Null));

    // A Raw-coded frame arrives -> the source must switch codecs
    let payload = raw_frame(&[0.5, -0.5], 1, 32);
    let frame = wire_frame(CodecType::Raw, &payload);
    let packet = pack_frame(&frame).unwrap();

    let frames = source.handle_packet(&packet).await;
    assert_eq!(frames, 1);
    assert_eq!(source.codec_type(), Some(CodecType::Raw));

    let mut switched = false;
    let mut decoded = false;
    while let Ok(event) = events.try_recv() {
        match event {
            LinkSourceEvent::CodecSwitched(t) => {
                switched = true;
                assert_eq!(t, CodecType::Raw);
            }
            LinkSourceEvent::Frame(f) => {
                decoded = true;
                assert_eq!(f.samples, vec![0.5, -0.5]);
            }
            _ => {}
        }
    }
    assert!(switched && decoded);

    // Further Raw frames no longer report a switch
    let packet = pack_frame(&frame).unwrap();
    source.handle_packet(&packet).await;
    let mut second_switch = false;
    while let Ok(event) = events.try_recv() {
        if matches!(event, LinkSourceEvent::CodecSwitched(_)) {
            second_switch = true;
        }
    }
    assert!(!second_switch);
}

#[tokio::test]
async fn link_source_reports_unknown_codec() {
    let (mut source, mut events) = LinkSource::with_codec(CodecType::Null);

    // 0x7f is not a registered codec header byte
    let frame = wire_frame_bytes(0x7f, &[1, 2, 3]);
    let packet = pack_frame(&frame).unwrap();

    let frames = source.handle_packet(&packet).await;
    assert_eq!(frames, 0);

    let mut unknown = false;
    while let Ok(event) = events.try_recv() {
        if let LinkSourceEvent::UnknownCodec(b) = event {
            unknown = true;
            assert_eq!(b, 0x7f);
        }
    }
    assert!(unknown);
}

fn wire_frame_bytes(header: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![header];
    v.extend_from_slice(payload);
    v
}

#[tokio::test]
async fn link_source_handles_multiple_frames_per_packet() {
    let (mut source, mut events) = LinkSource::with_codec(CodecType::Raw);

    let f1 = wire_frame(CodecType::Raw, &raw_frame(&[0.25], 1, 32));
    let f2 = wire_frame(CodecType::Raw, &raw_frame(&[-0.75], 1, 32));

    let mut buf = Vec::new();
    rmp::encode::write_map_len(&mut buf, 1).unwrap();
    rmp::encode::write_pfix(&mut buf, FIELD_FRAMES).unwrap();
    rmp::encode::write_array_len(&mut buf, 2).unwrap();
    rmp::encode::write_bin(&mut buf, &f1).unwrap();
    rmp::encode::write_bin(&mut buf, &f2).unwrap();

    let frames = source.handle_packet(&buf).await;
    assert_eq!(frames, 2);

    let mut got = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let LinkSourceEvent::Frame(f) = event {
            got.push(f.samples[0]);
        }
    }
    assert_eq!(got, vec![0.25, -0.75]);
}

#[tokio::test]
async fn link_source_survives_malformed_packets() {
    let (mut source, mut events) = LinkSource::with_codec(CodecType::Null);

    // truncated msgpack
    assert_eq!(
        source.handle_packet(&[0x81, 0x01, 0xc4, 0xff, 0x01]).await,
        0
    );
    // empty frame
    let packet = pack_frame(&[]).unwrap();
    assert_eq!(source.handle_packet(&packet).await, 0);
    // non-map payload
    assert_eq!(source.handle_packet(&[0x93, 0x01, 0x02, 0x03]).await, 0);
    // the source keeps working afterwards
    let payload = raw_frame(&[0.5], 1, 32);
    let frame = wire_frame(CodecType::Raw, &payload);
    let packet = pack_frame(&frame).unwrap();
    assert_eq!(source.handle_packet(&packet).await, 1);

    let _ = events.try_recv();
}

#[tokio::test]
async fn unknown_signal_codes_pass_through() {
    let (mut source, mut events) = LinkSource::with_codec(CodecType::Null);

    // 0x42 is not a known Signal, but it is a valid fixint
    let packet = pack_signalling(&[0x42]).unwrap();
    source.handle_packet(&packet).await;

    while let Ok(event) = events.try_recv() {
        if let LinkSourceEvent::Signals(s) = event {
            assert_eq!(s, vec![0x42]);
            assert!(Signal::from_code(0x42).is_none());
            assert_eq!(SignalCode::from_code(0x42), SignalCode::Unknown(0x42));
            return;
        }
    }
    panic!("no signalling event");
}

#[test]
fn signal_codes_match_python() {
    // Python Primitives/Telephony.py Signalling constants
    assert_eq!(Signal::StatusBusy.code(), 0x00);
    assert_eq!(Signal::StatusRejected.code(), 0x01);
    assert_eq!(Signal::StatusCalling.code(), 0x02);
    assert_eq!(Signal::StatusAvailable.code(), 0x03);
    assert_eq!(Signal::StatusRinging.code(), 0x04);
    assert_eq!(Signal::StatusConnecting.code(), 0x05);
    assert_eq!(Signal::StatusEstablished.code(), 0x06);

    for code in 0x00..=0x06u8 {
        assert_eq!(Signal::from_code(code).unwrap().code(), code);
    }
    assert!(Signal::from_code(0x07).is_none());

    // AUTO_STATUS_CODES = [CALLING, AVAILABLE, RINGING, CONNECTING, ESTABLISHED]
    assert!(Signal::StatusCalling.is_auto_status());
    assert!(Signal::StatusAvailable.is_auto_status());
    assert!(Signal::StatusRinging.is_auto_status());
    assert!(Signal::StatusConnecting.is_auto_status());
    assert!(Signal::StatusEstablished.is_auto_status());
    assert!(!Signal::StatusBusy.is_auto_status());
    assert!(!Signal::StatusRejected.is_auto_status());
}

#[test]
fn wire_format_shapes() {
    // {0x00: [2]} -> 81 00 91 02
    assert_eq!(pack_signalling(&[2]).unwrap(), vec![0x81, 0x00, 0x91, 0x02]);
    // {0x01: b"ab"} -> 81 01 c4 02 61 62
    assert_eq!(
        pack_frame(b"ab").unwrap(),
        vec![0x81, 0x01, 0xc4, 0x02, b'a', b'b']
    );

    // long frames choose bin16
    let payload = vec![7u8; 70000];
    let packed = pack_frame(&payload).unwrap();
    assert_eq!(&packed[..5], &[0x81, 0x01, 0xc6, 0x00, 0x01]); // bin32

    let msg = unpack_message(&packed).unwrap();
    assert_eq!(msg.frames[0], payload);
}

#[tokio::test]
async fn decode_adopts_codec_channels() {
    // Python: "if self.codec.channels: self.channels = self.codec.channels"
    let (mut source, _events) = LinkSource::with_codec(CodecType::Raw);

    let mut codec = Raw::new(Some(3), 32);
    let payload = codec
        .encode(&AudioFrame::from_interleaved(vec![0.1, 0.2, 0.3], 3))
        .unwrap();
    let frame = wire_frame(CodecType::Raw, &payload);
    source.handle_packet(&pack_frame(&frame).unwrap()).await;

    // The decoder learned the 3-channel layout from the frame header
    let decoded_channels = source.codec().channels();
    assert_eq!(decoded_channels, Some(3));
}

//***************************************************************************//
// Sink/packetizer framing path
//***************************************************************************//

#[tokio::test]
async fn remote_sink_forwards_to_channel() {
    use lxst::sinks::{RemoteSink, Sink, SinkFrame};

    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let mut sink = RemoteSink::new(CodecType::Raw, tx);

    let source_id = lxst::common::new_source_id();
    assert!(sink.can_receive(source_id).await);
    sink.handle_frame(SinkFrame::Encoded(vec![1, 2, 3]), source_id)
        .await;
    assert_eq!(sink.frames_sent(), 1);

    // decoded frames are rejected (the packetizer expects encoded bytes)
    sink.handle_frame(
        SinkFrame::Decoded(AudioFrame::from_interleaved(vec![0.5], 1)),
        source_id,
    )
    .await;
    assert_eq!(sink.frames_sent(), 1);
    assert_eq!(sink.dropped(), 1);

    assert_eq!(rx.recv().await.unwrap(), vec![1, 2, 3]);
}
