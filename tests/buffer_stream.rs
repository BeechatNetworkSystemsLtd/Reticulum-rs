//! Buffer stream tests: Rust round-trips and wire-format vectors.

use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use reticulum::buffer_stream::{
    attach_bidirectional_buffer, create_bidirectional_buffer, StreamDataMessage, MAX_DATA_LEN,
};
use reticulum::channel::{Message, CHANNEL_MDU};
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::error::RnsError;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init()
    });
}

async fn build_transport(name: &str, bind: &str, forward: &str) -> (Transport, PrivateIdentity) {
    let id = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(TransportConfig::new(name, &id));
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(bind, Some(forward), false),
        UdpInterface::spawn,
    );
    (transport, id)
}

/// Two transports exchange a stream over a channel: the wire frames must
/// match the Python `StreamDataMessage` layout.
#[tokio::test]
async fn buffer_round_trip() {
    setup();

    let (transport_a, id_a) = build_transport("a", "127.0.0.1:8181", "127.0.0.1:8182").await;
    let (transport_b, _) = build_transport("b", "127.0.0.1:8182", "127.0.0.1:8181").await;

    let mut in_link_events = transport_a.in_link_events();
    let mut out_link_events = transport_b.out_link_events();
    let mut recv_announces = transport_b.recv_announces().await;

    let dest = transport_a
        .add_destination(id_a, DestinationName::new("test", "buffers.stream"))
        .await;
    dest.lock().await.proof_strategy = reticulum::destination::ProofStrategy::All;
    transport_a.send_announce(&dest, None).await;
    let announce = recv_announces.recv().await.unwrap();

    let link = transport_b
        .link(announce.destination.lock().await.desc)
        .await;
    let (channel_b, receiver_b) = transport_b
        .mk_channel::<StreamDataMessage>(link)
        .await
        .unwrap();

    let event = in_link_events.recv().await.unwrap();
    let (channel_a, receiver_a) = match event.event {
        LinkEvent::Activated => {
            let link = transport_a.find_in_link(&event.id).await.unwrap();
            transport_a
                .mk_channel::<StreamDataMessage>(link)
                .await
                .unwrap()
        }
        _ => unreachable!(),
    };
    assert!(matches!(
        out_link_events.recv().await.unwrap().event,
        LinkEvent::Activated
    ));

    // Wait for the channel to be ready before writing
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !channel_b.is_ready().await {
        assert!(tokio::time::Instant::now() < deadline, "channel not ready");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // B writes a stream to A; A writes a stream back
    let stream_b = create_bidirectional_buffer(&channel_b, receiver_b, 1, 2);
    let stream_a = create_bidirectional_buffer(&channel_a, receiver_a, 2, 1);

    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();

    // write from B
    let mut writer_b = stream_b.writer;
    writer_b.write_all(&payload).await.expect("write");
    log::debug!("TEST: write_all done");
    writer_b.shutdown().await.expect("eof");
    log::debug!("TEST: shutdown done");

    // read on A
    let mut received = Vec::new();
    let mut reader_a = stream_a.reader;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut done = false;
    while !done {
        assert!(
            tokio::time::Instant::now() < deadline,
            "stream did not complete"
        );
        let mut tmp = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), reader_a.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read error");
        if n == 0 {
            done = true;
        } else {
            received.extend_from_slice(&tmp[..n]);
        }
    }
    assert_eq!(received, payload);
}

#[test]
fn frame_layout_matches_python() {
    // Python: struct.pack(">H", (0x3fff & 1) | 0x8000 if eof) + data
    let msg = StreamDataMessage {
        stream_id: 1,
        data: b"abc".to_vec(),
        eof: true,
        compressed: false,
    };
    assert_eq!(msg.pack_bytes(), vec![0x80, 0x01, b'a', b'b', b'c']);
}

#[test]
fn mdu_bound() {
    // Python: channel MDU is link.mdu - 6, stream payload is that minus the
    // 2-byte stream header. Neither budget is PACKET_MDU (2048).
    assert_eq!(CHANNEL_MDU, reticulum::packet::LINK_MDU - 6);
    assert_eq!(MAX_DATA_LEN, reticulum::packet::LINK_MDU - 8);
    assert_eq!(MAX_DATA_LEN, CHANNEL_MDU - 2);
    const { assert!(CHANNEL_MDU < reticulum::packet::PACKET_MDU) };
    assert_eq!(CHANNEL_MDU, 425);
}

#[derive(Clone)]
struct Note(Vec<u8>);

impl Message for Note {
    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError> {
        if message_type == 0x0003 {
            Ok(Note(packed.to_vec()))
        } else {
            Err(RnsError::ChannelUnknownMessageType)
        }
    }

    fn pack(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn message_type(&self) -> u16 {
        0x0003
    }
}

/// A user message type and a buffer stream (system type 0xff00) share one
/// channel. The stream is registered the way Python registers
/// `StreamDataMessage` on an existing channel.
#[tokio::test]
async fn buffer_shares_channel_with_user_message() {
    setup();

    let (transport_a, id_a) = build_transport("a", "127.0.0.1:8193", "127.0.0.1:8194").await;
    let (transport_b, _) = build_transport("b", "127.0.0.1:8194", "127.0.0.1:8193").await;

    let mut in_link_events = transport_a.in_link_events();
    let mut out_link_events = transport_b.out_link_events();
    let mut recv_announces = transport_b.recv_announces().await;

    let dest = transport_a
        .add_destination(id_a, DestinationName::new("test", "buffers.shared"))
        .await;
    dest.lock().await.proof_strategy = reticulum::destination::ProofStrategy::All;
    transport_a.send_announce(&dest, None).await;
    let announce = recv_announces.recv().await.unwrap();

    let link = transport_b
        .link(announce.destination.lock().await.desc)
        .await;
    let (channel_b, mut user_b) = transport_b.mk_channel::<Note>(link).await.unwrap();

    let event = in_link_events.recv().await.unwrap();
    let (channel_a, _user_a) = match event.event {
        LinkEvent::Activated => {
            let link = transport_a.find_in_link(&event.id).await.unwrap();
            transport_a.mk_channel::<Note>(link).await.unwrap()
        }
        _ => unreachable!(),
    };
    assert!(matches!(
        out_link_events.recv().await.unwrap().event,
        LinkEvent::Activated
    ));

    let stream_b = attach_bidirectional_buffer(&channel_b, 1, 2).unwrap();
    let stream_a = attach_bidirectional_buffer(&channel_a, 2, 1).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !channel_b.is_ready().await {
        assert!(tokio::time::Instant::now() < deadline, "channel not ready");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let live_mdu = channel_b.mdu().await;
    assert_eq!(live_mdu, channel_b.link.lock().await.mdu() - 6);
    assert!(live_mdu <= 0xFFFF);
    assert!(live_mdu < reticulum::packet::PACKET_MDU);

    // User traffic and the buffer stream share the window. Deliver the
    // short user message before the stream so the two are not racing for
    // the initial window of 2.
    channel_a
        .send(&Note(b"hello-user".to_vec()))
        .await
        .expect("user message");
    let note = tokio::time::timeout(Duration::from_secs(5), user_b.recv())
        .await
        .expect("user message timeout")
        .expect("user message");
    assert_eq!(note.0, b"hello-user");

    let payload = b"shared-channel-stream".to_vec();
    let mut writer_b = stream_b.writer;
    writer_b.write_all(&payload).await.expect("write");
    writer_b.shutdown().await.expect("eof");

    let mut received = Vec::new();
    let mut reader_a = stream_a.reader;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "stream did not complete"
        );
        let mut tmp = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), reader_a.read(&mut tmp))
            .await
            .expect("read timeout")
            .expect("read error");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(received, payload);
}
