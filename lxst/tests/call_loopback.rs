//! Call endpoint loopback test: two transports wired through a UDP
//! interface exchange a real LXST audio frame end to end.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use tokio::sync::Mutex;

use reticulum::destination::link::{Link, LinkStatus};
use reticulum::destination::DestinationDesc;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::Transport;

use lxst::call::{call_endpoint_name, CallEndpoint, RemoteCallDestination};
use lxst::codecs::{Codec, CodecType, Raw};
use lxst::common::AudioFrame;
use lxst::network::{LinkSourceEvent, Signal};

/// Spawn a UDP interface pair connecting two transports (loopback).
async fn udp_pair(a: &Arc<Transport>, b: &Arc<Transport>, port_a: u16, port_b: u16) {
    a.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{port_a}"),
            Some(format!("127.0.0.1:{port_b}")),
            false,
        ),
        UdpInterface::spawn,
    );
    b.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{port_b}"),
            Some(format!("127.0.0.1:{port_a}")),
            false,
        ),
        UdpInterface::spawn,
    );
}

fn transport(name: &str) -> (PrivateIdentity, Arc<Transport>) {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let t = Arc::new(Transport::new(reticulum::transport::TransportConfig::new(
        name, &identity,
    )));
    (identity, t)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn call_end_to_end_over_udp() {
    // --- callee ------------------------------------------------------------
    let callee_identity = PrivateIdentity::new_from_rand(OsRng);
    // register the call destination before wrapping the transport in an Arc
    let callee_transport = Transport::new(reticulum::transport::TransportConfig::new(
        "callee",
        &callee_identity,
    ));
    let destination = callee_transport
        .add_destination(callee_identity.clone(), call_endpoint_name())
        .await;
    let callee_transport = Arc::new(callee_transport);

    let (mut callee, mut callee_events) = CallEndpoint::with_destination(
        callee_transport.clone(),
        destination,
        callee_identity.clone(),
    );

    // --- caller ------------------------------------------------------------
    let (_caller_identity, caller_transport) = transport("caller");

    udp_pair(&caller_transport, &callee_transport, 45931, 45932).await;

    // --- announce + link ----------------------------------------------------
    callee.announce().await;

    let mut announces = caller_transport.recv_announces().await;
    let mut remote_desc: Option<DestinationDesc> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if let Ok(announce) = announces.try_recv() {
            let d = announce.destination.lock().await.desc;
            if d.address_hash
                == RemoteCallDestination::for_identity(&callee_identity)
                    .desc
                    .address_hash
            {
                remote_desc = Some(d);
                break;
            }
        }
        callee.announce().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let remote_desc = remote_desc.expect("caller learned the callee announce");

    let link = caller_transport.link(remote_desc).await;

    // wait for the caller link to activate
    let mut caller_ok = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if link.lock().await.status() == LinkStatus::Active {
            caller_ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(caller_ok, "caller link never activated");

    // wait for the incoming call event on the callee
    let mut incoming_link_id: Option<reticulum::destination::link::LinkId> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        while let Ok(event) = callee_events.try_recv() {
            if let lxst::call::CallEvent::IncomingCall(id) = event {
                incoming_link_id = Some(id);
            }
        }
        if incoming_link_id.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let incoming_link_id = incoming_link_id.expect("callee saw the incoming call");
    let call_link = callee_transport
        .find_in_link(&incoming_link_id)
        .await
        .expect("in-link present");

    // --- answer -------------------------------------------------------------
    let handle = callee
        .answer(call_link, CodecType::Raw, Some(48_000), Some(1))
        .await
        .expect("answer");
    assert_eq!(handle.codec_type(), CodecType::Raw);

    // --- transmit audio from the caller -------------------------------------
    let mut codec = Raw::new(Some(1), 32);
    let frame = codec
        .encode(&AudioFrame::from_interleaved(vec![0.5, -0.5, 0.25], 1))
        .unwrap();

    let (packetizer, mut _rx) = lxst::network::Packetizer::new_for_link(
        caller_transport.clone(),
        link.clone(),
        CodecType::Raw,
    );
    packetizer.send_frame(&frame).await.unwrap();

    // The callee receives a decoded frame
    let mut received = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        while let Ok(event) = callee_events.try_recv() {
            if let lxst::call::CallEvent::Frame(_, f) = event {
                received = Some(f);
            }
        }
        if received.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let received = received.expect("callee received the audio frame");
    assert_eq!(received.samples, vec![0.5, -0.5, 0.25]);

    // --- signalling ----------------------------------------------------------
    packetizer
        .send_signal(Signal::StatusEstablished.code())
        .await
        .unwrap();
    let mut saw_signal = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        while let Ok(event) = callee_events.try_recv() {
            if let lxst::call::CallEvent::Signalling(_, codes) = event {
                assert_eq!(codes, vec![Signal::StatusEstablished.code()]);
                saw_signal = true;
            }
        }
        if saw_signal {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(saw_signal, "callee received signalling");

    // --- terminate ------------------------------------------------------------
    callee.terminate().await.unwrap();
    assert!(!callee.has_active_call());
}

//***************************************************************************//

/// A smaller in-process test that avoids networking: drive a `LinkSource`
/// with packets produced by a `Packetizer` frame payload, verifying the
/// full encode -> frame -> decode path without interfaces.
#[tokio::test]
async fn packetizer_to_link_source_loop() {
    use lxst::network::{LinkSource, Packetizer};

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(reticulum::transport::TransportConfig::new(
        "loop", &identity,
    ));
    let _dest = transport
        .add_destination(identity.clone(), call_endpoint_name())
        .await;
    let transport = Arc::new(transport);

    // Build an active link by hand; the packetizer only needs status Active.
    let remote = RemoteCallDestination::for_identity(&identity);
    let mut link = Link::new(remote.desc);
    let packet = link.request(); // assigns the link id
    let _ = packet;
    link.set_status(LinkStatus::Active);
    let link = Arc::new(Mutex::new(link));

    let (packetizer, _rx) =
        Packetizer::new_for_link(transport.clone(), link.clone(), CodecType::Raw);

    let (mut source, mut events) = LinkSource::with_codec(CodecType::Raw);

    // Build the payload exactly as the packetizer would and feed it to the
    // source directly (no interface needed).
    let mut codec = Raw::new(Some(2), 32);
    let frame = codec
        .encode(&AudioFrame::from_interleaved(
            vec![0.5, -0.5, 0.25, 0.125],
            2,
        ))
        .unwrap();
    let payload = packetizer.frame_payload(&frame).unwrap();
    source.handle_packet(&payload).await;

    let event = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("event")
        .expect("open channel");
    match event {
        LinkSourceEvent::Frame(f) => {
            assert_eq!(f.channels, 2);
            assert_eq!(f.samples, vec![0.5, -0.5, 0.25, 0.125]);
        }
        other => panic!("unexpected event {other:?}"),
    }
}
