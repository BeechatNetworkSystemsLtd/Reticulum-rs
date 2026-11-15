//! Async request handlers (awaited on the runtime, not under the
//! transport lock) round-trip over UDP, including deferred responses that
//! used to deadlock when the handler guard was held across user code.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::link::LinkEvent;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

async fn pair(port_a: u16, port_b: u16) -> (Transport, Transport) {
    let a = TransportConfig::new("a", &PrivateIdentity::new_from_rand(OsRng)).build();
    let b = TransportConfig::new("b", &PrivateIdentity::new_from_rand(OsRng)).build();
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
    (a, b)
}

async fn connect(
    server: &Transport,
    client: &Transport,
    dest: &DestArc,
) -> reticulum::destination::DestinationDesc {
    let hash = dest.lock().await.desc.address_hash;
    let mut announces = client.recv_announces().await;
    server.send_announce(dest, None).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "no announce");
        let event = tokio::time::timeout_at(deadline, announces.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if event.destination.lock().await.desc.address_hash == hash {
            return event.destination.lock().await.desc;
        }
    }
}

type DestArc = Arc<tokio::sync::Mutex<reticulum::destination::SingleInputDestination>>;

async fn activate(
    client: &Transport,
    desc: reticulum::destination::DestinationDesc,
) -> Arc<tokio::sync::Mutex<reticulum::destination::link::Link>> {
    let link = client.link(desc).await;
    let mut events = client.out_link_events();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "link inactive");
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("timeout")
            .expect("channel");
        if let LinkEvent::Activated = event.event {
            return link;
        }
    }
}

#[tokio::test]
async fn async_handler_immediate_response() {
    let (server, client) = pair(4781, 4782).await;
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let dest = server
        .add_destination(identity, DestinationName::new("test", "async"))
        .await;
    let desc = connect(&server, &client, &dest).await;
    let hash = dest.lock().await.desc.address_hash;
    let link = activate(&client, desc).await;

    server
        .register_async_request_handler(&hash, "echo", |_ctx| async move {
            Some(reticulum::resource::msgpack_bin(b"async-pong"))
        })
        .await;

    let rid = client
        .request(&link, "echo", b"ping")
        .await
        .expect("request");
    let response = client
        .await_request_response(rid, Duration::from_secs(5))
        .await;
    assert_eq!(response, Some(b"async-pong".to_vec()));
}

#[tokio::test]
async fn async_handler_deferred_response() {
    let (server, client) = pair(4783, 4784).await;
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let dest = server
        .add_destination(identity, DestinationName::new("test", "async2"))
        .await;
    let desc = connect(&server, &client, &dest).await;
    let hash = dest.lock().await.desc.address_hash;
    let link = activate(&client, desc).await;

    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    let arrived = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let arrived_flag = arrived.clone();
    let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
    server
        .register_async_request_handler(&hash, "echo", move |_ctx| {
            let arrived_flag = arrived_flag.clone();
            let release_rx = release_rx.clone();
            async move {
                arrived_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                // Poll until the deferred response is released.
                loop {
                    let taken = release_rx.lock().unwrap().take();
                    if let Some(rx) = taken {
                        let response = rx.await.unwrap_or_default();
                        return Some(reticulum::resource::msgpack_bin(&response));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        })
        .await;

    let rid = client
        .request(&link, "echo", b"ping")
        .await
        .expect("request");

    // Wait until the handler was invoked, then release the response.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !arrived.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "handler never invoked"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    release_tx.send(b"deferred-pong".to_vec()).expect("release");

    let response = client
        .await_request_response(rid, Duration::from_secs(10))
        .await;
    assert_eq!(response, Some(b"deferred-pong".to_vec()));
}
