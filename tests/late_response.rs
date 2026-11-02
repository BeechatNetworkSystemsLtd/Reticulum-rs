//! Late-subscription request/response: a response that completes before
//! the caller enters `await_request_response` must still be delivered.

use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;

#[tokio::test]
async fn response_before_await_is_delivered() {
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let a = TransportConfig::new("late-a", &identity_a).build();
    let b = TransportConfig::new("late-b", &identity_b).build();

    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4532", Some("127.0.0.1:4533"), true),
            UdpInterface::spawn,
        );
    }
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4533", Some("127.0.0.1:4532"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let destination = b
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("late", "echo"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    b.register_request_handler(&dest_hash, "/echo", |ctx| {
        Some(reticulum::resource::msgpack_bin(&ctx.data))
    })
    .await;
    let mut announces = a.recv_announces().await;
    b.send_announce(&destination, None).await;
    let announce = tokio::time::timeout(Duration::from_secs(10), announces.recv())
        .await
        .expect("announce")
        .expect("channel");
    let desc = announce.destination.lock().await.desc;

    let link = a.link(desc).await;
    let mut events = a.out_link_events();
    let _ = tokio::time::timeout(Duration::from_secs(10), events.recv()).await;

    let rid = a
        .request(&link, "/echo", b"late response payload")
        .await
        .expect("request");

    // Deliberately sleep past the moment the response arrives: the
    // response completes before we subscribe.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let response = a
        .await_request_response(rid, Duration::from_secs(10))
        .await
        .expect("response must be retained for late awaiters");

    assert_eq!(response, b"late response payload");
}
