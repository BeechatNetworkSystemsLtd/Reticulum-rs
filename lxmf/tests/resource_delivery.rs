//! Resource-backed LXMF delivery of large messages over UDP loopback.

use std::time::Duration;

use lxmf::router::{AnnounceInfo, DeliveryConfig, LxmEvent, LxmRouter, RouterConfig};
use lxmf::{delivery_destination_hash, LXMessage, DIRECT};
use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkStatus};
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::resource::{ResourceStatus, ResourceStrategy};

async fn build_transport(name: &str, bind: &str, forward: &str) -> Transport {
    let id = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(TransportConfig::new(name, &id));
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(bind, Some(forward), false),
        UdpInterface::spawn,
    );
    transport
}
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

fn fixed_identity(key_hex: &str) -> PrivateIdentity {
    PrivateIdentity::new_from_hex_string(key_hex).expect("valid identity")
}

const ALICE_KEY: &str = "f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964c\
                         fb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7";
const BOB_KEY: &str = "d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add65\
                       0ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697";

fn temp_storage(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("lxmf-resource-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[tokio::test]
async fn large_message_delivered_as_resource() {
    let alice_identity = fixed_identity(ALICE_KEY);
    let bob_identity = fixed_identity(BOB_KEY);
    let alice_delivery = delivery_destination_hash(alice_identity.as_identity());
    let bob_delivery = delivery_destination_hash(bob_identity.as_identity());

    let transport_a = build_transport("alice", "127.0.0.1:41011", "127.0.0.1:41012").await;
    let transport_b = build_transport("bob", "127.0.0.1:41012", "127.0.0.1:41011").await;

    let router_a = LxmRouter::new(
        transport_a,
        alice_identity.clone(),
        temp_storage("alice"),
        Some("Alice"),
        Some(DeliveryConfig {
            identity: Some(alice_identity.clone()),
            display_name: Some("Alice".into()),
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;
    let router_b = LxmRouter::new(
        transport_b,
        bob_identity.clone(),
        temp_storage("bob"),
        Some("Bob"),
        Some(DeliveryConfig {
            identity: Some(bob_identity.clone()),
            display_name: Some("Bob".into()),
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;

    let mut events_a = router_a.subscribe();
    let mut events_b = router_b.subscribe();

    router_a.announce_delivery().await;
    router_b.announce_delivery().await;

    // wait for mutual announces
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                events_a.recv().await,
                Ok(LxmEvent::Announce(AnnounceInfo::Delivery { .. }))
            ) {
                return;
            }
        }
    })
    .await
    .expect("alice learned bob announce");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                events_b.recv().await,
                Ok(LxmEvent::Announce(AnnounceInfo::Delivery { .. }))
            ) {
                return;
            }
        }
    })
    .await
    .expect("bob learned alice announce");

    // A large message that cannot fit in a single link packet is delivered
    // as a resource transfer (Python `LXMessage.__as_resource`).
    let content: Vec<u8> = (0..3000u32).map(|i| b'a' + (i % 26) as u8).collect();
    let mut message = LXMessage::new(alice_delivery, bob_delivery, b"Big", &content);
    router_b
        .send(&mut message, &bob_identity)
        .await
        .expect("send");

    let received = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match events_a.recv().await.expect("event") {
                LxmEvent::Received(message) => return message,
                LxmEvent::SendFailed { reason, .. } => {
                    panic!("unexpected send failure: {reason:?}")
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("large message within timeout");

    assert_eq!(received.content, content);
    assert_eq!(received.source_hash, bob_delivery);
    assert!(received.signature_validated, "source announced earlier");
    assert_eq!(received.method, DIRECT);
}

#[tokio::test]
async fn unrelated_destination_resources_are_not_ingested_as_lxmf() {
    let alice_identity = fixed_identity(ALICE_KEY);
    let bob_identity = fixed_identity(BOB_KEY);
    let alice_delivery = delivery_destination_hash(alice_identity.as_identity());
    let bob_delivery = delivery_destination_hash(bob_identity.as_identity());

    let transport_a = build_transport("alice-mixed", "127.0.0.1:41021", "127.0.0.1:41022").await;
    let transport_b = build_transport("bob-mixed", "127.0.0.1:41022", "127.0.0.1:41021").await;
    let router_a = LxmRouter::new(
        transport_a,
        alice_identity.clone(),
        temp_storage("alice-mixed"),
        Some("Alice"),
        Some(DeliveryConfig {
            identity: Some(alice_identity),
            display_name: Some("Alice".into()),
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;
    let router_b = LxmRouter::new(
        transport_b,
        bob_identity.clone(),
        temp_storage("bob-mixed"),
        Some("Bob"),
        Some(DeliveryConfig {
            identity: Some(bob_identity.clone()),
            display_name: Some("Bob".into()),
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;
    let mut router_events = router_a.subscribe();
    let mut announces = router_b.transport().recv_announces().await;
    let mut incoming_links = router_a.transport().in_link_events();
    let mut resources = router_a.transport().resource_events().await;

    let unrelated = router_a
        .transport()
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("unrelated", "resource.endpoint"),
        )
        .await;
    let unrelated_hash = unrelated.lock().await.desc.address_hash;
    router_a.transport().send_announce(&unrelated, None).await;

    let desc = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = announces.recv().await.expect("announce");
            let destination = event.destination.lock().await;
            if destination.desc.address_hash == unrelated_hash {
                return destination.desc;
            }
        }
    })
    .await
    .expect("unrelated announce");
    let link = router_b.transport().link(desc).await;
    let link_id = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = incoming_links.recv().await.expect("link event");
            if event.address_hash == unrelated_hash && matches!(event.event, LinkEvent::Activated) {
                return event.id;
            }
        }
    })
    .await
    .expect("unrelated link activation");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if link.lock().await.status() == LinkStatus::Active {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("initiator link activation");

    // Simulate an unrelated application that accepts resources on its link.
    // The shared LXMF watcher must still ignore the completed transfer.
    router_a
        .transport()
        .set_resource_strategy(link_id, ResourceStrategy::All)
        .await;
    let mut message = LXMessage::new(alice_delivery, bob_delivery, b"Wrong link", b"ignore me");
    message.pack(&bob_identity).expect("pack LXMF message");
    router_b
        .transport()
        .send_resource(&link, message.packed.clone().unwrap())
        .await
        .expect("send unrelated resource");

    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let event = resources.recv().await.expect("resource event");
            if event.link_id == link_id && event.status == ResourceStatus::Complete {
                return;
            }
        }
    })
    .await
    .expect("unrelated resource completion");

    let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, router_events.recv()).await {
        assert!(!matches!(event, LxmEvent::Received(_)));
    }
}
