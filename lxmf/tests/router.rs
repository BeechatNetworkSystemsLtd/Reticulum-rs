//! End-to-end router tests over UDP loopback interfaces.

use std::sync::Arc;
use std::time::Duration;

use lxmf::router::{AnnounceInfo, DeliveryConfig, LxmEvent, LxmRouter, RouterConfig};
use lxmf::{delivery_destination_hash, LXMessage, DIRECT, OPPORTUNISTIC};
use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

fn fixed_identity(key_hex: &str) -> PrivateIdentity {
    PrivateIdentity::new_from_hex_string(key_hex).expect("valid identity")
}

const ALICE_KEY: &str = "f8953ffaf607627e615603ff1530c82c434cf87c07179dd7689ea776f30b964c\
                         fb7ba6164af00c5111a45e69e57d885e1285f8dbfe3a21e95ae17cf676b0f8b7";
const BOB_KEY: &str = "d85d036245436a3c33d3228affae06721f8203bc364ee0ee7556368ac62add65\
                       0ebf8f926abf628da9d92baaa12db89bd6516ee92ec29765f3afafcb8622d697";

async fn build_transport(name: &str, bind: &str, forward: &str) -> Transport {
    let id = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(TransportConfig::new(name, &id));
    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(bind, Some(forward), false),
        UdpInterface::spawn,
    );
    transport
}

fn temp_storage(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("lxmf-router-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[tokio::test]
async fn direct_delivery_over_udp_with_receipt() {
    let alice_identity = fixed_identity(ALICE_KEY);
    let bob_identity = fixed_identity(BOB_KEY);
    let alice_delivery = delivery_destination_hash(alice_identity.as_identity());
    let bob_delivery = delivery_destination_hash(bob_identity.as_identity());

    let transport_a = build_transport("alice", "127.0.0.1:41001", "127.0.0.1:41002").await;
    let transport_b = build_transport("bob", "127.0.0.1:41002", "127.0.0.1:41001").await;

    let router_a = LxmRouter::new(
        transport_a,
        alice_identity.clone(),
        temp_storage("alice-direct"),
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
        temp_storage("bob-direct"),
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

    // Both sides announce their delivery destinations
    router_a.announce_delivery().await;
    router_b.announce_delivery().await;

    // Bob receives Alice's announce (and Alice receives Bob's, which lets
    // her verify the signature on messages from him)
    let announce = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events_b.recv().await.expect("event") {
                LxmEvent::Announce(AnnounceInfo::Delivery {
                    destination_hash,
                    display_name,
                    ..
                }) if destination_hash == alice_delivery => {
                    return display_name;
                }
                _ => continue,
            }
        }
    })
    .await
    .expect("announce within timeout");
    assert_eq!(announce.as_deref(), Some("Alice"));

    // Alice learns Bob's identity from his announce
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

    // Bob sends a direct message to Alice over a link
    let mut message = LXMessage::new(alice_delivery, bob_delivery, b"Hello", b"Hello from Bob!");
    router_b
        .send(&mut message, &bob_identity)
        .await
        .expect("send");

    // Alice receives and validates it
    let received = tokio::time::timeout(Duration::from_secs(20), async {
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
    .expect("message within timeout");

    assert_eq!(received.title, b"Hello");
    assert_eq!(received.content, b"Hello from Bob!");
    assert_eq!(received.source_hash, bob_delivery);
    assert!(received.signature_validated, "source announced earlier");
    assert_eq!(received.unverified_reason, None);
    assert_eq!(received.method, DIRECT);

    // Bob receives the delivery receipt
    let receipt = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match events_b.recv().await.expect("event") {
                LxmEvent::DeliveryReceipt { .. } => return,
                LxmEvent::SendFailed { reason, .. } => {
                    panic!("unexpected send failure: {reason:?}")
                }
                _ => continue,
            }
        }
    })
    .await;
    assert!(receipt.is_ok(), "delivery receipt expected");

    // Redelivering the same packed bytes is deduplicated
    let packed = message.packed.clone().unwrap();
    let delivered = router_a
        .lxmf_delivery(&packed, Some(DIRECT), None, false, false)
        .await
        .expect("delivery handling");
    assert!(!delivered);

    let duplicate = tokio::time::timeout(Duration::from_secs(5), events_a.recv())
        .await
        .expect("duplicate event")
        .expect("event");
    assert!(matches!(duplicate, LxmEvent::Duplicate(_)));
}

#[tokio::test]
async fn send_to_unknown_destination_queues_and_fails_gracefully() {
    let bob_identity = fixed_identity(BOB_KEY);
    let bob_delivery = delivery_destination_hash(bob_identity.as_identity());
    let unknown = delivery_destination_hash(fixed_identity(ALICE_KEY).as_identity());

    let transport = build_transport("solo", "127.0.0.1:41003", "127.0.0.1:41004").await;
    let router = Arc::new(
        LxmRouter::new(
            transport,
            bob_identity.clone(),
            temp_storage("solo"),
            None::<&str>,
            Some(DeliveryConfig {
                identity: Some(bob_identity.clone()),
                display_name: None,
                stamp_cost: None,
            }),
            RouterConfig::default(),
        )
        .await,
    );

    let mut events = router.subscribe();

    // Direct send to a destination we have no identity or path for
    let mut message = LXMessage::new(unknown, bob_delivery, b"t", b"no path");
    router
        .send(&mut message, &bob_identity)
        .await
        .expect("send");
    assert_eq!(message.state, lxmf::OUTBOUND);

    // The message is queued, no failure is emitted yet (delivery will be
    // retried when an announce arrives).
    let event = tokio::time::timeout(Duration::from_millis(500), events.recv()).await;
    assert!(event.is_err(), "no events expected while queued");

    // Propagated send without a configured propagation node fails without
    // an event, since the message has no hash yet at that point.
    let mut propagated = LXMessage::new(unknown, bob_delivery, b"t", b"c");
    propagated.desired_method = Some(lxmf::PROPAGATED);
    assert!(router.send(&mut propagated, &bob_identity).await.is_err());
    assert_eq!(propagated.state, lxmf::FAILED);

    // Messages too large for a single packet are queued for resource-backed
    // delivery once a path becomes known (mirroring the packet path).
    let mut large = LXMessage::new(unknown, bob_delivery, b"t", "z".repeat(1000).as_bytes());
    large.pack(&bob_identity).expect("pack");
    assert_eq!(large.representation, lxmf::RESOURCE);
    router.send(&mut large, &bob_identity).await.expect("send");

    // No failure is emitted: the message is queued awaiting a path.
    let event = tokio::time::timeout(Duration::from_millis(500), events.recv()).await;
    assert!(event.is_err(), "large message queued without failure event");
}

#[tokio::test]
async fn opportunistic_delivery_over_udp() {
    let alice_identity = fixed_identity(ALICE_KEY);
    let bob_identity = fixed_identity(BOB_KEY);
    let alice_delivery = delivery_destination_hash(alice_identity.as_identity());
    let bob_delivery = delivery_destination_hash(bob_identity.as_identity());

    let transport_a = build_transport("alice-o", "127.0.0.1:41005", "127.0.0.1:41006").await;
    let transport_b = build_transport("bob-o", "127.0.0.1:41006", "127.0.0.1:41005").await;

    let router_a = LxmRouter::new(
        transport_a,
        alice_identity.clone(),
        temp_storage("alice-opp"),
        Some("Alice"),
        Some(DeliveryConfig {
            identity: Some(alice_identity.clone()),
            display_name: None,
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;

    let router_b = LxmRouter::new(
        transport_b,
        bob_identity.clone(),
        temp_storage("bob-opp"),
        Some("Bob"),
        Some(DeliveryConfig {
            identity: Some(bob_identity.clone()),
            display_name: None,
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;

    let mut events_a = router_a.subscribe();
    let mut events_b = router_b.subscribe();

    // Both sides announce; Bob needs Alice's identity to encrypt for her
    router_a.announce_delivery().await;
    router_b.announce_delivery().await;

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

    // Bob sends an opportunistic single-packet message
    let mut message = LXMessage::new(alice_delivery, bob_delivery, b"Opp", b"Opportunistic hello");
    message.desired_method = Some(OPPORTUNISTIC);
    router_b
        .send(&mut message, &bob_identity)
        .await
        .expect("send");
    assert_eq!(message.method, OPPORTUNISTIC);

    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match events_a.recv().await.expect("event") {
                LxmEvent::Received(message) => return message,
                other => {
                    log::debug!("other event: {other:?}");
                    continue;
                }
            }
        }
    })
    .await
    .expect("message within timeout");

    assert_eq!(received.title, b"Opp");
    assert_eq!(received.content, b"Opportunistic hello");
    assert_eq!(received.method, OPPORTUNISTIC);
    assert!(received.signature_validated);
}

#[tokio::test]
async fn paper_uri_ingest() {
    let alice_identity = fixed_identity(ALICE_KEY);
    let bob_identity = fixed_identity(BOB_KEY);
    let alice_delivery = delivery_destination_hash(alice_identity.as_identity());
    let bob_delivery = delivery_destination_hash(bob_identity.as_identity());

    let transport = Transport::new(TransportConfig::new("paper", &bob_identity));
    let router = LxmRouter::new(
        transport,
        bob_identity.clone(),
        temp_storage("paper"),
        None::<&str>,
        Some(DeliveryConfig {
            identity: Some(bob_identity.clone()),
            display_name: None,
            stamp_cost: None,
        }),
        RouterConfig::default(),
    )
    .await;

    // Bob writes a paper message for Alice
    let mut message = LXMessage::new(alice_delivery, bob_delivery, b"Paper", b"Out of band");
    message.destination_identity = Some(*alice_identity.as_identity());
    message
        .pack_paper(&bob_identity, OsRng)
        .expect("pack paper");
    let uri = message.as_uri().expect("uri");

    // The paper message is destined for Alice, not Bob. It is "ingested"
    // (processed, and deduplicated on retry) but not locally delivered,
    // since Bob does not operate a propagation node.
    let mut events = router.subscribe();
    assert!(router.ingest_lxm_uri(&uri, false).await.unwrap());
    assert!(!router.ingest_lxm_uri(&uri, false).await.unwrap());

    let event = tokio::time::timeout(Duration::from_millis(200), events.recv()).await;
    assert!(event.is_err(), "no local delivery expected");

    // A paper message for Bob himself is delivered locally
    let mut own = LXMessage::new(bob_delivery, alice_delivery, b"Paper", b"For me");
    own.destination_identity = Some(*bob_identity.as_identity());
    own.pack_paper(&alice_identity, OsRng).expect("pack paper");
    let own_uri = own.as_uri().expect("uri");
    assert!(router.ingest_lxm_uri(&own_uri, false).await.unwrap());

    let received = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("delivery event")
        .expect("event");
    match received {
        LxmEvent::Received(message) => {
            assert_eq!(message.content, b"For me");
            assert_eq!(message.source_hash, alice_delivery);
        }
        other => panic!("expected Received, got {other:?}"),
    }
}

#[tokio::test]
async fn propagation_node_announce_peering() {
    let pn_identity = fixed_identity(ALICE_KEY);
    let client_identity = fixed_identity(BOB_KEY);

    let transport_pn = build_transport("pn", "127.0.0.1:41007", "127.0.0.1:41008").await;
    let transport_client = build_transport("pn-client", "127.0.0.1:41008", "127.0.0.1:41007").await;

    // A propagation node with a lower peering cost than the local maximum
    let router_pn = LxmRouter::new(
        transport_pn,
        pn_identity.clone(),
        temp_storage("pn-node"),
        Some("Test PN"),
        None::<DeliveryConfig>,
        RouterConfig {
            propagation_node: true,
            ..Default::default()
        },
    )
    .await;

    let router_client = LxmRouter::new(
        transport_client,
        client_identity.clone(),
        temp_storage("pn-client"),
        None::<&str>,
        None::<DeliveryConfig>,
        RouterConfig {
            propagation_node: true,
            ..Default::default()
        },
    )
    .await;

    let mut client_events = router_client.subscribe();

    router_pn.announce_propagation_node().await;

    // The client receives the propagation node announce and peers with it
    let announced = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client_events.recv().await.expect("event") {
                LxmEvent::Announce(AnnounceInfo::PropagationNode { info, .. }) => return info,
                _ => continue,
            }
        }
    })
    .await
    .expect("propagation announce within timeout");

    assert!(announced.node_state);
    assert_eq!(announced.stamp_cost, lxmf::router::PROPAGATION_COST);
    assert_eq!(announced.peering_cost, lxmf::router::PEERING_COST);

    // The node has been added to the peer table
    let peers = router_client.peers().await;
    let pn_propagation_destination = router_pn.propagation_destination_hash();
    let peer = peers.get(&pn_propagation_destination).expect("peered");
    assert!(peer.alive);
    assert_eq!(peer.peering_cost, Some(lxmf::router::PEERING_COST));
    assert_eq!(peer.propagation_transfer_limit, Some(256.0));

    // The node's own announce data round-trips through the parser
    let app_data = router_pn.get_propagation_node_app_data();
    let parsed = lxmf::pn_announce_data_from_app_data(Some(&app_data)).expect("valid");
    assert_eq!(parsed.stamp_cost, announced.stamp_cost);
    assert_eq!(
        lxmf::pn_name_from_app_data(Some(&app_data)).as_deref(),
        Some("Test PN")
    );
}

#[tokio::test]
async fn delivery_destination_registration() {
    let identity = fixed_identity(ALICE_KEY);

    let transport = Transport::new(TransportConfig::new("dests", &identity));
    let router = LxmRouter::new(
        transport,
        identity.clone(),
        temp_storage("dests"),
        None::<&str>,
        Some(DeliveryConfig {
            identity: Some(identity.clone()),
            display_name: Some("Test".into()),
            stamp_cost: Some(12),
        }),
        RouterConfig::default(),
    )
    .await;

    let delivery_hash = router.delivery_destination_hash().await.expect("delivery");
    assert_eq!(
        delivery_hash,
        delivery_destination_hash(identity.as_identity())
    );
    assert_eq!(router.inbound_stamp_cost().await, Some(12));

    // Stamp cost updates from announces are tracked
    let other = fixed_identity(BOB_KEY);
    let other_delivery = delivery_destination_hash(other.as_identity());
    router.update_stamp_cost(&other_delivery, Some(9)).await;
    assert_eq!(
        router.get_outbound_stamp_cost(&other_delivery).await,
        Some(9)
    );

    // Tickets
    let ticket = router
        .generate_ticket(&other_delivery)
        .await
        .expect("ticket");
    router
        .remember_ticket(&other_delivery, ticket.0, ticket.1)
        .await;
    let remembered = router.get_outbound_ticket(&other_delivery).await;
    assert_eq!(remembered, Some(ticket.1));

    // A ticket is not regenerated within the delivery interval
    let second = router.generate_ticket(&other_delivery).await;
    assert_eq!(
        second.map(|t| t.1),
        Some(ticket.1),
        "ticket should be reused"
    );
}
