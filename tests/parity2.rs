//! Tests for proof strategies (Phase 2.3), path expiry (Phase 6.1) and
//! blackholes (Phase 6.5).

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use tokio::sync::Mutex;

use reticulum::destination::link::{Link, LinkEvent};
use reticulum::destination::{DestinationName, ProofStrategy};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

async fn pair(ports: (u16, u16)) -> (Transport, Transport, Arc<Mutex<Link>>) {
    let server_identity = PrivateIdentity::new_from_rand(OsRng);
    let server = TransportConfig::new("srv", &server_identity).build();
    let client = TransportConfig::new("cli", &PrivateIdentity::new_from_rand(OsRng)).build();

    server.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{}", ports.0),
            Some(format!("127.0.0.1:{}", ports.1)),
            false,
        ),
        UdpInterface::spawn,
    );
    client.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{}", ports.1),
            Some(format!("127.0.0.1:{}", ports.0)),
            false,
        ),
        UdpInterface::spawn,
    );

    let destination = server
        .add_destination(server_identity, DestinationName::new("test", "proofs"))
        .await;
    destination
        .lock()
        .await
        .set_proof_strategy(ProofStrategy::All);
    let hash = destination.lock().await.desc.address_hash;
    let mut announces = client.recv_announces().await;
    server.send_announce(&destination, None).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let desc = loop {
        assert!(tokio::time::Instant::now() < deadline, "no announce");
        let event = tokio::time::timeout_at(deadline, announces.recv())
            .await
            .expect("t")
            .expect("c");
        if event.destination.lock().await.desc.address_hash == hash {
            break event.destination.lock().await.desc;
        }
    };

    let mut events = client.out_link_events();
    let link = client.link(desc).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "link inactive");
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("t")
            .expect("c");
        if let LinkEvent::Activated = event.event {
            break;
        }
    }
    (server, client, link)
}

#[tokio::test]
async fn proof_strategy_prove_all_delivers_proofs() {
    let (server, client, link) = pair((4611, 4612)).await;
    let _ = server;

    // The test destination explicitly uses PROVE_ALL.
    let mut events = client.out_link_events();
    let packet = link.lock().await.data_packet(b"prove me").expect("packet");
    client.send_packet(packet).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut got_proof = false;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("t")
            .expect("c");
        if let LinkEvent::Proof(_) = event.event {
            got_proof = true;
            break;
        }
    }
    assert!(got_proof, "expected a message proof with PROVE_ALL");
}

#[tokio::test]
async fn path_unresponsive_and_drop() {
    let (server, client, link) = pair((4621, 4622)).await;
    let _ = (server, link);

    // The client learned the server destination's path from the announce
    // during `pair`; discover it through the path table instead of waiting
    // for another (never-sent) announce.
    let server_hash = client
        .handler_public_path_probe()
        .await
        .expect("at least one known path");

    assert!(client.hops_to(&server_hash).await.is_some());

    assert!(client.mark_path_unresponsive(&server_hash).await);
    assert!(client.path_is_unresponsive(&server_hash).await);
    assert!(client.mark_path_responsive(&server_hash).await);
    assert!(!client.path_is_unresponsive(&server_hash).await);

    assert!(client.drop_path(&server_hash).await);
    assert!(!client.path_is_unresponsive(&server_hash).await);
}

#[tokio::test]
async fn blackhole_blocks_announces() {
    let (server, client, link) = pair((4631, 4632)).await;
    let _ = (server, link);

    // Learn a destination via announce
    let mut announces = client.recv_announces().await;
    let (other_identity, other) = {
        let id = PrivateIdentity::new_from_rand(OsRng);
        let t = TransportConfig::new("other", &id).build();
        t.iface_manager().lock().await.spawn(
            UdpInterface::new("127.0.0.1:4633", Some("127.0.0.1:4632"), false),
            UdpInterface::spawn,
        );
        let d = t
            .add_destination(id.clone(), DestinationName::new("test", "blocked"))
            .await;
        (id, (t, d))
    };

    other.1.lock().await.set_proof_strategy(ProofStrategy::None);
    other.0.send_announce(&other.1, None).await;

    // First: without blackholing we receive the announce
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut got = false;
    while tokio::time::Instant::now() < deadline {
        let event = tokio::time::timeout_at(deadline, announces.recv())
            .await
            .expect("t")
            .expect("c");
        let announced_name = event.destination.lock().await.desc.name;
        if announced_name.desc_hash_matches(&DestinationName::new("test", "blocked")) {
            got = true;
            break;
        }
    }
    assert!(got, "announce should arrive before blackholing");

    // Blackhole the identity and announce again: must not be delivered
    let identity_hash = other_identity.address_hash();
    client.blackhole_identity(*identity_hash, None, None).await;
    assert!(client.is_blackholed(identity_hash).await);

    other.0.send_announce(&other.1, None).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut got_blocked = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, announces.recv()).await {
            Ok(Ok(event)) => {
                let announced_name = event.destination.lock().await.desc.name;
                if announced_name.desc_hash_matches(&DestinationName::new("test", "blocked")) {
                    got_blocked = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(
        !got_blocked,
        "announce from blackholed identity must be dropped"
    );

    // And unblackhole works
    assert!(client.unblackhole_identity(identity_hash).await);
    assert!(!client.is_blackholed(identity_hash).await);
}
