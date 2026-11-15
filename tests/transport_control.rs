//! Transport control parity tests (Phase 6.2 / 6.3 / 6.8):
//! * announce ingress limiting holds and later releases announces
//! * announce egress cap defers and queues announces
//! * interface mode announce-forwarding policy
//! * `await_path` resolves for announced destinations
//!
//! The ingress/egress unit semantics are covered in `iface::control::tests`;
//! these tests exercise the wiring inside the transport.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::control::{IfaceControlParams, InterfaceMode};
use reticulum::iface::udp::UdpInterface;
use reticulum::iface::{InterfaceManager, TxMessage, TxMessageType};
use reticulum::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketDataBuffer,
    PacketType, PropagationType,
};
use reticulum::storage::{MemoryStorage, Storage, DESTINATION_TABLE_FILE};
use reticulum::transport::{ReceiptStatus, Transport, TransportConfig};

/// Two Rust transports bridged over a UDP interface pair.
struct Pair {
    a: Transport,
    b: Transport,
    a_iface: AddressHash,
}

async fn pair(name: &str, port_a: u16, port_b: u16) -> Pair {
    let a = TransportConfig::new(
        format!("rust-{name}-a"),
        &PrivateIdentity::new_from_rand(OsRng),
    )
    .set_retransmit(true)
    .build();

    let b = TransportConfig::new(
        format!("rust-{name}-b"),
        &PrivateIdentity::new_from_rand(OsRng),
    )
    .set_retransmit(true)
    .build();

    let a_iface = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_a}"),
                Some(format!("127.0.0.1:{port_b}")),
                true,
            ),
            UdpInterface::spawn,
        )
    };

    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_b}"),
                Some(format!("127.0.0.1:{port_a}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }

    // Give the sockets time to bind.
    tokio::time::sleep(Duration::from_millis(200)).await;

    Pair { a, b, a_iface }
}

async fn iface_of(transport: &Transport) -> AddressHash {
    let manager: Arc<tokio::sync::Mutex<InterfaceManager>> = transport.iface_manager();
    let manager = manager.lock().await;
    manager.stats().first().map(|stat| stat.address).unwrap()
}

async fn announce_distinct(transport: &Transport, app: &str) -> AddressHash {
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new(app, "ingress"),
    );
    let hash = destination.desc.address_hash;
    transport
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;
    hash
}

#[tokio::test]
async fn ingress_limiting_holds_and_releases_announces() {
    let Pair { a, b, a_iface } = pair("ingress", 4312, 4313).await;

    // Shorten the control windows so the test runs quickly.
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        let params = IfaceControlParams {
            ic_burst_freq_new: 5.0,
            ic_burst_penalty: Duration::from_secs(1),
            ic_burst_hold: Duration::from_millis(500),
            ic_held_release_interval: Duration::from_millis(300),
            ..IfaceControlParams::default()
        };
        manager.with_control(&a_iface, |control| control.set_params(params));
    }

    // A burst of distinct-destination announces from the peer trips the
    // new-interface ingress limit (ic_burst_freq_new = 3 Hz).
    let mut held_destinations = Vec::new();
    for _ in 0..10 {
        held_destinations.push(announce_distinct(&b, "burst").await);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    // The interface must now be ingress limited.
    let limited = async {
        for _ in 0..40 {
            let manager = a.iface_manager();
            let manager = manager.lock().await;
            if manager
                .with_control(&a_iface, |control| {
                    control.should_ingress_limit(tokio::time::Instant::now())
                })
                .unwrap_or(false)
            {
                return true;
            }
            drop(manager);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(
        limited,
        "interface should be ingress limited after announce burst"
    );

    // At least one of the burst destinations must have been held (no path
    // learned yet).
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut known = 0;
    for dest in &held_destinations {
        if a.has_path(dest).await {
            known += 1;
        }
    }
    assert!(
        known < 10,
        "not all burst announces should be processed immediately"
    );

    // Once the burst penalty has elapsed, the ticker releases held
    // announces and the paths become known.
    let released = async {
        for _ in 0..250 {
            let mut all_known = true;
            for dest in &held_destinations {
                if !a.has_path(dest).await {
                    all_known = false;
                }
            }
            if all_known {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
    .await;
    assert!(
        released,
        "held announces must be released after the burst penalty"
    );
}

#[tokio::test]
async fn announce_cap_queues_forwarded_announces() {
    let Pair { a, a_iface, .. } = pair("egress", 4322, 4323).await;

    // A slow radio bitrate makes the announce cap bite.
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.set_iface_bitrate(&a_iface, 1200);
    }

    // Two forwarded (hops > 0) announces: the first spends the airtime
    // budget, the second must be queued.
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Box::new(announce_packet(2)),
            })
            .await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Box::new(announce_packet(3)),
            })
            .await;
    }

    let queued = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .with_control(&a_iface, |control| control.queued_announces_len())
            .unwrap_or(0)
    };
    assert!(
        queued >= 1,
        "second forwarded announce must be queued by the announce cap"
    );
}

#[tokio::test]
async fn mode_policy_blocks_roaming_to_roaming_announces() {
    let Pair { a, .. } = pair("modes", 4332, 4333).await;

    // A second interface on the forwarding node, so both endpoints of the
    // policy decision are managed by the same transport.
    let iface_a = iface_of(&a).await;
    let iface_b = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:4334", Some("127.0.0.1:4335"), true),
            UdpInterface::spawn,
        )
    };

    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.set_iface_mode(&iface_a, InterfaceMode::Roaming);
        manager.set_iface_mode(&iface_b, InterfaceMode::Roaming);
    }

    let blocked = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.announce_forwarding_allowed(&iface_b, Some(iface_a))
    };
    assert!(
        !blocked,
        "announces from roaming-mode interfaces must not be forwarded onto roaming-mode interfaces"
    );

    let allowed_local = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.announce_forwarding_allowed(&iface_b, None)
    };
    assert!(
        allowed_local,
        "locally originated announces bypass mode gating"
    );
}

#[tokio::test]
async fn control_params_override_defaults() {
    let Pair { a, a_iface, .. } = pair("params", 4342, 4343).await;

    // Disable both the new and steady-state burst thresholds.
    let params = IfaceControlParams {
        ic_burst_freq_new: 100.0,
        ic_burst_freq: 100.0,
        ..IfaceControlParams::default()
    };
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.with_control(&a_iface, |control| control.set_params(params));
    }

    // Feed announce samples directly: even a dense burst stays under the
    // raised threshold.
    for _ in 0..10 {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.received_announce(&a_iface, 0);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let limited = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .with_control(&a_iface, |control| {
                control.should_ingress_limit(tokio::time::Instant::now())
            })
            .unwrap_or(false)
    };
    assert!(
        !limited,
        "raised burst threshold must disable ingress limiting"
    );
}

#[tokio::test]
async fn await_path_resolves_for_announced_destinations() {
    let Pair { a, b, .. } = pair("await", 4352, 4353).await;

    // An unknown destination can never resolve.
    let unknown = AddressHash::new_from_rand(OsRng);
    let found = a
        .await_path(&unknown, Some(Duration::from_millis(300)), None)
        .await;
    assert!(!found, "no path can resolve for an unannounced destination");

    // The peer announces a destination shortly: await_path resolves as
    // soon as the announce arrives.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("awaited", "dest"),
    );
    let hash = destination.desc.address_hash;

    let dest_arc = Arc::new(tokio::sync::Mutex::new(destination));
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        b.send_announce(&dest_arc, None).await;
    });

    let found = a
        .await_path(&hash, Some(Duration::from_secs(10)), None)
        .await;
    assert!(found, "await_path must resolve once the peer announces");
}

async fn wait_hops(transport: &Transport, destination: &AddressHash) -> Option<u8> {
    for _ in 0..100 {
        if let Some(hops) = transport.hops_to(destination).await {
            return Some(hops);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn local_hops_delta_rewrites_egress_announces() {
    let a = TransportConfig::new("rust-delta-a", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .set_local_hops_delta(true)
        .build();
    let b = TransportConfig::new("rust-delta-b", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .build();

    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47012", Some("127.0.0.1:47013"), true),
            UdpInterface::spawn,
        );
    }
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47013", Some("127.0.0.1:47012"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("delta", "hops"),
    );
    let hash = destination.desc.address_hash;
    a.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let hops = wait_hops(&b, &hash).await.expect("path learned");
    // Wire hops are sampled in 2..=7; the path table stores that plus one.
    assert!(
        (3..=8).contains(&hops),
        "local hops delta must land in 3..=8, got {hops}"
    );
}

#[tokio::test]
async fn receipt_stays_sent_until_timeout_or_cull() {
    let Pair { a, b, .. } = pair("receipt", 47014, 47015).await;

    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("receipt", "peer"),
    );
    let hash = destination.desc.address_hash;
    b.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;
    wait_hops(&a, &hash).await.expect("path");

    let packet_hash = a
        .send_to_destination(&hash, b"still in flight")
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let info = a.receipt(&packet_hash).await.expect("receipt");
    assert_eq!(info.status, ReceiptStatus::Sent);
    assert!(info.timeout.is_some());
    assert!(info.rtt.is_none());

    assert!(
        a.set_receipt_timeout(&packet_hash, Some(Duration::from_millis(1)))
            .await
    );
    let failed = async {
        for _ in 0..40 {
            if let Some(info) = a.receipt(&packet_hash).await {
                if info.status == ReceiptStatus::Failed {
                    return info;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("receipt did not fail");
    }
    .await;
    assert!(failed.rtt.is_some());

    let culled_hash = a
        .send_to_destination(&hash, b"cull me")
        .await
        .expect("send");
    assert!(a.set_receipt_timeout(&culled_hash, None).await);
    let culled = async {
        for _ in 0..40 {
            if let Some(info) = a.receipt(&culled_hash).await {
                if info.status == ReceiptStatus::Culled {
                    return info;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("receipt was not culled");
    }
    .await;
    assert!(culled.timeout.is_none());
    assert!(culled.rtt.is_some());
}

#[tokio::test]
async fn path_table_reloads_on_the_same_interfaces() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let a = TransportConfig::new("rust-persist-a", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .set_storage(storage.clone())
        .build();
    let b = TransportConfig::new("rust-persist-b", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .build();

    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47010", Some("127.0.0.1:47011"), true),
            UdpInterface::spawn,
        );
    }
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47011", Some("127.0.0.1:47010"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("persist", "path"),
    );
    let hash = destination.desc.address_hash;
    b.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;
    let hops = wait_hops(&a, &hash).await.expect("path learned");

    a.persist_data().await;
    let saved = storage
        .read(DESTINATION_TABLE_FILE)
        .expect("destination table written");
    assert!(saved.len() > 16, "path table file must hold the entry");

    assert!(a.drop_path(&hash).await);
    assert!(!a.has_path(&hash).await);

    a.load_persisted_state().await;
    assert!(
        a.has_path(&hash).await,
        "path must reload on the live interface"
    );
    assert_eq!(a.hops_to(&hash).await, Some(hops));
}

fn stored_announce_hops(bytes: &[u8]) -> Option<u8> {
    let value = rmpv::decode::read_value(&mut &bytes[..]).ok()?;
    let entries = value.as_array()?;
    let fields = entries.first()?.as_array()?;
    let announce = fields.get(8)?.as_slice()?;
    announce.get(1).copied()
}

#[tokio::test]
async fn path_table_survives_interface_address_restart() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    {
        let a = TransportConfig::new("rust-restart-a", &PrivateIdentity::new_from_rand(OsRng))
            .set_retransmit(true)
            .set_storage(storage.clone())
            .build();
        let b = TransportConfig::new("rust-restart-b", &PrivateIdentity::new_from_rand(OsRng))
            .set_retransmit(true)
            .build();
        {
            let manager = a.iface_manager();
            let mut manager = manager.lock().await;
            manager.spawn(
                UdpInterface::new("127.0.0.1:47030", Some("127.0.0.1:47031"), true),
                UdpInterface::spawn,
            );
        }
        {
            let manager = b.iface_manager();
            let mut manager = manager.lock().await;
            manager.spawn(
                UdpInterface::new("127.0.0.1:47031", Some("127.0.0.1:47030"), true),
                UdpInterface::spawn,
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let destination = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("restart", "path"),
        );
        let hash = destination.desc.address_hash;
        b.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
            .await;
        let hops = wait_hops(&a, &hash).await.expect("path learned");
        a.persist_data().await;
        let saved = storage
            .read(DESTINATION_TABLE_FILE)
            .expect("destination table written");
        let wire_hops = stored_announce_hops(&saved).expect("cached announce hops");
        drop(b);
        drop(a);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let a = TransportConfig::new("rust-restart-a", &PrivateIdentity::new_from_rand(OsRng))
            .set_retransmit(true)
            .set_storage(storage.clone())
            .build();
        {
            let manager = a.iface_manager();
            let mut manager = manager.lock().await;
            manager.spawn(
                UdpInterface::new("127.0.0.1:47030", Some("127.0.0.1:47031"), true),
                UdpInterface::spawn,
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        a.load_persisted_state().await;
        assert!(
            a.has_path(&hash).await,
            "a restart must keep the path when the interface kind and name match"
        );
        assert_eq!(a.hops_to(&hash).await, Some(hops));

        a.persist_data().await;
        let again = storage
            .read(DESTINATION_TABLE_FILE)
            .expect("destination table rewritten");
        assert_eq!(
            stored_announce_hops(&again),
            Some(wire_hops),
            "saving a reloaded path must not add a hop to the cached announce"
        );
        assert!(a.drop_path(&hash).await);
        a.load_persisted_state().await;
        assert_eq!(a.hops_to(&hash).await, Some(hops));
    }
}

#[tokio::test]
async fn path_table_restores_interfaces_added_at_different_times() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let hash1;
    let hash2;
    let hops1;
    let hops2;
    {
        let a = TransportConfig::new("rust-stagger-a", &PrivateIdentity::new_from_rand(OsRng))
            .set_retransmit(true)
            .set_storage(storage.clone())
            .build();
        let b =
            TransportConfig::new("rust-stagger-b", &PrivateIdentity::new_from_rand(OsRng)).build();
        let c =
            TransportConfig::new("rust-stagger-c", &PrivateIdentity::new_from_rand(OsRng)).build();
        {
            let manager = a.iface_manager();
            let mut manager = manager.lock().await;
            manager.spawn(
                UdpInterface::new("127.0.0.1:47060", Some("127.0.0.1:47061"), true),
                UdpInterface::spawn,
            );
            manager.spawn(
                UdpInterface::new("127.0.0.1:47062", Some("127.0.0.1:47063"), true),
                UdpInterface::spawn,
            );
        }
        {
            let manager = b.iface_manager();
            let mut manager = manager.lock().await;
            manager.spawn(
                UdpInterface::new("127.0.0.1:47061", Some("127.0.0.1:47060"), true),
                UdpInterface::spawn,
            );
        }
        {
            let manager = c.iface_manager();
            let mut manager = manager.lock().await;
            manager.spawn(
                UdpInterface::new("127.0.0.1:47063", Some("127.0.0.1:47062"), true),
                UdpInterface::spawn,
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let destination1 = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("stagger", "one"),
        );
        hash1 = destination1.desc.address_hash;
        b.send_announce(&Arc::new(tokio::sync::Mutex::new(destination1)), None)
            .await;
        let destination2 = SingleInputDestination::new(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("stagger", "two"),
        );
        hash2 = destination2.desc.address_hash;
        c.send_announce(&Arc::new(tokio::sync::Mutex::new(destination2)), None)
            .await;
        hops1 = wait_hops(&a, &hash1)
            .await
            .expect("path on the first interface");
        hops2 = wait_hops(&a, &hash2)
            .await
            .expect("path on the second interface");
        a.persist_data().await;
        drop(c);
        drop(b);
        drop(a);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let a = TransportConfig::new("rust-stagger-a", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .set_storage(storage)
        .build();
    let iface1 = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47060", Some("127.0.0.1:47061"), true),
            UdpInterface::spawn,
        )
    };
    let restored = wait_hops(&a, &hash1).await;
    assert!(
        restored.is_some(),
        "the first interface's path must reload before the second interface exists"
    );
    assert!(
        !a.has_path(&hash2).await,
        "a path for an interface that is not up yet must not be attached or dropped"
    );
    let iface2 = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47062", Some("127.0.0.1:47063"), true),
            UdpInterface::spawn,
        )
    };
    assert_eq!(
        wait_hops(&a, &hash2).await,
        Some(hops2),
        "adding the second interface later must restore its path"
    );
    assert_eq!(a.hops_to(&hash1).await, Some(hops1));
    let (_via, bound1) = a.next_hop(&hash1).await.expect("path 1");
    let (_via, bound2) = a.next_hop(&hash2).await.expect("path 2");
    assert_eq!(bound1, iface1);
    assert_eq!(bound2, iface2);
}

fn announce_packet(hops: u8) -> Packet {
    let mut data = PacketDataBuffer::new();
    data.safe_write(&[1u8; 32]);
    data.safe_write(&[2u8; 32]);
    data.safe_write(&[3u8; 10]);
    data.safe_write(&[0u8; 5]);
    data.safe_write(&42u64.to_be_bytes()[3..8]);
    data.safe_write(&[4u8; 64]);

    Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            context_flag: false,
            header_type: HeaderType::Type2,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops,
        },
        ifac: None,
        destination: AddressHash::new_from_rand(OsRng),
        transport: None,
        context: PacketContext::None,
        data,
    }
}
