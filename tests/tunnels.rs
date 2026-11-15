//! Tunnel lifecycle over a UDP interface pair (Phase 6.4):
//! synthesize -> associate announces -> void -> re-synthesize restores.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::storage::{MemoryStorage, Storage, TUNNELS_FILE};
use reticulum::transport::{Transport, TransportConfig};

async fn udp_pair(name: &str, port_a: u16, port_b: u16) -> (Transport, Transport, AddressHash) {
    let a = TransportConfig::new(
        format!("tunnel-{name}-a"),
        &PrivateIdentity::new_from_rand(OsRng),
    )
    .set_retransmit(true)
    .build();

    let b = TransportConfig::new(
        format!("tunnel-{name}-b"),
        &PrivateIdentity::new_from_rand(OsRng),
    )
    .set_retransmit(true)
    .build();

    let iface_a = {
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

    tokio::time::sleep(Duration::from_millis(200)).await;

    (a, b, iface_a)
}

async fn iface_of(transport: &Transport) -> AddressHash {
    let manager = transport.iface_manager();
    let manager = manager.lock().await;
    manager.stats().first().map(|stat| stat.address).unwrap()
}

#[tokio::test]
async fn tunnel_synthesize_associate_and_restore() {
    let (a, b, iface_a) = udp_pair("life", 4362, 4363).await;
    let iface_b = iface_of(&b).await;

    // A synthesizes a tunnel on its interface: B must establish the
    // tunnel endpoint bound to its own interface.
    a.synthesize_tunnel(iface_a).await.expect("synthesize");

    let tunnel_id = async {
        for _ in 0..100 {
            let tunnels = b.tunnel_table_snapshot().await;
            if let Some(entry) = tunnels.first() {
                return entry.clone();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("tunnel was not established on the remote side");
    }
    .await;

    assert_eq!(tunnel_id.iface, Some(iface_b));

    // A announces a destination: B associates the path with the tunnel.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("tunneled", "dest"),
    );
    let dest_hash = destination.desc.address_hash;
    b.drop_path(&dest_hash).await; // ensure fresh
    a.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let associated = async {
        for _ in 0..100 {
            let tunnels = b.tunnel_table_snapshot().await;
            if tunnels.first().map(|t| t.paths).unwrap_or(0) >= 1 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(associated, "announce must be associated with the tunnel");

    // B forgets the path but keeps the tunnel, then voids the tunnel.
    assert!(b.drop_path(&dest_hash).await);
    assert!(b.void_tunnel(&tunnel_id.tunnel_id).await);
    assert!(
        !b.has_path(&dest_hash).await,
        "path must be dropped before restore"
    );

    // A re-synthesizes: the tunnel re-appears and B restores the path.
    a.synthesize_tunnel(iface_a).await.expect("re-synthesize");

    let restored = async {
        for _ in 0..100 {
            if b.has_path(&dest_hash).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(restored, "tunnel paths must be restored on re-appearance");
}

#[tokio::test]
async fn tunnel_table_persists_to_storage() {
    let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
    let a = TransportConfig::new("tunnel-persist-a", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .build();
    let b = TransportConfig::new("tunnel-persist-b", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .set_storage(storage.clone())
        .build();

    let iface_a = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47016", Some("127.0.0.1:47017"), true),
            UdpInterface::spawn,
        )
    };
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new("127.0.0.1:47017", Some("127.0.0.1:47016"), true),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    a.synthesize_tunnel(iface_a).await.expect("synthesize");
    for _ in 0..100 {
        if !b.tunnel_table_snapshot().await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !b.tunnel_table_snapshot().await.is_empty(),
        "tunnel must be established before it can be persisted"
    );

    b.persist_data().await;
    let saved = storage.read(TUNNELS_FILE).expect("tunnel table written");
    assert!(saved.len() > 16, "tunnel table file must hold the entry");
}
