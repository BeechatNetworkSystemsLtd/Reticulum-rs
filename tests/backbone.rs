//! Backbone interface end-to-end (Phase 5.8): server + initiator client
//! exchange announces over HDLC-framed TCP, the client requests tunnel
//! synthesis, and fast-flapping remotes get blocked.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::backbone::{
    BackboneClient, BackboneServer, FastFlapTable, BLOCK_FAST_FLAPPING, FAST_FLAP_EXPIRY,
    FAST_FLAP_GRACE, FAST_FLAP_THRESHOLD, HW_MTU,
};
use reticulum::transport::TransportConfig;

#[tokio::test]
async fn backbone_end_to_end_and_tunnel_request() {
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let a = Arc::new(TransportConfig::new("bb-a", &identity_a).build());

    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let b = Arc::new(TransportConfig::new("bb-b", &identity_b).build());

    // Server on A.
    let server_addr = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            BackboneServer::new(
                "127.0.0.1:4442",
                a.iface_manager(),
                Arc::new(tokio::sync::Mutex::new(FastFlapTable::new(
                    BLOCK_FAST_FLAPPING,
                    FAST_FLAP_THRESHOLD,
                    FAST_FLAP_GRACE,
                    FAST_FLAP_EXPIRY,
                ))),
            ),
            BackboneServer::spawn,
        )
    };
    let _ = server_addr;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Initiator client on B.
    let client_addr = {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            BackboneClient::new("127.0.0.1:4442").with_manager(b.iface_manager()),
            BackboneClient::spawn,
        )
    };

    // B announces: A must learn the path.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("backbone", "test"),
    );
    let dest_hash = destination.desc.address_hash;

    let online = async {
        for _ in 0..200 {
            let stats = b.interface_stats().await;
            if stats
                .iter()
                .any(|stat| stat.address == client_addr && stat.online)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online, "client must connect");

    b.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let learned = async {
        for _ in 0..200 {
            if a.has_path(&dest_hash).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(learned, "server must learn the announced path");

    // The client flags tunnel synthesis after connecting; the transport
    // ticker synthesizes the tunnel and the server must establish it
    // (Python `wants_tunnel` -> `Transport.synthesize_tunnel` ->
    // remote `handle_tunnel`).
    let tunneled = async {
        for _ in 0..200 {
            let tunnels = a.tunnel_table_snapshot().await;
            if !tunnels.is_empty() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(tunneled, "server must establish the synthesized tunnel");

    let _ = HW_MTU;
}

#[tokio::test]
async fn fast_flap_accounting_blocks_repeat_offenders() {
    let mut table = FastFlapTable::new(
        BLOCK_FAST_FLAPPING,
        FAST_FLAP_THRESHOLD,
        FAST_FLAP_GRACE,
        FAST_FLAP_EXPIRY,
    );

    let t0 = tokio::time::Instant::now();

    // Short-lived connections count as flaps.
    for _ in 0..FAST_FLAP_GRACE {
        table.account_disconnect("10.0.0.1", Duration::from_secs(2), t0);
    }
    assert!(!table.is_blocked("10.0.0.1", t0), "still within grace");

    table.account_disconnect("10.0.0.1", Duration::from_secs(2), t0);
    assert!(table.is_blocked("10.0.0.1", t0), "blocked past grace");

    // Long-lived connections do not count.
    table.account_disconnect("10.0.0.2", Duration::from_secs(60), t0);
    assert!(!table.is_blocked("10.0.0.2", t0));

    // Blocks expire after the flap-free period.
    assert_eq!(table.blocked_count(), 1);
    let later = t0 + FAST_FLAP_EXPIRY + Duration::from_secs(1);
    assert_eq!(table.clean(later), 1);
    assert_eq!(table.blocked_count(), 0);
    assert!(!table.is_blocked("10.0.0.1", later));
}
