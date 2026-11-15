//! Facade smoke test (Phase 7.1): the `Reticulum` struct mirrors the
//! Python `RNS.Reticulum` entrypoint.

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::reticulum::Reticulum;
use reticulum::transport::TransportConfig;

#[tokio::test]
async fn facade_lifecycle() {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let reticulum = Reticulum::new(TransportConfig::new("facade", &identity));

    assert!(!reticulum.is_transport_enabled().await);
    assert_eq!(reticulum.identity_hash().await, *identity.address_hash());

    let destination = reticulum
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("facade", "test"),
        )
        .await;

    reticulum.announce(&destination, Some(b"hello")).await;

    assert!(reticulum.path_table().await.is_empty());
    assert!(reticulum.interface_stats().await.is_empty());
    assert!(reticulum.tunnel_table().await.is_empty());

    // Management destinations.
    reticulum.enable_probe_destination().await;
    reticulum.enable_remote_management().await;
    reticulum.enable_blackhole_publishing().await;
}
