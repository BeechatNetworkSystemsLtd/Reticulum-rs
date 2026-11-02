//! Tests for the local shared-instance interfaces (`src/iface/local.rs`,
//! Phase 5.3): two transports exchanging announces/links through a
//! `LocalServer` shared instance, mirroring `tests/hop_test.rs`.

use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::local::LocalClient,
    iface::local::LocalServer,
    iface::local::SharedInstanceAddress,
    transport::{Transport, TransportConfig},
};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init()
    });
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Shared instance transport with a local server on `address`.
async fn build_shared_instance(name: &str, address: SharedInstanceAddress) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .build();

    transport.iface_manager().lock().await.spawn(
        LocalServer::new(address, transport.iface_manager()),
        LocalServer::spawn,
    );

    transport
}

/// Client transport attached to a shared instance.
async fn build_local_client(name: &str, address: SharedInstanceAddress) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng)).build();

    transport.iface_manager().lock().await.spawn(
        LocalClient::new(name.to_string(), address),
        LocalClient::spawn,
    );

    transport
}

#[tokio::test]
async fn local_tcp_shared_instance_announce() {
    setup();

    let address = SharedInstanceAddress::tcp(free_tcp_port());
    let shared = build_shared_instance("shared", address.clone()).await;
    let client_a = build_local_client("client-a", address.clone()).await;
    let client_b = build_local_client("client-b", address.clone()).await;

    // let the shared instance come up and the clients connect
    time::sleep(Duration::from_secs(2)).await;

    let id = PrivateIdentity::new_from_name("local-announce-a");
    let dest = client_a
        .add_destination(id, DestinationName::new("test", "local"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    // client B receives the announce relayed through the shared instance
    let mut announces = client_b.recv_announces().await;
    client_a.send_announce(&dest, None).await;
    let result = time::timeout(Duration::from_secs(30), announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            assert_eq!(
                announce.destination.lock().await.desc.address_hash,
                dest_hash
            );
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for announce over local interface"),
    }

    // interface statistics must show the local server clients
    let stats = shared.interface_stats().await;
    log::info!("shared instance stats: {stats:#?}");
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "LocalClient" && stat.received > 0 && stat.rx_bytes > 0));

    // the client-side interface of B received the relayed announce
    let stats = client_b.interface_stats().await;
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "LocalClient" && stat.received >= 1 && stat.online));

    // and the shared instance relayed it out to at least one client
    let stats = shared.interface_stats().await;
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "LocalClient" && stat.sent >= 1));
}

#[cfg(unix)]
#[tokio::test]
async fn local_unix_abstract_shared_instance_announce() {
    setup();

    // abstract socket \0rns/<name> (LocalInterface.py address format)
    let address = SharedInstanceAddress::unix_abstract("rs-test-instance");
    let shared = build_shared_instance("shared-unix", address.clone()).await;
    let client_a_unix = build_local_client("client-a-unix", address.clone()).await;
    let client_b_unix = build_local_client("client-b-unix", address.clone()).await;

    time::sleep(Duration::from_secs(2)).await;

    let id = PrivateIdentity::new_from_name("local-announce-unix");
    let dest = client_a_unix
        .add_destination(id, DestinationName::new("test", "local"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    let mut announces = client_b_unix.recv_announces().await;
    client_a_unix.send_announce(&dest, None).await;
    let result = time::timeout(Duration::from_secs(30), announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            assert_eq!(
                announce.destination.lock().await.desc.address_hash,
                dest_hash
            );
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for announce over unix local interface"),
    }

    let _ = shared;
}

#[tokio::test]
async fn local_tcp_shared_instance_path_request() {
    setup();

    let address = SharedInstanceAddress::tcp(free_tcp_port());
    let _shared = build_shared_instance("shared-pr", address.clone()).await;
    let client_a_pr = build_local_client("client-a-pr", address.clone()).await;
    let client_b_pr = build_local_client("client-b-pr", address.clone()).await;

    time::sleep(Duration::from_secs(2)).await;

    let id = PrivateIdentity::new_from_name("local-pr-b");
    let dest = client_b_pr
        .add_destination(id, DestinationName::new("test", "local"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    // A learns B's path through the shared instance
    client_a_pr.request_path(&dest_hash, None, None).await;

    time::sleep(Duration::from_secs(4)).await;

    assert!(client_a_pr.knows_destination(&dest_hash).await);
}

/// Shared instance enforcing a required access token.
async fn build_gated_shared_instance(
    address: SharedInstanceAddress,
    access: reticulum::iface::local::SharedInstanceAccessConfig,
) -> Transport {
    let transport = TransportConfig::new("shared-gated", &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .build();

    transport.iface_manager().lock().await.spawn(
        LocalServer::new_with_access(address, transport.iface_manager(), access),
        LocalServer::spawn,
    );

    transport
}

/// Authenticated local client (carries the shared-instance token).
async fn build_authenticated_client(
    name: &str,
    address: SharedInstanceAddress,
    token: Vec<u8>,
) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng)).build();

    transport.iface_manager().lock().await.spawn(
        LocalClient::new_authenticated(name.to_string(), address, token),
        LocalClient::spawn,
    );

    transport
}

async fn announce_reaches(
    destination_hash: reticulum::hash::AddressHash,
    sink: &Transport,
) -> bool {
    let mut announces = sink.recv_announces().await;
    let deadline = time::Instant::now() + Duration::from_secs(10);
    while time::Instant::now() < deadline {
        match time::timeout_at(deadline, announces.recv()).await {
            Ok(Ok(announce)) => {
                if announce.destination.lock().await.desc.address_hash == destination_hash {
                    return true;
                }
            }
            _ => return false,
        }
    }
    false
}

#[tokio::test]
async fn shared_instance_with_token_accepts_authenticated_client() {
    setup();

    let address = SharedInstanceAddress::tcp(free_tcp_port());
    let access = reticulum::iface::local::SharedInstanceAccessConfig {
        allow: Vec::new(),
        required_token: Some(b"sekrit-shared-token".to_vec()),
        max_clients: None,
    };
    let shared = build_gated_shared_instance(address.clone(), access).await;
    let client_a =
        build_authenticated_client("auth-a", address.clone(), b"sekrit-shared-token".to_vec())
            .await;
    let client_b =
        build_authenticated_client("auth-b", address.clone(), b"sekrit-shared-token".to_vec())
            .await;

    time::sleep(Duration::from_secs(2)).await;

    let id = PrivateIdentity::new_from_name("gated-announce-a");
    let dest = client_a
        .add_destination(id, DestinationName::new("test", "gated"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    client_a.send_announce(&dest, None).await;

    assert!(
        announce_reaches(dest_hash, &client_b).await,
        "authenticated clients must exchange traffic through the gated shared instance"
    );

    // The gated server tracks its authenticated client interfaces.
    let stats = shared.interface_stats().await;
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "LocalClient" && stat.received > 0));
}

#[tokio::test]
async fn shared_instance_rejects_client_without_token() {
    setup();

    let address = SharedInstanceAddress::tcp(free_tcp_port());
    let access = reticulum::iface::local::SharedInstanceAccessConfig {
        allow: Vec::new(),
        required_token: Some(b"sekrit-shared-token".to_vec()),
        max_clients: None,
    };
    let _shared = build_gated_shared_instance(address.clone(), access).await;
    let authenticated =
        build_authenticated_client("auth-c", address.clone(), b"sekrit-shared-token".to_vec())
            .await;
    // This client never authenticates.
    let unauthenticated = build_local_client("plain", address.clone()).await;

    time::sleep(Duration::from_secs(2)).await;

    let id = PrivateIdentity::new_from_name("gated-announce-plain");
    let dest = unauthenticated
        .add_destination(id, DestinationName::new("test", "gated-reject"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    unauthenticated.send_announce(&dest, None).await;

    assert!(
        !announce_reaches(dest_hash, &authenticated).await,
        "unauthenticated clients must not reach authenticated ones"
    );
}

#[tokio::test]
async fn shared_instance_rejects_wrong_token() {
    setup();

    let address = SharedInstanceAddress::tcp(free_tcp_port());
    let access = reticulum::iface::local::SharedInstanceAccessConfig {
        allow: Vec::new(),
        required_token: Some(b"sekrit-shared-token".to_vec()),
        max_clients: None,
    };
    let _shared = build_gated_shared_instance(address.clone(), access).await;
    let authenticated =
        build_authenticated_client("auth-d", address.clone(), b"sekrit-shared-token".to_vec())
            .await;
    let wrong_token =
        build_authenticated_client("auth-e", address.clone(), b"wrong-token".to_vec()).await;

    time::sleep(Duration::from_secs(2)).await;

    let id = PrivateIdentity::new_from_name("gated-announce-wrong");
    let dest = wrong_token
        .add_destination(id, DestinationName::new("test", "gated-wrong"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    wrong_token.send_announce(&dest, None).await;

    assert!(
        !announce_reaches(dest_hash, &authenticated).await,
        "clients with a wrong token must be rejected"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn shared_instance_allow_list_blocks_unknown_names() {
    setup();

    let address = SharedInstanceAddress::tcp(free_tcp_port());
    let access = reticulum::iface::local::SharedInstanceAccessConfig {
        allow: vec!["vip".to_string()],
        required_token: None,
        max_clients: None,
    };
    let _shared = build_gated_shared_instance(address.clone(), access).await;
    let vip = build_authenticated_client("vip", address.clone(), Vec::new()).await;
    let outsider = build_local_client("outsider", address.clone()).await;

    time::sleep(Duration::from_secs(2)).await;

    let id = PrivateIdentity::new_from_name("gated-announce-outsider");
    let dest = outsider
        .add_destination(id, DestinationName::new("test", "gated-allow"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    outsider.send_announce(&dest, None).await;

    assert!(
        !announce_reaches(dest_hash, &vip).await,
        "clients not on the allow list must be rejected"
    );
}

#[tokio::test]
async fn shared_instance_max_clients_caps_connections() {
    setup();

    let address = SharedInstanceAddress::tcp(free_tcp_port());
    let access = reticulum::iface::local::SharedInstanceAccessConfig {
        allow: Vec::new(),
        required_token: None,
        max_clients: Some(1),
    };
    let shared = build_gated_shared_instance(address.clone(), access).await;
    let client_a = build_local_client("cap-a", address.clone()).await;
    let _client_b = build_local_client("cap-b", address.clone()).await;

    time::sleep(Duration::from_secs(2)).await;

    // The cap does not disconnect the first client.
    let id = PrivateIdentity::new_from_name("gated-announce-cap");
    let dest = client_a
        .add_destination(id, DestinationName::new("test", "gated-cap"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;
    client_a.send_announce(&dest, None).await;
    assert!(announce_reaches(dest_hash, &shared).await);

    // And a second client stays unconnected: no LocalClient interface for
    // it appears on the shared instance.
    time::sleep(Duration::from_secs(3)).await;
    let stats = shared.interface_stats().await;
    assert_eq!(
        stats
            .iter()
            .filter(|stat| stat.kind == "LocalClient")
            .count(),
        1,
        "the client cap must hold"
    );
}
