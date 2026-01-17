use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    transport::{Transport, TransportConfig},
};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("trace")
        ).init()
    });
}

async fn build_transport_full(
    name: &str,
    server_addr: &str,
    client_addr: &[&str],
    retransmit: bool
) -> Transport {
    let mut config = TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
        true
    );

    if retransmit {
        config.set_retransmit(true);
    }

    let transport = Transport::new(config);

    transport.iface_manager().lock().await.spawn(
        TcpServer::new(server_addr, transport.iface_manager()),
        TcpServer::spawn,
    );

    for &addr in client_addr {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(addr), TcpClient::spawn);
    }

    log::info!("test: transport {} created", name);

    transport
}

async fn build_transport(name: &str, server_addr: &str, client_addr: &[&str]) -> Transport {
    build_transport_full(name, server_addr, client_addr, false).await
}

#[tokio::test]
async fn calculate_hop_distance() {
    setup();

    let mut transport_a = build_transport("a", "127.0.0.1:8081", &[]).await;
    let mut transport_b = build_transport("b", "127.0.0.1:8082", &["127.0.0.1:8081"]).await;
    let mut transport_c =
        build_transport("c", "127.0.0.1:8083", &["127.0.0.1:8081", "127.0.0.1:8082"]).await;

    let id_a = PrivateIdentity::new_from_name("a");
    let id_b = PrivateIdentity::new_from_name("b");
    let id_c = PrivateIdentity::new_from_name("c");

    let dest_a = transport_a
        .add_destination(id_a, DestinationName::new("test", "hop"))
        .await;

    let dest_b = transport_b
        .add_destination(id_b, DestinationName::new("test", "hop"))
        .await;

    let dest_c = transport_c
        .add_destination(id_c, DestinationName::new("test", "hop"))
        .await;

    time::sleep(Duration::from_secs(2)).await;

    println!("======");
    transport_a.send_announce(&dest_a, None).await;

    transport_b.recv_announces().await;
    transport_c.recv_announces().await;

    time::sleep(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn direct_path_request_and_response() {
    setup();

    let mut transport_a = build_transport("a", "127.0.0.1:8081", &[]).await;
    let mut transport_b = build_transport("b", "127.0.0.1:8082", &["127.0.0.1:8081"]).await;

    let id_a = PrivateIdentity::new_from_name("a");
    let id_b = PrivateIdentity::new_from_name("b");

    let dest_b = transport_b
        .add_destination(id_b, DestinationName::new("test", "hop"))
        .await;
    let dest_b_hash = dest_b.lock().await.desc.address_hash;

    time::sleep(Duration::from_secs(2)).await;

    transport_a.request_path(&dest_b_hash, None, None).await;

    time::sleep(Duration::from_secs(2)).await;

    assert!(transport_a.knows_destination(&dest_b_hash).await);
}

#[tokio::test]
async fn remote_path_request_and_response() {
    setup();

    let mut transport_a = build_transport("a", "127.0.0.1:8081", &[]).await;
    let mut transport_b = build_transport_full(
        "b",
        "127.0.0.1:8082",
        &["127.0.0.1:8081"],
        true
    ).await;
    let mut transport_c = build_transport("c", "127.0.0.1:8083", &["127.0.0.1:8082"]).await;

    let id_c = PrivateIdentity::new_from_name("c");
    let dest_c = transport_c
        .add_destination(id_c, DestinationName::new("test", "hop"))
        .await;
    let dest_c_hash = dest_c.lock().await.desc.address_hash;

    let id_b = PrivateIdentity::new_from_name("b");
    let dest_b = transport_b
        .add_destination(id_b, DestinationName::new("test", "hop"))
        .await;
    let dest_b_hash = dest_b.lock().await.desc.address_hash;

    time::sleep(Duration::from_secs(2)).await;

    transport_c.send_announce(&dest_c, None).await;
    transport_b.recv_announces().await;

    time::sleep(Duration::from_secs(2)).await;

    // Advance time past the announce timeout, so the regular announce of
    // destination c is not propagated to a and we can test if a's path
    // request is successful.
    time::pause();
    time::advance(time::Duration::from_secs(3600)).await;

    transport_b.send_announce(&dest_b, None).await; 
    transport_a.recv_announces().await;
    transport_a.request_path(&dest_c_hash, None, None).await;

    assert!(transport_a.knows_destination(&dest_c_hash).await);
}
