use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    transport::{Transport, TransportConfig},
};
use reticulum_core::{destination::DestinationName, identity::PrivateIdentity};
use tokio::time;

async fn build_transport(name: &str, server_addr: &str, client_addr: &[&str]) -> Transport {
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    ));

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

#[tokio::test]
async fn calculate_hop_distance() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

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
