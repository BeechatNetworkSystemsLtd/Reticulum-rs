use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    hash::AddressHash,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    packet::{Packet, PacketDataBuffer},
    transport::{Transport, TransportConfig},
};
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

fn create_packet(data: &[u8], destination: AddressHash) -> Packet {
    let mut packet: Packet = Default::default();

    packet.data = PacketDataBuffer::new_from_slice(data);
    packet.destination = destination;

    packet
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

#[tokio::test]
async fn regression_transport_stalls_on_duplicate_package() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut transport_a = build_transport("a", "127.0.0.1:8081", &[]).await;
    let mut transport_b = build_transport("b", "127.0.0.1:8082", &["127.0.0.1:8081"]).await;

    let id_a = PrivateIdentity::new_from_name("a");
    let dest_a = transport_a
        .add_destination(id_a, DestinationName::new("test", "test"))
        .await;

    let destination_hash = dest_a.lock().await.desc.address_hash;

    let data1 = [1u8];
    let packet1 = create_packet(&data1, destination_hash);
    let packet1_again = packet1.clone();

    let data2 = [3u8, 3u8, 3u8];
    let packet2 = create_packet(&data2, destination_hash);

    let mut receiver = transport_a.received_data_events();

    transport_a.send_announce(&dest_a, None).await;

    transport_b.send_packet(packet1).await;
    transport_b.send_packet(packet1_again).await;

    tokio::select!(
        result = receiver.recv() => {
            assert_eq!(result.unwrap().data.as_slice(), data1);
        },
        _ = time::sleep(Duration::from_secs(5)) => {
            panic!("Timeout, expected packet not received.");
        }
    );

    transport_b.send_packet(packet2).await;

    tokio::select!(
        result = receiver.recv() => {
            assert_eq!(result.unwrap().data.as_slice(), data2);
            // duplicate packet was dropped
        },
        _ = time::sleep(Duration::from_secs(5)) => {
            panic!("Timeout, transport stalled after duplicate?");
        }
    );

    assert!(receiver.is_empty());
}
