use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    packet::Packet,
    transport::{Transport, TransportConfig},
};
use tokio_util::sync::CancellationToken;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init()
    });
}

fn free_local_addr() -> String {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

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
async fn packet_overload() {
    setup();

    let transport_a = build_transport("a", "127.0.0.1:8081", &[]).await;
    let transport_b = build_transport("b", "127.0.0.1:8082", &["127.0.0.1:8081"]).await;

    let stop = CancellationToken::new();

    let producer_task = {
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut tx_counter = 0;

            let mut payload_size = 0;
            loop {
                tokio::select! {
                    _ = stop.cancelled() => {
                            break;
                    },
                    _ = tokio::time::sleep(std::time::Duration::from_micros(1)) => {

                        let mut packet = Packet::default();

                        packet.data.resize(payload_size);

                        payload_size += 1;
                        if payload_size >= 3072 {
                            payload_size = 0;
                        }

                        transport_a.send_packet(packet).await;
                        tx_counter += 1;
                    },
                };
            }

            return tx_counter;
        })
    };

    let consumer_task = {
        let stop = stop.clone();
        let mut messages = transport_b.iface_rx();
        tokio::spawn(async move {
            let mut rx_counter = 0;
            loop {
                tokio::select! {
                    _ = stop.cancelled() => {
                            break;
                    },
                    Ok(_) = messages.recv() => {
                        rx_counter += 1;
                    },
                };
            }

            return rx_counter;
        })
    };

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    stop.cancel();

    let tx_counter = producer_task.await.unwrap();
    let rx_counter = consumer_task.await.unwrap();

    log::info!("TX: {}, RX: {}", tx_counter, rx_counter);
}

#[tokio::test]
async fn unavailable_tcp_client_does_not_block_server_traffic() {
    setup();

    let server_addr_a = free_local_addr();
    let server_addr_b = free_local_addr();
    let unavailable_addr = free_local_addr();

    let transport_a = build_transport("a", &server_addr_a, &[&unavailable_addr]).await;
    let transport_b = build_transport("b", &server_addr_b, &[&server_addr_a]).await;

    tokio::time::sleep(Duration::from_secs(1)).await;

    let sender = tokio::spawn(async move {
        for counter in 0..3u8 {
            let mut packet = Packet::default();
            packet.data.write(&[counter]).unwrap();
            transport_a.send_packet(packet).await;
        }
    });

    tokio::time::timeout(Duration::from_secs(2), sender)
        .await
        .expect("send_packet stalled behind an unavailable TCP client")
        .unwrap();

    let mut iface_rx = transport_b.iface_rx();
    let mut received = 0usize;

    tokio::time::timeout(Duration::from_secs(2), async {
        while received < 3 {
            iface_rx.recv().await.unwrap();
            received += 1;
        }
    })
    .await
    .expect("TCP server traffic stopped after another TCP client failed to connect");
}
