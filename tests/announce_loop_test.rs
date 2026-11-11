use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    hash::AddressHash,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    packet::PacketType,
    transport::{Transport, TransportConfig},
};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init()
    });
}

async fn build_transport(name: &str, server_addr: &str, client_addr: &[&str], retransmit: bool) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(retransmit)
        .build();

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

    transport
}

/// Announces once from `origin` and returns the announce counts of all nodes
/// 5 and 10 seconds later.
async fn announce_once(origin: &mut Transport, relays: &[&Transport]) -> (Vec<u32>, Vec<u32>) {
    /// Counts the announces for `destination` received on all interfaces of `transport`.
    fn count_announces(transport: &Transport, destination: AddressHash) -> Arc<AtomicU32> {
        let count = Arc::new(AtomicU32::new(0));
        let mut iface_rx = transport.iface_rx();
        let task_count = count.clone();
        tokio::spawn(async move {
            loop {
                match iface_rx.recv().await {
                    Ok(message) => {
                        if message.packet.header.packet_type == PacketType::Announce
                            && message.packet.destination == destination
                        {
                            task_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    // skipped messages are not counted, but counting goes on
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
        });
        count
    }

    let destination = origin
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "loop"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    let counts: Vec<_> = std::iter::once(&*origin)
        .chain(relays.iter().copied())
        .map(|transport| count_announces(transport, address))
        .collect();
    let load = || counts.iter().map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>();

    // wait for the TCP connections to come up
    time::sleep(Duration::from_secs(2)).await;

    origin.send_announce(&destination, None).await;

    time::sleep(Duration::from_secs(5)).await;
    let after_5s = load();
    time::sleep(Duration::from_secs(5)).await;
    let after_10s = load();

    println!("announces received after 5s: {:?}, after 10s: {:?}", after_5s, after_10s);

    (after_5s, after_10s)
}

#[tokio::test]
async fn announce_loop_stops() {
    setup();

    // a -- b, and b, c, d all connected to each other
    let mut transport_a = build_transport("a", "127.0.0.1:8981", &[], false).await;
    let transport_b = build_transport("b", "127.0.0.1:8982", &["127.0.0.1:8981"], true).await;
    let transport_c = build_transport("c", "127.0.0.1:8983", &["127.0.0.1:8982"], true).await;
    let transport_d =
        build_transport("d", "127.0.0.1:8984", &["127.0.0.1:8982", "127.0.0.1:8983"], true).await;

    let mut announces_c = transport_c.recv_announces().await;
    let mut announces_d = transport_d.recv_announces().await;

    let (after_5s, after_10s) =
        announce_once(&mut transport_a, &[&transport_b, &transport_c, &transport_d]).await;

    assert_eq!(after_5s, after_10s, "announces still circulating");
    assert!(after_10s.iter().all(|&count| count < 20), "too many announces: {:?}", after_10s);

    for announces in [&mut announces_c, &mut announces_d] {
        assert!(!matches!(announces.try_recv(), Err(TryRecvError::Empty)));
    }
}

#[tokio::test]
async fn announce_triangle_with_origin_settles() {
    setup();

    // a, b, c all connected to each other
    let mut transport_a = build_transport("a", "127.0.0.1:8991", &[], false).await;
    let transport_b = build_transport("b", "127.0.0.1:8992", &["127.0.0.1:8991"], true).await;
    let transport_c =
        build_transport("c", "127.0.0.1:8993", &["127.0.0.1:8991", "127.0.0.1:8992"], true).await;

    let (after_5s, after_10s) = announce_once(&mut transport_a, &[&transport_b, &transport_c]).await;

    assert_eq!(after_5s, after_10s, "announces still circulating");
}
