use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::{link::LinkEvent, DestinationName},
    hash::AddressHash,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    transport::{AnnounceEvent, Transport, TransportConfig},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init()
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
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
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

/// Builds `n` nodes, and for each edge `(u, v)` with `u < v` connects node `v` to
/// the server of node `u`, so that each node has one TCP interface per neighbour.
async fn mesh(n: usize, edges: &[(usize, usize)]) -> Vec<Transport> {
    let server_addr: Vec<_> = (0..n).map(|_| free_local_addr()).collect();

    let mut transports = Vec::with_capacity(n);
    for v in 0..n {
        let client_addr: Vec<_> = edges
            .iter()
            .filter(|&&(_, to)| to == v)
            .map(|&(from, _)| server_addr[from].as_str())
            .collect();
        transports.push(build_transport(&v.to_string(), &server_addr[v], &client_addr).await);
    }

    // wait for the TCP connections to come up
    time::sleep(Duration::from_secs(2)).await;

    transports
}

/// 3×3 grid, opposite corners 0 and 8 are 4 hops apart:
///
/// ```text
/// 0 - 1 - 2
/// |   |   |
/// 3 - 4 - 5
/// |   |   |
/// 6 - 7 - 8
/// ```
fn grid() -> Vec<(usize, usize)> {
    let rows = (0..9).filter(|i| i % 3 != 2).map(|i| (i, i + 1));
    let columns = (0..6).map(|i| (i, i + 3));
    rows.chain(columns).collect()
}

/// Waits for the announce of `destination`, skipping other announces.
async fn recv_announce(
    announces: &mut broadcast::Receiver<AnnounceEvent>,
    destination: AddressHash,
) -> AnnounceEvent {
    loop {
        match announces.recv().await {
            Ok(event) => {
                if event.destination.lock().await.desc.address_hash == destination {
                    return event;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => panic!("announce channel closed"),
        }
    }
}

#[tokio::test]
async fn announce_reaches_all_nodes() {
    setup();

    let mut transports = mesh(9, &grid()).await;

    let mut announces = Vec::new();
    for transport in &transports[1..] {
        announces.push(transport.recv_announces().await);
    }

    let destination = transports[0]
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "mesh"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    transports[0].send_announce(&destination, None).await;

    for (i, announces) in announces.iter_mut().enumerate() {
        time::timeout(Duration::from_secs(10), recv_announce(announces, address))
            .await
            .unwrap_or_else(|_| panic!("announce not received by node {}", i + 1));
    }
}

#[tokio::test]
async fn link_across_mesh() {
    setup();

    let mut transports = mesh(9, &grid()).await;

    let mut announces = transports[0].recv_announces().await;
    let mut out_link_events = transports[0].out_link_events();
    let mut in_link_events = transports[8].in_link_events();

    let destination = transports[8]
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "mesh"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    transports[8].send_announce(&destination, None).await;

    let event = time::timeout(Duration::from_secs(10), recv_announce(&mut announces, address))
        .await
        .expect("announce of node 8 not received by node 0");
    let desc = event.destination.lock().await.desc;

    let link = transports[0].link(desc).await;
    let link_id = *link.lock().await.id();

    time::timeout(Duration::from_secs(10), async {
        loop {
            match out_link_events.recv().await {
                Ok(event) if event.id == link_id && matches!(event.event, LinkEvent::Activated) => {
                    break
                }
                Ok(_) | Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => panic!("out link event channel closed"),
            }
        }
    })
    .await
    .expect("link from node 0 to node 8 not activated");

    transports[0].send_to_out_links(&address, b"hello mesh").await;

    time::timeout(Duration::from_secs(10), async {
        loop {
            match in_link_events.recv().await {
                Ok(event) => {
                    if let LinkEvent::Data(payload) = event.event {
                        assert_eq!(payload.as_slice(), b"hello mesh");
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => panic!("in link event channel closed"),
            }
        }
    })
    .await
    .expect("link data not received by node 8");
}
