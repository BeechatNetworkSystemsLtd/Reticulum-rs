use std::sync::{Arc, Once};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::packet::PacketType;
use reticulum::{
    destination::{
        link::{LinkEvent, LinkEventData, LinkId},
        DestinationName,
    },
    hash::AddressHash,
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    transport::{AnnounceEvent, TimerConfig, Transport, TransportConfig},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time;

static INIT: Once = Once::new();

/// Below the ephemeral port range, so that the ports of the servers do not collide
/// with connections of tests running in parallel
static NEXT_PORT: AtomicU16 = AtomicU16::new(20000);

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init()
    });
}

fn free_local_addr() -> String {
    format!("127.0.0.1:{}", NEXT_PORT.fetch_add(1, Ordering::Relaxed))
}

async fn build_transport(
    name: &str,
    server_addr: &str,
    client_addr: &[&str],
    timer_config: TimerConfig,
    restart_outlinks: bool,
) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(true)
        .set_restart_outlinks(restart_outlinks)
        .set_timer_config(timer_config)
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
async fn mesh(
    n: usize,
    edges: &[(usize, usize)],
    timer_config: TimerConfig,
    restart_outlinks: bool,
) -> Vec<Transport> {
    let server_addr: Vec<_> = (0..n).map(|_| free_local_addr()).collect();

    let mut transports = Vec::with_capacity(n);
    for v in 0..n {
        let client_addr: Vec<_> = edges
            .iter()
            .filter(|&&(_, to)| to == v)
            .map(|&(from, _)| server_addr[from].as_str())
            .collect();
        transports.push(
            build_transport(
                &v.to_string(),
                &server_addr[v],
                &client_addr,
                timer_config,
                restart_outlinks,
            )
            .await,
        );
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

async fn wait_activated(events: &mut broadcast::Receiver<LinkEventData>, link_id: LinkId) {
    loop {
        match events.recv().await {
            Ok(event) if event.id == link_id && matches!(event.event, LinkEvent::Activated) => {
                break
            }
            Ok(_) | Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => panic!("link event channel closed"),
        }
    }
}

async fn wait_closed(events: &mut broadcast::Receiver<LinkEventData>, link_id: LinkId) {
    loop {
        match events.recv().await {
            Ok(event) if event.id == link_id && matches!(event.event, LinkEvent::Closed) => break,
            Ok(_) | Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => panic!("link event channel closed"),
        }
    }
}

/// Waits for data received over any link and checks it is `data`.
async fn wait_data(events: &mut broadcast::Receiver<LinkEventData>, data: &[u8]) {
    loop {
        match events.recv().await {
            Ok(event) => {
                if let LinkEvent::Data(payload) = event.event {
                    assert_eq!(payload.as_slice(), data);
                    break;
                }
            }
            Err(RecvError::Lagged(_)) => continue,
            Err(RecvError::Closed) => panic!("link event channel closed"),
        }
    }
}

/// Announces a new destination on `destination_node`, waits for the announce on
/// `link_node` and links to it. Returns the destination address and the link id.
async fn link_after_announce(
    link_node: &Transport,
    destination_node: &mut Transport,
) -> (AddressHash, LinkId) {
    let mut announces = link_node.recv_announces().await;
    let mut out_link_events = link_node.out_link_events();

    let destination = destination_node
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "mesh"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    destination_node.send_announce(&destination, None).await;

    let event = time::timeout(Duration::from_secs(10), recv_announce(&mut announces, address))
        .await
        .expect("announce not received");
    let desc = event.destination.lock().await.desc;

    let link = link_node.link(desc).await;
    let link_id = *link.lock().await.id();

    time::timeout(Duration::from_secs(10), wait_activated(&mut out_link_events, link_id))
        .await
        .expect("link not activated");

    (address, link_id)
}

#[tokio::test]
async fn announce_reaches_all_nodes() {
    setup();

    let mut transports = mesh(9, &grid(), TimerConfig::default(), true).await;

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

    let mut transports = mesh(9, &grid(), TimerConfig::default(), true).await;
    let mut node_8 = transports.pop().unwrap();
    let node_0 = &transports[0];

    let mut out_link_events = node_0.out_link_events();
    let mut in_link_events = node_8.in_link_events();

    let (address, _) = link_after_announce(node_0, &mut node_8).await;

    node_0.send_to_out_links(&address, b"hello mesh").await;

    time::timeout(Duration::from_secs(10), wait_data(&mut in_link_events, b"hello mesh"))
        .await
        .expect("link data not received by node 8");

    node_8.send_to_in_links(&address, b"hello back").await;

    time::timeout(Duration::from_secs(10), wait_data(&mut out_link_events, b"hello back"))
        .await
        .expect("link reply not received by node 0");
}

/// Short link timers, so that a link over a dropped relay goes stale and is
/// restarted quickly. The in-link of the destination is closed (after 4 s)
/// before the out-link is restarted (after 8 s), otherwise the destination
/// ignores the repeated link request.
fn fast_timers() -> TimerConfig {
    TimerConfig {
        out_link_keep: Duration::from_secs(1),
        out_link_stale: Duration::from_secs(3),
        out_link_restart: Duration::from_secs(8),
        out_link_repeat: Duration::from_secs(2),
        in_link_stale: Duration::from_secs(3),
        in_link_close: Duration::from_secs(1),
        ..TimerConfig::default()
    }
}

/// Links node 0 to node 8, drops a relay on the path of the link and checks that the
/// link recovers over the remaining nodes after node 8 announces again. With
/// `close_interfaces` the TCP connections of the relay are closed, otherwise they stay
/// open but the relay no longer routes (a hung node). With `restart_outlinks` the link
/// is restarted with the same id, otherwise it closes and node 0 links again.
async fn link_recovers_after_relay_drop(close_interfaces: bool, restart_outlinks: bool) {
    setup();

    let mut transports = mesh(9, &grid(), fast_timers(), restart_outlinks).await;
    let mut node_8 = transports.pop().unwrap();
    let node_0 = transports.remove(0);
    // relays: nodes 1 to 7
    let mut relays: Vec<_> = transports.into_iter().map(Some).collect();

    let mut announces = node_0.recv_announces().await;
    let mut out_link_events = node_0.out_link_events();
    let mut in_link_events = node_8.in_link_events();

    let destination = node_8
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "mesh"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    node_8.send_announce(&destination, None).await;

    let event = time::timeout(Duration::from_secs(10), recv_announce(&mut announces, address))
        .await
        .expect("announce of node 8 not received by node 0");
    let desc = event.destination.lock().await.desc;

    // the link request is sent on all interfaces of node 0, but over TCP the proof
    // is only sent back over the relays of the path, so the neighbour of node 0
    // that receives it is on the path
    let neighbours = [1, 3];
    let iface_rx: Vec<_> = neighbours
        .iter()
        .map(|&i| relays[i - 1].as_ref().unwrap().iface_rx())
        .collect();

    let link = node_0.link(desc).await;
    let link_id = *link.lock().await.id();

    let on_path: Vec<_> = iface_rx.into_iter().map(|rx| {
        // watch for proofs
        let mut iface_rx = rx;
        let seen = Arc::new(AtomicBool::new(false));
        let task_seen = seen.clone();
        tokio::spawn(async move {
            loop {
                match iface_rx.recv().await {
                    Ok(message) => {
                        if message.packet.header.packet_type == PacketType::Proof
                            && message.packet.destination == link_id
                        {
                            task_seen.store(true, Ordering::SeqCst);
                        }
                    }
                    Err(RecvError::Lagged(_)) => continue,
                    Err(RecvError::Closed) => break,
                }
            }
        });
        seen
    }).collect();

    time::timeout(Duration::from_secs(10), wait_activated(&mut out_link_events, link_id))
        .await
        .expect("link from node 0 to node 8 not activated");

    // exactly one neighbor is on the path
    assert!(on_path.iter().filter(|seen| seen.load(Ordering::SeqCst)).count() == 1);
    let dropped = neighbours[on_path
        .iter()
        .position(|seen| seen.load(Ordering::SeqCst))
        .expect("no neighbour of node 0 on the path of the link")];
    println!("dropping relay {}", dropped);

    let relay = relays[dropped - 1].take().unwrap();
    if close_interfaces {
        relay.iface_manager().lock().await.shutdown();
    }
    drop(relay);

    // announces are only accepted if emitted at a later second
    time::sleep(Duration::from_secs(1)).await;
    node_8.send_announce(&destination, None).await;

    let new_link_id = if restart_outlinks {
        link_id
    } else {
        // until the link is closed, `link` returns the existing one
        time::timeout(Duration::from_secs(20), wait_closed(&mut out_link_events, link_id))
            .await
            .expect("link from node 0 to node 8 not closed");

        let new_link_id = *node_0.link(desc).await.lock().await.id();
        assert_ne!(new_link_id, link_id);
        new_link_id
    };

    time::timeout(Duration::from_secs(20), wait_activated(&mut out_link_events, new_link_id))
        .await
        .expect("link from node 0 to node 8 not recovered");

    node_0.send_to_out_links(&address, b"hello again").await;

    time::timeout(Duration::from_secs(10), wait_data(&mut in_link_events, b"hello again"))
        .await
        .expect("link data not received by node 8 after recovery");
}

#[tokio::test]
async fn link_recovers_after_hung_relay() {
    link_recovers_after_relay_drop(false, true).await;
}

#[tokio::test]
async fn link_recovers_after_closed_relay() {
    link_recovers_after_relay_drop(true, true).await;
}

#[tokio::test]
async fn link_reopened_after_hung_relay() {
    link_recovers_after_relay_drop(false, false).await;
}

#[tokio::test]
async fn link_reopened_after_closed_relay() {
    link_recovers_after_relay_drop(true, false).await;
}
