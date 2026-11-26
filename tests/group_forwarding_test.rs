use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    crypt::group::GroupKey,
    destination::{DestinationName, GroupInputDestination},
    identity::{GroupIdentity, PrivateIdentity},
    iface::{Interface, InterfaceContext, RxMessage},
    packet::{DestinationType, Packet},
    transport::{GroupRelayConfig, ReceivedData, Transport, TransportConfig},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init()
    });
}

/// Only hears the packets of the nodes in range, never itself
struct Radio {
    tx: Option<broadcast::Sender<Packet>>,
    rx: Vec<broadcast::Receiver<Packet>>,
}

impl Radio {
    fn new(air: &broadcast::Sender<Packet>, in_range: &[&broadcast::Sender<Packet>]) -> Self {
        Self {
            tx: Some(air.clone()),
            rx: in_range.iter().map(|air| air.subscribe()).collect(),
        }
    }

    async fn spawn(context: InterfaceContext<Self>) {
        let (tx, rx) = {
            let mut inner = context.inner.lock().unwrap();
            (inner.tx.take().expect("radio spawned once"), std::mem::take(&mut inner.rx))
        };
        let iface_address = context.channel.address;
        let (rx_channel, mut tx_channel) = context.channel.split();

        for mut rx in rx {
            let rx_channel = rx_channel.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(packet) => {
                            let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                        }
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => break,
                    }
                }
            });
        }

        while let Some(message) = tx_channel.recv().await {
            let _ = tx.send(message.packet);
        }
    }
}

impl Interface for Radio {
    fn mtu() -> usize {
        2048
    }
}

async fn build_transport(
    name: &str,
    radio: Radio,
    group_forwarding: bool,
    retransmit: bool,
) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng))
        .set_group_forwarding(group_forwarding)
        .set_retransmit(retransmit)
        .build();

    transport.iface_manager().lock().await.spawn(radio, Radio::spawn);

    transport
}

async fn build_relay(name: &str, radio: Radio, relay: GroupRelayConfig) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng))
        .set_group_forwarding(true)
        .set_retransmit(true)
        .set_group_relay(relay)
        .build();
    transport.iface_manager().lock().await.spawn(radio, Radio::spawn);
    transport
}

fn group_name() -> DestinationName {
    DestinationName::new("test", "group")
}

fn group_identity(key: &GroupKey) -> GroupIdentity {
    GroupIdentity::new(*PrivateIdentity::new_from_name("group").as_identity(), key.clone())
}

async fn join(transport: &mut Transport, key: &GroupKey) -> broadcast::Receiver<ReceivedData> {
    transport.add_group_destination(group_identity(key), group_name()).await;
    transport.received_data_events()
}

async fn send_group(transport: &Transport, key: &GroupKey, data: &[u8]) {
    let sender = GroupInputDestination::new(group_identity(key), group_name());
    transport.send_packet(sender.data_packet(OsRng, data).unwrap()).await;
}

/// Counts the GROUP packets received on all interfaces of `transport`.
fn count_group_packets(transport: &Transport) -> Arc<AtomicU32> {
    let count = Arc::new(AtomicU32::new(0));
    let mut iface_rx = transport.iface_rx();
    let task_count = count.clone();
    tokio::spawn(async move {
        loop {
            match iface_rx.recv().await {
                Ok(message) => {
                    if message.packet.header.destination_type == DestinationType::Group {
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

/// a and c are both in range of b, but not of each other. b relays only with
/// `group_forwarding` and `b_retransmit`, and c accepts relayed packets only
/// with `group_forwarding`.
async fn line(group_forwarding: bool, b_retransmit: bool) -> (Transport, Transport, Transport) {
    let (air_a, _) = broadcast::channel(64);
    let (air_b, _) = broadcast::channel(64);
    let (air_c, _) = broadcast::channel(64);

    let transport_a = build_transport("a", Radio::new(&air_a, &[&air_b]), false, false).await;
    let transport_b = build_transport(
        "b",
        Radio::new(&air_b, &[&air_a, &air_c]),
        group_forwarding,
        b_retransmit,
    )
    .await;
    let transport_c =
        build_transport("c", Radio::new(&air_c, &[&air_b]), group_forwarding, false).await;

    (transport_a, transport_b, transport_c)
}

#[tokio::test]
async fn group_forwarded_over_single_radio() {
    setup();

    let key = GroupKey::new_rand(OsRng);
    let (transport_a, mut transport_b, mut transport_c) = line(true, true).await;
    // b relays only what it can read
    join(&mut transport_b, &key).await;
    let mut received_c = join(&mut transport_c, &key).await;

    send_group(&transport_a, &key, b"hello group").await;

    let data = time::timeout(Duration::from_secs(2), received_c.recv())
        .await
        .expect("group packet not forwarded over b's radio")
        .expect("received data");
    assert_eq!(data.data.as_slice(), b"hello group");
}

#[tokio::test]
async fn group_not_forwarded_without_retransmit() {
    setup();

    let key = GroupKey::new_rand(OsRng);
    let (transport_a, mut transport_b, mut transport_c) = line(true, false).await;
    join(&mut transport_b, &key).await;
    let mut received_c = join(&mut transport_c, &key).await;

    send_group(&transport_a, &key, b"hello group").await;

    assert!(
        time::timeout(Duration::from_secs(1), received_c.recv()).await.is_err(),
        "group packet forwarded by a node without retransmit"
    );
}

#[tokio::test]
async fn group_forwarding_stops() {
    setup();

    // a -- b, and b, c, d all in range of each other
    let (air_a, _) = broadcast::channel(64);
    let (air_b, _) = broadcast::channel(64);
    let (air_c, _) = broadcast::channel(64);
    let (air_d, _) = broadcast::channel(64);

    let transport_a = build_transport("a", Radio::new(&air_a, &[&air_b]), false, false).await;
    let mut transport_b =
        build_transport("b", Radio::new(&air_b, &[&air_a, &air_c, &air_d]), true, true).await;
    let mut transport_c =
        build_transport("c", Radio::new(&air_c, &[&air_b, &air_d]), true, true).await;
    let mut transport_d =
        build_transport("d", Radio::new(&air_d, &[&air_b, &air_c]), true, true).await;

    let key = GroupKey::new_rand(OsRng);
    join(&mut transport_b, &key).await;
    let mut received_c = join(&mut transport_c, &key).await;
    let mut received_d = join(&mut transport_d, &key).await;

    let counts: Vec<_> = [&transport_a, &transport_b, &transport_c, &transport_d]
        .into_iter()
        .map(count_group_packets)
        .collect();
    let load = || counts.iter().map(|count| count.load(Ordering::Relaxed)).collect::<Vec<_>>();

    send_group(&transport_a, &key, b"hello group").await;

    time::sleep(Duration::from_secs(2)).await;
    let after_2s = load();
    time::sleep(Duration::from_secs(2)).await;
    let after_4s = load();

    println!("group packets received after 2s: {:?}, after 4s: {:?}", after_2s, after_4s);

    assert_eq!(after_2s, after_4s, "group packets still circulating");

    for received in [&mut received_c, &mut received_d] {
        assert_eq!(received.try_recv().expect("received data").data.as_slice(), b"hello group");
        assert!(received.try_recv().is_err(), "group data delivered twice");
    }
}

// paused time, so a slow machine cannot make every wait end at once
#[tokio::test(start_paused = true)]
async fn group_relays_wait_and_copies_cancel_them() {
    setup();

    // a -- b, and b, c, d all in range of each other: b's relay is the first copy c and d
    // hear, so both schedule one; whichever goes first is the second copy for the other
    let (air_a, _) = broadcast::channel(64);
    let (air_b, _) = broadcast::channel(64);
    let (air_c, _) = broadcast::channel(64);
    let (air_d, _) = broadcast::channel(64);
    let relay = GroupRelayConfig::shared_medium(8);

    let transport_a = build_transport("a", Radio::new(&air_a, &[&air_b]), false, false).await;
    let mut transport_b = build_relay("b", Radio::new(&air_b, &[&air_a, &air_c, &air_d]), relay).await;
    let mut transport_c = build_relay("c", Radio::new(&air_c, &[&air_b, &air_d]), relay).await;
    let mut transport_d = build_relay("d", Radio::new(&air_d, &[&air_b, &air_c]), relay).await;

    let key = GroupKey::new_rand(OsRng);
    join(&mut transport_b, &key).await;
    let mut received_c = join(&mut transport_c, &key).await;
    let mut received_d = join(&mut transport_d, &key).await;

    send_group(&transport_a, &key, b"hello group").await;
    time::sleep(Duration::from_secs(1)).await;

    for received in [&mut received_c, &mut received_d] {
        let data = received.try_recv().expect("received data");
        assert_eq!(data.data.as_slice(), b"hello group");
        assert_eq!(data.hops, 1, "through b");
        assert!(received.try_recv().is_err(), "group data delivered twice");
    }
    let (b, c, d) = (transport_b.group_relay_stats(), transport_c.group_relay_stats(), transport_d.group_relay_stats());
    assert_eq!(b.relayed, 1, "b bridges a to the others");
    // two waits ending in the same instant both go out: rare, and allowed
    assert_eq!(c.relayed + d.relayed + c.suppressed + d.suppressed, 2);
    assert!(c.relayed + d.relayed >= 1, "someone relays past b");
}

/// A line of nodes, each hearing only the next: what each node heard, and its relay stats.
async fn along_a_line(nodes: usize, relay: GroupRelayConfig) -> Vec<(Vec<u8>, u64)> {
    let airs: Vec<_> = (0..nodes).map(|_| broadcast::channel::<Packet>(64).0).collect();
    let near = |i: usize| airs.iter().enumerate().filter(|(j, _)| j.abs_diff(i) == 1).map(|(_, air)| air).collect::<Vec<_>>();
    let key = GroupKey::new_rand(OsRng);
    let sender = build_transport("n0", Radio::new(&airs[0], &near(0)), false, false).await;
    let mut line = Vec::new();
    for i in 1..nodes {
        let mut transport = build_relay(&format!("n{i}"), Radio::new(&airs[i], &near(i)), relay).await;
        let received = join(&mut transport, &key).await;
        line.push((transport, received));
    }
    send_group(&sender, &key, b"hello group").await;
    time::sleep(Duration::from_secs(1)).await;
    line.iter_mut()
        .map(|(transport, received)| {
            let mut hops = Vec::new();
            while let Ok(data) = received.try_recv() {
                hops.push(data.hops);
            }
            (hops, transport.group_relay_stats().relayed)
        })
        .collect()
}

#[tokio::test(start_paused = true)]
async fn group_relays_stop_at_the_hop_limit() {
    setup();

    // max_hops 4: three relays, so the packet reaches four nodes out, each once
    let heard = along_a_line(7, GroupRelayConfig::shared_medium(4)).await;
    let hops: Vec<_> = heard.iter().map(|(hops, _)| hops.clone()).collect();
    assert_eq!(hops, vec![vec![0], vec![1], vec![2], vec![3], vec![], vec![]]);
    let relayed: Vec<_> = heard.iter().map(|(_, relayed)| *relayed).collect();
    assert_eq!(relayed, vec![1, 1, 1, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn a_node_that_cannot_read_a_group_packet_does_not_relay_it() {
    setup();

    let (air_a, _) = broadcast::channel(64);
    let (air_b, _) = broadcast::channel(64);
    let (air_c, _) = broadcast::channel(64);
    let relay = GroupRelayConfig::shared_medium(8);
    let transport_a = build_transport("a", Radio::new(&air_a, &[&air_b]), false, false).await;
    let mut transport_b = build_relay("b", Radio::new(&air_b, &[&air_a, &air_c]), relay).await;
    let mut transport_c = build_relay("c", Radio::new(&air_c, &[&air_b]), relay).await;
    let key = GroupKey::new_rand(OsRng);
    let mut received_c = join(&mut transport_c, &key).await;

    // b is not in the group, then holds another key: neither relays it
    send_group(&transport_a, &key, b"one").await;
    time::sleep(Duration::from_secs(1)).await;
    join(&mut transport_b, &GroupKey::new_rand(OsRng)).await;
    send_group(&transport_a, &key, b"two").await;
    time::sleep(Duration::from_secs(1)).await;

    assert!(received_c.try_recv().is_err(), "relayed by a node without the key");
    assert_eq!(transport_b.group_relay_stats().relayed, 0);
}

#[tokio::test(start_paused = true)]
async fn in_a_cluster_that_all_hears_the_sender_one_node_relays() {
    setup();

    let airs: Vec<_> = (0..4).map(|_| broadcast::channel::<Packet>(64).0).collect();
    let others = |me: usize| airs.iter().enumerate().filter(|(i, _)| *i != me).map(|(_, air)| air).collect::<Vec<_>>();
    let relay = GroupRelayConfig::shared_medium(8);
    let transport_a = build_transport("a", Radio::new(&airs[0], &others(0)), false, false).await;
    let mut relays = Vec::new();
    for (i, name) in ["b", "c", "d"].into_iter().enumerate() {
        relays.push(build_relay(name, Radio::new(&airs[i + 1], &others(i + 1)), relay).await);
    }
    let key = GroupKey::new_rand(OsRng);
    let mut received: Vec<_> = Vec::new();
    for relay in &mut relays {
        received.push(join(relay, &key).await);
    }

    send_group(&transport_a, &key, b"hello group").await;
    time::sleep(Duration::from_secs(1)).await;

    let mut relayed = 0;
    for (relay, received) in relays.iter().zip(&mut received) {
        assert_eq!(received.try_recv().expect("received data").hops, 0, "straight from a");
        assert!(received.try_recv().is_err(), "group data delivered twice");
        relayed += relay.group_relay_stats().relayed;
    }
    // two waits ending in the same instant both go out: rare, and allowed
    assert!((1..=2).contains(&relayed), "the first relay cancels the others: {relayed}");
}
