use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    crypt::GroupKey,
    destination::{DestinationName, GroupInputDestination},
    identity::{GroupIdentity, PrivateIdentity},
    iface::{Interface, InterfaceContext, RxMessage},
    packet::{DestinationType, Packet},
    transport::{ReceivedData, Transport, TransportConfig},
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
    let (transport_a, _transport_b, mut transport_c) = line(true, true).await;
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
    let (transport_a, _transport_b, mut transport_c) = line(true, false).await;
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
    let transport_b =
        build_transport("b", Radio::new(&air_b, &[&air_a, &air_c, &air_d]), true, true).await;
    let mut transport_c =
        build_transport("c", Radio::new(&air_c, &[&air_b, &air_d]), true, true).await;
    let mut transport_d =
        build_transport("d", Radio::new(&air_d, &[&air_b, &air_c]), true, true).await;

    let key = GroupKey::new_rand(OsRng);
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
