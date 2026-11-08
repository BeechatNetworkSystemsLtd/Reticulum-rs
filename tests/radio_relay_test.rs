use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::{link::LinkEvent, DestinationName},
    identity::PrivateIdentity,
    iface::{Interface, InterfaceContext, RxMessage},
    packet::{Packet, PacketType},
    transport::{Transport, TransportConfig},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init()
    });
}

/// Only heards the packets of the nodes in range, never itself
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

async fn build_transport(name: &str, radio: Radio, retransmit: bool) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng))
        .set_retransmit(retransmit)
        .build();

    transport.iface_manager().lock().await.spawn(radio, Radio::spawn);

    transport
}

#[tokio::test]
async fn announce_relayed_over_single_radio() {
    setup();

    // a and c are both in range of b, but not of each other
    let (air_a, _) = broadcast::channel(64);
    let (air_b, _) = broadcast::channel(64);
    let (air_c, _) = broadcast::channel(64);

    let mut transport_a = build_transport("a", Radio::new(&air_a, &[&air_b]), false).await;
    let transport_b = build_transport("b", Radio::new(&air_b, &[&air_a, &air_c]), true).await;
    let transport_c = build_transport("c", Radio::new(&air_c, &[&air_b]), false).await;

    let mut announces_b = transport_b.recv_announces().await;
    let mut announces_c = transport_c.recv_announces().await;

    let destination = transport_a
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "radio"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    transport_a.send_announce(&destination, None).await;

    let event = time::timeout(Duration::from_secs(2), announces_b.recv())
        .await
        .expect("announce not heard by b")
        .expect("announce event");
    assert_eq!(event.destination.lock().await.desc.address_hash, address);

    let event = time::timeout(Duration::from_secs(5), announces_c.recv())
        .await
        .expect("announce not relayed over b's radio")
        .expect("announce event");
    assert_eq!(event.destination.lock().await.desc.address_hash, address);
}

/// A packet sent on the air of a node
struct Transmission {
    node: usize,
    packet: Packet,
}

/// Records every packet sent on the air of each node
fn monitor(air: &[broadcast::Sender<Packet>]) -> Arc<Mutex<Vec<Transmission>>> {
    let transmissions = Arc::new(Mutex::new(Vec::new()));

    for (node, air) in air.iter().enumerate() {
        let mut rx = air.subscribe();
        let transmissions = transmissions.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(packet) => transmissions.lock().unwrap().push(Transmission { node, packet }),
                    Err(RecvError::Lagged(n)) => panic!("air monitor missed {n} packets"),
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }

    transmissions
}

/// Nodes 0 and 5 are out of range of each other, nodes 1 to 4 are in range of all. One
/// relay is enough for the link from node 0 to node 5, so the others must not repeat
/// its packets.
#[tokio::test]
async fn link_two_hops_over_radios() {
    setup();

    const NODES: usize = 6;

    let air: Vec<_> = (0..NODES).map(|_| broadcast::channel(1024).0).collect();
    let transmissions = monitor(&air);

    let ends = [0, NODES - 1];
    let mut transports = Vec::new();
    for node in 0..NODES {
        let in_range: Vec<_> = air.iter().enumerate()
            .filter(|&(other, _)| other != node && !(ends.contains(&node) && ends.contains(&other)))
            .map(|(_, air)| air)
            .collect();
        transports.push(
            build_transport(&node.to_string(), Radio::new(&air[node], &in_range), true).await,
        );
    }
    let mut node_5 = transports.pop().unwrap();
    let node_0 = &transports[0];

    let mut announces = node_0.recv_announces().await;
    let mut out_link_events = node_0.out_link_events();
    let mut in_link_events = node_5.in_link_events();

    let destination = node_5
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "radio"))
        .await;
    let address = destination.lock().await.desc.address_hash;

    node_5.send_announce(&destination, None).await;

    let event = time::timeout(Duration::from_secs(5), announces.recv())
        .await
        .expect("announce not heard by node 0")
        .expect("announce event");
    let desc = event.destination.lock().await.desc;
    assert_eq!(desc.address_hash, address);

    let link = node_0.link(desc).await;
    let link_id = *link.lock().await.id();

    time::timeout(Duration::from_secs(5), async {
        loop {
            let event = out_link_events.recv().await.expect("link event");
            if event.id == link_id && matches!(event.event, LinkEvent::Activated) {
                break;
            }
        }
    })
    .await
    .expect("link not activated");

    for i in 0..5 {
        let message = format!("message {i}");
        node_0.send_to_out_links(&address, message.as_bytes()).await;

        time::timeout(Duration::from_secs(5), async {
            loop {
                if let LinkEvent::Data(payload) = in_link_events.recv().await.expect("link event").event {
                    assert_eq!(payload.as_slice(), message.as_bytes());
                    break;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{message} not received by node 5"));
    }

    // let relayed copies be recorded
    time::sleep(Duration::from_secs(1)).await;

    // nodes that sent each link packet, in order
    let mut senders: HashMap<_, Vec<_>> = HashMap::new();
    for transmission in transmissions.lock().unwrap().iter() {
        if transmission.packet.header.packet_type != PacketType::Announce {
            senders.entry(transmission.packet.hash()).or_default().push(transmission.node);
        }
    }

    // every link packet is sent by the node that created it and by the same relay
    let mut relays = Vec::new();
    for senders in senders.values() {
        assert_eq!(senders.len(), 2, "link packet sent by nodes {senders:?}");
        relays.push(senders[1]);
    }
    relays.dedup();
    assert_eq!(relays.len(), 1, "link packets relayed by different nodes {relays:?}");
}
