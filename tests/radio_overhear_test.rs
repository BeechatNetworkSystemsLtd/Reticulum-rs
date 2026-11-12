//! Relays on a shared radio channel overhearing packets of nodes further along a chain:
//! a copy heard out of turn must neither be relayed nor hide the copy that should be.

use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::{link::LinkEvent, DestinationName},
    identity::PrivateIdentity,
    iface::{Interface, InterfaceContext, RxMessage},
    packet::{DestinationType, Packet, PacketContext, PacketType},
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

type Filter = fn(&Packet) -> bool;
fn all(_: &Packet) -> bool { true }
fn only_link_proof(p: &Packet) -> bool { p.context == PacketContext::LinkRequestProof }
fn only_link_data(p: &Packet) -> bool {
    p.header.packet_type == PacketType::Data && p.header.destination_type == DestinationType::Link
        && p.context == PacketContext::None
}

struct Radio {
    tx: Option<broadcast::Sender<Packet>>,
    rx: Vec<(broadcast::Receiver<Packet>, Filter)>,
}

impl Radio {
    fn new(air: &broadcast::Sender<Packet>, in_range: &[(&broadcast::Sender<Packet>, Filter)]) -> Self {
        Self { tx: Some(air.clone()), rx: in_range.iter().map(|(air, f)| (air.subscribe(), *f)).collect() }
    }
    async fn spawn(context: InterfaceContext<Self>) {
        let (tx, rx) = {
            let mut inner = context.inner.lock().unwrap();
            (inner.tx.take().unwrap(), std::mem::take(&mut inner.rx))
        };
        let iface_address = context.channel.address;
        let (rx_channel, mut tx_channel) = context.channel.split();
        for (mut rx, filter) in rx {
            let rx_channel = rx_channel.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(packet) => {
                            if filter(&packet) {
                                let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                            }
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
impl Interface for Radio { fn mtu() -> usize { 2048 } }

async fn build(name: &str, radio: Radio) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng)).set_retransmit(true).build();
    transport.iface_manager().lock().await.spawn(radio, Radio::spawn);
    transport
}

/// A link over a chain of `n` nodes, each hearing only its neighbours, plus `extra`: (listener,
/// speaker, filter) a node that also overhears some packets of a node further along.
/// Returns whether data went through forward (initiator to destination) and backward.
async fn chain_link(n: usize, extra: Option<(usize, usize, Filter)>) -> (bool, bool) {
    setup();
    let air: Vec<_> = (0..n).map(|_| broadcast::channel(1024).0).collect();
    let mut transports = Vec::new();
    for node in 0..n {
        let mut in_range: Vec<(&broadcast::Sender<Packet>, Filter)> = Vec::new();
        if node > 0 { in_range.push((&air[node - 1], all)); }
        if node + 1 < n { in_range.push((&air[node + 1], all)); }
        if let Some((listener, speaker, filter)) = extra { if listener == node { in_range.push((&air[speaker], filter)); } }
        transports.push(build(&node.to_string(), Radio::new(&air[node], &in_range)).await);
    }
    let mut last = transports.pop().unwrap();
    let first = &transports[0];
    let mut announces = first.recv_announces().await;
    let mut out_events = first.out_link_events();
    let mut in_events = last.in_link_events();
    let destination = last.add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "radio")).await;
    let address = destination.lock().await.desc.address_hash;
    last.send_announce(&destination, None).await;
    let event = time::timeout(Duration::from_secs(10), announces.recv()).await.expect("announce").expect("event");
    let desc = event.destination.lock().await.desc;
    let link = first.link(desc).await;
    let link_id = *link.lock().await.id();
    time::timeout(Duration::from_secs(10), async {
        loop {
            let event = out_events.recv().await.expect("link event");
            if event.id == link_id && matches!(event.event, LinkEvent::Activated) { break; }
        }
    }).await.expect("link not activated");
    time::sleep(Duration::from_millis(500)).await;

    // initiator -> destination
    first.send_to_out_links(&address, b"forward").await;
    let forward = time::timeout(Duration::from_secs(3), async {
        loop {
            if let LinkEvent::Data(payload) = in_events.recv().await.expect("event").event {
                if payload.as_slice() == b"forward" { break; }
            }
        }
    }).await.is_ok();
    // destination -> initiator
    last.send_to_in_links(&address, b"backward").await;
    let backward = time::timeout(Duration::from_secs(3), async {
        loop {
            if let LinkEvent::Data(payload) = out_events.recv().await.expect("event").event {
                if payload.as_slice() == b"backward" { break; }
            }
        }
    }).await.is_ok();
    (forward, backward)
}

/// A(0)-R1(1)-R2(2)-B(3), and R1 overhears B's link proof before R2 relays it: R1 must keep
/// the hops of R2's copy, or it drops everything R2 relays from B.
#[tokio::test]
async fn a_relay_that_overhears_the_proof_early_still_relays_the_destination() {
    let (forward, backward) = chain_link(4, Some((1, 3, only_link_proof))).await;
    assert!(forward, "initiator to destination");
    assert!(backward, "destination to initiator");
}

/// A(0)-R1-R2-R3-B(4), and R3 overhears R1's link data: the copy it does not relay must not
/// make R2's copy a duplicate.
#[tokio::test]
async fn a_relay_that_overhears_data_two_hops_back_still_relays_it() {
    let (forward, backward) = chain_link(5, Some((3, 1, only_link_data))).await;
    assert!(forward, "initiator to destination");
    assert!(backward, "destination to initiator");
}

/// C announced before A was there; B, a transport node, answers A's path request for C.
#[tokio::test]
async fn a_relay_answers_a_path_request_for_a_remote_destination() {
    setup();
    let air: Vec<_> = (0..3).map(|_| broadcast::channel::<Packet>(1024).0).collect();
    let _b = build("b", Radio::new(&air[1], &[(&air[0], all), (&air[2], all)])).await;
    let mut c = build("c", Radio::new(&air[2], &[(&air[1], all)])).await;
    let destination = c.add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "radio")).await;
    let address = destination.lock().await.desc.address_hash;
    c.send_announce(&destination, None).await;
    time::sleep(Duration::from_secs(9)).await;
    let a = build("a", Radio::new(&air[0], &[(&air[1], all)])).await;
    time::sleep(Duration::from_millis(200)).await;
    assert!(!a.knows_destination(&address).await);
    a.request_path(&address, None, None).await;
    time::timeout(Duration::from_secs(5), async {
        while !a.knows_destination(&address).await {
            time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("path response from the relay");
}
