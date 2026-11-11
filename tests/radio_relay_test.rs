use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::{Interface, InterfaceContext, RxMessage},
    packet::Packet,
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
