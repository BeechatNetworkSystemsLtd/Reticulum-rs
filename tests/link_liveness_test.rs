//! Link liveness over a shared radio channel with a relay: node 0 links to node 2 through
//! node 1 (nodes 0 and 2 do not hear each other). The relay repeats every link packet on the
//! one channel, so node 0 also hears its own keepalives back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::{
        link::{LinkEvent, LinkStatus},
        DestinationName,
    },
    identity::PrivateIdentity,
    iface::{Interface, InterfaceContext, RxMessage},
    packet::Packet,
    transport::{TimerConfig, Transport, TransportConfig},
};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init()
    });
}

/// Hears the nodes in range, never itself; a muted radio neither sends nor hears.
struct Radio {
    tx: Option<broadcast::Sender<Packet>>,
    rx: Vec<broadcast::Receiver<Packet>>,
    muted: Arc<AtomicBool>,
}

impl Radio {
    fn new(air: &broadcast::Sender<Packet>, in_range: &[&broadcast::Sender<Packet>], muted: Arc<AtomicBool>) -> Self {
        Self { tx: Some(air.clone()), rx: in_range.iter().map(|air| air.subscribe()).collect(), muted }
    }

    async fn spawn(context: InterfaceContext<Self>) {
        let (tx, rx, muted) = {
            let mut inner = context.inner.lock().unwrap();
            (inner.tx.take().expect("radio spawned once"), std::mem::take(&mut inner.rx), inner.muted.clone())
        };
        let iface_address = context.channel.address;
        let (rx_channel, mut tx_channel) = context.channel.split();

        for mut rx in rx {
            let rx_channel = rx_channel.clone();
            let muted = muted.clone();
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(packet) => {
                            if !muted.load(Ordering::SeqCst) {
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
            if !muted.load(Ordering::SeqCst) {
                let _ = tx.send(message.packet);
            }
        }
    }
}

impl Interface for Radio {
    fn mtu() -> usize {
        2048
    }
}

/// Stale after 10 s without hearing the peer, closed 20 s after that.
fn timers() -> TimerConfig {
    TimerConfig {
        out_link_stale: Duration::from_secs(10),
        out_link_close: Duration::from_secs(20),
        in_link_stale: Duration::from_secs(10),
        in_link_close: Duration::from_secs(20),
        ..Default::default()
    }
}

/// Node 0 with an active link to node 2 through node 1; node 2's radio can be muted.
async fn linked() -> (Vec<Transport>, Arc<AtomicBool>, reticulum::destination::link::LinkId, broadcast::Receiver<reticulum::destination::link::LinkEventData>, reticulum::hash::AddressHash) {
    setup();
    let air: Vec<_> = (0..3).map(|_| broadcast::channel(1024).0).collect();
    let muted: Vec<_> = (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let mut transports = Vec::new();
    for node in 0..3 {
        let in_range: Vec<_> = air
            .iter()
            .enumerate()
            .filter(|&(other, _)| other != node && !(node != 1 && other != 1))
            .map(|(_, air)| air)
            .collect();
        let transport = TransportConfig::new(node.to_string(), &PrivateIdentity::new_from_rand(OsRng))
            .set_retransmit(node == 1)
            .set_timer_config(timers())
            .build();
        transport.iface_manager().lock().await.spawn(Radio::new(&air[node], &in_range, muted[node].clone()), Radio::spawn);
        transports.push(transport);
    }

    let mut announces = transports[0].recv_announces().await;
    let mut events = transports[0].out_link_events();
    let destination = transports[2]
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "liveness"))
        .await;
    let address = destination.lock().await.desc.address_hash;
    transports[2].send_announce(&destination, None).await;
    let desc = loop {
        let event = time::timeout(Duration::from_secs(5), announces.recv()).await.expect("announce").expect("event");
        let desc = event.destination.lock().await.desc;
        if desc.address_hash == address {
            break desc;
        }
    };
    let link_id = *transports[0].link(desc).await.lock().await.id();
    time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.expect("link event");
            if event.id == link_id && matches!(event.event, LinkEvent::Activated) {
                break;
            }
        }
    })
    .await
    .expect("link activated");
    (transports, muted[2].clone(), link_id, events, address)
}

async fn status(transport: &Transport, link_id: &reticulum::destination::link::LinkId) -> Option<LinkStatus> {
    match transport.find_out_link(link_id).await {
        Some(link) => Some(link.lock().await.status()),
        None => None,
    }
}

/// The destination is gone (restarted, out of range): the initiator must close the link
/// although the relay keeps repeating its keepalives back to it.
#[tokio::test]
async fn a_link_closes_when_the_destination_is_gone_behind_a_relay() {
    let (transports, muted, link_id, mut events, address) = linked().await;
    muted.store(true, Ordering::SeqCst);

    // keep sending, as an application would: our own sends do not keep the link alive
    let sender = async {
        loop {
            transports[0].send_to_out_links(&address, b"anyone there?").await;
            time::sleep(Duration::from_secs(1)).await;
        }
    };
    let closed = async {
        loop {
            let event = events.recv().await.expect("link event");
            if event.id == link_id && matches!(event.event, LinkEvent::Closed) {
                break;
            }
        }
    };
    tokio::select! {
        _ = sender => unreachable!(),
        result = time::timeout(Duration::from_secs(45), closed) => result.expect("link closed after the destination went silent"),
    }
}

/// A silence shorter than the close time (lost frames) makes the link stale, and the link is
/// active again as soon as the destination is heard.
#[tokio::test]
async fn a_stale_link_is_active_again_when_the_destination_is_heard() {
    let (transports, muted, link_id, mut events, _address) = linked().await;
    muted.store(true, Ordering::SeqCst);
    time::sleep(Duration::from_secs(13)).await;
    assert_eq!(status(&transports[0], &link_id).await, Some(LinkStatus::Stale), "stale while silent");
    muted.store(false, Ordering::SeqCst);

    time::timeout(Duration::from_secs(12), async {
        while status(&transports[0], &link_id).await != Some(LinkStatus::Active) {
            time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("active again once the destination is heard");
    while let Ok(event) = events.try_recv() {
        assert!(!(event.id == link_id && matches!(event.event, LinkEvent::Closed)), "the link was not closed");
    }
}
