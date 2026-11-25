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
    packet::{DestinationType, Packet, PacketContext, PacketType},
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
    let (transports, muted, link_id, events, address, _) = linked_with(timers(), false).await;
    (transports, muted, link_id, events, address)
}

/// Node 0 and node 2 (behind relay 1) with `timers`, and what node 0 sends on the air.
async fn nodes_with(timers: TimerConfig) -> (Vec<Transport>, Arc<AtomicBool>, broadcast::Receiver<Packet>) {
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
            .set_timer_config(timers)
            .build();
        transport.iface_manager().lock().await.spawn(Radio::new(&air[node], &in_range, muted[node].clone()), Radio::spawn);
        transports.push(transport);
    }
    let sent = air[0].subscribe();
    (transports, muted[2].clone(), sent)
}

/// Node 0 learns node 2's destination from its announce.
async fn announced(transports: &mut [Transport]) -> reticulum::destination::DestinationDesc {
    let mut announces = transports[0].recv_announces().await;
    let destination = transports[2]
        .add_destination(PrivateIdentity::new_from_rand(OsRng), DestinationName::new("test", "liveness"))
        .await;
    let address = destination.lock().await.desc.address_hash;
    transports[2].send_announce(&destination, None).await;
    loop {
        let event = time::timeout(Duration::from_secs(5), announces.recv()).await.expect("announce").expect("event");
        let desc = event.destination.lock().await.desc;
        if desc.address_hash == address {
            return desc;
        }
    }
}

async fn linked_with(timers: TimerConfig, link_recovery: bool) -> (Vec<Transport>, Arc<AtomicBool>, reticulum::destination::link::LinkId, broadcast::Receiver<reticulum::destination::link::LinkEventData>, reticulum::hash::AddressHash, broadcast::Receiver<Packet>) {
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
            .set_timer_config(timers)
            .set_link_recovery(link_recovery)
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
    let sent = air[0].subscribe();
    (transports, muted[2].clone(), link_id, events, address, sent)
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

/// The hub's radio timers, scaled down: keepalive every 3 s (±10 %), stale after 4 s, probes
/// every 1 s, closed 8 s after the destination was last heard.
fn radio_timers() -> TimerConfig {
    TimerConfig {
        out_link_keep: Duration::from_secs(3),
        out_link_stale: Duration::from_secs(4),
        out_link_probe: Duration::from_secs(1),
        out_link_close: Duration::from_secs(4),
        out_link_repeat: Duration::from_secs(2),
        out_link_repeat_max: Duration::from_secs(4),
        in_link_stale: Duration::from_secs(6),
        in_link_close: Duration::from_secs(4),
        jitter_percent: 10,
        ..Default::default()
    }
}

fn keepalive_requests(sent: &mut broadcast::Receiver<Packet>) -> usize {
    let mut count = 0;
    while let Ok(packet) = sent.try_recv() {
        if packet.context == PacketContext::KeepAlive && packet.data.as_slice() == [0xFF] {
            count += 1;
        }
    }
    count
}

/// A link whose destination went silent is closed within stale + close, and probes the
/// destination more often once stale.
#[tokio::test]
async fn a_dead_link_is_probed_and_closed_within_its_bound() {
    let (_transports, muted, link_id, mut events, _address, mut sent) = linked_with(radio_timers(), false).await;
    let _ = keepalive_requests(&mut sent);
    muted.store(true, Ordering::SeqCst);
    let start = time::Instant::now();
    time::timeout(Duration::from_secs(15), async {
        loop {
            let event = events.recv().await.expect("link event");
            if event.id == link_id && matches!(event.event, LinkEvent::Closed) {
                break;
            }
        }
    })
    .await
    .expect("closed");
    let took = start.elapsed();
    let probes = keepalive_requests(&mut sent);
    // 8 s after it last heard the destination (up to one keepalive interval before the
    // mute), checked once a second.
    assert!(took <= Duration::from_secs(10), "closed after {took:?}");
    // At 3 s intervals 8 s hold two or three keepalives; probing at 1 s while stale adds more.
    assert!(probes >= 4, "{probes} keepalives before closing");
}

/// An unanswered link request is repeated after 2 s, 4 s, then every 4 s (±10 %), not
/// every 2 s: a destination out of reach costs little.
#[tokio::test]
async fn an_unanswered_link_request_is_repeated_less_often_up_to_a_cap() {
    let (mut transports, muted, mut sent) = nodes_with(radio_timers()).await;
    let desc = announced(&mut transports).await;
    muted.store(true, Ordering::SeqCst);
    while sent.try_recv().is_ok() {}
    let link_id = *transports[0].link(desc).await.lock().await.id();
    let start = time::Instant::now();
    let mut at = Vec::new();
    while start.elapsed() < Duration::from_secs(19) {
        match time::timeout(Duration::from_millis(200), sent.recv()).await {
            Ok(Ok(packet)) if packet.header.packet_type == PacketType::LinkRequest => at.push(start.elapsed()),
            _ => {}
        }
    }
    assert_eq!(status(&transports[0], &link_id).await, Some(LinkStatus::Pending));
    let gaps: Vec<u64> = at.windows(2).map(|pair| (pair[1] - pair[0]).as_millis() as u64).collect();
    // sent at 0, then about 2, 6, 10, 14, 18 s (checked once a second)
    assert!((5..=7).contains(&at.len()), "{} requests at {at:?}", at.len());
    assert!(gaps[0] < 3_500 && gaps[1..].iter().all(|gap| (3_000..=5_500).contains(gap)), "gaps {gaps:?}");
}

/// Stale after 4 s without hearing the destination, then a probe only every 10 s and closed
/// 30 s later: long enough to see what a stale link does.
fn stale_timers() -> TimerConfig {
    TimerConfig {
        out_link_keep: Duration::from_secs(3),
        out_link_stale: Duration::from_secs(4),
        out_link_probe: Duration::from_secs(10),
        out_link_close: Duration::from_secs(30),
        in_link_stale: Duration::from_secs(30),
        in_link_close: Duration::from_secs(10),
        ..Default::default()
    }
}

/// What node 0 did once its link to node 2 went stale, with `link_recovery` on or off.
struct WhileStale {
    /// A keepalive went out within 1.5 s of the link going stale.
    probed_at_once: bool,
    /// Data could still be sent over the link.
    carried_data: bool,
    /// Node 0 asked again for the path to node 2.
    asked_for_path: bool,
}

async fn while_stale(link_recovery: bool) -> WhileStale {
    let (transports, muted, link_id, _events, address, mut sent) = linked_with(stale_timers(), link_recovery).await;
    muted.store(true, Ordering::SeqCst);
    while sent.try_recv().is_ok() {}
    // what node 0 sends from the mute on, and when the link went stale
    let (mut keepalives, mut stale_at, mut asked_for_path) = (Vec::new(), None, false);
    let start = time::Instant::now();
    while stale_at.is_none_or(|at: time::Instant| at.elapsed() < Duration::from_secs(3)) {
        assert!(start.elapsed() < Duration::from_secs(15), "stale while the destination is silent");
        if stale_at.is_none() && status(&transports[0], &link_id).await == Some(LinkStatus::Stale) {
            stale_at = Some(time::Instant::now());
        }
        let Ok(Ok(packet)) = time::timeout(Duration::from_millis(50), sent.recv()).await else { continue };
        if packet.context == PacketContext::KeepAlive && packet.data.as_slice() == [0xFF] {
            keepalives.push(time::Instant::now());
        }
        // a path request: plain, its data starts with the destination asked for
        if stale_at.is_some() && packet.header.destination_type == DestinationType::Plain && packet.data.as_slice().starts_with(address.as_slice()) {
            asked_for_path = true;
        }
    }
    let stale_at = stale_at.expect("stale");
    // the link check runs once a second: a probe sent with the change to stale is seen just
    // before or after it
    let probed_at_once = keepalives.iter().any(|at| {
        let (early, late) = (stale_at.saturating_duration_since(*at), at.saturating_duration_since(stale_at));
        early <= Duration::from_millis(300) && late <= Duration::from_millis(1500)
    });
    let carried_data = !transports[0].send_to_out_links(&address, b"still there?").await.is_empty();
    WhileStale { probed_at_once, carried_data, asked_for_path }
}

/// With link recovery, a link that goes stale probes its destination at once, still
/// carries data, and asks again for the path to a destination behind a relay.
#[tokio::test]
async fn a_recovering_link_probes_carries_data_and_asks_for_the_path_when_stale() {
    let stale = while_stale(true).await;
    assert!(stale.probed_at_once, "probed at once");
    assert!(stale.carried_data, "data sent over the stale link");
    assert!(stale.asked_for_path, "the path asked for again");
}

/// Without link recovery (the default) a stale link waits for its next probe, carries no
/// data, and the path is not asked for.
#[tokio::test]
async fn without_link_recovery_a_stale_link_only_waits() {
    let stale = while_stale(false).await;
    assert!(!stale.carried_data, "no data over a stale link");
    assert!(!stale.asked_for_path, "no path request");
}
