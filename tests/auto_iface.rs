//! AutoInterface tests (feature `iface-auto`).
//!
//! The pure logic (multicast address derivation, discovery tokens) is unit
//! tested against golden vectors generated from `AutoInterface.py` (v1.4.2)
//! and runs everywhere.
//!
//! The full two-node peering test needs IPv6 link-local addresses and
//! multicast routing on the loopback interface, which most CI sandboxes
//! don't provide. It therefore only runs when `RETICULUM_TEST_AUTOIFACE=1`
//! is set *and* two dedicated link-local addresses exist on `lo`
//! (as root):
//!
//! ```sh
//! sudo ip addr add fe80::1/64 dev lo
//! sudo ip addr add fe80::2/64 dev lo
//! sudo ip -6 route add local ff00::/8 dev lo table local
//! RETICULUM_TEST_AUTOIFACE=1 cargo test -p reticulum --features iface-auto --test auto_iface
//! ```

#![cfg(feature = "iface-auto")]

#[cfg(target_os = "linux")]
use std::sync::Once;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use rand_core::OsRng;
#[cfg(target_os = "linux")]
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::auto::AutoInterface,
    iface::auto::AutoInterfaceConfig,
    transport::{Transport, TransportConfig},
};
#[cfg(target_os = "linux")]
use tokio::time;

#[cfg(target_os = "linux")]
static INIT: Once = Once::new();

#[cfg(target_os = "linux")]
fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init()
    });
}

#[cfg(target_os = "linux")]
fn auto_config(group: &str, adopt: &str, discovery_port: u16) -> AutoInterfaceConfig {
    AutoInterfaceConfig {
        group_id: group.to_string(),
        discovery_port,
        data_port: discovery_port + 2000,
        devices: vec!["lo".to_string()],
        adopt: Some(adopt.parse().expect("valid link-local address")),
        ..AutoInterfaceConfig::default()
    }
}

#[cfg(target_os = "linux")]
async fn auto_transport(name: &str, config: AutoInterfaceConfig) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng)).build();

    transport.iface_manager().lock().await.spawn(
        AutoInterface::new(config, transport.iface_manager()),
        AutoInterface::spawn,
    );

    transport
}

#[cfg(target_os = "linux")]
fn two_node_ready() -> bool {
    if std::env::var("RETICULUM_TEST_AUTOIFACE").ok().as_deref() != Some("1") {
        return false;
    }

    // both dedicated addresses must exist on lo
    let ifaces = reticulum::iface::auto::suitable_interfaces(&["lo".to_string()], &[], None);
    ifaces.len() == 1
        && ifaces[0].name == "lo"
        && ifaces[0].link_local.to_string().contains("fe80:")
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn auto_interface_peers_and_exchanges_announce() {
    setup();

    if !two_node_ready() {
        log::warn!("skipping: RETICULUM_TEST_AUTOIFACE=1 and fe80:: addresses on lo required");
        return;
    }

    // distinct ports from the defaults so a real reticulum on the host
    // isn't disturbed
    let node_a = auto_transport("auto-a", auto_config("rs-test-auto", "fe80::1", 39716)).await;
    let node_b = auto_transport("auto-b", auto_config("rs-test-auto", "fe80::2", 39716)).await;

    // wait for the peering (beacon every 1.6s, peering wait 1.2x announce)
    time::sleep(Duration::from_secs(6)).await;

    let stats = node_a.interface_stats().await;
    assert!(
        stats
            .iter()
            .any(|stat| stat.kind == "AutoPeer" && stat.online),
        "node a should have peered with node b: {stats:#?}"
    );

    let id = PrivateIdentity::new_from_name("auto-announce-a");
    let dest = node_a
        .add_destination(id, DestinationName::new("test", "auto"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    let mut announces = node_b.recv_announces().await;
    node_a.send_announce(&dest, None).await;
    let result = time::timeout(Duration::from_secs(15), announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            assert_eq!(
                announce.destination.lock().await.desc.address_hash,
                dest_hash
            );
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for announce over auto-peered link"),
    }

    let stats = node_b.interface_stats().await;
    let peer = stats
        .iter()
        .find(|stat| stat.kind == "AutoPeer" && stat.received >= 1)
        .expect("auto peer should have received the announce");
    log::info!("node b peer stats: {peer:#?}");
}

#[test]
fn fake_address_source_drives_discovery() {
    use std::net::Ipv6Addr;
    use std::time::Duration;
    use std::time::Instant;

    use reticulum::iface::auto::select_interfaces;
    use reticulum::iface::auto::DiscoveryEvent;
    use reticulum::iface::auto::DiscoveryState;
    use reticulum::iface::auto::ObservedAddr;
    use reticulum::iface::auto::ANNOUNCE_INTERVAL;
    use reticulum::iface::auto::PEERING_TIMEOUT;

    let addrs = vec![
        ObservedAddr {
            name: "lo0".to_string(),
            ifindex: 1,
            addr: "fe80::1".parse().unwrap(),
        },
        ObservedAddr {
            name: "eth0".to_string(),
            ifindex: 2,
            addr: "fe80::a".parse().unwrap(),
        },
        ObservedAddr {
            name: "eth0".to_string(),
            ifindex: 2,
            addr: "fe80::b".parse().unwrap(),
        },
        ObservedAddr {
            name: "eth1".to_string(),
            ifindex: 3,
            addr: "2001:db8::1".parse().unwrap(),
        },
    ];
    let selected = select_interfaces(&addrs, &[], &[], None);
    assert!(selected.adopted.iter().all(|iface| iface.name != "lo0"));
    let eth0 = selected
        .adopted
        .iter()
        .find(|iface| iface.name == "eth0")
        .expect("eth0 adopted");
    assert_eq!(eth0.link_local, "fe80::b".parse::<Ipv6Addr>().unwrap());
    assert!(selected
        .own_addresses
        .contains(&"fe80::a".parse::<Ipv6Addr>().unwrap()));

    let mut state = DiscoveryState::new(selected.own_addresses);
    let start = Instant::now();
    assert_eq!(state.observe(eth0.link_local, start), DiscoveryEvent::Echo);

    let peer: Ipv6Addr = "fe80::99".parse().unwrap();
    assert_eq!(state.observe(peer, start), DiscoveryEvent::New);
    state.insert(peer, "eth0", start);
    assert_eq!(state.observe(peer, start), DiscoveryEvent::Refresh);

    let interval = Duration::from_secs_f64(ANNOUNCE_INTERVAL.as_secs_f64() * 3.25);
    assert!(state.take_reverse(start + interval, interval).is_empty());
    let due = state.take_reverse(start + interval + Duration::from_nanos(1), interval);
    assert_eq!(due, vec![(peer, "eth0".to_string())]);

    let removed = state.expire(
        start + PEERING_TIMEOUT + Duration::from_nanos(1),
        PEERING_TIMEOUT,
    );
    assert_eq!(removed, vec![(peer, "eth0".to_string())]);
}
