//! End-to-end network interface discovery: node A announces a
//! discoverable TCP server interface, node B's `InterfaceDiscovery`
//! validates the announce, tracks it and auto-connects to it.

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use reticulum_discovery::{
    AutoconnectPolicy, DiscoveredStatus, InterfaceAnnouncer, InterfaceDiscovery, InterfaceInfo,
};

async fn udp_bridge(a: &Arc<Transport>, b: &Arc<Transport>, port_a: u16, port_b: u16) {
    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_a}"),
                Some(format!("127.0.0.1:{port_b}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_b}"),
                Some(format!("127.0.0.1:{port_a}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn discovery_announce_validate_and_autoconnect() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);

    let a = Arc::new(TransportConfig::new("disc-a", &identity_a).build());
    let b = Arc::new(TransportConfig::new("disc-b", &identity_b).build());

    // UDP bridge for the discovery announces.
    udp_bridge(&a, &b, 4432, 4433).await;

    // A also runs a TCP server interface which it announces as
    // discoverable.
    let tcp_port = 4434u16;
    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            TcpServer::new(format!("127.0.0.1:{tcp_port}"), a.iface_manager()),
            TcpServer::spawn,
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Low stamp value keeps the test fast.
    let announcer = InterfaceAnnouncer::start(&a, &identity_a, 4, Duration::from_millis(300)).await;

    announcer
        .announce_interface(InterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            // Python `connect_discovered` only dials transport nodes.
            transport: true,
            transport_id: *identity_a.address_hash(),
            name: Some("test-server".to_string()),
            latitude: None,
            longitude: None,
            height: None,
            // A hostname, not a loopback literal: Python 1.5.0 never
            // auto-connects discovered interfaces on invalid IPs like
            // 127.0.0.1.
            reachable_on: Some("localhost".to_string()),
            port: Some(tcp_port),
            frequency: None,
            bandwidth: None,
            spreadingfactor: None,
            codingrate: None,
            channel: None,
            modulation: None,
            ifac_netname: None,
            ifac_netkey: None,
            transport_impl: None,
            transport_vers: None,
            operator_lxmf_address: None,
        })
        .await;

    // B listens with a matching required stamp value and autoconnect.
    let discovery = InterfaceDiscovery::start(&b, 4, true).await;

    // The announce must arrive and validate.
    let discovered = async {
        for _ in 0..200 {
            if discovery.discovered_count().await >= 1 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
    .await;
    assert!(
        discovered,
        "discovery announce must be received and validated"
    );

    let table = discovery.list().await;
    assert_eq!(table.len(), 1);
    assert_eq!(table[0].info.name.as_deref(), Some("test-server"));
    assert_eq!(table[0].info.port, Some(tcp_port));
    assert_eq!(table[0].status(), DiscoveredStatus::Available);
    assert_eq!(table[0].info.transport_impl.as_deref(), Some("RNS"));
    assert_eq!(table[0].info.transport_vers.as_deref(), Some("1.5.5"));

    // Python dials only BackboneInterface. This test widens the Rust
    // AutoconnectPolicy to TCPServerInterface. The wire identity is
    // RNS 1.5.5, which passes the version gate.
    assert_eq!(discovery.connect_discovered().await, 0);
    discovery
        .set_autoconnect_policy(AutoconnectPolicy {
            types: vec!["TCPServerInterface".to_string()],
            ..AutoconnectPolicy::default()
        })
        .await;

    let connected = discovery.connect_discovered().await;
    assert!(
        connected >= 1,
        "discovered TCP interface must be auto-connected when the policy allows it"
    );

    let stats = b.interface_stats().await;
    assert!(
        stats
            .iter()
            .any(|stat| stat.kind == "TcpClient" && stat.name == "test-server"),
        "b must have a TCP client named test-server"
    );
}

fn fixture_info(interface_type: &str) -> InterfaceInfo {
    InterfaceInfo {
        interface_type: interface_type.to_string(),
        transport: true,
        transport_id: AddressHash::new([0x11; 16]),
        name: Some("node".to_string()),
        latitude: None,
        longitude: None,
        height: None,
        reachable_on: None,
        port: None,
        frequency: None,
        bandwidth: None,
        spreadingfactor: None,
        codingrate: None,
        channel: None,
        modulation: None,
        ifac_netname: None,
        ifac_netkey: None,
        transport_impl: None,
        transport_vers: None,
        operator_lxmf_address: None,
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Byte vectors produced by Python `RNS.vendor.umsgpack` with the field
/// order of `InterfaceAnnouncer.get_interface_announce_data` (no network).
#[test]
fn pack_matches_python_umsgpack_fixtures() {
    let cases = [
        (
            {
                let mut info = fixture_info("BackboneInterface");
                info.reachable_on = Some("gw.example".to_string());
                info.port = Some(4242);
                info
            },
            "8b00b14261636b626f6e65496e7465726661636501c3ccfec41011111111111111111111111111111111ccfda3524e53ccfca5312e352e35ccffa46e6f646503c004c005c002aa67772e6578616d706c6506cd1092",
        ),
        (
            {
                let mut info = fixture_info("RNodeInterface");
                info.frequency = Some(868_000_000);
                info.bandwidth = Some(125_000);
                info.spreadingfactor = Some(8);
                info.codingrate = Some("5".to_string());
                info
            },
            "8d00ae524e6f6465496e7465726661636501c3ccfec41011111111111111111111111111111111ccfda3524e53ccfca5312e352e35ccffa46e6f646503c004c005c009ce33bca1000ace0001e8480b080c05",
        ),
        (
            {
                let mut info = fixture_info("WeaveInterface");
                info.frequency = Some(915_000_000);
                info.bandwidth = Some(500_000);
                info.channel = Some(3);
                info.modulation = Some("16".to_string());
                info
            },
            "8d00ae5765617665496e7465726661636501c3ccfec41011111111111111111111111111111111ccfda3524e53ccfca5312e352e35ccffa46e6f646503c004c005c009ce3689cac00ace0007a1200e030d10",
        ),
        (
            {
                let mut info = fixture_info("KISSInterface");
                info.frequency = Some(145_000_000);
                info.bandwidth = Some(9_600);
                info.modulation = Some("AFSK".to_string());
                info
            },
            "8c00ad4b495353496e7465726661636501c3ccfec41011111111111111111111111111111111ccfda3524e53ccfca5312e352e35ccffa46e6f646503c004c005c009ce08a486400acd25800da44146534b",
        ),
        (
            {
                let mut info = fixture_info("I2PInterface");
                info.reachable_on = Some("abcdefghijklmnopqrstuvwxyz234567.b32.i2p".to_string());
                info
            },
            "8a00ac493250496e7465726661636501c3ccfec41011111111111111111111111111111111ccfda3524e53ccfca5312e352e35ccffa46e6f646503c004c005c002d9286162636465666768696a6b6c6d6e6f707172737475767778797a3233343536372e6233322e693270",
        ),
    ];

    for (info, hex) in cases {
        let expected = decode_hex(hex);
        assert_eq!(info.pack(), expected, "{}", info.interface_type);
        let unpacked = InterfaceInfo::unpack(&expected).expect(&info.interface_type);
        assert_eq!(unpacked.interface_type, info.interface_type);
        assert_eq!(unpacked.transport_impl.as_deref(), Some("RNS"));
        assert_eq!(unpacked.transport_vers.as_deref(), Some("1.5.5"));
        assert_eq!(unpacked.reachable_on, info.reachable_on);
        assert_eq!(unpacked.port, info.port);
        assert_eq!(unpacked.frequency, info.frequency);
        assert_eq!(unpacked.codingrate, info.codingrate);
        assert_eq!(unpacked.modulation, info.modulation);
    }

    let mut tcp = fixture_info("TCPServerInterface");
    tcp.name = Some("test-server".to_string());
    tcp.latitude = Some(55.5);
    tcp.reachable_on = Some("localhost".to_string());
    tcp.port = Some(4434);
    tcp.ifac_netname = Some("mesh".to_string());
    tcp.ifac_netkey = Some("secret".to_string());
    tcp.operator_lxmf_address = Some(AddressHash::new([0xAB; 16]));
    let tcp_hex = "8e00b2544350536572766572496e7465726661636501c3ccfec41011111111111111111111111111111111ccfda3524e53ccfca5312e352e35ccffab746573742d73657276657203cb404bc0000000000004c005c0ccf0c410abababababababababababababababab02a96c6f63616c686f737406cd115207a46d65736808a6736563726574";
    assert_eq!(tcp.pack(), decode_hex(tcp_hex));
    let unpacked = InterfaceInfo::unpack(&decode_hex(tcp_hex)).unwrap();
    assert_eq!(unpacked.latitude, Some(55.5));
    assert_eq!(
        unpacked.operator_lxmf_address,
        Some(AddressHash::new([0xAB; 16]))
    );
    assert_eq!(unpacked.ifac_netname.as_deref(), Some("mesh"));
}
