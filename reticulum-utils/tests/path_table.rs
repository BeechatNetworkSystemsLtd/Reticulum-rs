//! Path table snapshot tests (Phase 8: `rnpath -t` / `rnstatus`).

use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use reticulum_utils::rnpath;

async fn udp_pair(server_port: u16, client_port: u16) -> (Transport, Transport) {
    let server = TransportConfig::new("srv", &PrivateIdentity::new_from_rand(OsRng)).build();
    let client = TransportConfig::new("cli", &PrivateIdentity::new_from_rand(OsRng)).build();
    server.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{server_port}"),
            Some(format!("127.0.0.1:{client_port}")),
            false,
        ),
        UdpInterface::spawn,
    );
    client.iface_manager().lock().await.spawn(
        UdpInterface::new(
            format!("127.0.0.1:{client_port}"),
            Some(format!("127.0.0.1:{server_port}")),
            false,
        ),
        UdpInterface::spawn,
    );
    (server, client)
}

#[tokio::test]
async fn snapshot_reflects_announced_paths() {
    let (server, client) = udp_pair(4601, 4602).await;

    let destination = server
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("test", "paths"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    server.send_announce(&destination, None).await;

    let found = rnpath::wait_for_path(&client, &dest_hash, Duration::from_secs(10))
        .await
        .expect("path should be found");
    assert_eq!(found.destination, dest_hash);
    assert_eq!(found.hops, 1);

    // Next hop for a directly connected destination is the destination itself.
    let (via, iface) = client.next_hop(&dest_hash).await.expect("next hop");
    assert_eq!(via, dest_hash);
    assert!(!iface.as_slice().iter().all(|b| *b == 0));

    let snapshot = client.path_table_snapshot().await;
    let entry = snapshot
        .iter()
        .find(|entry| entry.destination == dest_hash)
        .expect("snapshot contains the announced destination");
    assert_eq!(entry.hops, 1);
    assert_eq!(entry.via, dest_hash);

    // rnpath table helpers: filtered and hop-limited views.
    let table = rnpath::path_table(&client, Some(&dest_hash), None).await;
    assert_eq!(table.len(), 1);
    let none = rnpath::path_table(&client, Some(&dest_hash), Some(0)).await;
    assert!(none.is_empty());
    assert!(client.has_path(&dest_hash).await);
    assert_eq!(client.hops_to(&dest_hash).await, Some(1));

    // Link counters: none yet.
    let counts = client.link_counts().await;
    assert_eq!(counts.link_table, 0);
    assert_eq!(counts.inbound, 0);
    assert_eq!(counts.outbound, 0);
}

#[tokio::test]
async fn status_report_shows_paths_and_interfaces() {
    let (server, client) = udp_pair(4611, 4612).await;
    let destination = server
        .add_destination(
            PrivateIdentity::new_from_rand(OsRng),
            DestinationName::new("test", "status"),
        )
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;
    server.send_announce(&destination, None).await;
    assert!(
        rnpath::wait_for_path(&client, &dest_hash, Duration::from_secs(10))
            .await
            .is_some()
    );

    let report = reticulum_utils::rnstatus::collect(&client, false).await;
    assert!(report
        .paths
        .iter()
        .any(|entry| entry.destination == dest_hash));
    // One UDP interface on the client.
    assert_eq!(report.interfaces.len(), 1);
    assert_eq!(report.interfaces[0].status, "Up");
    let text = report.render();
    assert!(text.contains("Path table (1 entries)"));
    assert!(text.contains("Standalone instance"));
    let json = report.to_json();
    assert!(json.contains("\"transport_id\""));
}

/// Drive the production RPC client and formatters against a fake control
/// listener. No daemon is started.
#[tokio::test]
async fn fixture_rpc_renders_status_and_path_table() {
    use reticulum_utils::rnpath;
    use reticulum_utils::rnstatus::{self, StatusView};
    use reticulum_utils::rpc;

    const NOW: f64 = 1_800_000_000.0;
    const KEY: &str = "00112233445566778899aabbccddeeff";
    let authkey = rpc::decode_hex_key(KEY).expect("authkey");
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let authkey_task = authkey.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let authkey = authkey_task.clone();
            if rpc::server_handshake(&mut sock, &authkey).await.is_err() {
                continue;
            }
            let Ok(Some(frame)) = rpc::recv_bytes(&mut sock, None).await else {
                continue;
            };
            let Ok(request) = rmpv::decode::read_value(&mut frame.as_slice()) else {
                continue;
            };
            let response = fixture_response(&request);
            let mut packed = Vec::new();
            if rmpv::encode::write_value(&mut packed, &response).is_err() {
                continue;
            }
            let _ = rpc::send_bytes(&mut sock, &packed).await;
        }
    });

    let dir = std::env::temp_dir().join(format!("rn-operator-{}-{}", std::process::id(), port));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        format!(
            "[reticulum]\nshare_instance = true\nshared_instance_type = \"tcp\"\ninstance_control_port = {port}\nrpc_key = \"{KEY}\"\n"
        ),
    )
    .unwrap();

    let view = StatusView {
        link_stats: true,
        totals: true,
        pps: true,
        queues: true,
        profiling: true,
        ..StatusView::default()
    };
    let status = rnstatus::fetch_status(&dir, &view).await.expect("status");
    assert!(status.contains("Point-to-Point"));
    assert!(status.contains("1.20 kbps"));
    assert!(status.contains("MTU 500"));
    assert!(status.contains("TX Drops  : 4 (1.50 KB)"));
    assert!(status.contains("Airtime   : 12.5% (15s), 3.25% (1h)"));
    assert!(status.contains("Status    : Up"));
    assert!(status.contains("TCPInterface[Peer]"));
    assert!(!status.contains("LocalInterface[secret]"));
    assert!(status.contains("4 pps"));
    assert!(status.contains("8 pps"));
    assert!(status.contains("50.0% total, 3 pkts, 1 dropped"));
    assert!(status.contains("Transport Instance <abababababababababababababababab> running"));
    assert!(status.contains("Uptime is 1h, 1m and 1.0s, 2 entries in link table (1 active)"));
    assert!(status.contains("inbound"));
    assert!(status.contains("Samples  : 4 from 1 thread"));

    let discovered = rnstatus::fetch_status(
        &dir,
        &StatusView {
            discovered_only: true,
            ..StatusView::default()
        },
    )
    .await
    .expect("discovery");
    assert!(discovered.contains("RNode"));
    assert!(discovered.contains("Available"));
    assert!(discovered.contains("Just now"));
    assert!(discovered.contains("RNS 1.5.5"));
    assert!(discovered.contains("1.5, 2.5"));

    let table = rnpath::path_table_text(&dir, None, None)
        .await
        .expect("path table");
    assert!(table.contains("<11111111111111111111111111111111>"));
    assert!(table.contains("is 2 hops away"));
    assert!(table.contains("via <22222222222222222222222222222222>"));
    assert!(table.contains("on TCPInterface[Peer]"));
    assert!(table.contains("expires 2027-01-15 08:00:00"));

    let rates = rnpath::rates_text(&dir, None, NOW).await.expect("rates");
    assert!(rates.contains("2 minutes ago"));
    assert!(rates.contains("0.5 announces/hour"));
    assert!(rates.contains("in the last 2 hours"));
    assert!(rates.contains("2 active rate violations"));

    let path = reticulum::hash::AddressHash::new([0x11; 16]);
    let dropped = rnpath::drop_path_text(&dir, &path).await.expect("drop");
    assert_eq!(
        dropped,
        "Dropped path to <11111111111111111111111111111111>"
    );
    let missing = rnpath::drop_path_text(&dir, &reticulum::hash::AddressHash::new([0x99; 16]))
        .await
        .expect_err("missing path");
    assert!(missing.contains("Unable to drop path"));
    assert!(missing.contains("Does it exist?"));

    let announces = rnpath::drop_announces_text(&dir).await.expect("announces");
    assert_eq!(announces, "Dropping announce queues on all interfaces...");
    let via = rnpath::drop_via_text(&dir, &reticulum::hash::AddressHash::new([0x22; 16]))
        .await
        .expect("via");
    assert_eq!(
        via,
        "Dropped all paths via <22222222222222222222222222222222>"
    );
    let no_via = rnpath::drop_via_text(&dir, &reticulum::hash::AddressHash::new([0x99; 16]))
        .await
        .expect_err("no via");
    assert!(no_via.contains("Unable to drop paths via"));

    let shown = "44444444444444444444444444444444";
    let identity = reticulum::hash::AddressHash::new([0x44; 16]);
    let blackholed = rnpath::blackhole_text(&dir, &identity, shown, None, Some("spam"))
        .await
        .expect("blackhole");
    assert_eq!(blackholed, format!("Blackholed identity {shown}"));
    let already = rnpath::blackhole_text(
        &dir,
        &reticulum::hash::AddressHash::new([0; 16]),
        "00",
        None,
        None,
    )
    .await
    .expect("already");
    assert_eq!(already, "Identity 00 already blackholed");
    let lifted = rnpath::unblackhole_text(&dir, &identity, shown)
        .await
        .expect("unblackhole");
    assert_eq!(lifted, format!("Lifted blackhole for identity {shown}"));
    let list = rnpath::blackholed_text(&dir, None, NOW, None)
        .await
        .expect("list");
    assert!(list.contains("blackholed indefinitely"));
    assert!(list.contains("(spam)"));
    assert!(list.contains("by <55555555555555555555555555555555>"));

    let attached = rnstatus::manage_interface(&dir, "attach", "radio")
        .await
        .expect("attach");
    assert_eq!(attached, "Interface radio was attached");
    let detached = rnstatus::manage_interface(&dir, "detach", "busy")
        .await
        .expect_err("detach");
    assert_eq!(detached, "Could not detach interface busy");
    let missing = rnstatus::manage_interface(&dir, "reload", "missing")
        .await
        .expect_err("reload");
    assert_eq!(missing, "The interface missing does not exist");

    let _ = std::fs::remove_dir_all(dir);
}

fn fixture_response(request: &rmpv::Value) -> rmpv::Value {
    let key = |name: &str| {
        request.as_map().and_then(|rows| {
            rows.iter()
                .find(|(key, _)| key.as_str() == Some(name))
                .map(|(_, value)| value)
        })
    };
    if let Some(op) = key("get").and_then(|value| value.as_str()) {
        return match op {
            "interface_stats" => fixture_stats(),
            "path_table" => fixture_paths(),
            "rate_table" => fixture_rates(),
            "link_count" => rmpv::Value::from(2u64),
            "active_link_count" => rmpv::Value::from(1u64),
            "profiling_results" => fixture_profile(),
            "blackholed_identities" => fixture_blackholes(),
            _ => rmpv::Value::Nil,
        };
    }
    if let Some(op) = key("drop").and_then(|value| value.as_str()) {
        let hash = key("destination_hash").and_then(|value| value.as_slice());
        return match op {
            "path" => rmpv::Value::Boolean(hash.is_some_and(|hash| hash.first() == Some(&0x11))),
            "all_via" => {
                rmpv::Value::from(if hash.is_some_and(|hash| hash.first() == Some(&0x22)) {
                    3u64
                } else {
                    0u64
                })
            }
            "announce_queues" => rmpv::Value::Nil,
            _ => rmpv::Value::Nil,
        };
    }
    if let Some(hash) = key("blackhole_identity").and_then(|value| value.as_slice()) {
        if hash.first() == Some(&0x44) {
            return rmpv::Value::Boolean(true);
        }
        if hash.first() == Some(&0) {
            return rmpv::Value::Nil;
        }
        return rmpv::Value::Boolean(false);
    }
    if let Some(hash) = key("unblackhole_identity").and_then(|value| value.as_slice()) {
        return if hash.first() == Some(&0x44) {
            rmpv::Value::Boolean(true)
        } else {
            rmpv::Value::Nil
        };
    }
    if let Some(op) = key("manage").and_then(|value| value.as_str()) {
        let name = key("name").and_then(|value| value.as_str()).unwrap_or("");
        return match (op, name) {
            ("attach_interface", "radio") => rmpv::Value::Boolean(true),
            ("detach_interface", "busy") => rmpv::Value::Boolean(false),
            ("reload_interface", "missing") => rmpv::Value::Nil,
            _ => rmpv::Value::Boolean(false),
        };
    }
    rmpv::Value::Nil
}

fn fixture_stats() -> rmpv::Value {
    let iface = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("name"),
            rmpv::Value::from("TCPInterface[Peer]"),
        ),
        (rmpv::Value::from("status"), rmpv::Value::Boolean(true)),
        (rmpv::Value::from("mode"), rmpv::Value::from(2u64)),
        (rmpv::Value::from("bitrate"), rmpv::Value::from(1200u64)),
        (rmpv::Value::from("mtu"), rmpv::Value::from(500u64)),
        (rmpv::Value::from("txdrp"), rmpv::Value::from(4u64)),
        (rmpv::Value::from("txdrb"), rmpv::Value::from(1500u64)),
        (rmpv::Value::from("txb"), rmpv::Value::from(1000u64)),
        (rmpv::Value::from("rxb"), rmpv::Value::from(2000u64)),
        (rmpv::Value::from("txs"), rmpv::Value::from(0u64)),
        (rmpv::Value::from("rxs"), rmpv::Value::from(0u64)),
        (
            rmpv::Value::from("airtime_short"),
            rmpv::Value::from(12.5f64),
        ),
        (
            rmpv::Value::from("airtime_long"),
            rmpv::Value::from(3.25f64),
        ),
        (rmpv::Value::from("clients"), rmpv::Value::Nil),
    ]);
    let hidden = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("name"),
            rmpv::Value::from("LocalInterface[secret]"),
        ),
        (rmpv::Value::from("status"), rmpv::Value::Boolean(true)),
        (rmpv::Value::from("mode"), rmpv::Value::from(1u64)),
        (rmpv::Value::from("bitrate"), rmpv::Value::Nil),
    ]);
    let heard = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("interfaces"),
            rmpv::Value::Array(vec![iface, hidden]),
        ),
        (rmpv::Value::from("txb"), rmpv::Value::from(5_000u64)),
        (rmpv::Value::from("rxb"), rmpv::Value::from(8_000u64)),
        (rmpv::Value::from("txs"), rmpv::Value::from(0u64)),
        (rmpv::Value::from("rxs"), rmpv::Value::from(0u64)),
        (rmpv::Value::from("txpps"), rmpv::Value::from(4u64)),
        (rmpv::Value::from("rxpps"), rmpv::Value::from(8u64)),
        (rmpv::Value::from("tqpressure"), rmpv::Value::from(0.5f64)),
        (rmpv::Value::from("rxqt"), rmpv::Value::from(3u64)),
        (rmpv::Value::from("rxqtd"), rmpv::Value::from(1u64)),
        (rmpv::Value::from("dqpressure"), rmpv::Value::from(0.0f64)),
        (rmpv::Value::from("aqpressure"), rmpv::Value::from(0.0f64)),
        (rmpv::Value::from("pqpressure"), rmpv::Value::from(0.0f64)),
        (rmpv::Value::from("ilqpressure"), rmpv::Value::from(0.0f64)),
        (
            rmpv::Value::from("transport_id"),
            rmpv::Value::Binary(vec![0xab; 16]),
        ),
        (
            rmpv::Value::from("network_id"),
            rmpv::Value::Binary(vec![0xcd; 16]),
        ),
        (
            rmpv::Value::from("probe_responder"),
            rmpv::Value::Binary(vec![0xef; 16]),
        ),
        (
            rmpv::Value::from("transport_uptime"),
            rmpv::Value::from(3661.0f64),
        ),
        (
            rmpv::Value::from("discovered"),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                (rmpv::Value::from("name"), rmpv::Value::from("radio1")),
                (
                    rmpv::Value::from("type"),
                    rmpv::Value::from("RNodeInterface"),
                ),
                (rmpv::Value::from("status"), rmpv::Value::from("available")),
                (rmpv::Value::from("last_heard"), rmpv::Value::from(heard)),
                (rmpv::Value::from("value"), rmpv::Value::from(128u64)),
                (rmpv::Value::from("impl_name"), rmpv::Value::from("RNS")),
                (rmpv::Value::from("version"), rmpv::Value::from("1.5.5")),
                (rmpv::Value::from("latitude"), rmpv::Value::from(1.5f64)),
                (rmpv::Value::from("longitude"), rmpv::Value::from(2.5f64)),
            ])]),
        ),
    ])
}

fn fixture_paths() -> rmpv::Value {
    rmpv::Value::Array(vec![rmpv::Value::Map(vec![
        (
            rmpv::Value::from("hash"),
            rmpv::Value::Binary(vec![0x11; 16]),
        ),
        (
            rmpv::Value::from("via"),
            rmpv::Value::Binary(vec![0x22; 16]),
        ),
        (rmpv::Value::from("hops"), rmpv::Value::from(2u64)),
        (
            rmpv::Value::from("interface"),
            rmpv::Value::from("TCPInterface[Peer]"),
        ),
        (
            rmpv::Value::from("expires"),
            rmpv::Value::from(1_800_000_000.0f64),
        ),
    ])])
}

fn fixture_rates() -> rmpv::Value {
    const NOW: f64 = 1_800_000_000.0;
    rmpv::Value::Array(vec![rmpv::Value::Map(vec![
        (
            rmpv::Value::from("hash"),
            rmpv::Value::Binary(vec![0x33; 16]),
        ),
        (rmpv::Value::from("last"), rmpv::Value::from(NOW - 120.0)),
        (
            rmpv::Value::from("rate_violations"),
            rmpv::Value::from(2u64),
        ),
        (
            rmpv::Value::from("blocked_until"),
            rmpv::Value::from(0.0f64),
        ),
        (
            rmpv::Value::from("timestamps"),
            rmpv::Value::Array(vec![rmpv::Value::from(NOW - 7_200.0)]),
        ),
    ])])
}

fn fixture_profile() -> rmpv::Value {
    rmpv::Value::Map(vec![(
        rmpv::Value::from("inbound"),
        rmpv::Value::Map(vec![
            (rmpv::Value::from("name"), rmpv::Value::from("inbound")),
            (rmpv::Value::from("super"), rmpv::Value::Nil),
            (
                rmpv::Value::from("stats_all"),
                rmpv::Value::Map(vec![
                    (rmpv::Value::from("count"), rmpv::Value::from(4u64)),
                    (rmpv::Value::from("threads"), rmpv::Value::from(1u64)),
                    (rmpv::Value::from("mean"), rmpv::Value::Nil),
                    (rmpv::Value::from("median"), rmpv::Value::Nil),
                    (rmpv::Value::from("min"), rmpv::Value::Nil),
                    (rmpv::Value::from("max"), rmpv::Value::Nil),
                    (rmpv::Value::from("stdev"), rmpv::Value::Nil),
                    (rmpv::Value::from("sum"), rmpv::Value::Nil),
                ]),
            ),
            (rmpv::Value::from("stats_1m"), rmpv::Value::Nil),
            (rmpv::Value::from("stats_5m"), rmpv::Value::Nil),
            (rmpv::Value::from("stats_30m"), rmpv::Value::Nil),
            (rmpv::Value::from("stats_60m"), rmpv::Value::Nil),
        ]),
    )])
}

fn fixture_blackholes() -> rmpv::Value {
    rmpv::Value::Map(vec![(
        rmpv::Value::Binary(vec![0x44; 16]),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("source"),
                rmpv::Value::Binary(vec![0x55; 16]),
            ),
            (rmpv::Value::from("until"), rmpv::Value::Nil),
            (rmpv::Value::from("reason"), rmpv::Value::from("spam")),
        ]),
    )])
}
