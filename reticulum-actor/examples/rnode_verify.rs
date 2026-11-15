//! `rnode_verify` — drive an RNode-class LoRa device through the actor
//! engine and verify the full control path end-to-end:
//!
//!   1. `Start` the node
//!   2. `AddInterface` an `RnodeSerial` interface (KISS detect, firmware
//!      validation, radio configuration, CMD_READY flow control)
//!   3. `CreateDestination` + `Announce` — put a real packet on the air
//!   4. watch the interface record go online and check counters, then
//!      listen for any neighbours that answer
//!
//! Usage:
//!   cargo run -p reticulum-actor --example rnode_verify \
//!       --features "iface-rnode,iface-serial" -- \
//!       --port /dev/ttyUSB0 --listen-secs 30
//!
//! Radio parameters are the repo hardware-test channel (867.5 MHz,
//! BW 125 kHz, SF9, CR 4/5, 2 dBm) — kept deliberately low power.

use std::time::{Duration, Instant};

use reticulum_actor::types::{Action, InterfaceConfig, InterfaceSummary, NodeStatus, Update};
use reticulum_actor::App;

fn arg_string(name: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn arg_u64(name: &str, default: u64) -> u64 {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn wait_for(rx: &flume::Receiver<Update>, pred: impl Fn(&Update) -> bool, what: &str) -> Option<Update> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(u) = rx.recv_timeout(Duration::from_millis(250)) {
            if pred(&u) {
                return Some(u);
            }
        }
    }
    eprintln!("[verify] TIMEOUT waiting for {what}");
    None
}

fn fmt_iface(i: &InterfaceSummary) -> String {
    format!(
        "online={} failed={} sent={} received={} announces_sent={} rssi={:?} snr={:?}",
        i.online, i.failed, i.sent, i.received, i.announces_sent, i.rssi, i.snr
    )
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port = arg_string("--port", "/dev/ttyUSB0");
    let speed = arg_u64("--speed", 115200) as u32;
    let listen_secs = arg_u64("--listen-secs", 30);

    let data_dir = format!("/tmp/reticulum-actor-rnode-verify-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&data_dir);
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    println!("== MK Stack / RNode verification via reticulum-actor ==");
    println!("   port : {port} @ {speed} baud");
    let (app, rx) = App::new(data_dir.clone());
    std::thread::sleep(Duration::from_millis(100));

    // 1. Start the node ---------------------------------------------------
    app.dispatch(Action::Start { transport_enabled: true, identity_address: None });
    wait_for(&rx, |u| matches!(u, Update::NodeStatus(NodeStatus::Running { .. })), "node running")
        .expect("node did not reach Running");
    println!("[ok] node started (transport enabled)");

    // 2. RNode serial interface ------------------------------------------
    app.dispatch(Action::AddInterface {
        name: "c6l-rnode".into(),
        config: InterfaceConfig::RnodeSerial { port: port.clone(), speed },
        ifac: None,
        enabled: true,
    });
    let added = wait_for(
        &rx,
        |u| matches!(u, Update::InterfaceAdded { name, .. } if name == "c6l-rnode"),
        "interface added",
    )
    .expect("interface was not added");
    let Update::InterfaceAdded { address, kind, .. } = added else { unreachable!() };
    println!("[ok] interface added: {address} ({kind})");

    // Live interface status arrives via NetworkTick updates (1 Hz); the
    // KISS handshake + radio validation takes a few seconds.
    app.dispatch(Action::StartNetworkTick { interval_ms: 1000 });
    let mut online = false;
    let deadline = Instant::now() + Duration::from_secs(25);
    'wait_online: while Instant::now() < deadline {
        while let Ok(u) = rx.try_recv() {
            if let Update::NetworkTick(t) = &u {
                if let Some(i) = t.interfaces.iter().find(|i| i.address == address) {
                    if i.online {
                        online = true;
                        break 'wait_online;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(online, "RNode interface did not come online (detect/radio config failed)");
    println!("[ok] RNode online: KISS detect + firmware validation + radio config validated");

    // 3. Destination + announce -------------------------------------------
    app.dispatch(Action::CreateDestination {
        app_name: "example".into(),
        aspect: "rnode_verify".into(),
    });
    // destination hash surfaces via state; poll for it
    let mut dest_hash = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let state = app.state();
        if let Some(d) = state
            .destinations
            .iter()
            .find(|d| d.app_name == "example" && d.aspect == "rnode_verify")
        {
            dest_hash = Some(d.address_hash.clone());
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let dest_hash = dest_hash.expect("destination not created");
    println!("[ok] destination created: {dest_hash} (app=example aspect=rnode_verify)");

    let stamp = format!("c6l rust-sdk verify @ {}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
    app.dispatch(Action::Announce {
        destination_hash: dest_hash.clone(),
        app_data: stamp.as_bytes().to_vec(),
    });
    std::thread::sleep(Duration::from_secs(3));
    println!("[ok] announce dispatched over the air");

    // 4. Verify counters from the freshest NetworkTick after the announce ----
    let mut iface: Option<InterfaceSummary> = None;
    let deadline = Instant::now() + Duration::from_secs(8);
    'wait_stats: while Instant::now() < deadline {
        while let Ok(u) = rx.try_recv() {
            if let Update::NetworkTick(t) = u {
                if let Some(i) = t.interfaces.into_iter().find(|i| i.address == address) {
                    if i.sent >= 1 {
                        iface = Some(i);
                        break 'wait_stats;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let iface = iface.expect("no interface stats observed after announce");
    println!("[iface] {}", fmt_iface(&iface));
    assert!(iface.online, "interface dropped offline");
    assert!(iface.sent >= 1, "announce did not increment sent counter");
    assert!(iface.announces_sent >= 1, "announce not counted");

    // 5. Listen for neighbours ---------------------------------------------
    println!("[listen] waiting {listen_secs}s for replies / other nodes...");
    let deadline = Instant::now() + Duration::from_secs(listen_secs);
    let mut heard = 0usize;
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Update::AnnounceReceived { address_hash, hops, app_data, .. }) => {
                heard += 1;
                println!(
                    "  [announce] from {address_hash} hops={hops:?} app_data={}",
                    String::from_utf8_lossy(&app_data)
                );
            }
            Ok(Update::InterfaceUpdated { address: a, online, failed }) if a == address => {
                println!("  [iface] online={online} failed={failed}");
                assert!(!failed, "interface entered failed state");
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    if heard == 0 {
        println!("  (no other Reticulum nodes in range on this channel)");
    }

    // 6. Shut down cleanly ---------------------------------------------------
    app.dispatch(Action::Stop);
    wait_for(&rx, |u| matches!(u, Update::NodeStatus(NodeStatus::Stopped)), "node stopped");
    println!("[ok] node stopped cleanly");
    println!("\nVERIFICATION PASSED: MK Stack C6L (Heltec V3 / RNode fw) driven by reticulum-actor");
}
