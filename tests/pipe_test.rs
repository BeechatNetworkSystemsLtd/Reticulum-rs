//! PipeInterface tests (feature `iface-pipe`): spawn a command and exchange
//! HDLC-framed packets on its stdin/stdout (`RNS/Interfaces/PipeInterface.py`).
//!
//! `/bin/cat` is used as the pipe command: everything written to the
//! interface is echoed back, which exercises the full encode/decode path.

#![cfg(feature = "iface-pipe")]

use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName, identity::PrivateIdentity, iface::pipe::PipeInterface,
    packet::PacketType, transport::TransportConfig,
};

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init()
    });
}

/// Send an announce through the pipe (`/bin/cat` echo loop) and expect the
/// same announce to come back on the interface rx broadcast.
#[tokio::test]
async fn pipe_echo_with_cat() {
    setup();

    let transport = TransportConfig::new("pipe", &PrivateIdentity::new_from_rand(OsRng)).build();

    transport
        .iface_manager()
        .lock()
        .await
        .spawn(PipeInterface::new("/bin/cat"), PipeInterface::spawn);

    // let the subprocess come up
    tokio::time::sleep(Duration::from_secs(1)).await;

    let id = PrivateIdentity::new_from_name("pipe-echo");
    let destination = transport
        .add_destination(id, DestinationName::new("test", "pipe"))
        .await;
    let dest_hash = destination.lock().await.desc.address_hash;

    let mut iface_rx = transport.iface_rx();

    transport.send_announce(&destination, None).await;

    let echoed = tokio::time::timeout(Duration::from_secs(10), iface_rx.recv())
        .await
        .expect("timeout waiting for echo over /bin/cat pipe")
        .expect("interface rx channel closed");

    assert_eq!(echoed.packet.header.packet_type, PacketType::Announce);
    assert_eq!(echoed.packet.destination, dest_hash);

    // interface statistics must account for the echo round trip
    let stats = transport.interface_stats().await;
    let stats = stats
        .iter()
        .find(|stat| stat.kind == "PipeInterface")
        .expect("pipe interface in stats");
    assert_eq!(stats.sent, 1);
    assert_eq!(stats.received, 1);
    assert!(stats.tx_bytes > 0);
    assert!(stats.rx_bytes > 0);
    assert!(stats.online);
}

/// An exiting command is respawned after the configured delay
/// (`reconnect_pipe` in `PipeInterface.py`).
#[tokio::test]
async fn pipe_respawns_after_exit() {
    setup();

    let marker =
        std::env::temp_dir().join(format!("reticulum-pipe-respawn-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&marker);

    let transport =
        TransportConfig::new("pipe-respawn", &PrivateIdentity::new_from_rand(OsRng)).build();

    // the command appends one marker line per start and exits shortly after;
    // growing marker count proves the respawn loop
    let command = format!("sh -c 'echo x >> {:?}; sleep 0.2'", marker);

    transport.iface_manager().lock().await.spawn(
        PipeInterface::new(command).with_respawn_delay(Duration::from_millis(100)),
        PipeInterface::spawn,
    );

    tokio::time::sleep(Duration::from_millis(600)).await;
    let first = std::fs::read_to_string(&marker)
        .map(|content| content.lines().count())
        .unwrap_or(0);

    tokio::time::sleep(Duration::from_millis(900)).await;
    let second = std::fs::read_to_string(&marker)
        .map(|content| content.lines().count())
        .unwrap_or(0);

    let _ = std::fs::remove_file(&marker);

    assert!(first >= 1, "pipe command should have run at least once");
    assert!(
        second > first,
        "pipe command should have been respawned (first {first}, second {second})"
    );
}
