//! Serial-family interface tests (feature `iface-serial`):
//!
//! * unit framing tests live in `src/iface/kiss.rs` / `src/iface/ax25.rs`
//!   (golden byte vectors generated from `KISSInterface.py` /
//!   `AX25KISSInterface.py` v1.4.2),
//! * these integration tests exchange real packets between two transports
//!   over a pseudo-terminal pair (`tokio_serial::SerialStream::pair`),
//!   replacing the `socat` pty bridge used by the Python test approach.

#![cfg(feature = "iface-serial")]

use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    destination::DestinationName,
    identity::PrivateIdentity,
    iface::kiss::CsmaParams,
    iface::kiss::KissInterface,
    iface::kiss::KissMode,
    iface::serial::SerialInterface,
    transport::{Transport, TransportConfig},
};
use tokio::time;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init()
    });
}

async fn kiss_transport(
    name: &str,
    mode: KissMode,
    stream: tokio_serial::SerialStream,
) -> Transport {
    let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng)).build();

    transport.iface_manager().lock().await.spawn(
        KissInterface::from_stream(mode, CsmaParams::default(), false, stream),
        KissInterface::spawn,
    );

    transport
}

#[tokio::test]
async fn kiss_announce_over_pty_pair() {
    setup();

    let (master, slave) = tokio_serial::SerialStream::pair().expect("pty pair");

    let node_a = kiss_transport("kiss-a", KissMode::Kiss, master).await;
    let node_b = kiss_transport("kiss-b", KissMode::Kiss, slave).await;

    time::sleep(Duration::from_secs(1)).await;

    let id = PrivateIdentity::new_from_name("kiss-announce-a");
    let dest = node_a
        .add_destination(id, DestinationName::new("test", "kiss"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    let mut announces = node_b.recv_announces().await;
    node_a.send_announce(&dest, None).await;
    let result = time::timeout(Duration::from_secs(10), announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            assert_eq!(
                announce.destination.lock().await.desc.address_hash,
                dest_hash
            );
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for announce over KISS pty pair"),
    }

    let stats = node_a.interface_stats().await;
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "KissInterface" && stat.sent >= 1));
    let stats = node_b.interface_stats().await;
    assert!(stats
        .iter()
        .any(|stat| stat.kind == "KissInterface" && stat.received >= 1));
}

#[tokio::test]
async fn ax25_kiss_announce_over_pty_pair() {
    setup();

    let (master, slave) = tokio_serial::SerialStream::pair().expect("pty pair");

    let node_a = kiss_transport(
        "ax25-a",
        KissMode::Ax25 {
            callsign: "N0CALL".to_string(),
            ssid: 1,
        },
        master,
    )
    .await;
    let node_b = kiss_transport(
        "ax25-b",
        KissMode::Ax25 {
            callsign: "N0CALL".to_string(),
            ssid: 2,
        },
        slave,
    )
    .await;

    time::sleep(Duration::from_secs(1)).await;

    let id = PrivateIdentity::new_from_name("ax25-announce-a");
    let dest = node_a
        .add_destination(id, DestinationName::new("test", "ax25"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    let mut announces = node_b.recv_announces().await;
    node_a.send_announce(&dest, None).await;
    let result = time::timeout(Duration::from_secs(10), announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            assert_eq!(
                announce.destination.lock().await.desc.address_hash,
                dest_hash
            );
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for announce over AX.25 KISS pty pair"),
    }
}

#[tokio::test]
async fn serial_hdlc_announce_over_pty_pair() {
    setup();

    let (master, slave) = tokio_serial::SerialStream::pair().expect("pty pair");

    async fn build(name: &str, stream: tokio_serial::SerialStream) -> Transport {
        let transport = TransportConfig::new(name, &PrivateIdentity::new_from_rand(OsRng)).build();

        transport
            .iface_manager()
            .lock()
            .await
            .spawn(SerialInterface::from_stream(stream), SerialInterface::spawn);

        transport
    }

    let node_a = build("serial-a", master).await;
    let node_b = build("serial-b", slave).await;

    time::sleep(Duration::from_secs(1)).await;

    let id = PrivateIdentity::new_from_name("serial-announce-a");
    let dest = node_a
        .add_destination(id, DestinationName::new("test", "serial"))
        .await;
    let dest_hash = dest.lock().await.desc.address_hash;

    let mut announces = node_b.recv_announces().await;
    node_a.send_announce(&dest, None).await;
    let result = time::timeout(Duration::from_secs(10), announces.recv()).await;
    match result {
        Ok(Ok(announce)) => {
            assert_eq!(
                announce.destination.lock().await.desc.address_hash,
                dest_hash
            );
        }
        Ok(Err(err)) => panic!("error waiting for announce: {err}"),
        Err(_) => panic!("timeout waiting for announce over serial pty pair"),
    }
}
