//! Minimal blackhole publisher for interop testing: a transport with
//! `publish_blackhole` that blackholes one identity and answers `/list`.
//!
//! Usage: blackhole_publisher <listen> <forward> <victim-hex> [until-f64] [reason]

use std::time::Duration;

use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::TransportConfig;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let listen: u16 = std::env::args()
        .nth(1)
        .expect("listen port")
        .parse()
        .unwrap();
    let forward: u16 = std::env::args()
        .nth(2)
        .expect("forward port")
        .parse()
        .unwrap();
    let victim = AddressHash::new_from_hex_string(&std::env::args().nth(3).expect("victim hex"))
        .expect("valid victim hash");
    let until: Option<f64> = std::env::args().nth(4).and_then(|value| value.parse().ok());
    let reason = std::env::args().nth(5);

    let identity = PrivateIdentity::new_from_rand(rand_core::OsRng);
    let transport = TransportConfig::new("publisher", &identity)
        .set_retransmit(true)
        .set_blackhole_publish(true)
        .build();

    {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{listen}"),
                Some(format!("127.0.0.1:{forward}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }

    transport.enable_blackhole_publishing().await;
    transport.blackhole_identity(victim, until, reason).await;

    println!(
        "PUBLISHER-ID {}",
        transport.identity_hash().await.to_hex_string()
    );
    println!("PUBLISH-READY");

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
