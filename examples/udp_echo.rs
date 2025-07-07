use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

async fn client() {
    let transport = Transport::new(TransportConfig::default());

    let client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(
          UdpInterface::new("127.0.0.1:4243", None, transport.iface_manager()),
        UdpInterface::spawn);

    let id = PrivateIdentity::new_from_rand(OsRng);

    let destination = SingleInputDestination::new(id, DestinationName::new("example", "app"));

    tokio::time::sleep(Duration::from_secs(3)).await;

    transport
        .send_direct(client_addr, destination.announce(OsRng, None).unwrap())
        .await;

    let _ = tokio::signal::ctrl_c().await;
}

async fn server() {
    let transport = Transport::new(TransportConfig::new(
        "server",
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    ));

    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4242", None, transport.iface_manager()),
        UdpInterface::spawn);

    for iface in transport.iface_manager().lock().await.ifaces.iter() {
        println!("IFACE ADDRESS: {}", iface.address);
    }

    let _ = tokio::signal::ctrl_c().await;
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> UDP ECHO APP <<<");

    match std::env::args().skip(1).next().as_ref().map(String::as_str) {
        Some("-s") | Some("--server") => server().await,
        _ => client().await
    }

    log::info!("exit");
}
