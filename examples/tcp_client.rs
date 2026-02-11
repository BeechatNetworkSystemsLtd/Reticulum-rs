use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> TCP CLIENT APP <<<");

    let transport = Transport::new(TransportConfig::default());

    let client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    let id = PrivateIdentity::new_from_rand(OsRng);

    let mut destination = SingleInputDestination::new(id, DestinationName::new("example", "app"));

    tokio::time::sleep(Duration::from_secs(3)).await;

    transport
        .send_direct(client_addr, destination.announce(OsRng, None).unwrap())
        .await;

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
