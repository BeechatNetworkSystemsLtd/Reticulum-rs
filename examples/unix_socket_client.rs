use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::unix_socket_client::UnixSocketClient;
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
        .spawn(UnixSocketClient::new("/tmp/rns_default"), UnixSocketClient::spawn);

    let id = PrivateIdentity::new_from_rand(OsRng);

    let destination = SingleInputDestination::new(id, DestinationName::new("example", "app"));

    tokio::time::sleep(Duration::from_secs(3)).await;

    transport
        .send_direct(client_addr, destination.announce(OsRng, None).unwrap())
        .await;

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
