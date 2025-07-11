use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> UDP APP <<<");

    let id = PrivateIdentity::new_from_rand(OsRng);
    let destination = SingleInputDestination::new(id.clone(), DestinationName::new("example", "app"));
    let transport = Transport::new(TransportConfig::new("server", &id, true));

    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4243", Some("127.0.0.1:4242")),
        UdpInterface::spawn);

    let dest = std::sync::Arc::new(tokio::sync::Mutex::new (destination));

    loop {
        transport
            .send_announce(&dest, None)
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    //log::info!("exit");
}
