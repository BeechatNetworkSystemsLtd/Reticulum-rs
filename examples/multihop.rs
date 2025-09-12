use std::env::args;

use rand_core::OsRng;

use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::packet::HeaderType;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    // Call: cargo run --example multihop <place in chain>
    let place = args().nth(1).map_or(0, |s| s.parse::<u16>().unwrap_or(0));

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> MULTIHOP EXAMPLE (place in chain: {}) <<<", place);

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_id = identity.address_hash().clone();

    let mut config = TransportConfig::new("server", &identity, true);
    config.set_retransmit(true);
    let transport = Transport::new(config);

    let our_address = format!("0.0.0.0:{}", place + 5101);

    let _ = transport.iface_manager().lock().await.spawn(
        TcpServer::new(our_address, transport.iface_manager()),
        TcpServer::spawn,
    );

    if place > 0 {
        let connect_to = format!("127.0.0.1:{}", place + 5100);
        let client_addr = transport.iface_manager().lock().await.spawn(
            TcpClient::new(connect_to),
            TcpClient::spawn,
        );

        let id = PrivateIdentity::new_from_rand(OsRng);
        let name = format!("link-{}", place);
        let destination = SingleInputDestination::new(
            id,
            DestinationName::new(&name, "app"),
        );
        log::info!("Created destination {}", destination.desc);

        let mut announce = destination.announce(OsRng, None).unwrap();

        announce.transport = Some(transport_id);
        announce.header.header_type = HeaderType::Type2;
        transport.send_direct(client_addr, announce).await;
    }

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
