use rand_core::OsRng;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};
use reticulum_core::identity::PrivateIdentity;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> TCP SERVER APP <<<");

    let transport = Transport::new(TransportConfig::new(
        "server",
        &PrivateIdentity::new_from_rand(OsRng),
        true,
    ));

    let _ = transport.iface_manager().lock().await.spawn(
        TcpServer::new("0.0.0.0:4242", transport.iface_manager()),
        TcpServer::spawn,
    );

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
