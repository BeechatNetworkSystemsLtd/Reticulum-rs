use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::unix_socker_server::UnixSocketServer;
use reticulum::transport::{Transport, TransportConfig};

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
        UnixSocketServer::new("/tmp/rns_default", transport.iface_manager()),
        UnixSocketServer::spawn,
    );

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
