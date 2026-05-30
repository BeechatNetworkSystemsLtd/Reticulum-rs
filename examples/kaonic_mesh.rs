use std::sync::Arc;

use reticulum::iface::kaonic::kaonic_grpc::KaonicGrpc;
use reticulum::iface::kaonic::{RadioConfig, RadioModule};
use reticulum::transport::TransportConfig;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">> packet retransmitter <<");

    let transport = Arc::new(Mutex::new(TransportConfig::default()
        .set_retransmit(true)
        .set_broadcast(false)
        .build()));

    let _ = transport.lock().await.iface_manager().lock().await.spawn(
        KaonicGrpc::new(
            "http://127.0.0.1:8080",
            RadioConfig::new_for_module(RadioModule::RadioA),
            None,
        ),
        KaonicGrpc::spawn,
    );

    let _ = tokio::signal::ctrl_c().await;
}
