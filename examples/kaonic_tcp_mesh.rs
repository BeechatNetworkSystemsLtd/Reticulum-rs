use std::env;
use std::sync::Arc;

use reticulum::iface::kaonic::kaonic_grpc::KaonicGrpc;
use reticulum::iface::kaonic::{RadioConfig, RadioModule};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::TransportConfig;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let args: Vec<String> = env::args().collect();

    let transport = Arc::new(Mutex::new(TransportConfig::default()
        .set_retransmit(true)
        .set_broadcast(false)
        .build()));

    if args.len() < 3 {
        println!("Usage: {} <tcp-server> <kaonic-grpc>", args[0]);
        return;
    }

    log::info!("start kaonic client");

    let _ = transport.lock().await.iface_manager().lock().await.spawn(
        KaonicGrpc::new(
            format!("http://{}", args[2]),
            RadioConfig::new_for_module(RadioModule::RadioA),
            None,
        ),
        KaonicGrpc::spawn,
    );

    log::info!("start tcp client");

    let _ = transport
        .lock()
        .await
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new(&args[1]), TcpClient::spawn);

    log::info!("start tcp client");

    let _ = tokio::signal::ctrl_c().await;
}
