use std::env;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::kaonic::kaonic_grpc::KaonicGrpc;
use reticulum::iface::kaonic::{RadioConfig, RadioModule};
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <grpc-addr>", args[0]);
        return;
    }

    let grpc_addr = &args[1];

    let transport = Arc::new(Mutex::new(Transport::new(TransportConfig::default())));

    log::info!("start kaonic client");

    let _ = transport.lock().await.iface_manager().lock().await.spawn(
        KaonicGrpc::new(
            format!("http://{}", grpc_addr),
            RadioConfig::new_for_module(RadioModule::RadioA),
            None,
        ),
        KaonicGrpc::spawn,
    );

    let identity = PrivateIdentity::new_from_name("kaonic-example");

    let in_destination = transport
        .lock()
        .await
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "linkexample"),
        )
        .await;

    // Announce task
    {
        let transport = transport.clone();
        tokio::spawn(async move {
            loop {
                log::trace!("announce");

                if let Some(receipt) = transport
                    .lock()
                    .await
                    .send_packet(in_destination.lock().await.announce(OsRng, None).unwrap())
                    .await
                {
                    drop(receipt);
                }

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
