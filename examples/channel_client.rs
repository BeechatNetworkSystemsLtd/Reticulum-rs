use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;

use reticulum::channel::Channel;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};

mod utils;
use utils::channel::ExampleMessage;


#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace")
    ).init();

    let transport = Transport::new(TransportConfig::default());

    transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    tokio::spawn(async move {
        let recv = transport.recv_announces();
        let mut recv = recv.await;
        let arc_transport = Arc::new(Mutex::new(transport));

        let link = if let Ok(announce) = recv.recv().await {
            arc_transport.lock().await.link(
                announce.destination.lock().await.desc
            ).await
        } else {
            log::error!("Could not establish link, is the server running?");
            return;
        };

        let channel = Channel::<ExampleMessage>::new(link, &arc_transport)
            .await
            .unwrap();
        log::info!("channel created");

        let message = ExampleMessage::new_text("foo");
        loop {
            let watch_delivery;
            let packet_hash;

            match channel.send(&message).await {
                Ok(hash) => {
                    watch_delivery = channel.watch_message_delivery(hash).await;
                    log::info!(
                        "message {} successfully sent over channel", 
                        hash
                    );
                    packet_hash = hash;
                },
                Err(e) => {
                    log::info!("error sending message: {:?}", e);
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            }

            if let Some(mut watch) = watch_delivery {
                if watch.recv().await.unwrap() {
                    log::info!("message {} delivered!", packet_hash);
                }
            }

            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let _ = tokio::signal::ctrl_c().await;
}

