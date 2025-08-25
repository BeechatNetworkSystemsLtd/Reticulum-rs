use rand_core::OsRng;

use std::sync::Arc;
use tokio::sync::Mutex;

use reticulum::channel::{Message, WrappedLink};
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};

mod channel_util;
use channel_util::TextMessage;


#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("trace")
    ).init();

    let mut transport = Transport::new(TransportConfig::default());

    let client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    let identity = PrivateIdentity::new_from_name("link-example");

    let in_destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "linkexample")
        )
        .await;

    transport
        .send_direct(client_addr, in_destination.lock().await.announce(OsRng, None).unwrap())
        .await;

    tokio::spawn(async move {
        let recv = transport.recv_announces();
        let mut recv = recv.await;
        let arc_transport = Arc::new(Mutex::new(transport));
        loop {
            if let Ok(announce) = recv.recv().await {
                let link = arc_transport.lock().await.link(
                    announce.destination.lock().await.desc
                ).await;
                let mut wrapped = WrappedLink::new(link).await;
                log::info!("channel created");
                let message: Arc<dyn Message> = Arc::new(channel_util::TextMessage::new("bla"));
                let result = wrapped.get_channel().send(&message, &arc_transport).await;
                if result.is_ok() {
                    log::info!("message successfully sent over channel");
                } else {
                    log::info!("error sending message over channel");
                }
            }
        }
    });

    let _ = tokio::signal::ctrl_c().await;
}

