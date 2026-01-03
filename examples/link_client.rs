use rand_core::OsRng;

use reticulum::destination::link::LinkEvent;
use reticulum::destination::{DestinationAnnounce, DestinationName};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut transport = Transport::new(TransportConfig::default());

    log::info!("start tcp app");

    {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);
    }

    let identity = PrivateIdentity::new_from_name("link-example");

    let in_destination = transport
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "linkexample"),
        )
        .await;

    let packet = in_destination
        .lock()
        .await
        .announce(OsRng, None)
        .unwrap();
    let _ = transport.send_packet(packet).await;

    tokio::spawn(async move {
        let recv = transport.recv_announces();
        let mut recv = recv.await;
        loop {
            if let Ok(announce) = recv.recv().await {
                log::debug!(
                    "destination announce {}",
                    announce.destination.lock().await.desc.address_hash
                );

                let _link = transport.link(announce.destination.lock().await.desc).await;
            }
        }
    });


    let _ = tokio::signal::ctrl_c().await;
}
