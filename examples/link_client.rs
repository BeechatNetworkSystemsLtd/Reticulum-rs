use rand_core::OsRng;

use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::Transport;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut transport = Transport::new();

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

    transport
        .send_packet(in_destination.lock().await.announce(OsRng, None).unwrap())
        .await;

    // let mut recv = transport.recv();
    // loop {
    //     if let Ok(packet) = recv.recv().await {
    //         if let Ok(dest) = DestinationAnnounce::validate(&packet) {
    //             log::debug!("destination announce {}", dest.desc);
    //             // let link = transport.link(dest.desc);
    //         }
    //     }
    // }
}
