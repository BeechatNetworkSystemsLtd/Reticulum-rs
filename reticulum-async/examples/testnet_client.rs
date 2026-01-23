use std::sync::Arc;

use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};
use tokio::select;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> TESTNET CLIENT <<<");

    let transport = Transport::new(TransportConfig::default());

    // https://reticulum.network/manual/gettingstartedfast.html#connect-to-the-public-testnet
    transport.iface_manager().lock().await.spawn(
        TcpClient::new("amsterdam.connect.reticulum.network:4965"),
        TcpClient::spawn,
    );

    let transport = Arc::new(Mutex::new(transport));
    let cancel = CancellationToken::new();

    {
        let transport = transport.clone();
        let cancel = cancel.clone();

        tokio::spawn(async move {
            let mut announce = transport.lock().await.recv_announces().await;

            loop {
                select! {
                    _ = cancel.cancelled() => {
                        break;
                    },
                    Ok(announce) = announce.recv() => {
                        let destination = announce.destination.lock().await;
                        log::debug!("new announce {}", destination.desc.address_hash);
                    },
                }
            }
        });
    }

    let _ = tokio::signal::ctrl_c().await;

    cancel.cancel();

    log::info!("exit");
}
