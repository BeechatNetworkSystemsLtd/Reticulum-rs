use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::error::TryRecvError;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::destination::link::{Link, LinkEvent, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};



#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    log::info!(">>> TCP SERVER FOR LINK AND CHANNEL EXAMPLES  <<<");

    let id = PrivateIdentity::new_from_name("link-example");
    let mut transport = Transport::new(TransportConfig::new("server", &id, true));
    log::trace!("transport instantiated");

    let dest = transport.add_destination(
        id,
        DestinationName::new("example_utilities", "linkexample")
    ).await;

    let _ = transport.iface_manager().lock().await.spawn(
        TcpServer::new("0.0.0.0:4242", transport.iface_manager()),
        TcpServer::spawn);

    let mut announce_recv = transport.recv_announces().await;
    let mut out_link_events = transport.out_link_events();

    let mut links = HashMap::<AddressHash, Arc<tokio::sync::Mutex<Link>>>::new();

    loop {
        match announce_recv.try_recv() {
            Ok(announce) => {
                let destination = announce.destination.lock().await;
                let link = match links.get(&destination.desc.address_hash) {
                    Some(link) => link.clone(),
                    None => {
                        let link = transport.link(destination.desc).await;
                        links.insert(destination.desc.address_hash, link.clone());
                        link
                    }
                };
                let link = link.lock().await;
                log::info!("link {}: {:?}", link.id(), link.status());
            },
            Err(error) => {
                if error != TryRecvError::Empty {
                    log::info!("Announce channel error: {}", error);
                }
            }
        }

        match out_link_events.try_recv() {
            Ok(link_event) => {
                match link_event.event {
                    LinkEvent::Activated => log::info!("link {} activated", link_event.id),
                    LinkEvent::Closed => log::info!("link {} closed", link_event.id),
                    LinkEvent::Data(payload) => log::error!("link {} data payload: {}", link_event.id,
                        std::str::from_utf8(payload.as_slice())
                            .map(str::to_string)
                            .unwrap_or_else(|_| format!("{:?}", payload.as_slice()))),
                };
                out_link_events.resubscribe();
            },
            Err(error) => {
                if error != TryRecvError::Empty {
                    log::info!("out_link_events channel error: {}", error);
                }
            }
        }

        transport.send_announce(&dest, None).await;

        log::error!("Channel closed? {:?}", out_link_events.is_closed());
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
