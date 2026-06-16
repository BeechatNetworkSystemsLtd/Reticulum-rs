use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::sync::broadcast::error::TryRecvError;

use reticulum::channel::Channel;
use reticulum::destination::DestinationName;
use reticulum::destination::link::LinkEvent;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};

mod utils;
use utils::channel::ExampleMessage;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    log::info!(">>> TCP SERVER FOR CHANNEL EXAMPLE  <<<");

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
    let mut in_link_events = transport.in_link_events();

    let mut links = HashMap::<AddressHash, Arc<tokio::sync::Mutex<Channel<ExampleMessage>>>>::new();
    let mut in_links = vec![];

    let transport = Arc::new(Mutex::new(transport));

    loop {
        match announce_recv.try_recv() {
            Ok(announce) => {
                let len = links.len();
                let destination = announce.destination.lock().await;
                if links.contains_key(&destination.desc.address_hash) {
                    let link = transport.lock().await.link(destination.desc).await;
                    let link = Arc::new(
                        tokio::sync::Mutex::new(
                            Channel::<ExampleMessage>::new(link, &transport)
                                .await
                                .unwrap()
                        )
                    );
                    links.insert(destination.desc.address_hash, link.clone());
                };
                log::trace!("{} to {} links", len, links.len());
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
                    LinkEvent::Proof(_) => {},
                };
                out_link_events.resubscribe();
            },
            Err(error) => {
                if error != TryRecvError::Empty {
                    log::info!("out_link_events channel error: {}", error);
                }
            }
        }

        if let Ok(link_event) = in_link_events.try_recv() {
            let id = link_event.id;
            if let LinkEvent::Activated = link_event.event {
                let maybe_link = transport.lock().await.find_in_link(&id).await;
                if let Some(link) = maybe_link {
                    let channel = Channel::<ExampleMessage>::new(link, &transport)
                        .await
                        .unwrap();
                    let mut incoming = channel.subscribe();
                    in_links.push(channel);
                    log::info!("in-link {} activated, wrapped", id);
                    tokio::spawn(async move {
                        while let Ok(message) = incoming.recv().await {
                            log::info!("received message on {}: {}", id, message);
                        }
                    });
                } else {
                    log::info!("Got activate for {}, but not found", id);
                }
            }
        }

        transport.lock().await.send_announce(&dest, None).await;

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
