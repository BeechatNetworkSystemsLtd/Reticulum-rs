use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::error::TryRecvError;

use rand_core::OsRng;
use reticulum::channel::WrappedLink;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::destination::link::{Link, LinkEvent, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};

mod channel_util;
use channel_util::ExampleMessage;

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

    let mut links = HashMap::<AddressHash, Arc<tokio::sync::Mutex<WrappedLink<ExampleMessage>>>>::new();
    let mut in_links = vec![];

    loop {
        match announce_recv.try_recv() {
            Ok(announce) => {
                let len = links.len();
                let destination = announce.destination.lock().await;
                let link = match links.get(&destination.desc.address_hash) {
                    Some(link) => link.clone(),
                    None => {
                        let link = transport.link(destination.desc).await;
                        log::trace!("wl");
                        let link = Arc::new(
                            tokio::sync::Mutex::new(
                                WrappedLink::<ExampleMessage>::new(link).await
                            ) 
                        );
                        links.insert(destination.desc.address_hash, link.clone());
                        link
                    }
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
            match link_event.event {
                LinkEvent::Activated => {
                    if let Some(link) = transport.find_in_link(&id).await {
                        let wrapped = WrappedLink::<ExampleMessage>::new(link).await;
                        let mut incoming = wrapped.subscribe();
                        in_links.push(wrapped);
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
                _ => {}
            }
        }

        transport.send_announce(&dest, None).await;

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
