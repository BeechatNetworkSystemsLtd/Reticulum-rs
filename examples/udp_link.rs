//! To communicate with a local instance of Python RNS should use a config like:
//!
//! ```text
//! [[UDP Interface]]
//! type = UDPInterface
//! enabled = yes
//! listen_ip = 0.0.0.0
//! listen_port = 4242
//! forward_ip = 127.0.0.1
//! forward_port = 4243
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::destination::link::{Link, LinkEvent, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    log::info!(">>> UDP LINK APP <<<");

    let id = PrivateIdentity::new_from_rand(OsRng);
    let destination = SingleInputDestination::new(id.clone(), DestinationName::new("example", "app"));
    let transport = Transport::new(TransportConfig::new("server", &id, true));

    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4243", Some("127.0.0.1:4242")),
        UdpInterface::spawn);

    let dest = Arc::new(tokio::sync::Mutex::new (destination));

    let mut announce_recv = transport.recv_announces().await;
    let mut out_link_events = transport.out_link_events();

    let mut links = HashMap::<AddressHash, Arc<tokio::sync::Mutex<Link>>>::new();

    loop {
        while let Ok(announce) = announce_recv.try_recv() {
            let destination = announce.destination.lock().await;
            //println!("ANNOUNCE: {}", destination.desc.address_hash);
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
            if link.status() == LinkStatus::Active {
                let packet = link.data_packet (b"foo").unwrap();
                transport.send_packet(packet).await;
            }
        }
        while let Ok(link_event) = out_link_events.try_recv() {
            match link_event.event {
                LinkEvent::Activated => log::info!("link {} activated", link_event.id),
                LinkEvent::Closed => log::info!("link {} closed", link_event.id),
                LinkEvent::Data(payload) => log::info!("link {} data payload: {}", link_event.id,
                    std::str::from_utf8(payload.as_slice())
                        .map(str::to_string)
                        .unwrap_or_else(|_| format!("{:?}", payload.as_slice()))),
                _ => {},
            }
        }
        transport
            .send_announce(&dest, None)
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    //log::info!("exit");
}
