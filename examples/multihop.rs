use std::env::args;
use std::str::from_utf8;

use tokio::io::AsyncBufReadExt;

use rand_core::OsRng;

use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::destination::link::{LinkEvent, LinkStatus};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::packet::{HeaderType, Packet, PacketDataBuffer, PropagationType};
use reticulum::transport::{Transport, TransportConfig};

fn create_data_packet(message: &String, destination: AddressHash) -> Packet {
    let mut packet: Packet = Default::default();

    packet.header.propagation_type = PropagationType::Transport;
    packet.destination = destination;
    packet.data = PacketDataBuffer::new_from_slice(message.as_bytes());

    packet
}

#[tokio::main]
async fn main() {
    // Call: cargo run --example multihop <number of our hop> <number of last hop>
    // Once the chain is set up, type a line to send it as a message to the last hop
    // or type "link" to request a link to the last hop.

    let mut args = args();
    let our_hop = args.nth(1).map_or(0, |s| s.parse::<u16>().unwrap_or(0));
    let last_hop = args.next().map_or(128, |s| s.parse::<u16>().unwrap_or(128));

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> MULTIHOP EXAMPLE (place in chain: {}/{}) <<<", our_hop, last_hop);

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport_id = identity.address_hash().clone();

    let last_hop_id = PrivateIdentity::new_from_name("last_hop");
    let last_hop_name = DestinationName::new("last_hop", "app");

    let last_hop_destination = SingleInputDestination::new(
        last_hop_id.clone(),
        last_hop_name,
    );
    let last_hop_address = last_hop_destination.desc.address_hash.clone();

    log::info!("Destination on last hop will be {}", last_hop_destination.desc);

    let mut config = TransportConfig::new("server", &identity, false);
    config.set_retransmit(true);
    let mut transport = Transport::new(config);

    let our_address = format!("0.0.0.0:{}", our_hop + 5101);

    let _ = transport.iface_manager().lock().await.spawn(
        TcpServer::new(our_address, transport.iface_manager()),
        TcpServer::spawn,
    );

    if our_hop > 0 {
        let connect_to = format!("127.0.0.1:{}", our_hop + 5100);
        let client_addr = transport.iface_manager().lock().await.spawn(
            TcpClient::new(connect_to),
            TcpClient::spawn,
        );

        let destination;
        if our_hop == last_hop {
            destination = transport.add_destination(
                last_hop_id,
                last_hop_name
            ).await;
        } else {
            let id = PrivateIdentity::new_from_rand(OsRng);
            let name = DestinationName::new(&format!("hop-{}", our_hop), "app");
            destination = transport.add_destination(id, name).await;
        }

        log::info!("Created destination {}", destination.lock().await.desc);

        let mut announce = destination
            .lock()
            .await
            .announce(OsRng, None)
            .unwrap();

        announce.transport = Some(transport_id);
        announce.header.header_type = HeaderType::Type2;
        transport.send_direct(client_addr, announce).await;
    }

    if our_hop == last_hop {
        let mut data_event = transport.received_data_events();
        let mut link_event = transport.in_link_events();

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    break;
                },

                event = data_event.recv() => {
                    if let Ok(event) = event {
                        if let Ok(text) = from_utf8(event.data.as_slice()) {
                            log::info!("Message received: {}", text);
                        } else {
                            log::info!("Broken message received (invalid utf8)");
                        }
                    }
                },

                result = link_event.recv() => {
                    match result {
                        Ok(event_data) => match event_data.event {
                            LinkEvent::Activated => {
                                log::info!("Inbound link {} established", event_data.id);
                            },
                            LinkEvent::Data(payload) => {
                                if let Ok(text) = from_utf8(payload.as_slice()) {
                                    log::info!("Message over link received: {}", text);
                                } else {
                                    log::info!("Broken message over link (invalid utf8)");
                                }
                            },
                            LinkEvent::Closed => {
                                log::info!("Link closed");
                            },
                            _ => {},
                        },
                        Err(error) => {
                            log::info!("Link error: {}", error);
                        }
                    }
                }
            }
        }

    } else {
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        let mut link = None;

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    break;
                },
                input = lines.next_line() => {
                    let message = match input {
                        Ok(m) => m.unwrap_or("foo".to_string()),
                        Err(e) => {
                            log::info!("Error reading from stdin: {}", e);
                            continue;
                        }
                    };

                    if link.is_none() && message == "link" {
                        log::info!("Requesting link to last hop");

                        link = Some(transport.link(last_hop_destination.desc).await);
                        continue;
                    }

                    if let Some(ref link) = link {
                        let link = link.lock().await;

                        if link.status() == LinkStatus::Active {
                            log::info!("Sending message over link: {}", &message);

                            let packet = link.data_packet(message.as_bytes()).unwrap();
                            transport.send_packet(packet).await;
                            continue;
                        }
                    }

                    log::info!("Sending message: {}", &message);

                    let packet = create_data_packet(&message, last_hop_address);
                    transport.outbound(&packet).await;
                }
            }
        }
    }

    log::info!("exit");
}
