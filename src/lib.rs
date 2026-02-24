//! A Rust implementation of the [Reticulum Python reference implementation](https://github.com/markqvist/reticulum),
//! the cryptography-based networking stack for building unstoppable
//! networks with LoRa, Packet Radio, WiFi and everything in between.
//!
//! Reticulum is the cryptography-based networking stack for building local
//! and wide-area networks with readily available hardware. It can operate
//! even with very high latency and extremely low bandwidth. Reticulum allows
//! you to build wide-area networks with off-the-shelf tools, and offers end-to-end
//! encryption and connectivity, initiator anonymity, autoconfiguring
//! cryptographically backed multi-hop transport, efficient addressing,
//! unforgeable delivery acknowledgements and more.
//! 
//! More Resources:
//!
//! * [Homepage](https://reticulum.network/)
//! * [Manual](https://reticulum.network/manual/index.html)
//! * [unsigned.io](https://unsigned.io/software/index.html)
//!
//! # A tour of this Reticulum implementation
//!
//! Reticlum consists of one main [`transport::Transport`] that can connect to other reticulum instances
//! via different kind of interfaces by connecting them with the [`iface::InterfaceManager`]:
//! * [`iface::tcp_client::TcpClient`]
//! * [`iface::tcp_server::TcpServer`]
//! * [`iface::udp::UdpInterface`]
//! * Kaonic
//!
//! The main instance can be used to send messages to [`destination::Destination`]s directly
//! or over [`destination::link::Link`]s. 
//! 
//! [`hash::AddressHash`] is used for adressing destinations and [`destination::link::LinkId`] for links.
//! 
//! [`Resources`] can be used to send arbitrary amounts of data
//! using a simple interface.
//!
//! ## Creating a Transport
//!
//! ```
//! # {
//! #[tokio::main]
//! async fn main() {
//!     let transport = Transport::new(TransportConfig::default());
//! }
//! # }
//! ```
//!
//! ## Connecting interfaces
//!
//! ```
//! # {
//! #[tokio::main]
//! async fn main() {
//!     let client_addr = transport.iface_manager()
//!         .lock().await
//!         .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);
//! }
//! # }
//! ```
//! 
//! ## Set up and announce destinations
//! 
//! Destinations are used as targets for messages or links. 
//! Destinations need to be announced to the network. 
//! 
//! ```
//! # {
//! use rand_core::OsRng;
//! #[tokio::main]
//! async fn main() {
//!     let id = PrivateIdentity::new_from_rand(OsRng);
//! 
//!     let destination = SingleInputDestination::new(id, DestinationName::new("example", "app"));
//! 
//!     transport.send_direct(client_addr, destination.announce(OsRng, None).unwrap()).await;
//! }
//! # }
//! ```
//!
//! ## Setting up links
//! 
//! Links should be used for prolonged bidirectional communication. 
//! Links are established by sending a link-request to the target
//! destination. After the response from the target the link can be used. 
//! 
//! ```
//! # {
//! #[tokio::main]
//! async fn main() {
//!     let target_destination: AddressHash;
//! 
//!     let mut link: Option<Link> = None;
//! 
//!     let announce_receiver = transport.recv_announces().await;
//!     while let Ok(announcement) = announce_reciver.recv.await {
//!         if accouncement.destination.lock().await.desc.address_hash == target_destination {
//!             // send link request to target destination
//!             link = Some(transport.link(announcement.destination.lock().await.desc).await);
//!             break;
//!         }
//!     }
//!     let link_id = link.lock().await.id().clone();
//! 
//!     // look for the response to the link request
//!     // This is only neccessary if you want to track 
//!     // when the link becomes active.
//!     let link_event_receiver = transport.link_in_events();
//!     loop {
//!         let link_event_data = link_event_receiver.recv().await.unwrap();
//!         if link_event_data.id = link_id {
//!             match link_event_data.event {
//!                 LinkEvent::Activated => {
//!                     // now this link can be used
//!                 }
//!                 _ => {}
//!             }
//!         }
//!     }
//! }
//! # }
//! ```
//! 
//! ## Send data
//! 
//! Create a data packet with the link and send that packet. 
//! 
//! ```
//! # {
//! #[tokio::main]
//! async fn main() {
//!     let link = transport.find_out_link(&link_id).await.unwrap();
//!     let link = link.lock().await;
//!     let packet = link.data_packet(&bytes).unwrap();
//!     transport.send_packet(packet).await;
//! }
//! # }
//! ```
//! 
//! ## Receive data
//! 
//! Look for incoming data events matching a link id. 
//! 
//! ```
//! # {
//! #[tokio::main]
//! async fn main() {
//!     let in_link_events = transport.link_in_events();
//!     loop {
//!         let event = in_link_events.recv().await.unwrap();
//!         if event.id = link_id {
//!             match event.event {
//!                 LinkEvent::Data(payload) => {
//!                     let bytes: &[u8] = payload.as_slice();
//!                     // use data
//!                 }
//!             }
//!         }
//!     }
//! }
//! # }
//! ```
//! 

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod buffer;
pub mod crypt;
pub mod destination;
pub mod error;
pub mod hash;
pub mod identity;
pub mod iface;
pub mod packet;
pub mod transport;

mod serde;
mod utils;
