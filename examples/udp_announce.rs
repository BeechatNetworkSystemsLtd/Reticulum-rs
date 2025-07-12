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

use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use reticulum::packet::{self, Packet};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> UDP APP <<<");

    let id = PrivateIdentity::new_from_rand(OsRng);
    let destination = SingleInputDestination::new(id.clone(), DestinationName::new("example", "app"));
    let transport = Transport::new(TransportConfig::new("server", &id, true));

    let _ = transport.iface_manager().lock().await.spawn(
        UdpInterface::new("0.0.0.0:4243", Some("127.0.0.1:4242")),
        UdpInterface::spawn);

    let dest = std::sync::Arc::new(tokio::sync::Mutex::new (destination));

    let mut announce_recv = transport.recv_announces().await;

    loop {
        while let Ok(announce) = announce_recv.try_recv() {
            let destination = announce.destination.lock().await;
            //println!("ANNOUNCE: {}", destination.desc.address_hash);
            let packet = Packet {
                header: packet::Header {
                    ifac_flag: packet::IfacFlag::Open,
                    header_type: packet::HeaderType::Type1,
                    propagation_type: packet::PropagationType::Transport,
                    destination_type: packet::DestinationType::Single,
                    packet_type: packet::PacketType::Data,
                    hops: 0
                },
                ifac: None,
                destination: destination.desc.address_hash,
                transport: None,
                context: packet::PacketContext::None,
                data: packet::PacketDataBuffer::new_from_slice(b"foo")
            };
            transport.send_packet(packet).await;
        }
        transport
            .send_announce(&dest, None)
            .await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    //log::info!("exit");
}
