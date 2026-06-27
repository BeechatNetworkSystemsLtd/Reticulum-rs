use std::sync::{Arc, Once};
use rand_core::OsRng;
use reticulum::{
    channel::{self, Channel},
    destination::DestinationName,
    destination::link::LinkEvent,
    error::RnsError,
    identity::PrivateIdentity,
    iface::udp::UdpInterface,
    transport::{Transport, TransportConfig},
};
use tokio::sync::Mutex;

static INIT: Once = Once::new();

#[derive(Clone)]
pub struct ChannelMessage(pub Vec <u8>);

impl channel::Message for ChannelMessage {
  fn unpack(packed: &[u8], _message_type: u16) -> Result<Self, RnsError> {
    Ok(ChannelMessage(packed.to_vec()))
  }

  fn pack(&self) -> Vec<u8> {
    self.0.clone()
  }

  fn message_type(&self) -> u16 {
    0x00
  }
}

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("trace")
        ).init()
    });
}

async fn build_transport(name: &str, bind_addr: &str, forward_addr: &str)
    -> (Transport, PrivateIdentity)
{
    let id = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(TransportConfig::new(
        name,
        &id,
        true,
    ));

    transport.iface_manager().lock().await.spawn(
        UdpInterface::new(bind_addr, Some(forward_addr), false),
        UdpInterface::spawn,
    );

    log::info!("test: transport {} created", name);

    (transport, id)
}

#[tokio::test]
async fn channel_send() {
    setup();

    let (mut transport_a, id_a) = build_transport("a", "127.0.0.1:8081", "127.0.0.1:8082").await;
    let (transport_b, _) = build_transport("b", "127.0.0.1:8082", "127.0.0.1:8081").await;

    let mut in_link_events = transport_a.in_link_events();
    let mut out_link_events = transport_b.out_link_events();
    let mut recv_announces = transport_b.recv_announces().await;
    let dest = transport_a.add_destination(
        id_a.clone(),
        DestinationName::new("test", "channels.send_multiple")).await;
    transport_a.send_announce(&dest, None).await;
    let transport_a = Arc::new(Mutex::new(transport_a));
    let announce = recv_announces.recv().await.unwrap();
    // initiate the link from transport B and upgrade to channel
    let link = transport_b.link(announce.destination.lock().await.desc).await;
    let transport_b = Arc::new(Mutex::new(transport_b));
    let (_channel_endpoint_b, _receiver_b) = Channel::<ChannelMessage>::new(link, &transport_b)
        .await.unwrap();
    // wait for link activated event on transport A and upgrade to channel
    let event = in_link_events.recv().await.unwrap();
    let (channel_endpoint_a, _receiver_a) = match event.event {
        LinkEvent::Activated => {
            let link = transport_a.lock().await.find_in_link(&event.id).await.unwrap();
            Channel::<ChannelMessage>::new(link, &transport_a).await.unwrap()
        }
        _ => unreachable!()
    };
    //let sub_a = channel_endpoint_a.subscribe();
    assert!(matches!(out_link_events.recv().await.unwrap().event, LinkEvent::Activated));
    // send message A -> B and watch message delivery
    let message = ChannelMessage(b"test1".to_vec());
    let hash = channel_endpoint_a.send(&message).await.unwrap();
    assert!(channel_endpoint_a.watch_message_delivery(hash).await.unwrap().recv().await.unwrap());
}
