use rand_core::OsRng;
use reticulum::{
    channel::{self, Message, CHANNEL_MDU},
    destination::link::LinkEvent,
    destination::DestinationName,
    error::RnsError,
    identity::PrivateIdentity,
    iface::udp::UdpInterface,
    packet::PACKET_MDU,
    transport::{Transport, TransportConfig},
};
use std::sync::Once;

static INIT: Once = Once::new();

#[derive(Clone)]
pub struct ChannelMessage(pub Vec<u8>);

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
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init()
    });
}

async fn build_transport(
    name: &str,
    bind_addr: &str,
    forward_addr: &str,
) -> (Transport, PrivateIdentity) {
    let id = PrivateIdentity::new_from_rand(OsRng);
    let transport = Transport::new(TransportConfig::new(name, &id));

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

    let (transport_a, id_a) = build_transport("a", "127.0.0.1:18081", "127.0.0.1:18082").await;
    let (transport_b, _) = build_transport("b", "127.0.0.1:18082", "127.0.0.1:18081").await;

    let mut in_link_events = transport_a.in_link_events();
    let mut out_link_events = transport_b.out_link_events();
    let mut recv_announces = transport_b.recv_announces().await;
    let dest = transport_a
        .add_destination(
            id_a.clone(),
            DestinationName::new("test", "channels.send_multiple"),
        )
        .await;
    transport_a.send_announce(&dest, None).await;
    let announce = recv_announces.recv().await.unwrap();
    // initiate the link from transport B and upgrade to channel
    let link = transport_b
        .link(announce.destination.lock().await.desc)
        .await;
    let (_channel_endpoint_b, _receiver_b) = transport_b
        .mk_channel::<ChannelMessage>(link)
        .await
        .unwrap();
    // wait for link activated event on transport A and upgrade to channel
    let event = in_link_events.recv().await.unwrap();
    let (channel_endpoint_a, _receiver_a) = match event.event {
        LinkEvent::Activated => {
            let link = transport_a.find_in_link(&event.id).await.unwrap();
            transport_a
                .mk_channel::<ChannelMessage>(link)
                .await
                .unwrap()
        }
        _ => unreachable!(),
    };
    //let sub_a = channel_endpoint_a.subscribe();
    assert!(matches!(
        out_link_events.recv().await.unwrap().event,
        LinkEvent::Activated
    ));
    // send message A -> B and watch message delivery
    let message = ChannelMessage(b"test1".to_vec());
    let hash = channel_endpoint_a.send(&message).await.unwrap();
    assert!(channel_endpoint_a
        .watch_message_delivery(hash)
        .await
        .unwrap()
        .recv()
        .await
        .unwrap());
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TypedMessage {
    message_type: u16,
    data: Vec<u8>,
}

impl Message for TypedMessage {
    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError> {
        if message_type == 0x0001 {
            Ok(Self {
                message_type,
                data: packed.to_vec(),
            })
        } else {
            Err(RnsError::ChannelUnknownMessageType)
        }
    }

    fn pack(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn message_type(&self) -> u16 {
        self.message_type
    }
}

/// Link MDU minus the 6-byte envelope is enforced, and a user type plus
/// system type 0xff00 can be registered on the same channel.
#[tokio::test]
async fn channel_mdu_and_registered_types() {
    setup();

    let id_a = PrivateIdentity::new_from_rand(OsRng);
    let id_b = PrivateIdentity::new_from_rand(OsRng);
    let transport_a =
        Transport::new(TransportConfig::new("a", &id_a).set_link_mtu_discovery(false));
    let transport_b =
        Transport::new(TransportConfig::new("b", &id_b).set_link_mtu_discovery(false));
    transport_a.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:8093", Some("127.0.0.1:8094"), false),
        UdpInterface::spawn,
    );
    transport_b.iface_manager().lock().await.spawn(
        UdpInterface::new("127.0.0.1:8094", Some("127.0.0.1:8093"), false),
        UdpInterface::spawn,
    );

    let mut in_link_events = transport_a.in_link_events();
    let mut out_link_events = transport_b.out_link_events();
    let mut recv_announces = transport_b.recv_announces().await;
    let dest = transport_a
        .add_destination(id_a, DestinationName::new("test", "channels.mdu"))
        .await;
    transport_a.send_announce(&dest, None).await;
    let announce = recv_announces.recv().await.unwrap();

    let link = transport_b
        .link(announce.destination.lock().await.desc)
        .await;
    let (channel_b, mut incoming_b) = transport_b.mk_channel::<TypedMessage>(link).await.unwrap();

    let event = in_link_events.recv().await.unwrap();
    let (channel_a, _incoming_a) = match event.event {
        LinkEvent::Activated => {
            let link = transport_a.find_in_link(&event.id).await.unwrap();
            transport_a.mk_channel::<TypedMessage>(link).await.unwrap()
        }
        _ => unreachable!(),
    };
    assert!(matches!(
        out_link_events.recv().await.unwrap().event,
        LinkEvent::Activated
    ));

    let link_mdu = channel_a.link.lock().await.mdu();
    assert_eq!(channel_a.mdu().await, link_mdu - 6);
    assert_eq!(channel_a.mdu().await, CHANNEL_MDU);
    assert!(channel_a.mdu().await < PACKET_MDU);
    assert_eq!(channel_a.window().await, 2);

    assert_eq!(
        channel_b.register_message_type(0xff00, false).err(),
        Some(RnsError::ChannelError)
    );
    let mut system_rx = channel_b.register_message_type(0xff00, true).unwrap();

    let oversize = TypedMessage {
        message_type: 0x0001,
        data: vec![0xab; channel_a.mdu().await + 1],
    };
    assert_eq!(
        channel_a.send(&oversize).await,
        Err(RnsError::ChannelMessageTooBig)
    );

    let exact = TypedMessage {
        message_type: 0x0001,
        data: vec![0xcd; channel_a.mdu().await],
    };
    channel_a.send(&exact).await.unwrap();

    let system = TypedMessage {
        message_type: 0xff00,
        data: b"buf".to_vec(),
    };
    channel_a.send(&system).await.unwrap();

    let got = incoming_b.recv().await.unwrap();
    assert_eq!(got.data.len(), CHANNEL_MDU);
    assert!(got.data.iter().all(|byte| *byte == 0xcd));

    let raw = system_rx.recv().await.unwrap();
    assert_eq!(raw, b"buf");
}
