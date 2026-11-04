//! Remote management and probe destinations over a UDP interface pair
//! (Phase 6.7).

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::destination::SingleInputDestination;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::udp::UdpInterface;
use reticulum::iface::{TxMessage, TxMessageType};
use reticulum::packet::{
    DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketDataBuffer,
    PacketType, PropagationType,
};
use reticulum::transport::{Transport, TransportConfig};

async fn udp_pair(
    name: &str,
    port_a: u16,
    port_b: u16,
    identity_a: &PrivateIdentity,
    identity_b: &PrivateIdentity,
) -> (Transport, Transport) {
    let a = TransportConfig::new(format!("mgmt-{name}-a"), identity_a).build();
    let b = TransportConfig::new(format!("mgmt-{name}-b"), identity_b).build();

    {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_a}"),
                Some(format!("127.0.0.1:{port_b}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }
    {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            UdpInterface::new(
                format!("127.0.0.1:{port_b}"),
                Some(format!("127.0.0.1:{port_a}")),
                true,
            ),
            UdpInterface::spawn,
        );
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    (a, b)
}

#[tokio::test]
async fn probe_destination_proves_packets() {
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let (client, server) = udp_pair("probe", 4412, 4413, &identity_a, &identity_b).await;

    let probe = server.enable_probe_destination().await;
    let mut announces = client.recv_announces().await;
    server.send_announce(&probe, None).await;
    let announce = tokio::time::timeout(Duration::from_secs(10), announces.recv())
        .await
        .expect("announce timeout")
        .expect("announce channel");
    let probe_hash = announce.destination.lock().await.desc.address_hash;

    // Send an encrypted SINGLE-destination probe packet: the server must
    // prove it and the receipt must validate.
    let mut receipts = client.receipt_events();
    let payload: Vec<u8> = (0..64u32).map(|i| (i % 251) as u8).collect();
    client
        .send_to_destination(&probe_hash, &payload)
        .await
        .expect("send probe packet");

    let proved = tokio::time::timeout(Duration::from_secs(10), receipts.recv())
        .await
        .expect("proof timeout: probe destination must prove received packets");
    let _ = proved;
}

#[tokio::test]
async fn remote_management_status_and_path() {
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let (client, server) = udp_pair("mgmt", 4422, 4423, &identity_a, &identity_b).await;

    let management = server.enable_remote_management().await;
    let mut announces = client.recv_announces().await;
    server.send_announce(&management, None).await;
    let announce = tokio::time::timeout(Duration::from_secs(10), announces.recv())
        .await
        .expect("announce timeout")
        .expect("announce channel");

    let link = client.link(announce.destination.lock().await.desc).await;

    // Wait for the link to become active.
    let mut out_link_events = client.out_link_events();
    let active = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Ok(_event)) = tokio::time::timeout_at(deadline, out_link_events.recv()).await
            {
                return true;
            }
        }
        false
    }
    .await;
    assert!(active, "link to the management destination must activate");

    // Identify over the link so the server can apply the allow list.
    let identify_packet = {
        let link_guard = link.lock().await;
        link_guard.identify(&identity_a).expect("identify packet")
    };
    client.send_packet(identify_packet).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Management is deny-all until the identity is explicitly configured.
    let denied = client
        .request(&link, "/status", &pack_status_request())
        .await
        .expect("send denied status request");
    assert!(client
        .await_request_response(denied, Duration::from_millis(500))
        .await
        .is_none());

    server
        .remote_management_allow(*identity_a.address_hash())
        .await;

    // /status
    let rid = client
        .request(&link, "/status", &pack_status_request())
        .await
        .expect("send status request");
    let response = client
        .await_request_response(rid, Duration::from_secs(10))
        .await
        .expect("status response");
    assert!(response.len() > 4, "status response must be a msgpack list");

    // /path table: the client announces a destination, the server learns
    // the path, then the client lists its own path.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("mgmt", "path"),
    );
    let dest_hash = destination.desc.address_hash;
    client
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    // Give the server time to learn the path and refresh its snapshot.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let rid = client
        .request(&link, "/path", &pack_path_request(dest_hash.as_slice()))
        .await
        .expect("send path request");
    let response = client
        .await_request_response(rid, Duration::from_secs(10))
        .await
        .expect("path response");

    // The response lists the announced path.
    let found = response
        .windows(dest_hash.as_slice().len())
        .any(|window| window == dest_hash.as_slice());
    assert!(found, "path table response must contain the announced path");
}

#[tokio::test]
async fn drop_announce_queues_clears_queued_announces() {
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let (a, _) = udp_pair("dropq", 47030, 47031, &identity_a, &identity_b).await;
    let iface = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.stats().first().map(|stat| stat.address).unwrap()
    };
    {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager.set_iface_bitrate(&iface, 1200);
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Box::new(forwarded_announce(2)),
            })
            .await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet: Box::new(forwarded_announce(3)),
            })
            .await;
    }
    let queued = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .with_control(&iface, |control| control.queued_announces_len())
            .unwrap_or(0)
    };
    assert!(queued >= 1, "announce cap must queue a forwarded announce");

    a.drop_announce_queues().await;
    let left = {
        let manager = a.iface_manager();
        let manager = manager.lock().await;
        manager
            .with_control(&iface, |control| control.queued_announces_len())
            .unwrap_or(0)
    };
    assert_eq!(
        left, 0,
        "drop_announce_queues must clear every announce queue"
    );
}

fn forwarded_announce(hops: u8) -> Packet {
    let mut data = PacketDataBuffer::new();
    data.safe_write(&[1u8; 32]);
    data.safe_write(&[2u8; 32]);
    data.safe_write(&[3u8; 10]);
    data.safe_write(&[0u8; 5]);
    data.safe_write(&42u64.to_be_bytes()[3..8]);
    data.safe_write(&[4u8; 64]);
    Packet {
        header: Header {
            ifac_flag: IfacFlag::Open,
            context_flag: false,
            header_type: HeaderType::Type2,
            propagation_type: PropagationType::Broadcast,
            destination_type: DestinationType::Single,
            packet_type: PacketType::Announce,
            hops,
        },
        ifac: None,
        destination: AddressHash::new_from_rand(OsRng),
        transport: None,
        context: PacketContext::None,
        data,
    }
}

fn pack_status_request() -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_array_len(&mut out, 1).unwrap();
    rmp::encode::write_bool(&mut out, true).unwrap();
    out
}

fn pack_path_request(destination: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rmp::encode::write_array_len(&mut out, 3).unwrap();
    rmp::encode::write_str(&mut out, "table").unwrap();
    rmp::encode::write_bin(&mut out, destination).unwrap();
    rmp::encode::write_u64(&mut out, 16).unwrap();
    out
}
