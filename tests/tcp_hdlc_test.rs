use std::sync::Once;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::{
    identity::PrivateIdentity,
    iface::{tcp_client::TcpClient, tcp_server::TcpServer},
    packet::{Packet, PACKET_MDU},
    transport::{Transport, TransportConfig},
};

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init()
    });
}

fn free_local_addr() -> String {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

async fn build_transport(name: &str, server_addr: &str, client_addr: &[&str]) -> Transport {
    let transport = Transport::new(TransportConfig::new(
        name,
        &PrivateIdentity::new_from_rand(OsRng),
    ));

    transport.iface_manager().lock().await.spawn(
        TcpServer::new(server_addr, transport.iface_manager()),
        TcpServer::spawn,
    );

    for &addr in client_addr {
        transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(addr), TcpClient::spawn);
    }

    log::info!("test: transport {} created", name);

    transport
}

#[tokio::test]
async fn escape_heavy_packet_roundtrips_hdlc_window() {
    setup();

    let server_addr_a = free_local_addr();
    let server_addr_b = free_local_addr();

    let transport_a = build_transport("a", &server_addr_a, &[]).await;
    let transport_b = build_transport("b", &server_addr_b, &[&server_addr_a]).await;

    // Subscribe before sending so the broadcast is not missed.
    let mut iface_rx = transport_b.iface_rx();

    // A full data buffer of HDLC escape-sensitive bytes (0x7e flag, 0x7d
    // escape) doubles on the wire: the frame is over 4 KiB and used to
    // overflow the receive shift window, losing its opening delimiter.
    let mut payload = Vec::with_capacity(PACKET_MDU);
    for i in 0..PACKET_MDU {
        payload.push(if i % 2 == 0 { 0x7e } else { 0x7d });
    }

    let mut packet = Packet::default();
    packet.data.write(&payload).unwrap();

    // A broadcast only reaches interfaces registered in the manager;
    // A's spawned peer appears once its server accepts B's dial. A send
    // before that is dropped silently, so wait on the published online
    // flag (same contract as the i2p/local iface tests).
    async fn up(transport: &Transport) -> bool {
        transport
            .interface_stats()
            .await
            .iter()
            .any(|stat| stat.kind == "TcpClient" && stat.online)
    }
    let link_ready = async {
        for _ in 0..200 {
            if up(&transport_a).await && up(&transport_b).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(link_ready, "TCP link did not come online");

    transport_a.send_packet(packet).await;

    let message = tokio::time::timeout(Duration::from_secs(5), iface_rx.recv())
        .await
        .expect("escape-heavy HDLC frame was not received")
        .unwrap();

    assert_eq!(message.packet.data.as_slice(), payload.as_slice());
}

#[tokio::test]
async fn unavailable_tcp_client_does_not_block_server_traffic() {
    setup();

    let server_addr_a = free_local_addr();
    let server_addr_b = free_local_addr();
    let unavailable_addr = free_local_addr();

    let transport_a = build_transport("a", &server_addr_a, &[&unavailable_addr]).await;
    let transport_b = build_transport("b", &server_addr_b, &[&server_addr_a]).await;

    tokio::time::sleep(Duration::from_secs(1)).await;
    // Subscribe before sending, or B may receive everything first.
    let mut iface_rx = transport_b.iface_rx();

    let sender = tokio::spawn(async move {
        for counter in 0..3u8 {
            let mut packet = Packet::default();
            packet.data.write(&[counter]).unwrap();
            transport_a.send_packet(packet).await;
        }
    });

    tokio::time::timeout(Duration::from_secs(2), sender)
        .await
        .expect("send_packet stalled behind an unavailable TCP client")
        .unwrap();

    let mut received = 0usize;

    tokio::time::timeout(Duration::from_secs(2), async {
        while received < 3 {
            iface_rx.recv().await.unwrap();
            received += 1;
        }
    })
    .await
    .expect("TCP server traffic stopped after another TCP client failed to connect");
}
