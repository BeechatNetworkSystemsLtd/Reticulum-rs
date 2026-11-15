//! I2P interface end-to-end against a mock SAM bridge (Phase 5.6):
//! a connectable server session plus an initiator peer exchange
//! announces through SAMv3 SESSION/STREAM commands and HDLC framing.

#![cfg(feature = "iface-i2p")]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::i2p::{I2pPeer, I2pServer, SamSession, HW_MTU};
use reticulum::transport::TransportConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Sessions created on the mock bridge.
type Sessions = Arc<tokio::sync::Mutex<HashMap<String, String>>>;
/// Connectors waiting for a parked accepter, by destination.
type Connectors = Arc<tokio::sync::Mutex<HashMap<String, mpsc::Sender<TcpStream>>>>;

fn fake_destination(seed: &str) -> String {
    // Unique, valid-length I2P destination material.
    let seed_sum: usize = seed.bytes().map(|b| b as usize).sum();
    let mut bytes = Vec::new();
    for i in 0..516usize {
        let c = b'A' + ((i * 7 + seed_sum) % 26) as u8;
        bytes.push(c);
    }
    String::from_utf8(bytes).unwrap()
}

async fn read_line(stream: &mut TcpStream) -> Option<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&line).trim().to_string())
}

/// A minimal SAMv3 bridge: sessions by id, and STREAM CONNECT spliced to
/// a parked STREAM ACCEPT for the target destination.
async fn sam_bridge(port: u16, sessions: Sessions) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();

    let connectors: Connectors = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };

        let sessions = sessions.clone();
        let connectors = connectors.clone();
        tokio::spawn(async move {
            let mut socket = socket;
            let mut control_session = None;

            loop {
                let Some(line) = read_line(&mut socket).await else {
                    if let Some(id) = &control_session {
                        sessions.lock().await.remove(id);
                    }
                    return;
                };

                let mut parts = line.split_whitespace();
                match (parts.next(), parts.next()) {
                    (Some("HELLO"), _) => {
                        if socket
                            .write_all(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }

                    (Some("SESSION"), Some("CREATE")) => {
                        let mut id = String::new();
                        for token in parts {
                            if let Some(value) = token.strip_prefix("ID=") {
                                id = value.to_string();
                            }
                        }

                        let destination = fake_destination(&id);
                        sessions
                            .lock()
                            .await
                            .insert(id.clone(), destination.clone());
                        control_session = Some(id);

                        let reply = format!("SESSION STATUS RESULT=OK DESTINATION={destination}\n");
                        if socket.write_all(reply.as_bytes()).await.is_err() {
                            return;
                        }
                    }

                    (Some("STREAM"), Some("ACCEPT")) => {
                        let mut id = String::new();
                        for token in parts {
                            if let Some(value) = token.strip_prefix("ID=") {
                                id = value.to_string();
                            }
                        }

                        // Wait for a connector targeting this session's
                        // destination.
                        let (tx, mut rx) = mpsc::channel::<TcpStream>(1);
                        {
                            let sessions = sessions.lock().await;
                            let destination = sessions.get(&id).cloned().unwrap_or_default();
                            drop(sessions);
                            connectors.lock().await.insert(destination, tx);
                        }

                        let Some(mut connector) = rx.recv().await else {
                            let _ = socket.write_all(b"STREAM STATUS RESULT=I2P_ERROR\n").await;
                            return;
                        };

                        // Reply to the accepter, then splice the streams.
                        if socket
                            .write_all(b"STREAM STATUS RESULT=OK DESTINATION=CLIENT\n")
                            .await
                            .is_err()
                        {
                            return;
                        }

                        // Let the connector know it is connected.
                        let _ = connector.write_all(b"STREAM STATUS RESULT=OK\n").await;

                        // Splice accepter <-> connector.
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut connector).await;
                        return;
                    }

                    (Some("STREAM"), Some("CONNECT")) => {
                        let mut destination = String::new();
                        for token in parts {
                            if let Some(value) = token.strip_prefix("DESTINATION=") {
                                destination = value.to_string();
                            }
                        }

                        let accepter = connectors.lock().await.remove(&destination);
                        match accepter {
                            Some(accepter) => {
                                // Reply OK to the connector first: the
                                // accepter task performs the splice once it
                                // receives this socket.
                                if socket
                                    .write_all(b"STREAM STATUS RESULT=OK\n")
                                    .await
                                    .is_err()
                                {
                                    return;
                                }

                                let _ = accepter.send(socket).await;
                                return;
                            }
                            None => {
                                let _ = socket
                                    .write_all(b"STREAM STATUS RESULT=CANT_REACH_PEER\n")
                                    .await;
                                return;
                            }
                        }
                    }

                    _ => {
                        let _ = socket.write_all(b"HELLO REPLY RESULT=NOVERSION\n").await;
                        return;
                    }
                }
            }
        });
    }
}

#[tokio::test]
async fn i2p_session_fails_without_bridge() {
    assert!(SamSession::create("127.0.0.1:49959", "test").await.is_err());
}

#[tokio::test]
async fn sam_session_keeps_its_control_socket_open_until_drop() {
    const SAM_PORT: u16 = 49960;
    let sessions: Sessions = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    tokio::spawn(sam_bridge(SAM_PORT, sessions.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let session = SamSession::create(&format!("127.0.0.1:{SAM_PORT}"), "lifetime")
        .await
        .expect("session creation");
    assert!(sessions.lock().await.contains_key("lifetime"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        sessions.lock().await.contains_key("lifetime"),
        "the live session must retain its control connection"
    );

    drop(session);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while sessions.lock().await.contains_key("lifetime") && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!sessions.lock().await.contains_key("lifetime"));
}

#[tokio::test]
async fn i2p_end_to_end_over_mock_sam() {
    const SAM_PORT: u16 = 49961;
    let sam_addr = format!("127.0.0.1:{SAM_PORT}");

    let sessions: Sessions = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    tokio::spawn(sam_bridge(SAM_PORT, sessions));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Node A: connectable I2P server.
    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let a = Arc::new(TransportConfig::new("i2p-a", &identity_a).build());

    let server_address = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            I2pServer::new(
                sam_addr.clone(),
                String::from("session-a"),
                a.iface_manager(),
            ),
            I2pServer::spawn,
        )
    };

    // The published destination is whatever the bridge assigned to
    // session-a.
    let mut server_destination = String::new();
    for _ in 0..200 {
        let stats = a.interface_stats().await;
        if stats
            .iter()
            .any(|stat| stat.address == server_address && stat.online)
        {
            server_destination = fake_destination("session-a");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !server_destination.is_empty(),
        "server session must come online"
    );

    // Node B: initiator peer targeting A's destination.
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let b = Arc::new(TransportConfig::new("i2p-b", &identity_b).build());

    let peer_address = {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            I2pPeer::new_initiator(&sam_addr, "session-b", &server_destination)
                .with_manager(b.iface_manager()),
            I2pPeer::spawn,
        )
    };

    // B announces a destination: A must learn the path through the
    // spliced SAM stream and HDLC framing.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("i2p", "test"),
    );
    let dest_hash = destination.desc.address_hash;
    let dest = Arc::new(tokio::sync::Mutex::new(destination));

    // Wait for the peer tunnel to be online before announcing.
    let online = async {
        for _ in 0..200 {
            let stats = b.interface_stats().await;
            if stats
                .iter()
                .any(|stat| stat.address == peer_address && stat.online)
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online, "peer tunnel must come online");

    b.send_announce(&dest, None).await;

    let learned = async {
        for _ in 0..200 {
            if a.has_path(&dest_hash).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(learned, "server must learn the announced path over I2P");

    let _ = HW_MTU;
}
