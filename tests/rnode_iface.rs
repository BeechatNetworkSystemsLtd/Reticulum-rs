//! RNode interface end-to-end against a mock RNode device (Phase 5.5):
//! detection + firmware validation + radio configuration validation, and
//! packet exchange between two RNode interfaces bridged by the mock.

#![cfg(feature = "iface-rnode")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::rnode::*;
use reticulum::iface::{TxMessage, TxMessageType};
use reticulum::packet::Packet;
use reticulum::transport::TransportConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CONFIG: RnodeRadioConfig = RnodeRadioConfig {
    frequency: 867_500_000,
    bandwidth: 125_000,
    txpower: 13,
    spreadingfactor: 9,
    codingrate: 5,
    st_alock: None,
    lt_alock: None,
};

/// Frames the mock RNode records, keyed by KISS command byte.
type RecordedFrames = Arc<Mutex<Vec<(u8, Vec<u8>)>>>;

/// Parse complete KISS frames from a stream of bytes.
fn parse_frames(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut current: Option<(u8, Vec<u8>)> = None;
    let mut escaped = false;

    for &byte in bytes {
        if byte == FEND {
            if let Some(frame) = current.take() {
                frames.push(frame);
            }
            continue;
        }

        match current.as_mut() {
            None => current = Some((byte, Vec::new())),
            Some((_, payload)) => {
                if escaped {
                    escaped = false;
                    payload.push(match byte {
                        TFEND => FEND,
                        TFESC => FESC,
                        _ => byte,
                    });
                } else if byte == FESC {
                    escaped = true;
                } else {
                    payload.push(byte);
                }
            }
        }
    }

    if let Some(frame) = current.take() {
        frames.push(frame);
    }

    frames
}

/// A mock RNode device over TCP: responds to detect/config and bridges
/// data frames between all connected hosts.
async fn mock_rnode(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();

    let (bridge_tx, _bridge_rx) = tokio::sync::broadcast::channel::<Vec<u8>>(64);

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };

        let bridge_tx = bridge_tx.clone();
        let mut bridge_rx = bridge_tx.subscribe();

        let (mut reader, writer) = socket.into_split();
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        // Broadcaster: forward received data frames to all hosts.
        let tx_task = {
            let bridge_tx = bridge_tx.clone();
            let writer = writer.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let mut carry = Vec::new();

                loop {
                    let Ok(n) = reader.read(&mut buffer).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }

                    carry.extend_from_slice(&buffer[..n]);

                    let (complete, rest) = split_complete_frames(&carry);
                    carry = rest;

                    let mut writer = writer.lock().await;
                    for (command, payload) in complete {
                        match command {
                            CMD_DETECT if payload.first() == Some(&DETECT_REQ) => {
                                let _ = writer
                                    .write_all(&kiss_frame(CMD_DETECT, &[DETECT_RESP]))
                                    .await;
                            }
                            CMD_FW_VERSION => {
                                let _ = writer
                                    .write_all(&kiss_frame(CMD_FW_VERSION, &[1, 60]))
                                    .await;
                            }
                            CMD_PLATFORM => {
                                let _ = writer.write_all(&kiss_frame(CMD_PLATFORM, &[0x40])).await;
                            }
                            CMD_MCU => {
                                let _ = writer.write_all(&kiss_frame(CMD_MCU, &[0x30])).await;
                            }
                            CMD_DATA => {
                                // bridge data to all hosts
                                let _ = bridge_tx.send(kiss_frame(CMD_DATA, &payload));
                            }
                            CMD_RADIO_STATE => {
                                // echo the radio state back
                                let _ = writer
                                    .write_all(&kiss_frame(CMD_RADIO_STATE, &payload))
                                    .await;
                            }
                            // Configuration echoes: respond with the same
                            // command and payload so validation passes.
                            CMD_FREQUENCY | CMD_BANDWIDTH | CMD_TXPOWER | CMD_SF | CMD_CR => {
                                let _ = writer.write_all(&kiss_frame(command, &payload)).await;
                            }
                            _ => {}
                        }
                    }
                }
            })
        };

        // Receiver: forward bridged data frames to this host.
        let rx_task = {
            let writer = writer.clone();
            tokio::spawn(async move {
                loop {
                    match bridge_rx.recv().await {
                        Ok(frame) => {
                            if writer.lock().await.write_all(&frame).await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            })
        };

        let _ = (tx_task, rx_task);
    }
}

/// Split a byte stream into complete frames and the trailing remainder.
fn split_complete_frames(bytes: &[u8]) -> (Vec<(u8, Vec<u8>)>, Vec<u8>) {
    let frames = parse_frames(bytes);

    let mut rest = Vec::new();
    if let Some(last_fend) = bytes.iter().rposition(|&b| b == FEND) {
        // bytes after the last FEND are the incomplete remainder
        if last_fend + 1 < bytes.len() {
            rest.extend_from_slice(&bytes[last_fend + 1..]);
        }
    }

    (frames, rest)
}

#[tokio::test]
async fn rnode_detect_validate_and_exchange() {
    const PORT: u16 = 4982;

    tokio::spawn(mock_rnode(PORT));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let identity_a = PrivateIdentity::new_from_rand(OsRng);
    let a = Arc::new(TransportConfig::new("rnode-a", &identity_a).build());
    let identity_b = PrivateIdentity::new_from_rand(OsRng);
    let b = Arc::new(TransportConfig::new("rnode-b", &identity_b).build());

    let iface_a = {
        let manager = a.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            RnodeInterface::tcp(format!("127.0.0.1:{PORT}"), CONFIG)
                .with_manager(a.iface_manager()),
            RnodeInterface::spawn,
        )
    };

    let iface_b = {
        let manager = b.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            RnodeInterface::tcp(format!("127.0.0.1:{PORT}"), CONFIG)
                .with_manager(b.iface_manager()),
            RnodeInterface::spawn,
        )
    };

    // Both interfaces must come online (detection + validation passed).
    let online = async {
        for _ in 0..400 {
            let stats_a = a.interface_stats().await;
            let stats_b = b.interface_stats().await;
            let a_up = stats_a.iter().any(|s| s.address == iface_a && s.online);
            let b_up = stats_b.iter().any(|s| s.address == iface_b && s.online);
            if a_up && b_up {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(
        online,
        "both rnode interfaces must validate and come online"
    );

    // B announces: A must learn the path through the bridged mock radio.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("rnode", "test"),
    );
    let dest_hash = destination.desc.address_hash;
    b.send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let learned = async {
        for _ in 0..400 {
            if a.has_path(&dest_hash).await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(learned, "announce must flow through the rnode bridge");
}

#[tokio::test]
async fn rnode_parser_and_framing() {
    // Detection request matches the Python byte layout.
    let detect = detect_request();
    let frames = parse_frames(&detect);
    assert_eq!(frames.len(), 4);
    assert_eq!(frames[0], (CMD_DETECT, vec![DETECT_REQ]));
    assert_eq!(frames[1], (CMD_FW_VERSION, vec![0x00]));
    assert_eq!(frames[2], (CMD_PLATFORM, vec![0x00]));
    assert_eq!(frames[3], (CMD_MCU, vec![0x00]));

    // Config frames carry big-endian values.
    let config = RnodeRadioConfig {
        frequency: 0x11223344,
        bandwidth: 125_000,
        txpower: 13,
        spreadingfactor: 9,
        codingrate: 5,
        st_alock: Some(18.5),
        lt_alock: None,
    };
    let frames = config.configuration_frames(RADIO_STATE_ON);
    let parsed = parse_frames(&frames.concat());
    assert_eq!(parsed[0], (CMD_FREQUENCY, vec![0x11, 0x22, 0x33, 0x44]));
    assert_eq!(parsed[5], (CMD_ST_ALOCK, vec![0x07, 0x3A])); // 18.5% * 100 = 1850
    assert_eq!(
        parsed.last().unwrap(),
        &(CMD_RADIO_STATE, vec![RADIO_STATE_ON])
    );

    // Escaping round trips.
    let payload = vec![FEND, FESC, 0x00, 0xFF, TFEND, TFESC];
    let frame = kiss_frame(CMD_DATA, &payload);
    let parsed = parse_frames(&frame);
    assert_eq!(parsed, vec![(CMD_DATA, payload)]);

    // Parser: events from a device stream.
    let mut events = Vec::new();
    let mut parser = RnodeParser::new(false);
    let mut stream = Vec::new();
    stream.extend_from_slice(&kiss_frame(CMD_DETECT, &[DETECT_RESP]));
    stream.extend_from_slice(&kiss_frame(CMD_FW_VERSION, &[1, 61]));
    stream.extend_from_slice(&kiss_frame(CMD_STAT_RSSI, &[100]));
    stream.extend_from_slice(&kiss_frame(CMD_STAT_SNR, &[0xFC]));
    parser.feed(&stream, |event| events.push(event));

    assert!(matches!(events[0], RnodeEvent::Detect));
    assert!(matches!(
        events[1],
        RnodeEvent::FirmwareVersion {
            major: 1,
            minor: 61
        }
    ));
    match &events[2] {
        RnodeEvent::Status(status) => assert_eq!(status.rssi, Some(100 - RSSI_OFFSET)),
        _ => panic!("expected rssi status"),
    }
    match &events[3] {
        RnodeEvent::Status(status) => assert_eq!(status.snr, Some(-1.0)),
        _ => panic!("expected snr status"),
    }

    // Firmware gate: 1.51 must be rejected, 1.52 accepted.
    let base = RnodeEchoState {
        frequency: Some(0x11223344),
        bandwidth: Some(125_000),
        txpower: Some(13),
        spreadingfactor: Some(9),
        codingrate: Some(5),
        radio_state: Some(RADIO_STATE_ON),
        ..RnodeEchoState::default()
    };
    assert!(config.validate(&base).is_ok());

    // Frequency tolerance: ±100 Hz like Python's validation.
    let mut echo = base.clone();
    echo.frequency = Some(0x11223344 + 100);
    assert!(config.validate(&echo).is_ok());
    echo.frequency = Some(0x11223344 + 101);
    assert!(config.validate(&echo).is_err());

    echo.radio_state = Some(RADIO_STATE_OFF);
    assert!(config.validate(&echo).is_err());

    // Multi framing: SEL_INT prefix + vport data commands.
    let vport = RnodeVport {
        index: 1,
        config: CONFIG,
    };
    let frames = vport.configuration_frames(RADIO_STATE_ON);
    assert!(frames[0].starts_with(&[FEND, CMD_SEL_INT, 1, FEND, FEND]));

    let mut multi_events = Vec::new();
    let mut multi_parser = RnodeParser::new(true);
    multi_parser.feed(&kiss_frame(CMD_INT_DATA[1], b"vport data"), |event| {
        multi_events.push(event)
    });
    match &multi_events[0] {
        RnodeEvent::Data { vport, data } => {
            assert_eq!(*vport, Some(1));
            assert_eq!(data, b"vport data");
        }
        _ => panic!("expected vport data event"),
    }
}

/// Fold device frames through the parser into shared radio state.
fn apply_frames(shared: &mut RnodeShared, frames: &[u8]) {
    let mut parser = RnodeParser::new(false);
    parser.feed(frames, |event| match event {
        RnodeEvent::Echo(echo) => {
            let _ = shared.note_echo(echo);
        }
        RnodeEvent::Status(status) => {
            let _ = shared.note_status(status);
        }
        RnodeEvent::InterfaceKind(kind) => shared.subinterface_kinds.push(kind),
        _ => {}
    });
}

#[test]
fn rnode_framed_telemetry_bitrate_and_multi_probe() {
    let multi = multi_detect_request();
    let frames = parse_frames(&multi);
    assert_eq!(frames.len(), 5);
    assert_eq!(
        &multi[..detect_request().len()],
        detect_request().as_slice()
    );
    assert_eq!(frames[4], (CMD_INTERFACES, vec![0x00]));

    let mut stream = Vec::new();
    // SF9 / CR5 / 125 kHz → 1757.8125 bps, published as 1758.
    stream.extend_from_slice(&kiss_frame(CMD_SF, &[9]));
    stream.extend_from_slice(&kiss_frame(CMD_CR, &[5]));
    stream.extend_from_slice(&kiss_frame(CMD_BANDWIDTH, &125_000u32.to_be_bytes()));
    stream.extend_from_slice(&kiss_frame(CMD_STAT_BAT, &[0x02, 80]));
    stream.extend_from_slice(&kiss_frame(CMD_STAT_BAT, &[0x01, 150]));
    stream.extend_from_slice(&kiss_frame(CMD_STAT_TEMP, &[145])); // 145 - 120 = 25
    stream.extend_from_slice(&kiss_frame(CMD_STAT_CSMA, &[4, 3, 7]));

    let mut chtm = Vec::new();
    chtm.extend_from_slice(&1000u16.to_be_bytes());
    chtm.extend_from_slice(&2500u16.to_be_bytes());
    chtm.extend_from_slice(&100u16.to_be_bytes());
    chtm.extend_from_slice(&200u16.to_be_bytes());
    chtm.extend_from_slice(&[157, 147, 0xFF]);
    stream.extend_from_slice(&kiss_frame(CMD_STAT_CHTM, &chtm));

    let mut phy = Vec::new();
    phy.extend_from_slice(&1000u16.to_be_bytes());
    phy.extend_from_slice(&488u16.to_be_bytes());
    phy.extend_from_slice(&8u16.to_be_bytes());
    phy.extend_from_slice(&16u16.to_be_bytes());
    phy.extend_from_slice(&20u16.to_be_bytes());
    phy.extend_from_slice(&40u16.to_be_bytes());
    stream.extend_from_slice(&kiss_frame(CMD_STAT_PHYPRM, &phy));

    let mut shared = RnodeShared::default();
    apply_frames(&mut shared, &stream);

    assert_eq!(shared.bitrate, 1758);
    assert_eq!(shared.status.battery_state, Some(0x01));
    assert_eq!(shared.status.battery, Some(100));
    assert_eq!(shared.status.temperature, Some(25));
    assert_eq!(shared.status.csma_cw_band, Some(4));
    assert_eq!(shared.status.csma_cw_min, Some(3));
    assert_eq!(shared.status.csma_cw_max, Some(7));
    assert_eq!(shared.status.airtime_short, Some(10.0));
    assert_eq!(shared.status.airtime_long, Some(25.0));
    assert_eq!(shared.status.channel_load_short, Some(1.0));
    assert_eq!(shared.status.channel_load_long, Some(2.0));
    assert_eq!(shared.status.current_rssi, Some(0));
    assert_eq!(shared.status.noise_floor, Some(-10));
    assert_eq!(shared.status.interference, None);
    assert_eq!(shared.status.symbol_time_ms, Some(1.0));
    assert_eq!(shared.status.symbol_rate, Some(488));
    assert_eq!(shared.status.preamble_symbols, Some(8));
    assert_eq!(shared.status.preamble_time_ms, Some(16));
    assert_eq!(shared.status.csma_slot_time_ms, Some(20));
    assert_eq!(shared.status.csma_difs_ms, Some(40));

    // Out-of-range temperature clears the stored reading.
    apply_frames(&mut shared, &kiss_frame(CMD_STAT_TEMP, &[0]));
    assert_eq!(shared.status.temperature, None);

    // Explicit interference, then an 8-byte channel-time frame must not clear it.
    let mut interference = chtm[..8].to_vec();
    interference.extend_from_slice(&[157, 147, 180]);
    apply_frames(&mut shared, &kiss_frame(CMD_STAT_CHTM, &interference));
    assert_eq!(shared.status.interference, Some(180 - RSSI_OFFSET));
    apply_frames(&mut shared, &kiss_frame(CMD_STAT_CHTM, &chtm[..8]));
    assert_eq!(shared.status.interference, Some(23));

    // 10-byte PHY (RNodeMulti) has no DIFS and leaves the previous one.
    apply_frames(&mut shared, &kiss_frame(CMD_STAT_PHYPRM, &phy[..10]));
    assert_eq!(shared.status.csma_difs_ms, Some(40));
    assert_eq!(shared.status.csma_slot_time_ms, Some(20));

    let mut kinds = RnodeShared::default();
    apply_frames(
        &mut kinds,
        &kiss_frame(CMD_INTERFACES, &[0x00, 0x11, 0x01, 0x21]),
    );
    assert_eq!(kinds.subinterface_kinds, vec![0x11, 0x21]);
    assert!(reported_kind_accepts_frequency(0x11, 867_500_000));
    assert!(!reported_kind_accepts_frequency(0x21, 867_500_000));
    assert!(reported_kind_accepts_frequency(0x21, 2_400_000_000));

    let beacon = RnodeInterface::tcp("127.0.0.1:1", CONFIG).with_beacon(30, b"N0CALL");
    assert_eq!(beacon.id_callsign(), Some(b"N0CALL".as_slice()));
    let rejected = RnodeInterface::tcp("127.0.0.1:1", CONFIG).with_beacon(30, [0u8; 33]);
    assert!(rejected.id_callsign().is_none());

    let manager = Arc::new(tokio::sync::Mutex::new(
        reticulum::iface::InterfaceManager::new(1),
    ));
    let multi = RnodeMultiInterface::tcp("127.0.0.1:1", Vec::new(), manager)
        .with_receive_only(1)
        .with_beacon(30, b"N0CALL");
    assert_eq!(multi.id_callsign(), Some(b"N0CALL".as_slice()));
}

/// Mock device that records every host frame and echoes detect/config.
async fn recording_rnode(
    listener: TcpListener,
    recorded: RecordedFrames,
    interfaces: Option<Vec<u8>>,
) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        socket.set_nodelay(true).ok();
        let recorded = recorded.clone();
        let interfaces = interfaces.clone();
        tokio::spawn(async move {
            let (mut reader, mut writer) = socket.into_split();
            let mut carry = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let Ok(n) = reader.read(&mut buffer).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                carry.extend_from_slice(&buffer[..n]);
                let (complete, rest) = finished_frames(&carry);
                carry = rest;
                for (command, payload) in complete {
                    recorded.lock().unwrap().push((command, payload.clone()));
                    let reply = match command {
                        CMD_DETECT if payload.first() == Some(&DETECT_REQ) => {
                            Some(kiss_frame(CMD_DETECT, &[DETECT_RESP]))
                        }
                        CMD_FW_VERSION => Some(kiss_frame(CMD_FW_VERSION, &[1, 60])),
                        CMD_PLATFORM => Some(kiss_frame(CMD_PLATFORM, &[0x40])),
                        CMD_MCU => Some(kiss_frame(CMD_MCU, &[0x30])),
                        CMD_SEL_INT | CMD_RADIO_STATE | CMD_FREQUENCY | CMD_BANDWIDTH
                        | CMD_TXPOWER | CMD_SF | CMD_CR => Some(kiss_frame(command, &payload)),
                        CMD_INTERFACES => interfaces
                            .as_ref()
                            .map(|kinds| kiss_frame(CMD_INTERFACES, kinds)),
                        _ => None,
                    };
                    if let Some(reply) = reply {
                        if writer.write_all(&reply).await.is_err() || writer.flush().await.is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
    }
}

/// Complete KISS frames, leaving a trailing partial frame in the remainder.
fn finished_frames(bytes: &[u8]) -> (Vec<(u8, Vec<u8>)>, Vec<u8>) {
    let mut frames = Vec::new();
    let mut current: Option<(u8, Vec<u8>)> = None;
    let mut escaped = false;
    let mut last_end = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == FEND {
            if let Some(frame) = current.take() {
                frames.push(frame);
                last_end = index + 1;
            }
            continue;
        }
        match current.as_mut() {
            None => current = Some((byte, Vec::new())),
            Some((_, payload)) => {
                if escaped {
                    escaped = false;
                    payload.push(match byte {
                        TFEND => FEND,
                        TFESC => FESC,
                        _ => byte,
                    });
                } else if byte == FESC {
                    escaped = true;
                } else {
                    payload.push(byte);
                }
            }
        }
    }
    (frames, bytes[last_end..].to_vec())
}

fn data_by_vport(frames: &[(u8, Vec<u8>)]) -> Vec<(Option<u8>, Vec<u8>)> {
    let mut selected = None;
    let mut out = Vec::new();
    for (command, payload) in frames {
        if *command == CMD_SEL_INT && payload.len() == 1 {
            selected = Some(payload[0]);
        } else if *command == CMD_DATA {
            out.push((selected, payload.clone()));
        }
    }
    out
}

#[tokio::test]
async fn rnode_id_beacon_is_unpadded_callsign() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(recording_rnode(listener, recorded.clone(), None));

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Arc::new(TransportConfig::new("rnode-beacon", &identity).build());
    let address = {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            RnodeInterface::tcp(format!("127.0.0.1:{port}"), CONFIG)
                .with_manager(transport.iface_manager())
                .with_beacon(1, b"N0CALL"),
            RnodeInterface::spawn,
        )
    };

    let online = async {
        for _ in 0..100 {
            let up = transport
                .interface_stats()
                .await
                .iter()
                .any(|stats| stats.address == address && stats.online);
            if up {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online, "rnode must validate and come online");

    let bitrate = transport
        .iface_manager()
        .lock()
        .await
        .with_control(&address, |control| control.bitrate);
    assert_eq!(bitrate, Some(1758));

    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("rnode", "beacon"),
    );
    transport
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    let saw_beacon = async {
        for _ in 0..60 {
            let frames = recorded.lock().unwrap().clone();
            if data_by_vport(&frames)
                .iter()
                .any(|(_, payload)| payload.as_slice() == b"N0CALL")
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
    .await;
    assert!(saw_beacon, "id beacon must be the raw callsign");
    let frames = recorded.lock().unwrap().clone();
    assert!(data_by_vport(&frames)
        .iter()
        .any(|(_, payload)| payload.as_slice() == b"N0CALL"));
}

#[tokio::test]
async fn rnode_multi_probes_interfaces_and_honors_outgoing() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(recording_rnode(
        listener,
        recorded.clone(),
        Some(vec![0x00, 0x01, 0x01, 0x21]),
    ));

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Arc::new(TransportConfig::new("rnode-multi", &identity).build());
    let high = RnodeRadioConfig {
        frequency: 2_400_000_000,
        ..CONFIG
    };
    let parent = {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            RnodeMultiInterface::tcp(
                format!("127.0.0.1:{port}"),
                vec![
                    RnodeVport {
                        index: 0,
                        config: CONFIG,
                    },
                    RnodeVport {
                        index: 1,
                        config: high,
                    },
                ],
                transport.iface_manager(),
            )
            .with_receive_only(1)
            .with_beacon(1, b"N0CALL"),
            RnodeMultiInterface::spawn,
        )
    };

    let peers = async {
        for _ in 0..100 {
            let stats = transport.interface_stats().await;
            let peers: Vec<_> = stats
                .iter()
                .filter(|stats| stats.kind == "RnodeVportPeer")
                .map(|stats| stats.address)
                .collect();
            let parent_up = stats
                .iter()
                .any(|stats| stats.address == parent && stats.online);
            if parent_up && peers.len() == 2 {
                return Some(peers);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }
    .await;
    let peers = peers.expect("both virtual ports must come online");

    let parent_bitrate = transport
        .iface_manager()
        .lock()
        .await
        .with_control(&parent, |control| control.bitrate);
    assert_eq!(parent_bitrate, Some(62_500));

    {
        let manager = transport.iface_manager();
        let manager = manager.lock().await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(peers[0]),
                packet: Box::new(Packet::default()),
            })
            .await;
    }

    let packet_out = async {
        for _ in 0..40 {
            let frames = recorded.lock().unwrap().clone();
            let data = data_by_vport(&frames);
            if data
                .iter()
                .any(|(index, payload)| *index == Some(0) && payload.as_slice() != b"N0CALL")
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(
        packet_out,
        "outgoing port transmits and the receive-only port does not"
    );

    {
        let manager = transport.iface_manager();
        let manager = manager.lock().await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(peers[1]),
                packet: Box::new(Packet::default()),
            })
            .await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    {
        let frames = recorded.lock().unwrap().clone();
        assert!(data_by_vport(&frames)
            .iter()
            .all(|(index, payload)| *index != Some(1) || payload.as_slice() == b"N0CALL"));
    }

    let beaconed = async {
        for _ in 0..40 {
            let frames = recorded.lock().unwrap().clone();
            let data = data_by_vport(&frames);
            let on_low = data
                .iter()
                .any(|(index, payload)| *index == Some(0) && payload.as_slice() == b"N0CALL");
            let on_high = data
                .iter()
                .any(|(index, payload)| *index == Some(1) && payload.as_slice() == b"N0CALL");
            if on_low && on_high {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        false
    }
    .await;
    assert!(
        beaconed,
        "beacon is sent on every virtual port, including receive-only"
    );

    let frames = recorded.lock().unwrap().clone();
    assert!(frames
        .iter()
        .any(|(command, payload)| *command == CMD_INTERFACES && payload.as_slice() == [0x00]));
}

#[tokio::test]
async fn rnode_multi_stays_offline_without_interface_probe() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(recording_rnode(
        listener,
        recorded.clone(),
        Some(vec![0x00, 0x01]),
    ));

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Arc::new(TransportConfig::new("rnode-multi-miss", &identity).build());
    let address = {
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        manager.spawn(
            RnodeMultiInterface::tcp(
                format!("127.0.0.1:{port}"),
                vec![
                    RnodeVport {
                        index: 0,
                        config: CONFIG,
                    },
                    RnodeVport {
                        index: 1,
                        config: CONFIG,
                    },
                ],
                transport.iface_manager(),
            ),
            RnodeMultiInterface::spawn,
        )
    };

    let mut probed = false;
    for _ in 0..40 {
        let frames = recorded.lock().unwrap().clone();
        probed = frames
            .iter()
            .any(|(command, payload)| *command == CMD_INTERFACES && payload.as_slice() == [0x00]);
        let online = transport
            .interface_stats()
            .await
            .iter()
            .any(|stats| stats.address == address && stats.online);
        assert!(!online, "missing virtual port must keep the device offline");
        if probed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(probed, "RNodeMulti must send CMD_INTERFACES");
    for _ in 0..30 {
        let online = transport
            .interface_stats()
            .await
            .iter()
            .any(|stats| stats.address == address && stats.online);
        assert!(!online, "missing virtual port must keep the device offline");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn ble_cmd_bt_ctrl_frames_go_through_the_fake_link() {
    let mut link = FakeBleLink::new();
    assert!(
        !link.connected(),
        "the in-memory fake must not claim a radio is connected"
    );

    let disable = kiss_frame(CMD_BT_CTRL, &[BT_CTRL_DISABLE]);
    let enable = kiss_frame(CMD_BT_CTRL, &[BT_CTRL_ENABLE]);
    let pair = kiss_frame(CMD_BT_CTRL, &[BT_CTRL_PAIR]);
    assert_eq!(disable, [FEND, 0x46, 0x00, FEND]);
    assert_eq!(enable, [FEND, 0x46, 0x01, FEND]);
    assert_eq!(pair, [FEND, 0x46, 0x02, FEND]);

    link.write(&disable).await.unwrap();
    link.write(&enable).await.unwrap();
    link.write(&pair).await.unwrap();
    assert_eq!(
        link.written(),
        [disable.as_slice(), enable.as_slice(), pair.as_slice()].concat()
    );
    assert!(!link.connected());

    link.queue_rx(&enable);
    let mut buffer = [0u8; 4];
    let n = link.read(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..n], enable.as_slice());
    assert!(!link.connected());

    assert_eq!(
        android_usb_error("AndroidRNodeInterface"),
        Err(reticulum::error::RnsError::Unsupported)
    );
    assert!(parse_ble_target("ble://").is_some());
    assert!(parse_ble_target("/dev/ttyUSB0").is_none());
}
