//! Host-side parity tests: the modem core driven by the *real* RNode
//! host client from `reticulum::iface::rnode`, over a TCP loopback —
//! the same path production firmware serves over WiFi-TCP.
//!
//! This is the CI-level guarantee that any firmware built on this core
//! passes the exact same handshake and validation our (and Python's)
//! host implementations perform, before any hardware is involved.

use rnode_modem_core::frame::kiss_frame;
use rnode_modem_core::modem::Modem;
use rnode_modem_core::protocol::{DETECT_REQ, Protocol, CMD_DETECT};
use rnode_modem_core::radio::RadioParams;
use rnode_modem_core::{FW_VERSION_MAJ, FW_VERSION_MIN};
use reticulum::iface::rnode::{
    detect_and_validate, detect_request, RnodeLink, RnodeRadioConfig,
    SharedRnodeState,
};

/// Serve one TCP connection through the modem core on a worker thread.
fn spawn_modem_server() -> std::io::Result<String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    std::thread::spawn(move || {
        let (socket, _) = listener.accept().expect("accept");
        let mut socket = socket;
        let mut modem = Modem::new(Protocol::new(rnode_modem_core::MCU_ESP32_C6));
        let session = modem.add_session();

        // Drive the socket synchronously, one feed at a time. The test
        // traffic is small; blocking reads with a generous timeout are
        // fine.
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 2048];
        loop {
            let n = match socket.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            eprintln!("[srv] rx {} bytes: {:02x?}", n, &buf[..n]);
            let fed = modem.feed(session, &buf[..n]);
            // Perform the (virtual) radio op: accept every transmit.
            for op in &fed.ops {
                if let rnode_modem_core::protocol::RadioOp::Transmit(data) = op {
                    modem.protocol.tx_complete(data.len());
                }
            }
            for frame in fed.to_sender.iter().chain(fed.to_others.iter()) {
                eprintln!("[srv] tx frame cmd=0x{:02x}", frame.get(1).copied().unwrap_or(0));
                if socket.write_all(frame).is_err() {
                    return;
                }
            }
        }
    });
    Ok(addr)
}

use std::io::{Read, Write};

#[tokio::test(flavor = "multi_thread")]
async fn full_handshake_with_real_host_client() {
    // Constants must never drift from the host side.
    assert_eq!(
        (FW_VERSION_MAJ, FW_VERSION_MIN),
        (1, 90),
        "bump intentionally, but keep >= 1.52 gate happy"
    );

    let addr = spawn_modem_server().expect("spawn modem server");
    let mut link = RnodeLink::tcp(&addr).await.expect("connect to modem core");


    let config = RnodeRadioConfig {
        frequency: 867_500_017, // deliberately off-grid to test quantization
        bandwidth: 125_000,
        txpower: 2,
        spreadingfactor: 9,
        codingrate: 5,
        st_alock: None,
        lt_alock: None,
    };
    let shared: SharedRnodeState = Default::default();

    // The exact production handshake: detect burst, firmware gate,
    // platform/MCU collection and radio configuration validation.
    detect_and_validate(&mut link, &config, &shared)
        .await
        .expect("modem core must pass the real host handshake");

    let state = shared.read().unwrap_or_else(|e| e.into_inner());
    assert!(state.detected, "detect must have completed");
    assert_eq!(
        state.firmware,
        Some((FW_VERSION_MAJ, FW_VERSION_MIN)),
        "firmware version must be reported and stored"
    );
    assert_eq!(state.platform, Some(rnode_modem_core::PLATFORM_CUSTOM));
    assert_eq!(state.mcu, Some(rnode_modem_core::MCU_ESP32_C6));
}

#[test]
fn framing_matches_host_side_byte_for_byte() {
    // The core's builder must produce byte-identical frames to the host's.
    for (cmd, payload) in [
        (CMD_DETECT, vec![DETECT_REQ]),
        (0x00, vec![0xC0, 0xDB, 0xDC, 0xDD, 0x42]),
        (0x23, vec![0xFF]),
    ] {
        assert_eq!(
            kiss_frame(cmd, &payload),
            reticulum::iface::rnode::kiss_frame(cmd, &payload)
        );
    }
}

#[test]
fn detect_burst_parses_with_host_parser() {
    // The core must consume the host's exact detect request bytes.
    let mut modem = Modem::new(Protocol::new(rnode_modem_core::MCU_ESP32_C6));
    let session = modem.add_session();
    let fed = modem.feed(session, &detect_request());
    // The burst carries four queries (detect, fw, platform, MCU); the
    // core answers the detect frame with the full set *and* answers each
    // individual query — like the RNode firmware does — so seven frames.
    assert_eq!(fed.to_sender.len(), 7, "detect+fw+platform+mcu replies");
    assert!(fed.to_sender[0] == reticulum::iface::rnode::kiss_frame(0x08, &[0x46]));
}

#[test]
fn radio_params_default_to_the_test_channel() {
    // Keep the modem's power-on defaults aligned with the repo hardware
    // test channel (examples/rnode_listen.rs).
    let params = RadioParams::default();
    assert_eq!(params.frequency, 867_500_000);
    assert_eq!(params.bandwidth, 125_000);
    assert_eq!(params.sf, 9);
    assert_eq!(params.cr, 5);
    assert_eq!(params.txpower, 2);
}

#[tokio::test]
async fn raw_client_sees_modem_replies() {
    let addr = spawn_modem_server().expect("spawn modem server");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
    stream.set_nodelay(true).ok();
    stream.write_all(&detect_request()).await.unwrap();
    let mut buf = [0u8; 2048];
    let mut frames = 0usize; // complete frames, not read() calls
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while frames < 7 && std::time::Instant::now() < deadline {
        let n = tokio::time::timeout(std::time::Duration::from_secs(8), stream.read(&mut buf))
            .await
            .expect("raw client read timed out")
            .unwrap();
        frames += buf[..n].iter().filter(|&&b| b == 0xC0).count() / 2;
    }
    assert_eq!(frames, 7, "expected all seven reply frames");
}
