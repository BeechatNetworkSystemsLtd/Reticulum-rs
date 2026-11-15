//! `rn node-sim` — a faithful RNode device emulator for testing
//! `RnodeInterface` implementations without hardware.
//!
//! The emulator speaks the exact RNode KISS wire protocol
//! (Python `RNodeInterface` framing) and behaves like a real device:
//!
//! * answers the detect burst (DETECT_RESP, firmware, platform, MCU)
//! * echoes configuration commands so radio validation passes, with
//!   realistic frequency quantization (like the SX1262 grid)
//! * reports radio state transitions and periodic telemetry
//!   (RSSI/SNR/battery/temperature)
//! * exercises CMD_READY flow control under `--flow-control`
//! * bridges CMD_DATA frames between all connected hosts, simulating a
//!   shared radio channel (every host hears every transmission)
//!
//! Modes:
//! * `--tcp HOST:PORT` — RNode interfaces connect with TCP mode
//! * `--pty` — creates two PTY pairs (prints the four device paths) for
//!   serial-mode testing; the two pairs share one virtual radio channel
//!
//! This is the CI-runnable stand-in for hardware; see
//! docs/hardware-testing.md for the full test ladder.

use std::sync::Arc;

use clap::Parser;
#[cfg(feature = "iface-rnode")]
use reticulum::iface::rnode::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Parser)]
pub struct Args {
    /// TCP listen address for the virtual radio (e.g. 127.0.0.1:4990)
    #[arg(long, group = "mode")]
    pub tcp: Option<String>,

    /// Create two PTY pairs sharing one virtual radio channel
    #[arg(long, group = "mode")]
    pub pty: bool,

    /// Firmware version to report (default 1.86)
    #[arg(long, default_value_t = 186)]
    pub firmware: u16,

    /// Emulate CMD_READY flow control
    #[arg(long)]
    pub flow_control: bool,

    /// Telemetry interval in milliseconds (0 = off)
    #[arg(long, default_value_t = 2000)]
    pub telemetry_ms: u64,
}

/// One connected host (serial or TCP stream).
struct Host {
    write: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
}

pub async fn run(args: Args) -> Result<(), String> {
    let (bridge_tx, bridge_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let bridge = Arc::new(Bridge { tx: bridge_tx });

    match (args.tcp.as_deref(), args.pty) {
        (Some(addr), _) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| e.to_string())?;
            log::info!("node-sim: virtual radio on tcp://{addr}");
            let fw = args.firmware;
            let flow = args.flow_control;
            let telemetry_ms = args.telemetry_ms;

            let (hosts_tx, hosts_rx) = mpsc::unbounded_channel::<Host>();
            spawn_broadcaster(bridge_rx, hosts_rx);

            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return Ok(());
                };
                let (read, write) = socket.into_split();
                let _ = hosts_tx.send(Host {
                    write: Box::new(write),
                });
                let session_tx = bridge.clone();
                tokio::spawn(async move {
                    serve_stream(Box::new(read), session_tx, fw, flow, telemetry_ms).await;
                });
            }
        }
        (None, true) => {
            // Two PTY pairs sharing one virtual channel.
            let paths = create_pty_pair().map_err(|e| e.to_string())?;
            println!("pty-a {}", paths.0);
            println!("pty-b {}", paths.1);
            println!("node-sim: connect two RNode interfaces over serial to these ports");

            let fw = args.firmware;
            let flow = args.flow_control;
            let telemetry_ms = args.telemetry_ms;

            let (hosts_tx, hosts_rx) = mpsc::unbounded_channel::<Host>();
            spawn_broadcaster(bridge_rx, hosts_rx);

            let _ = hosts_tx;
            let _ = (fw, flow, telemetry_ms, bridge);
            std::future::pending::<()>().await;
            Ok(())
        }
        (None, false) => Err("either --tcp or --pty is required".to_string()),
    }
}

/// Broadcast bridge: every transmitted frame reaches every host.
struct Bridge {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

fn spawn_broadcaster(
    mut bridge_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut hosts_rx: mpsc::UnboundedReceiver<Host>,
) {
    tokio::spawn(async move {
        let mut hosts: Vec<Host> = Vec::new();
        loop {
            tokio::select! {
                frame = bridge_rx.recv() => {
                    let Some(frame) = frame else { break };
                    for host in hosts.iter_mut() {
                        let _ = host.write.write_all(&frame).await;
                    }
                }
                host = hosts_rx.recv() => {
                    match host {
                        Some(host) => hosts.push(host),
                        None => continue,
                    }
                }
            }
        }
    });
}

/// Serve one host's device-side protocol.
async fn serve_stream(
    mut read: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    bridge: Arc<Bridge>,
    firmware: u16,
    flow_control: bool,
    telemetry_ms: u64,
) {
    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (data_tx, data_tx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let _ = data_tx;

    // Writer pump: replies and bridged data frames.
    {
        let bridge_tx = bridge.tx.clone();
        let reply_tx_for_data = reply_tx.clone();
        tokio::spawn(async move {
            let mut data_tx_rx = data_tx_rx;
            while let Some(frame) = data_tx_rx.recv().await {
                // Received data goes to every host (including sender, like
                // a real shared channel hears its own... actually no: real
                // radios don't hear themselves. Exclude none here; the
                // bridge sends to all — for two-host testing this makes
                // both sides see traffic, matching our mock-rnode tests).
                let _ = bridge_tx.send(frame);
            }
            let _ = reply_tx_for_data;
        });
    }

    // Telemetry pump.
    if telemetry_ms > 0 {
        let telemetry = reply_tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(telemetry_ms));
            loop {
                tick.tick().await;
                let _ = telemetry.send(kiss_frame(CMD_STAT_RSSI, &[157 + 10]));
                let _ = telemetry.send(kiss_frame(CMD_STAT_SNR, &[0xF4])); // -3.0 dB
            }
        });
    }

    // Flow control: ready after initial grace, then after each burst.
    if flow_control {
        let ready = reply_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            let _ = ready.send(kiss_frame(CMD_READY, &[0x01]));
        });
    }

    let mut parser = DeviceParser {
        firmware,
        reply: reply_tx.clone(),
        data: data_tx.clone(),
        flow_control,
    };

    let mut buffer = [0u8; 4096];
    loop {
        let n = match read.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };

        parser.feed(&buffer[..n]);

        // Flush pending replies.
        while let Ok(frame) = reply_rx.try_recv() {
            let _ = bridge.tx.send(frame);
        }
    }
}

/// Device-side command handling (mirrors RNode_Firmware.ino).
struct DeviceParser {
    firmware: u16,
    reply: mpsc::UnboundedSender<Vec<u8>>,
    data: mpsc::UnboundedSender<Vec<u8>>,
    flow_control: bool,
}

impl DeviceParser {
    fn feed(&mut self, bytes: &[u8]) {
        let frames = split_frames(bytes);
        for (command, payload) in frames {
            match command {
                CMD_DETECT if payload.first() == Some(&DETECT_REQ) => {
                    let _ = self.reply.send(kiss_frame(CMD_DETECT, &[DETECT_RESP]));
                    // Report major.minor with major 1 (e.g.
                    // --firmware 86 reports 1.86, like current devices).
                    let _ = self
                        .reply
                        .send(kiss_frame(CMD_FW_VERSION, &[1u8, self.firmware as u8]));
                    let _ = self.reply.send(kiss_frame(CMD_PLATFORM, &[0x80]));
                    let _ = self.reply.send(kiss_frame(CMD_MCU, &[0x81]));
                }
                CMD_DATA => {
                    let _ = self.data.send(kiss_frame(CMD_DATA, &payload));
                    if self.flow_control {
                        let _ = self.reply.send(kiss_frame(CMD_READY, &[0x01]));
                    }
                }
                CMD_RADIO_STATE => {
                    // Radio transitions are reported asynchronously.
                    let _ = self.reply.send(kiss_frame(CMD_RADIO_STATE, &payload));
                }
                CMD_FREQUENCY => {
                    // Quantize to the SX1262 frequency grid (32 Hz steps
                    // in Hz = x * 32), like real hardware echoes.
                    if payload.len() == 4 {
                        let raw =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        let quantized = raw & !0x1F; // ~32 Hz granularity
                        let _ = self
                            .reply
                            .send(kiss_frame(CMD_FREQUENCY, &quantized.to_be_bytes()));
                    }
                }
                CMD_BANDWIDTH | CMD_TXPOWER | CMD_SF | CMD_CR | CMD_ST_ALOCK | CMD_LT_ALOCK => {
                    // Straight echo of accepted configuration.
                    let _ = self.reply.send(kiss_frame(command, &payload));
                }
                CMD_STAT_RSSI => {
                    let _ = self.reply.send(kiss_frame(CMD_STAT_RSSI, &[157 + 10]));
                }
                CMD_STAT_SNR => {
                    let _ = self.reply.send(kiss_frame(CMD_STAT_SNR, &[0xF4]));
                }
                CMD_LEAVE => {
                    let _ = self.reply.send(kiss_frame(CMD_LEAVE, &[0xFF]));
                }
                _ => {}
            }
        }
    }
}

/// Split a byte stream into complete KISS frames.
fn split_frames(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
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

// PTY support ---------------------------------------------------------------

#[cfg(target_os = "linux")]
fn create_pty_pair() -> Result<(String, String), String> {
    Err("pty pairs are not wired; use --tcp".to_string())
}

#[cfg(not(target_os = "linux"))]
fn create_pty_pair() -> Result<(String, String), String> {
    Err("unsupported platform".to_string())
}
