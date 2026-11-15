//! Raw serial interface, a port of `RNS/Interfaces/SerialInterface.py`
//! (v1.4.2).
//!
//! Wire format is simplified HDLC framing identical to `TCPInterface`:
//! `FLAG + escape(data) + FLAG` with `FLAG = 0x7E`, `ESC = 0x7D`,
//! `ESC_MASK = 0x20` (see [`crate::iface::hdlc`]). Frames longer than
//! `HW_MTU` (564) are truncated on receive like in Python.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio_serial::SerialStream;

use crate::buffer::InputBuffer;
use crate::buffer::OutputBuffer;
use crate::iface::hdlc::Hdlc;
use crate::iface::hdlc::HdlcDecoder;
use crate::iface::kiss::SerialPortConfig;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::Interface;
use super::InterfaceContext;

/// `SerialInterface.HW_MTU`
pub const HW_MTU: usize = 564;

/// Open a serial port with the given configuration
/// (`SerialInterface.open_port`).
pub(crate) fn open_serial_stream(
    config: &SerialPortConfig,
) -> Result<SerialStream, crate::error::RnsError> {
    let mut builder = tokio_serial::new(&config.port, config.speed);

    builder = builder.data_bits(match config.databits {
        5 => tokio_serial::DataBits::Five,
        6 => tokio_serial::DataBits::Six,
        7 => tokio_serial::DataBits::Seven,
        _ => tokio_serial::DataBits::Eight,
    });

    builder = builder.parity(match config.parity.to_lowercase().as_str() {
        "e" | "even" => tokio_serial::Parity::Even,
        "o" | "odd" => tokio_serial::Parity::Odd,
        _ => tokio_serial::Parity::None,
    });

    builder = builder.stop_bits(match config.stopbits {
        2 => tokio_serial::StopBits::Two,
        _ => tokio_serial::StopBits::One,
    });

    tokio_serial::SerialStream::open(&builder).map_err(|err| {
        log::warn!("serial: couldn't open port <{}>: {}", config.port, err);
        crate::error::RnsError::ConnectionError
    })
}

/// Serial interface using HDLC framing (`SerialInterface`).
pub struct SerialInterface {
    serial: SerialPortConfig,
    stream: Option<SerialStream>,
}

impl SerialInterface {
    pub fn new(serial: SerialPortConfig) -> Self {
        Self {
            serial,
            stream: None,
        }
    }

    /// Wrap an already opened serial stream (used for tests over a pty
    /// pair; skips the device initialisation delay and never reconnects).
    pub fn from_stream(stream: SerialStream) -> Self {
        Self {
            serial: SerialPortConfig::new("", 9600),
            stream: Some(stream),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();

        let serial = context.inner.lock().unwrap().serial.clone();
        let mut injected = context.inner.lock().unwrap().stream.take();
        // injected streams are consumed exactly once (test pty pairs)
        let is_injected = injected.is_some();

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let stream = match injected.take() {
                Some(stream) => stream,
                None => match serial.open() {
                    Ok(stream) => {
                        // Allow time for the interface to initialise
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        stream
                    }
                    Err(_) => {
                        log::warn!(
                            "serial: couldn't open serial port <{}>, retrying",
                            serial.port
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                },
            };

            log::info!("serial: port <{}> is now open", serial.port);
            stats.set_online(true);

            let cancel = context.cancel.clone();
            let stop = tokio_util::sync::CancellationToken::new();

            let (read_half, write_half) = tokio::io::split(stream);

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let mut read_half = read_half;
                let channel_ifac_rx = channel_ifac.clone();

                tokio::spawn(async move {
                    let mut decoder = HdlcDecoder::new(HW_MTU);
                    let mut buffer = [0u8; 4096];
                    let mut frames = Vec::new();

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            result = read_half.read(&mut buffer[..]) => match result {
                                Ok(0) => {
                                    log::warn!("serial: serial port closed");
                                    stop.cancel();
                                    break;
                                }
                                Ok(n) => {
                                    frames.clear();
                                    decoder.feed(&buffer[..n], |frame| {
                                        if !frame.is_empty() {
                                            frames.push(frame.to_vec());
                                        }
                                    });

                                    for frame in frames.drain(..) {
                                        let plain = {
                                            let ifac = channel_ifac_rx
                                                .read()
                                                .expect("ifac lock")
                                                .clone();
                                            match crate::iface::ifac::decode_inbound(
                                                &frame,
                                                ifac.as_deref(),
                                                Some(&stats),
                                            ) {
                                                Some(plain) => plain,
                                                None => {
                                                    log::debug!("serial: dropping packet with invalid access code");
                                                    continue;
                                                }
                                            }
                                        };
                                        match Packet::deserialize(
                                            &mut InputBuffer::new(&plain[..]),
                                        ) {
                                            Ok(packet) => {
                                                stats.count_rx(frame.len());
                                                let _ = rx_channel
                                                    .send(RxMessage {
                                                        address: iface_address,
                                                        packet: Box::new(packet),
                                                    })
                                                    .await;
                                            }
                                            Err(_) => log::debug!(
                                                "serial: couldn't decode packet"
                                            ),
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("serial: serial port error {}", e);
                                    stop.cancel();
                                    break;
                                }
                            }
                        }
                    }
                })
            };

            // Start transmit task
            let tx_task = {
                let cancel = cancel.clone();
                let tx_channel = tx_channel.clone();
                let stats = stats.clone();
                let mut write_half = write_half;
                let channel_ifac = channel_ifac.clone();

                tokio::spawn(async move {
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = stop.cancelled() => break,
                            Some(message) = tx_channel.recv() => message,
                        };

                        let packet = message.packet;
                        let mut buffer = [0u8; 2048];
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let ifac = channel_ifac.read().expect("ifac lock").clone();
                            let wire =
                                crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());
                            let frame = Hdlc::encode_frame_vec(&wire);
                            if write_half.write_all(&frame).await.is_ok() {
                                let _ = write_half.flush().await;
                                stats.count_tx(wire.len());
                            }
                        }
                    }
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            stats.set_online(false);
            log::warn!("serial: port <{}> closed", serial.port);

            if is_injected {
                break;
            }

            // Reticulum will attempt to reconnect the interface periodically.
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        iface_stop.cancel();
    }
}

impl Interface for SerialInterface {
    fn mtu() -> usize {
        HW_MTU
    }

    fn should_ingress_limit() -> bool {
        // Python `SerialInterface.should_ingress_limit` returns false.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::control::{hold_announce_burst, IfaceControlState};
    use crate::iface::InterfaceManager;

    #[test]
    fn constructor_without_beacon_stays_quiet() {
        // Serial has no `id_interval` / `id_callsign` in Python. The
        // constructor takes only the port and must keep working.
        let iface = SerialInterface::new(SerialPortConfig::new("/dev/null", 9600));
        assert!(iface.stream.is_none());
        assert!(!SerialInterface::should_ingress_limit());
    }

    #[tokio::test]
    async fn announce_burst_is_not_held() {
        let t0 = tokio::time::Instant::now();
        let mut generic = IfaceControlState::new(t0);
        assert!(
            hold_announce_burst(&mut generic, t0) > 0,
            "burst fixture must trip the generic limiter"
        );

        let (stream, _peer) = tokio_serial::SerialStream::pair().expect("pty pair");
        let mut manager = InterfaceManager::new(4);
        let address = manager.spawn(SerialInterface::from_stream(stream), SerialInterface::spawn);

        let held = manager
            .with_control(&address, |control| hold_announce_burst(control, t0))
            .unwrap();
        assert_eq!(held, 0);

        manager.stop_iface(&address);
    }
}
