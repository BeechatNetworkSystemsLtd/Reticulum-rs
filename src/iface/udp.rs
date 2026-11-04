use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::RxMessage;
use crate::packet::{Packet, PACKET_MDU};
use crate::serde::Serialize;

use super::{Interface, InterfaceContext};

// TODO: Configure via features
const PACKET_TRACE: bool = true;

/// Python `UDPInterface.HW_MTU`. This is the hardware MTU, not the
/// next-hop MTU (`next_hop_interface_hw_mtu` is `None` for UDP) and not
/// the packet MDU ([`Interface::mtu`] is 2048).
pub const HW_MTU: usize = 1064;

pub struct UdpInterface {
    bind_addr: String,
    forward_addr: Option<String>,
}

impl UdpInterface {
    pub fn new<T: Into<String>>(bind_addr: T, forward_addr: Option<T>, broadcast: bool) -> Self {
        // Python sets SO_BROADCAST on every socket and has no off switch.
        // Existing callers pass `false`; that argument must not disable it.
        let _ = broadcast;
        Self {
            bind_addr: bind_addr.into(),
            forward_addr: forward_addr.map(Into::into),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let bind_addr = { context.inner.lock().unwrap().bind_addr.clone() };
        let forward_addr = { context.inner.lock().unwrap().forward_addr.clone() };
        let iface_address = context.channel.address;
        let stats = context.channel.stats.clone();
        let channel_ifac = context.channel.ifac.clone();

        let (rx_channel, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let socket = bind_udp_socket(bind_addr.clone())
                .await
                .map_err(|_| RnsError::ConnectionError);

            if socket.is_err() {
                log::info!("udp_interface: couldn't bind to <{}>", bind_addr);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            stats.set_online(true);

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let socket = socket.unwrap();
            let read_socket = Arc::new(socket);
            let write_socket = read_socket.clone();

            log::info!("udp_interface bound to <{}>", bind_addr);
            stats.set_online(true);

            // Wire capacity for a serialized packet: PACKET_MDU + header/ifac
            // slack (same convention as control::packet_wire_len). The
            // in-memory `Packet` is boxed, so `size_of::<Packet>()` no longer
            // reflects wire size.
            const BUFFER_SIZE: usize = PACKET_MDU + 128;

            // Start receive task
            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let socket = read_socket;
                let rx_channel = rx_channel.clone();
                let stats = stats.clone();
                let channel_ifac = channel_ifac.clone();

                tokio::spawn(async move {
                    loop {
                        let mut rx_buffer = [0u8; BUFFER_SIZE];

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            result = socket.recv_from(&mut rx_buffer) => {
                                match result {
                                    Ok((0, _)) => {
                                        log::warn!("udp_interface: connection closed");
                                        stop.cancel();
                                        break;
                                    }
                                    Ok((n, _in_addr)) => {
                                        let plain = {
                                            let ifac = channel_ifac
                                                .read()
                                                .expect("ifac lock")
                                                .clone();
                                            match crate::iface::ifac::decode_inbound(
                                                &rx_buffer[..n],
                                                ifac.as_deref(),
                                                Some(&stats),
                                            ) {
                                                Some(plain) => plain,
                                                None => {
                                                    log::debug!(
                                                        "udp_interface: dropping packet with invalid access code"
                                                    );
                                                    continue;
                                                }
                                            }
                                        };
                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&plain[..])) {
                                            if PACKET_TRACE {
                                                log::trace!("udp_interface: rx << ({}) {}", iface_address, packet);
                                            }
                                            stats.count_rx(n);
                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet: Box::new(packet) }).await;
                                        } else {
                                            log::warn!("udp_interface: couldn't decode packet");
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("udp_interface: connection error {}", e);
                                        break;
                                    }
                                }
                            },
                        };
                    }
                })
            };

            if let Some(forward_addr) = forward_addr.clone() {
                // Start transmit task
                let tx_task = {
                    let cancel = cancel.clone();
                    let tx_channel = tx_channel.clone();
                    let stats = stats.clone();
                    let socket = write_socket;
                    let channel_ifac = channel_ifac.clone();

                    tokio::spawn(async move {
                        loop {
                            if stop.is_cancelled() {
                                break;
                            }

                            let mut tx_buffer = [0u8; BUFFER_SIZE];

                            let mut tx_channel = tx_channel.lock().await;

                            tokio::select! {
                                _ = cancel.cancelled() => {
                                        break;
                                }
                                _ = stop.cancelled() => {
                                        break;
                                }
                                Some(message) = tx_channel.recv() => {
                                    let packet = message.packet;
                                    if PACKET_TRACE {
                                        log::trace!("udp_interface: tx >> ({}) {}", iface_address, packet);
                                    }
                                    let mut output = OutputBuffer::new(&mut tx_buffer);
                                    if packet.serialize(&mut output).is_ok() {
                                        let ifac = channel_ifac
                                            .read()
                                            .expect("ifac lock")
                                            .clone();
                                        let wire = crate::iface::ifac::encode(
                                            output.as_slice(),
                                            ifac.as_deref(),
                                        );
                                        if socket.send_to(&wire, &forward_addr).await.is_ok() {
                                            stats.count_tx(wire.len());
                                        }
                                    } else {
                                        log::warn!(
                                            "udp_interface: dropping packet that does not serialize"
                                        );
                                    }
                                }
                            };
                        }
                    })
                };
                tx_task.await.unwrap();
            }

            rx_task.await.unwrap();

            stats.set_online(false);
            log::info!("udp_interface <{}>: closed", bind_addr);
        }
    }
}

/// Bind a UDP socket the way `UDPInterface` does. `SO_BROADCAST` is always
/// set (`UDPInterface.process_outgoing`); there is no Python off switch.
async fn bind_udp_socket(addr: impl tokio::net::ToSocketAddrs) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(addr).await?;
    if let Err(err) = socket.set_broadcast(true) {
        log::error!("error setting broadcast: {err}");
    }
    Ok(socket)
}

impl Interface for UdpInterface {
    fn mtu() -> usize {
        // Packet MDU. [`HW_MTU`] is the Python hardware MTU, not this value
        // and not the next-hop MTU.
        2048
    }

    fn endpoint(&self) -> &str {
        &self.bind_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_hw_mtu_is_python_hardware_mtu_not_packet_mdu() {
        // `false` is what existing callers pass. Spawn ignores it and
        // always sets SO_BROADCAST in `bind_udp_socket`.
        let _iface = UdpInterface::new("127.0.0.1:4242", None::<&str>, false);
        assert_eq!(HW_MTU, 1064);
        assert_eq!(<UdpInterface as Interface>::mtu(), 2048);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn udp_socket_is_created_with_broadcast_enabled() {
        // Same bind `spawn` uses.
        let socket = bind_udp_socket("127.0.0.1:0").await.unwrap();
        assert!(
            socket_broadcast_enabled(&socket),
            "SO_BROADCAST must be set on the socket spawn binds"
        );
    }

    #[cfg(target_os = "linux")]
    fn socket_broadcast_enabled(socket: &UdpSocket) -> bool {
        use std::os::fd::AsRawFd;

        let mut value: i32 = 0;
        let mut len: u32 = std::mem::size_of::<i32>() as u32;
        let rc = unsafe {
            getsockopt(
                socket.as_raw_fd(),
                1, // SOL_SOCKET
                6, // SO_BROADCAST
                &mut value as *mut i32 as *mut std::ffi::c_void,
                &mut len,
            )
        };
        rc == 0 && value != 0
    }
}

#[cfg(all(test, target_os = "linux"))]
unsafe extern "C" {
    fn getsockopt(
        sockfd: i32,
        level: i32,
        optname: i32,
        optval: *mut std::ffi::c_void,
        optlen: *mut u32,
    ) -> i32;
}
