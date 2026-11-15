use std::time::Duration;

use reticulum::buffer::{InputBuffer, OutputBuffer};
use reticulum::iface::{Interface, InterfaceContext, RxMessage};
use reticulum::packet::Packet;
use reticulum::serde::Serialize;

use crate::types::DynTransportBridge;

pub(crate) struct BridgeInterface {
    kind: String,
    bridge: DynTransportBridge,
}

impl BridgeInterface {
    pub(crate) fn new(kind: String, bridge: DynTransportBridge) -> Self {
        Self { kind, bridge }
    }

    pub(crate) async fn spawn(context: InterfaceContext<Self>) {
        let (kind, bridge) = {
            let inner = context.inner.lock().unwrap_or_else(|e| e.into_inner());
            (inner.kind.clone(), inner.bridge.clone())
        };
        let mtu = bridge.mtu(&kind) as usize;
        let max_packet = mtu.saturating_sub(4);
        let iface_address = context.channel.address;
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let ifac = context.channel.ifac.clone();
        let (rx_channel, mut tx_channel) = context.channel.split();
        let mut inbound = Vec::new();

        stats.set_online(true);
        loop {
            tokio::select! {
                _ = context.cancel.cancelled() => break,
                _ = iface_stop.cancelled() => break,
                message = tx_channel.recv() => {
                    let Some(message) = message else { break };
                    let mut raw = vec![0u8; max_packet];
                    let mut output = OutputBuffer::new(&mut raw);
                    if message.packet.serialize(&mut output).is_err() {
                        continue;
                    }
                    let wire = {
                        let key = ifac.read().unwrap_or_else(|e| e.into_inner()).clone();
                        reticulum::iface::ifac::encode(output.as_slice(), key.as_deref())
                    };
                    if wire.len() > max_packet || wire.len() > u32::MAX as usize {
                        continue;
                    }
                    let mut framed = Vec::with_capacity(wire.len() + 4);
                    framed.extend_from_slice(&(wire.len() as u32).to_le_bytes());
                    framed.extend_from_slice(&wire);
                    bridge.write_chunk(&kind, framed);
                    stats.count_tx(wire.len());
                }
                _ = tokio::time::sleep(Duration::from_millis(10)) => {
                    let chunk = bridge.read_chunk(&kind);
                    if !chunk.is_empty() {
                        inbound.extend_from_slice(&chunk);
                    }
                    loop {
                        if inbound.len() < 4 { break; }
                        let frame_len = u32::from_le_bytes(inbound[..4].try_into().expect("four-byte prefix")) as usize;
                        if frame_len > max_packet {
                            inbound.clear();
                            break;
                        }
                        if inbound.len() < frame_len + 4 { break; }
                        let frame: Vec<u8> = inbound.drain(..frame_len + 4).skip(4).collect();
                        let plain = {
                            let key = ifac.read().unwrap_or_else(|e| e.into_inner()).clone();
                            reticulum::iface::ifac::decode(&frame, key.as_deref())
                        };
                        let Some(plain) = plain else { continue };
                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&plain)) {
                            stats.count_rx(frame.len());
                            if rx_channel.send(RxMessage { address: iface_address, packet: Box::new(packet) }).await.is_err() {
                                stats.set_online(false);
                                return;
                            }
                        }
                    }
                }
            }
        }
        stats.set_online(false);
        iface_stop.cancel();
    }
}

impl Interface for BridgeInterface {
    fn mtu() -> usize {
        // The actual per-platform MTU is enforced by the worker at runtime.
        // `Packet` data is boxed now, so `size_of::<Packet>()` no longer
        // reflects wire size; report the protocol MDU like other transports.
        reticulum::packet::PACKET_MDU
    }
}
