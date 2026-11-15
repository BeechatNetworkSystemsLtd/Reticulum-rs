//! `rnode_listen` — put an RNode LoRa interface on the air and log every
//! Reticulum packet it hears, with announces decoded.
//!
//! Announces are how Reticulum nodes make themselves known, so anything
//! printed here is "another device around" in radio range on the chosen
//! channel.
//!
//! Usage:
//!   cargo run --example rnode_listen \
//!       --features "iface-rnode,iface-serial" -- \
//!       --port /dev/ttyUSB1 \
//!       --frequency 867500000 --bandwidth 125000 \
//!       --spreadingfactor 9 --codingrate 5 --txpower 2
//!
//! All radio parameters default to the values above (the repo's hardware
//! test channel). They must match whatever the nodes you want to hear are
//! using — an RNode can only listen on one channel at a time.

use std::sync::Arc;

use reticulum::iface::rnode::{RnodeInterface, RnodeRadioConfig};
use reticulum::packet::{HeaderType, PacketType};
use reticulum::transport::{Transport, TransportConfig};
use tokio::select;
use tokio_util::sync::CancellationToken;

fn arg_u64(name: &str, default: u64) -> u64 {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn arg_string(name: &str, default: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| default.to_string())
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Render app data as UTF-8 when printable, else as hex.
fn printable(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    match std::str::from_utf8(data) {
        Ok(s) if s.chars().all(|c| !c.is_control()) => format!("\"{s}\""),
        _ => format!("0x{}", hex(data)),
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port = arg_string("--port", "/dev/ttyUSB1");
    let radio = RnodeRadioConfig {
        frequency: arg_u64("--frequency", 867_500_000),
        bandwidth: arg_u64("--bandwidth", 125_000) as u32,
        txpower: arg_u64("--txpower", 2) as u8,
        spreadingfactor: arg_u64("--spreadingfactor", 9) as u8,
        codingrate: arg_u64("--codingrate", 5) as u8,
        st_alock: None,
        lt_alock: None,
    };

    println!("RNode listener");
    println!("  port      : {port}");
    println!(
        "  radio     : {:.3} MHz, BW {} kHz, SF{}, CR4/{}",
        radio.frequency as f64 / 1e6,
        radio.bandwidth as f64 / 1e3,
        radio.spreadingfactor,
        radio.codingrate
    );
    println!("Listening for Reticulum traffic (ctrl-c to stop)...\n");

    let transport = Transport::new(TransportConfig::default());

    let iface_addr = transport.iface_manager().lock().await.spawn(
        RnodeInterface::serial(port.clone(), 115200, radio).with_manager(transport.iface_manager()),
        RnodeInterface::spawn,
    );
    println!("  interface : {iface_addr}\n");

    let transport = Arc::new(transport);
    let cancel = CancellationToken::new();

    // Announce events: decoded, validated announces = discovered nodes.
    {
        let transport = transport.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            let mut announces = transport.recv_announces().await;
            loop {
                select! {
                    _ = cancel.cancelled() => break,
                    Ok(announce) = announces.recv() => {
                        let destination = announce.destination.lock().await;
                        println!(
                            "[announce] dest={} identity={} name_hash={}{}",
                            destination.desc.address_hash,
                            destination.desc.identity.address_hash,
                            destination.desc.name.hash,
                            if announce.ratchet.is_some() { " ratchet" } else { "" },
                        );
                        let app_data = announce.app_data.as_slice();
                        if !app_data.is_empty() {
                            println!("           app_data={}", printable(app_data));
                        }
                    },
                }
            }
        });
    }

    // Raw packet stream: every frame the radio picks up on this channel.
    let mut rx = transport.iface_rx();
    loop {
        select! {
            _ = tokio::signal::ctrl_c() => break,
            msg = rx.recv() => {
                match msg {
                    Ok(msg) => {
                        let packet = &msg.packet;
                        let kind = match packet.header.packet_type {
                            PacketType::Announce => "announce",
                            PacketType::Data => "data",
                            PacketType::LinkRequest => "linkreq",
                            PacketType::Proof => "proof",
                        };
                        println!(
                            "[packet] {kind:<9} dest={} hops={} ctx=0x{:02x} len={} bytes{}",
                            packet.destination,
                            packet.header.hops,
                            packet.context as u8,
                            packet.data.as_slice().len(),
                            if packet.header.header_type == HeaderType::Type2 {
                                " (transported)"
                            } else {
                                ""
                            },
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("[warn] dropped {n} packets (receiver lagged)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    cancel.cancel();
    println!("exit");
}
