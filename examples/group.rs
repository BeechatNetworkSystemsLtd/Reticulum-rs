//! Sends and receives symmetrically encrypted data over a GROUP destination.
//!
//! Reads 128-byte group keys file (the 64 byte private keys of an identity shared by
//! all members, followed by the 64 byte group key), and arrive at the same destination
//! address.
//!
//! Usage:
//!
//! ```text
//! cargo run --example group -- --create group.keys
//! cargo run --example group -- group.keys tcp <host:port> [channel]
//! cargo run --example group -- group.keys udp <bind addr> <forward addr> [channel]
//! ```

use std::fs::OpenOptions;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::os::unix::fs::OpenOptionsExt;
use std::process::exit;

use rand_core::OsRng;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;

use reticulum::crypt::{GroupKey, GROUP_KEY_LENGTH};
use reticulum::destination::DestinationName;
use reticulum::identity::{GroupIdentity, PrivateIdentity, PUBLIC_KEY_LENGTH};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

const APP_NAME: &str = "example_utilities";
const DEFAULT_CHANNEL: &str = "default";

const IDENTITY_LENGTH: usize = PUBLIC_KEY_LENGTH * 2;
const KEY_LENGTH: usize = GROUP_KEY_LENGTH;

fn usage() -> ! {
    eprintln!("usage: group --create <group keys file>");
    eprintln!("       group <group keys file> tcp <host:port> [channel]");
    eprintln!("       group <group keys file> udp <bind addr> <forward addr> [channel]");
    exit(1);
}

fn create_group_keys(path: &str) {
    let identity = PrivateIdentity::new_from_rand(OsRng);
    let key = GroupKey::new_rand(OsRng);
    let mut group_keys: Vec<u8> = {
      // private keys are only available as a hex string
      let hex = identity.to_hex_string();
      (0..hex.len())
          .step_by(2)
          .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
          .collect()
    };
    group_keys.extend_from_slice(key.as_bytes());
    // make the file readable by the current user only
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path);
    match file {
        Ok(mut file) => {
            file.write_all(&group_keys).expect("write group keys file");
            log::info!("Created new group keys file {}", path);
        }
        Err(err) => {
            log::error!("Could not create group keys file {}: {}", path, err);
            exit(1);
        }
    }
}

fn load_group_keys(path: &str) -> GroupIdentity {
    let group_keys = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) => {
            log::error!("Could not read group keys file {}: {}", path, err);
            exit(1);
        }
    };
    if group_keys.len() != IDENTITY_LENGTH + KEY_LENGTH {
        log::error!("Invalid group keys file {}", path);
        exit(1);
    }
    let identity_hex: String = group_keys[..IDENTITY_LENGTH].iter()
      .map(|byte| format!("{:02x}", byte)).collect();
    let identity = match PrivateIdentity::new_from_hex_string(&identity_hex) {
        Ok(identity) => identity,
        Err(_) => {
            log::error!("Could not load identity from group keys file {}", path);
            exit(1);
        }
    };
    let key = GroupKey::new_from_slice(&group_keys[IDENTITY_LENGTH..]).expect("valid group key");
    GroupIdentity::new(*identity.as_identity(), key)
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if let ["--create", path] = args[..] {
        create_group_keys(path);
        return;
    }
    let (group_path, interface, channel) = match args[..] {
        [path, "tcp", addr] => (path, ("tcp", addr, None), DEFAULT_CHANNEL),
        [path, "tcp", addr, channel] => (path, ("tcp", addr, None), channel),
        [path, "udp", bind, forward] => (path, ("udp", bind, Some(forward)), DEFAULT_CHANNEL),
        [path, "udp", bind, forward, channel] => (path, ("udp", bind, Some(forward)), channel),
        _ => usage(),
    };
    // validate addresses
    let (_, addr, forward) = interface;
    for addr in std::iter::once(addr).chain(forward) {
        if let Err(err) = addr.to_socket_addrs() {
            log::error!("Invalid address {}: {}", addr, err);
            exit(1);
        }
    }

    let group_identity = load_group_keys(group_path);
    let mut transport = Transport::new(TransportConfig::default());
    {
        let iface_manager = transport.iface_manager();
        let mut iface_manager = iface_manager.lock().await;
        match interface {
            ("tcp", addr, _) => {
                iface_manager.spawn(TcpClient::new(addr), TcpClient::spawn);
            }
            (_, bind, forward) => {
                iface_manager.spawn(UdpInterface::new(bind, forward, false), UdpInterface::spawn);
            }
        }
    }

    let destination = transport
        .add_group_destination(
            group_identity,
            DestinationName::new(APP_NAME, &format!("group.{}", channel)),
        )
        .await;

    let address = destination.lock().await.desc.address_hash;

    log::info!(
        "Group example {} running, enter text and hit enter to send to the group (Ctrl-C to quit)",
        address
    );

    let mut received_data = transport.received_data_events();

    // read stdin on a plain thread: tokio's stdin uses a blocking thread
    // that keeps the runtime from shutting down until another line is read
    let (lines_tx, mut lines) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lines().map_while(Result::ok) {
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut stdin_open = true;
    let prompt = || {
        print!("> ");
        // no trailing newline, so flush explicitly
        let _ = std::io::stdout().flush();
    };
    prompt();

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            line = lines.recv(), if stdin_open => match line {
                Some(line) => {
                    if !line.is_empty() {
                        match destination.lock().await.data_packet(OsRng, line.as_bytes()) {
                            Ok(packet) => transport.send_packet(packet).await,
                            Err(err) => log::error!("Could not send message: {:?}", err),
                        }
                    }
                    prompt();
                }
                // keep receiving after stdin is closed
                None => stdin_open = false,
            },
            data = received_data.recv() => match data {
                Ok(data) if data.destination == address => {
                    println!("\nReceived data: {}", String::from_utf8_lossy(data.data.as_slice()));
                    if stdin_open {
                        prompt();
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(count)) => log::warn!("Missed {} received messages", count),
                Err(RecvError::Closed) => break,
            },
        }
    }

    println!();   // end the prompt line
    log::info!("exit");
}
