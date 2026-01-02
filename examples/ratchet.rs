use std::env;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{
    self, DestinationName, SingleOutputDestination,
};
use reticulum::hash::AddressHash;
use reticulum::identity::{Identity, PrivateIdentity};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};
use reticulum::identity::HashIdentity;
use reticulum::destination::link::LinkEvent;
use std::sync::Arc;
use tokio::sync::Mutex;

const APP_NAME: &str = "example_utilities";

fn store_identity_to_file(id: &PrivateIdentity, path: &str) {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(path).expect("unable to create identity file");
    let hex = id.to_hex_string();
    file.write_all(hex.as_bytes())
        .expect("unable to write identity to file");
}

fn load_identity_from_file(path: &str) -> Option<PrivateIdentity> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path).ok()?;
    let mut hex = String::new();
    file.read_to_string(&mut hex).ok()?;
    PrivateIdentity::new_from_hex_string(&hex).ok()
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    let args: Vec<String> = env::args().collect();
    
    if args.len() != 2 {
        eprintln!("Usage: {} <32-character-hex-destination>", args[0]);
        eprintln!("Example: {} 564f0ec8b6ff3cbbedb3b2bb6069f567", args[0]);
        return;
    }

    let destination_hex = &args[1];

    // Validate that the destination is exactly 32 hex characters
    if destination_hex.len() != 32 {
        log::error!("Destination hash must be exactly 32 hexadecimal characters");
        return;
    }

    log::info!(">>> Ratchet client <<<");

    let transport = Transport::new(TransportConfig::default());

    let client_addr: AddressHash = transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);
    log::info!("TCP Client listening on {}", client_addr);
    let identity_path = "/tmp/client_identity";
    let id = load_identity_from_file(identity_path).unwrap_or_else(|| {
        let id = PrivateIdentity::new_from_rand(OsRng);
        store_identity_to_file(&id, identity_path);
        id
    });

    let destination_hash = match AddressHash::new_from_hex_string(destination_hex) {
        Ok(hash) => hash,
        Err(e) => {
            log::error!("Invalid destination hash: {}", e);
            return;
        }
    };
    tokio::time::sleep(Duration::from_secs(3)).await;
    loop {
        if transport.has_path(&destination_hash).await {
            log::info!("Destination found in cache for hash: {}", destination_hash);
            let server_identity = match transport.recall_identity(&destination_hash, false).await {
                Some(identity) => {
                    log::info!("Recalled identity hash: {}", 
                        identity.as_address_hash_slice().iter().map(|b| format!("{:02x}", b)).collect::<String>());
                    identity
                },
                None => {
                    log::error!("Failed to recall identity for destination");
                    return;
                }
            };
            
            // This handles encryption automatically, just like Python does
            let payload: &str = "Hello, Reticulum!";
            
            transport
            .send_to_destination(&destination_hash, payload.as_bytes(), reticulum::packet::PacketContext::None)
            .await
            .expect("packet send");
            log::info!("Sent echo request to {}", destination_hash);
            
            let _ = tokio::signal::ctrl_c().await;
            break;
        } else {
            transport.request_path(&destination_hash, None).await;
            log::info!("Added destination with hash: {}", destination_hash);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        let test_bool = transport.has_path(&destination_hash).await;
        log::info!("Path exists: {}", test_bool);
    }
}
