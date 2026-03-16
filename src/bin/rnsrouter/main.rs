mod config;

use config::{Config, InterfaceConfig};
use rand_core::OsRng;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};
use tokio::signal;

struct Daemon {
    transport: Transport,
    config_path: std::path::PathBuf,
}

impl Daemon {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let (config, config_path) = Config::load()?;

        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(config.log_filter())
        ).init();

        log::info!("Reticulum daemon starting");
        log::info!("Configuration loaded from: {}", config_path.display());

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let transport = Transport::new({
            let mut cfg = TransportConfig::new(
                "rns-daemon",
                &identity,
                config.reticulum.enable_transport,
            );
            cfg.set_retransmit(config.reticulum.enable_transport);
            cfg
        });

        let iface_manager = transport.iface_manager();

    for iface in config.interfaces {
        let enabled = match &iface.config {
            InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
            InterfaceConfig::TCPClientInterface { enabled, .. } => *enabled,
            InterfaceConfig::UDPInterface { enabled, .. } => *enabled,
            InterfaceConfig::AutoInterface { enabled, .. } => *enabled,
            InterfaceConfig::I2PInterface { enabled, .. } => *enabled,
            InterfaceConfig::RNodeInterface { enabled, .. } => *enabled,
            InterfaceConfig::BLEInterface { enabled, .. } => *enabled,
            InterfaceConfig::KISSInterface { enabled, .. } => *enabled,
            InterfaceConfig::AX25KISSInterface { enabled, .. } => *enabled,
            InterfaceConfig::Unsupported => false,
        };
    
        if !enabled {
            continue;
        }

        match iface.config {
            InterfaceConfig::TCPServerInterface { bind_host, bind_port, .. } => {
                let addr = format!("{}:{}", bind_host.trim_end_matches(':'), bind_port);
                log::info!("Enabling interface '{}': TCP Server on {}", iface.name, addr);
                iface_manager.lock().await.spawn(
                    TcpServer::new(addr, iface_manager.clone()),
                    TcpServer::spawn,
                );
            }
            InterfaceConfig::TCPClientInterface { target_host, target_port, .. } => {
                let addr = format!("{}:{}", target_host.trim_end_matches(':'), target_port);
                log::info!("Enabling interface '{}': TCP Client to {}", iface.name, addr);
                iface_manager.lock().await.spawn(
                    TcpClient::new(addr),
                    TcpClient::spawn,
                );
            }
            InterfaceConfig::UDPInterface { listen_ip, listen_port, forward_ip, forward_port, .. } => {
                let bind_addr = format!("{}:{}", listen_ip, listen_port);
                let forward_addr = format!("{}:{}", forward_ip, forward_port);
                log::info!("Enabling interface '{}': UDP {}→{}", iface.name, bind_addr, forward_addr);
                iface_manager.lock().await.spawn(
                    UdpInterface::new(bind_addr, Some(forward_addr)),
                    UdpInterface::spawn,
                );
            }
            InterfaceConfig::AutoInterface { .. } => {
                log::warn!("Interface '{}' type 'AutoInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::I2PInterface { .. } => {
                log::warn!("Interface '{}' type 'I2PInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::RNodeInterface { .. } => {
                log::warn!("Interface '{}' type 'RNodeInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::BLEInterface { .. } => {
                log::warn!("Interface '{}' type 'BLEInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::KISSInterface { .. } => {
                log::warn!("Interface '{}' type 'KISSInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::AX25KISSInterface { .. } => {
                log::warn!("Interface '{}' type 'AX25KISSInterface' is not yet supported", iface.name);
            }
            InterfaceConfig::Unsupported => {
                log::warn!("Interface '{}' uses an unsupported type", iface.name);
            }
        }
    }

        Ok(Self {
            transport,
            config_path,
        })
    }

    async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("Reticulum instance running, interfaces initialized");
        
        signal::ctrl_c().await?;
        
        log::info!("Shutdown signal received, cleaning up");
        drop(self.transport);
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let daemon = Daemon::new().await?;
    daemon.run().await
}
