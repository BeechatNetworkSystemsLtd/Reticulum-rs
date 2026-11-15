use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use flume::Receiver;

uniffi::setup_scaffolding!();

// ═════════════════════════════════════════════════════════════════════════════
// ║  State snapshot                                                            ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Record, Clone, Debug)]
pub struct AppState {
    pub rev: u64,
    pub status: NodeStatus,
    pub capabilities: BackendCapabilities,
    pub active_identity: Option<IdentitySummary>,
    pub identities: Vec<IdentitySummary>,
    pub interfaces: Vec<InterfaceSummary>,
    pub destinations: Vec<DestinationSummary>,
    pub peers: Vec<PeerSummary>,
    pub links: Vec<LinkSummary>,
    pub paths: Vec<PathSummary>,
    pub tunnels: Vec<TunnelSummary>,
    pub known_destinations: Vec<KnownDestinationSummary>,
    pub messages: Vec<MessageSummary>,
    pub calls: Vec<CallSummary>,
    pub propagation: PropagationState,
    pub resources: Vec<ResourceSummary>,
    pub discovery: DiscoveryState,
    pub shared_instance: SharedInstanceState,
    pub toast: Option<String>,
}

impl From<reticulum_actor::types::State> for AppState {
    fn from(s: reticulum_actor::types::State) -> Self {
        Self {
            rev: s.rev,
            status: s.status.into(),
            capabilities: s.capabilities.into(),
            active_identity: s.active_identity.map(Into::into),
            identities: s.identities.into_iter().map(Into::into).collect(),
            interfaces: s.interfaces.into_iter().map(Into::into).collect(),
            destinations: s.destinations.into_iter().map(Into::into).collect(),
            peers: s.peers.into_iter().map(Into::into).collect(),
            links: s.links.into_iter().map(Into::into).collect(),
            paths: s.paths.into_iter().map(Into::into).collect(),
            tunnels: s.tunnels.into_iter().map(Into::into).collect(),
            known_destinations: s.known_destinations.into_iter().map(Into::into).collect(),
            messages: s.messages.into_iter().map(Into::into).collect(),
            calls: s.calls.into_iter().map(Into::into).collect(),
            propagation: s.propagation.into(),
            resources: s.resources.into_iter().map(Into::into).collect(),
            discovery: s.discovery.into(),
            shared_instance: s.shared_instance.into(),
            toast: s.toast,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Status, capabilities, network tick, log level                             ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum NodeStatus {
    Stopped,
    Starting,
    Running { identity_hash: String },
    Error { message: String },
}

impl From<reticulum_actor::types::NodeStatus> for NodeStatus {
    fn from(s: reticulum_actor::types::NodeStatus) -> Self {
        match s {
            reticulum_actor::types::NodeStatus::Stopped => NodeStatus::Stopped,
            reticulum_actor::types::NodeStatus::Starting => NodeStatus::Starting,
            reticulum_actor::types::NodeStatus::Running { identity_hash } => {
                NodeStatus::Running { identity_hash }
            }
            reticulum_actor::types::NodeStatus::Error { message } => NodeStatus::Error { message },
        }
    }
}

impl From<NodeStatus> for reticulum_actor::types::NodeStatus {
    fn from(s: NodeStatus) -> Self {
        match s {
            NodeStatus::Stopped => reticulum_actor::types::NodeStatus::Stopped,
            NodeStatus::Starting => reticulum_actor::types::NodeStatus::Starting,
            NodeStatus::Running { identity_hash } => {
                reticulum_actor::types::NodeStatus::Running { identity_hash }
            }
            NodeStatus::Error { message } => reticulum_actor::types::NodeStatus::Error { message },
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct BackendCapabilities {
    pub tcp_client: bool,
    pub tcp_server: bool,
    pub udp: bool,
    pub auto: bool,
    pub rnode: bool,
    pub serial: bool,
    pub kiss: bool,
    pub ax25: bool,
    pub i2p: bool,
    pub pipe: bool,
    pub backbone: bool,
    pub local_client: bool,
    pub local_server: bool,
    pub transport_bridge: bool,
    pub keychain_bridge: bool,
    pub audio_bridge: bool,
    pub log: bool,
    pub lxmf: bool,
    pub propagation: bool,
    pub lxst: bool,
    pub resources: bool,
    pub discovery: bool,
    pub shared_instance: bool,
}

impl From<reticulum_actor::types::BackendCapabilities> for BackendCapabilities {
    fn from(c: reticulum_actor::types::BackendCapabilities) -> Self {
        Self {
            tcp_client: c.tcp_client,
            tcp_server: c.tcp_server,
            udp: c.udp,
            auto: c.auto,
            rnode: c.rnode,
            serial: c.serial,
            kiss: c.kiss,
            ax25: c.ax25,
            i2p: c.i2p,
            pipe: c.pipe,
            backbone: c.backbone,
            local_client: c.local_client,
            local_server: c.local_server,
            transport_bridge: c.transport_bridge,
            keychain_bridge: c.keychain_bridge,
            audio_bridge: c.audio_bridge,
            log: c.log,
            lxmf: c.lxmf,
            propagation: c.propagation,
            lxst: c.lxst,
            resources: c.resources,
            discovery: c.discovery,
            shared_instance: c.shared_instance,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct NetworkTick {
    pub timestamp_ms: u64,
    pub interfaces: Vec<InterfaceSummary>,
}

impl From<reticulum_actor::types::NetworkTick> for NetworkTick {
    fn from(t: reticulum_actor::types::NetworkTick) -> Self {
        Self {
            timestamp_ms: t.timestamp_ms,
            interfaces: t.interfaces.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<reticulum_actor::types::LogLevel> for LogLevel {
    fn from(l: reticulum_actor::types::LogLevel) -> Self {
        match l {
            reticulum_actor::types::LogLevel::Trace => LogLevel::Trace,
            reticulum_actor::types::LogLevel::Debug => LogLevel::Debug,
            reticulum_actor::types::LogLevel::Info => LogLevel::Info,
            reticulum_actor::types::LogLevel::Warn => LogLevel::Warn,
            reticulum_actor::types::LogLevel::Error => LogLevel::Error,
        }
    }
}

impl From<LogLevel> for reticulum_actor::types::LogLevel {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Trace => reticulum_actor::types::LogLevel::Trace,
            LogLevel::Debug => reticulum_actor::types::LogLevel::Debug,
            LogLevel::Info => reticulum_actor::types::LogLevel::Info,
            LogLevel::Warn => reticulum_actor::types::LogLevel::Warn,
            LogLevel::Error => reticulum_actor::types::LogLevel::Error,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Identities, interfaces, destinations, peers, links, paths                 ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Record, Clone, Debug)]
pub struct IdentitySummary {
    pub name: String,
    pub address_hash: String,
    pub public_key_hex: String,
    pub active: bool,
    pub encrypted: bool,
}

impl From<reticulum_actor::types::IdentitySummary> for IdentitySummary {
    fn from(s: reticulum_actor::types::IdentitySummary) -> Self {
        Self {
            name: s.name,
            address_hash: s.address_hash,
            public_key_hex: s.public_key_hex,
            active: s.active,
            encrypted: s.encrypted,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct InterfaceSummary {
    pub address: String,
    pub name: String,
    pub kind: String,
    pub enabled: bool,
    pub online: bool,
    pub failed: bool,
    pub sent: u64,
    pub received: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub announces_received: u64,
    pub announces_sent: u64,
    pub announce_bytes_received: u64,
    pub announce_bytes_sent: u64,
    pub path_requests_received: u64,
    pub path_requests_sent: u64,
    pub protocol_violations: u64,
    pub ifac_violations: u64,
    pub packet_filter_hits: u64,
    pub mode: String,
    pub bitrate: u64,
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    pub rssi: Option<i16>,
    pub snr: Option<f64>,
    pub quality: Option<f64>,
}

impl From<reticulum_actor::types::InterfaceSummary> for InterfaceSummary {
    fn from(s: reticulum_actor::types::InterfaceSummary) -> Self {
        Self {
            address: s.address,
            name: s.name,
            kind: s.kind,
            enabled: s.enabled,
            online: s.online,
            failed: s.failed,
            sent: s.sent,
            received: s.received,
            tx_bytes: s.tx_bytes,
            rx_bytes: s.rx_bytes,
            announces_received: s.announces_received,
            announces_sent: s.announces_sent,
            announce_bytes_received: s.announce_bytes_received,
            announce_bytes_sent: s.announce_bytes_sent,
            path_requests_received: s.path_requests_received,
            path_requests_sent: s.path_requests_sent,
            protocol_violations: s.protocol_violations,
            ifac_violations: s.ifac_violations,
            packet_filter_hits: s.packet_filter_hits,
            mode: s.mode,
            bitrate: s.bitrate,
            ifac_netname: s.ifac_netname,
            ifac_netkey: s.ifac_netkey,
            rssi: s.rssi,
            snr: s.snr,
            quality: s.quality,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct IfacConfig {
    pub netname: Option<String>,
    pub netkey: Option<String>,
    pub size: u32,
}

impl From<reticulum_actor::types::IfacConfig> for IfacConfig {
    fn from(c: reticulum_actor::types::IfacConfig) -> Self {
        Self {
            netname: c.netname,
            netkey: c.netkey,
            size: c.size,
        }
    }
}

impl From<IfacConfig> for reticulum_actor::types::IfacConfig {
    fn from(c: IfacConfig) -> Self {
        Self {
            netname: c.netname,
            netkey: c.netkey,
            size: c.size,
        }
    }
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum SharedInstanceAddress {
    Tcp { port: u16 },
    UnixAbstract { name: String },
}

impl From<reticulum_actor::types::SharedInstanceAddress> for SharedInstanceAddress {
    fn from(a: reticulum_actor::types::SharedInstanceAddress) -> Self {
        match a {
            reticulum_actor::types::SharedInstanceAddress::Tcp { port } => {
                SharedInstanceAddress::Tcp { port }
            }
            reticulum_actor::types::SharedInstanceAddress::UnixAbstract { name } => {
                SharedInstanceAddress::UnixAbstract { name }
            }
        }
    }
}

impl From<SharedInstanceAddress> for reticulum_actor::types::SharedInstanceAddress {
    fn from(a: SharedInstanceAddress) -> Self {
        match a {
            SharedInstanceAddress::Tcp { port } => {
                reticulum_actor::types::SharedInstanceAddress::Tcp { port }
            }
            SharedInstanceAddress::UnixAbstract { name } => {
                reticulum_actor::types::SharedInstanceAddress::UnixAbstract { name }
            }
        }
    }
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum InterfaceConfig {
    TcpClient {
        address: String,
    },
    TcpServer {
        bind: String,
    },
    Udp {
        bind: String,
        forward: Option<String>,
        broadcast: bool,
    },
    Auto {
        group_id: String,
    },
    RnodeTcp {
        address: String,
    },
    RnodeSerial {
        port: String,
        speed: u32,
    },
    RnodeMulti {
        tcp_addr: Option<String>,
        serial_port: Option<String>,
        baudrate: u32,
    },
    Serial {
        port: String,
        speed: u32,
    },
    Kiss {
        port: String,
        speed: u32,
    },
    KissAx25 {
        callsign: String,
        ssid: u8,
        port: String,
        speed: u32,
    },
    I2pClient {
        sam_addr: String,
        session_id: String,
        destination: String,
    },
    I2pServer {
        sam_addr: String,
        session_id: String,
    },
    Pipe {
        command: String,
    },
    BackboneClient {
        address: String,
    },
    BackboneServer {
        bind: String,
    },
    LocalClient {
        name: String,
        address: SharedInstanceAddress,
    },
    LocalServer {
        address: SharedInstanceAddress,
    },
    Bridge {
        kind: String,
    },
}

impl From<reticulum_actor::types::InterfaceConfig> for InterfaceConfig {
    fn from(c: reticulum_actor::types::InterfaceConfig) -> Self {
        match c {
            reticulum_actor::types::InterfaceConfig::TcpClient { address } => {
                InterfaceConfig::TcpClient { address }
            }
            reticulum_actor::types::InterfaceConfig::TcpServer { bind } => {
                InterfaceConfig::TcpServer { bind }
            }
            reticulum_actor::types::InterfaceConfig::Udp {
                bind,
                forward,
                broadcast,
            } => InterfaceConfig::Udp {
                bind,
                forward,
                broadcast,
            },
            reticulum_actor::types::InterfaceConfig::Auto { group_id } => {
                InterfaceConfig::Auto { group_id }
            }
            reticulum_actor::types::InterfaceConfig::RnodeTcp { address } => {
                InterfaceConfig::RnodeTcp { address }
            }
            reticulum_actor::types::InterfaceConfig::RnodeSerial { port, speed } => {
                InterfaceConfig::RnodeSerial { port, speed }
            }
            reticulum_actor::types::InterfaceConfig::RnodeMulti {
                tcp_addr,
                serial_port,
                baudrate,
            } => InterfaceConfig::RnodeMulti {
                tcp_addr,
                serial_port,
                baudrate,
            },
            reticulum_actor::types::InterfaceConfig::Serial { port, speed } => {
                InterfaceConfig::Serial { port, speed }
            }
            reticulum_actor::types::InterfaceConfig::Kiss { port, speed } => {
                InterfaceConfig::Kiss { port, speed }
            }
            reticulum_actor::types::InterfaceConfig::KissAx25 {
                callsign,
                ssid,
                port,
                speed,
            } => InterfaceConfig::KissAx25 {
                callsign,
                ssid,
                port,
                speed,
            },
            reticulum_actor::types::InterfaceConfig::I2pClient {
                sam_addr,
                session_id,
                destination,
            } => InterfaceConfig::I2pClient {
                sam_addr,
                session_id,
                destination,
            },
            reticulum_actor::types::InterfaceConfig::I2pServer {
                sam_addr,
                session_id,
            } => InterfaceConfig::I2pServer {
                sam_addr,
                session_id,
            },
            reticulum_actor::types::InterfaceConfig::Pipe { command } => {
                InterfaceConfig::Pipe { command }
            }
            reticulum_actor::types::InterfaceConfig::BackboneClient { address } => {
                InterfaceConfig::BackboneClient { address }
            }
            reticulum_actor::types::InterfaceConfig::BackboneServer { bind } => {
                InterfaceConfig::BackboneServer { bind }
            }
            reticulum_actor::types::InterfaceConfig::LocalClient { name, address } => {
                InterfaceConfig::LocalClient {
                    name,
                    address: address.into(),
                }
            }
            reticulum_actor::types::InterfaceConfig::LocalServer { address } => {
                InterfaceConfig::LocalServer {
                    address: address.into(),
                }
            }
            reticulum_actor::types::InterfaceConfig::Bridge { kind } => {
                InterfaceConfig::Bridge { kind }
            }
        }
    }
}

impl From<InterfaceConfig> for reticulum_actor::types::InterfaceConfig {
    fn from(c: InterfaceConfig) -> Self {
        match c {
            InterfaceConfig::TcpClient { address } => {
                reticulum_actor::types::InterfaceConfig::TcpClient { address }
            }
            InterfaceConfig::TcpServer { bind } => {
                reticulum_actor::types::InterfaceConfig::TcpServer { bind }
            }
            InterfaceConfig::Udp {
                bind,
                forward,
                broadcast,
            } => reticulum_actor::types::InterfaceConfig::Udp {
                bind,
                forward,
                broadcast,
            },
            InterfaceConfig::Auto { group_id } => {
                reticulum_actor::types::InterfaceConfig::Auto { group_id }
            }
            InterfaceConfig::RnodeTcp { address } => {
                reticulum_actor::types::InterfaceConfig::RnodeTcp { address }
            }
            InterfaceConfig::RnodeSerial { port, speed } => {
                reticulum_actor::types::InterfaceConfig::RnodeSerial { port, speed }
            }
            InterfaceConfig::RnodeMulti {
                tcp_addr,
                serial_port,
                baudrate,
            } => reticulum_actor::types::InterfaceConfig::RnodeMulti {
                tcp_addr,
                serial_port,
                baudrate,
            },
            InterfaceConfig::Serial { port, speed } => {
                reticulum_actor::types::InterfaceConfig::Serial { port, speed }
            }
            InterfaceConfig::Kiss { port, speed } => {
                reticulum_actor::types::InterfaceConfig::Kiss { port, speed }
            }
            InterfaceConfig::KissAx25 {
                callsign,
                ssid,
                port,
                speed,
            } => reticulum_actor::types::InterfaceConfig::KissAx25 {
                callsign,
                ssid,
                port,
                speed,
            },
            InterfaceConfig::I2pClient {
                sam_addr,
                session_id,
                destination,
            } => reticulum_actor::types::InterfaceConfig::I2pClient {
                sam_addr,
                session_id,
                destination,
            },
            InterfaceConfig::I2pServer {
                sam_addr,
                session_id,
            } => reticulum_actor::types::InterfaceConfig::I2pServer {
                sam_addr,
                session_id,
            },
            InterfaceConfig::Pipe { command } => {
                reticulum_actor::types::InterfaceConfig::Pipe { command }
            }
            InterfaceConfig::BackboneClient { address } => {
                reticulum_actor::types::InterfaceConfig::BackboneClient { address }
            }
            InterfaceConfig::BackboneServer { bind } => {
                reticulum_actor::types::InterfaceConfig::BackboneServer { bind }
            }
            InterfaceConfig::LocalClient { name, address } => {
                reticulum_actor::types::InterfaceConfig::LocalClient {
                    name,
                    address: address.into(),
                }
            }
            InterfaceConfig::LocalServer { address } => {
                reticulum_actor::types::InterfaceConfig::LocalServer {
                    address: address.into(),
                }
            }
            InterfaceConfig::Bridge { kind } => {
                reticulum_actor::types::InterfaceConfig::Bridge { kind }
            }
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct DestinationSummary {
    pub address_hash: String,
    pub app_name: String,
    pub aspect: String,
    pub accepts_links: bool,
    pub ratchets_enabled: bool,
}

impl From<reticulum_actor::types::DestinationSummary> for DestinationSummary {
    fn from(s: reticulum_actor::types::DestinationSummary) -> Self {
        Self {
            address_hash: s.address_hash,
            app_name: s.app_name,
            aspect: s.aspect,
            accepts_links: s.accepts_links,
            ratchets_enabled: s.ratchets_enabled,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PeerSummary {
    pub address_hash: String,
    pub name_hash_hex: String,
    pub app_data: Vec<u8>,
    pub hops: Option<u8>,
}

impl From<reticulum_actor::types::PeerSummary> for PeerSummary {
    fn from(s: reticulum_actor::types::PeerSummary) -> Self {
        Self {
            address_hash: s.address_hash,
            name_hash_hex: s.name_hash_hex,
            app_data: s.app_data,
            hops: s.hops,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct LinkSummary {
    pub id: String,
    pub destination_hash: String,
    pub status: String,
    pub is_outbound: bool,
    pub mdu: u64,
}

impl From<reticulum_actor::types::LinkSummary> for LinkSummary {
    fn from(s: reticulum_actor::types::LinkSummary) -> Self {
        Self {
            id: s.id,
            destination_hash: s.destination_hash,
            status: s.status,
            is_outbound: s.is_outbound,
            mdu: s.mdu,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PathSummary {
    pub destination_hash: String,
    pub hops: u8,
    pub via: String,
    pub interface: String,
    pub timestamp: f64,
    pub unresponsive: bool,
}

impl From<reticulum_actor::types::PathSummary> for PathSummary {
    fn from(s: reticulum_actor::types::PathSummary) -> Self {
        Self {
            destination_hash: s.destination_hash,
            hops: s.hops,
            via: s.via,
            interface: s.interface,
            timestamp: s.timestamp,
            unresponsive: s.unresponsive,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct TunnelSummary {
    pub destination_hash: String,
    pub interface: String,
    pub hops: u8,
    pub expires: f64,
}

impl From<reticulum_actor::types::TunnelSummary> for TunnelSummary {
    fn from(s: reticulum_actor::types::TunnelSummary) -> Self {
        Self {
            destination_hash: s.destination_hash,
            interface: s.interface,
            hops: s.hops,
            expires: s.expires,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct KnownDestinationSummary {
    pub destination_hash: String,
    pub app_data: Vec<u8>,
    pub retained: bool,
    pub last_seen: f64,
    pub identity_hash: Option<String>,
}

impl From<reticulum_actor::types::KnownDestinationSummary> for KnownDestinationSummary {
    fn from(s: reticulum_actor::types::KnownDestinationSummary) -> Self {
        Self {
            destination_hash: s.destination_hash,
            app_data: s.app_data,
            retained: s.retained,
            last_seen: s.last_seen,
            identity_hash: s.identity_hash,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  LXMF messaging                                                            ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Record, Clone, Debug)]
pub struct LxmfDeliveryConfig {
    pub display_name: Option<String>,
    pub stamp_cost: Option<u8>,
}

impl From<reticulum_actor::types::LxmfDeliveryConfig> for LxmfDeliveryConfig {
    fn from(c: reticulum_actor::types::LxmfDeliveryConfig) -> Self {
        Self {
            display_name: c.display_name,
            stamp_cost: c.stamp_cost,
        }
    }
}

impl From<LxmfDeliveryConfig> for reticulum_actor::types::LxmfDeliveryConfig {
    fn from(c: LxmfDeliveryConfig) -> Self {
        Self {
            display_name: c.display_name,
            stamp_cost: c.stamp_cost,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct RouterConfig {
    pub propagation_node: bool,
    pub message_storage_limit: u64,
    pub propagation_transfer_limit: u64,
    pub auto_announce: bool,
}

impl From<reticulum_actor::types::RouterConfig> for RouterConfig {
    fn from(c: reticulum_actor::types::RouterConfig) -> Self {
        Self {
            propagation_node: c.propagation_node,
            message_storage_limit: c.message_storage_limit,
            propagation_transfer_limit: c.propagation_transfer_limit,
            auto_announce: c.auto_announce,
        }
    }
}

impl From<RouterConfig> for reticulum_actor::types::RouterConfig {
    fn from(c: RouterConfig) -> Self {
        Self {
            propagation_node: c.propagation_node,
            message_storage_limit: c.message_storage_limit,
            propagation_transfer_limit: c.propagation_transfer_limit,
            auto_announce: c.auto_announce,
        }
    }
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum LxmfDeliveryMethod {
    Direct,
    Opportunistic,
    Propagated,
    Paper,
}

impl From<reticulum_actor::types::LxmfDeliveryMethod> for LxmfDeliveryMethod {
    fn from(m: reticulum_actor::types::LxmfDeliveryMethod) -> Self {
        match m {
            reticulum_actor::types::LxmfDeliveryMethod::Direct => LxmfDeliveryMethod::Direct,
            reticulum_actor::types::LxmfDeliveryMethod::Opportunistic => {
                LxmfDeliveryMethod::Opportunistic
            }
            reticulum_actor::types::LxmfDeliveryMethod::Propagated => {
                LxmfDeliveryMethod::Propagated
            }
            reticulum_actor::types::LxmfDeliveryMethod::Paper => LxmfDeliveryMethod::Paper,
        }
    }
}

impl From<LxmfDeliveryMethod> for reticulum_actor::types::LxmfDeliveryMethod {
    fn from(m: LxmfDeliveryMethod) -> Self {
        match m {
            LxmfDeliveryMethod::Direct => reticulum_actor::types::LxmfDeliveryMethod::Direct,
            LxmfDeliveryMethod::Opportunistic => {
                reticulum_actor::types::LxmfDeliveryMethod::Opportunistic
            }
            LxmfDeliveryMethod::Propagated => {
                reticulum_actor::types::LxmfDeliveryMethod::Propagated
            }
            LxmfDeliveryMethod::Paper => reticulum_actor::types::LxmfDeliveryMethod::Paper,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct LxmfMessageFields {
    pub text: Option<String>,
    pub title: Option<String>,
    pub image: Option<Vec<u8>>,
    pub audio: Option<Vec<u8>>,
    pub files: Vec<LxmfAttachment>,
    pub icon_appearance: Option<u32>,
    pub telemetry: Option<Vec<u8>>,
    pub reactions: Vec<LxmfReaction>,
    pub reply_to: Option<String>,
    pub reply_quote: Option<String>,
    pub renderer: Option<String>,
    pub custom_data: Option<Vec<u8>>,
    pub custom_type: Option<u32>,
}

impl From<reticulum_actor::types::LxmfMessageFields> for LxmfMessageFields {
    fn from(f: reticulum_actor::types::LxmfMessageFields) -> Self {
        Self {
            text: f.text,
            title: f.title,
            image: f.image,
            audio: f.audio,
            files: f.files.into_iter().map(Into::into).collect(),
            icon_appearance: f.icon_appearance,
            telemetry: f.telemetry,
            reactions: f.reactions.into_iter().map(Into::into).collect(),
            reply_to: f.reply_to,
            reply_quote: f.reply_quote,
            renderer: f.renderer,
            custom_data: f.custom_data,
            custom_type: f.custom_type,
        }
    }
}

impl From<LxmfMessageFields> for reticulum_actor::types::LxmfMessageFields {
    fn from(f: LxmfMessageFields) -> Self {
        Self {
            text: f.text,
            title: f.title,
            image: f.image,
            audio: f.audio,
            files: f.files.into_iter().map(Into::into).collect(),
            icon_appearance: f.icon_appearance,
            telemetry: f.telemetry,
            reactions: f.reactions.into_iter().map(Into::into).collect(),
            reply_to: f.reply_to,
            reply_quote: f.reply_quote,
            renderer: f.renderer,
            custom_data: f.custom_data,
            custom_type: f.custom_type,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct LxmfAttachment {
    pub file_name: String,
    pub data: Vec<u8>,
    pub mime_type: Option<String>,
}

impl From<reticulum_actor::types::LxmfAttachment> for LxmfAttachment {
    fn from(a: reticulum_actor::types::LxmfAttachment) -> Self {
        Self {
            file_name: a.file_name,
            data: a.data,
            mime_type: a.mime_type,
        }
    }
}

impl From<LxmfAttachment> for reticulum_actor::types::LxmfAttachment {
    fn from(a: LxmfAttachment) -> Self {
        Self {
            file_name: a.file_name,
            data: a.data,
            mime_type: a.mime_type,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct LxmfReaction {
    pub to_message_hash: String,
    pub content: String,
}

impl From<reticulum_actor::types::LxmfReaction> for LxmfReaction {
    fn from(r: reticulum_actor::types::LxmfReaction) -> Self {
        Self {
            to_message_hash: r.to_message_hash,
            content: r.content,
        }
    }
}

impl From<LxmfReaction> for reticulum_actor::types::LxmfReaction {
    fn from(r: LxmfReaction) -> Self {
        Self {
            to_message_hash: r.to_message_hash,
            content: r.content,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct MessageSummary {
    pub hash: String,
    pub source_hash: String,
    pub destination_hash: String,
    pub title: Option<String>,
    pub content: Option<String>,
    pub state: String,
    pub method: String,
    pub timestamp: f64,
    pub progress: f64,
    pub fields: LxmfMessageFields,
}

impl From<reticulum_actor::types::MessageSummary> for MessageSummary {
    fn from(s: reticulum_actor::types::MessageSummary) -> Self {
        Self {
            hash: s.hash,
            source_hash: s.source_hash,
            destination_hash: s.destination_hash,
            title: s.title,
            content: s.content,
            state: s.state,
            method: s.method,
            timestamp: s.timestamp,
            progress: s.progress,
            fields: s.fields.into(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct PropagationState {
    pub active_node: Option<String>,
    pub sync_state: String,
    pub sync_progress: f64,
    pub sync_size: u64,
    pub entries: Vec<PropagationEntrySummary>,
    pub peers: Vec<PropagationPeerSummary>,
}

impl From<reticulum_actor::types::PropagationState> for PropagationState {
    fn from(s: reticulum_actor::types::PropagationState) -> Self {
        Self {
            active_node: s.active_node,
            sync_state: s.sync_state,
            sync_progress: s.sync_progress,
            sync_size: s.sync_size,
            entries: s.entries.into_iter().map(Into::into).collect(),
            peers: s.peers.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PropagationEntrySummary {
    pub hash: String,
    pub source: String,
    pub destination: String,
    pub received: f64,
    pub size: u64,
}

impl From<reticulum_actor::types::PropagationEntrySummary> for PropagationEntrySummary {
    fn from(s: reticulum_actor::types::PropagationEntrySummary) -> Self {
        Self {
            hash: s.hash,
            source: s.source,
            destination: s.destination,
            received: s.received,
            size: s.size,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PropagationPeerSummary {
    pub destination_hash: String,
    pub name: Option<String>,
    pub peering_value: i64,
}

impl From<reticulum_actor::types::PropagationPeerSummary> for PropagationPeerSummary {
    fn from(s: reticulum_actor::types::PropagationPeerSummary) -> Self {
        Self {
            destination_hash: s.destination_hash,
            name: s.name,
            peering_value: s.peering_value,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  LXST calls                                                                ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum CallState {
    Idle,
    Calling,
    Ringing,
    Established,
    Ended,
}

impl From<reticulum_actor::types::CallState> for CallState {
    fn from(s: reticulum_actor::types::CallState) -> Self {
        match s {
            reticulum_actor::types::CallState::Idle => CallState::Idle,
            reticulum_actor::types::CallState::Calling => CallState::Calling,
            reticulum_actor::types::CallState::Ringing => CallState::Ringing,
            reticulum_actor::types::CallState::Established => CallState::Established,
            reticulum_actor::types::CallState::Ended => CallState::Ended,
        }
    }
}

impl From<CallState> for reticulum_actor::types::CallState {
    fn from(s: CallState) -> Self {
        match s {
            CallState::Idle => reticulum_actor::types::CallState::Idle,
            CallState::Calling => reticulum_actor::types::CallState::Calling,
            CallState::Ringing => reticulum_actor::types::CallState::Ringing,
            CallState::Established => reticulum_actor::types::CallState::Established,
            CallState::Ended => reticulum_actor::types::CallState::Ended,
        }
    }
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq)]
pub enum CodecType {
    Raw,
    Opus,
    Codec2,
    Null,
}

impl From<reticulum_actor::types::CodecType> for CodecType {
    fn from(c: reticulum_actor::types::CodecType) -> Self {
        match c {
            reticulum_actor::types::CodecType::Raw => CodecType::Raw,
            reticulum_actor::types::CodecType::Opus => CodecType::Opus,
            reticulum_actor::types::CodecType::Codec2 => CodecType::Codec2,
            reticulum_actor::types::CodecType::Null => CodecType::Null,
        }
    }
}

impl From<CodecType> for reticulum_actor::types::CodecType {
    fn from(c: CodecType) -> Self {
        match c {
            CodecType::Raw => reticulum_actor::types::CodecType::Raw,
            CodecType::Opus => reticulum_actor::types::CodecType::Opus,
            CodecType::Codec2 => reticulum_actor::types::CodecType::Codec2,
            CodecType::Null => reticulum_actor::types::CodecType::Null,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct CallSummary {
    pub id: String,
    pub destination_hash: String,
    pub state: String,
    pub codec: String,
    pub muted: bool,
    pub speaker: bool,
    pub quality: Option<f64>,
    pub rssi: Option<i16>,
    pub snr: Option<f64>,
    pub radio_quality: Option<f64>,
}

impl From<reticulum_actor::types::CallSummary> for CallSummary {
    fn from(s: reticulum_actor::types::CallSummary) -> Self {
        Self {
            id: s.id,
            destination_hash: s.destination_hash,
            state: s.state,
            codec: s.codec,
            muted: s.muted,
            speaker: s.speaker,
            quality: s.quality,
            rssi: s.rssi,
            snr: s.snr,
            radio_quality: s.radio_quality,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct AudioFrame {
    pub call_id: String,
    pub codec: String,
    pub data: Vec<u8>,
}

impl From<reticulum_actor::types::AudioFrame> for AudioFrame {
    fn from(f: reticulum_actor::types::AudioFrame) -> Self {
        Self {
            call_id: f.call_id,
            codec: f.codec,
            data: f.data,
        }
    }
}

impl From<AudioFrame> for reticulum_actor::types::AudioFrame {
    fn from(f: AudioFrame) -> Self {
        Self {
            call_id: f.call_id,
            codec: f.codec,
            data: f.data,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Resources, discovery, shared instance                                     ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Record, Clone, Debug)]
pub struct ResourceSummary {
    pub hash: String,
    pub link_id: String,
    pub status: String,
    pub progress: f64,
    pub size: u64,
    pub metadata: Option<Vec<u8>>,
    pub outgoing: bool,
}

impl From<reticulum_actor::types::ResourceSummary> for ResourceSummary {
    fn from(s: reticulum_actor::types::ResourceSummary) -> Self {
        Self {
            hash: s.hash,
            link_id: s.link_id,
            status: s.status,
            progress: s.progress,
            size: s.size,
            metadata: s.metadata,
            outgoing: s.outgoing,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct DiscoveryState {
    pub announcing: bool,
    pub listening: bool,
    pub autoconnect: bool,
    pub interfaces: Vec<DiscoveredInterfaceSummary>,
}

impl From<reticulum_actor::types::DiscoveryState> for DiscoveryState {
    fn from(s: reticulum_actor::types::DiscoveryState) -> Self {
        Self {
            announcing: s.announcing,
            listening: s.listening,
            autoconnect: s.autoconnect,
            interfaces: s.interfaces.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct DiscoveredInterfaceSummary {
    pub name: String,
    pub interface_type: String,
    pub address: String,
    pub port: u16,
    pub status: String,
    pub transport_id: String,
}

impl From<reticulum_actor::types::DiscoveredInterfaceSummary> for DiscoveredInterfaceSummary {
    fn from(s: reticulum_actor::types::DiscoveredInterfaceSummary) -> Self {
        Self {
            name: s.name,
            interface_type: s.interface_type,
            address: s.address,
            port: s.port,
            status: s.status,
            transport_id: s.transport_id,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct SharedInstanceState {
    pub hosting: bool,
    pub address: Option<SharedInstanceAddress>,
    pub clients: Vec<String>,
}

impl From<reticulum_actor::types::SharedInstanceState> for SharedInstanceState {
    fn from(s: reticulum_actor::types::SharedInstanceState) -> Self {
        Self {
            hosting: s.hosting,
            address: s.address.map(Into::into),
            clients: s.clients,
        }
    }
}

/// Access control for a hosted shared instance.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct AppSharedInstanceAccessConfig {
    /// Client names allowed to connect (empty = allow any).
    pub allow: Vec<String>,
    /// Require clients to authenticate with this token.
    pub required_token: Option<Vec<u8>>,
    /// Maximum simultaneously connected clients (None = unlimited).
    pub max_clients: Option<u32>,
}

impl From<AppSharedInstanceAccessConfig> for reticulum_actor::types::SharedInstanceAccessConfig {
    fn from(a: AppSharedInstanceAccessConfig) -> Self {
        Self {
            allow: a.allow,
            required_token: a.required_token,
            max_clients: a.max_clients,
        }
    }
}

/// Runtime audio-pump policy for LXST calls.
#[derive(uniffi::Record, Clone, Debug)]
pub struct AppAudioPolicy {
    /// Bridge callback latency (ms) above which `AppUpdate::AudioWarning`
    /// is emitted.
    pub warning_latency_ms: u64,
    /// Consecutive bridge failures before the pump falls back to
    /// null-codec mode.
    pub max_consecutive_failures: u32,
    /// Minimum call quality (0.0–1.0); calls below it auto-close.
    pub min_quality: Option<f64>,
    /// Consecutive low-quality network ticks tolerated before auto-close.
    pub quality_grace_ticks: u32,
}

impl From<AppAudioPolicy> for reticulum_actor::types::AudioPolicy {
    fn from(p: AppAudioPolicy) -> Self {
        Self {
            warning_latency_ms: p.warning_latency_ms,
            max_consecutive_failures: p.max_consecutive_failures,
            min_quality: p.min_quality,
            quality_grace_ticks: p.quality_grace_ticks,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Actions                                                                   ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Enum, Clone, Debug)]
pub enum AppAction {
    Start {
        transport_enabled: bool,
        identity_address: Option<String>,
    },
    Stop,

    AddInterface {
        name: String,
        config: InterfaceConfig,
        ifac: Option<IfacConfig>,
        enabled: bool,
    },
    RemoveInterface {
        address: String,
    },
    RenameInterface {
        address: String,
        name: String,
    },
    RestartInterface {
        address: String,
    },
    SetInterfaceEnabled {
        address: String,
        enabled: bool,
    },
    SetInterfaceMode {
        address: String,
        mode: String,
    },
    SetInterfaceBitrate {
        address: String,
        bitrate: u64,
    },
    SetInterfaceIfac {
        address: String,
        ifac: IfacConfig,
    },

    CreateIdentity {
        name: String,
    },
    ImportIdentity {
        name: String,
        hex: String,
    },
    ImportIdentityFile {
        name: String,
        path: String,
    },
    ExportIdentity {
        address: String,
        path: String,
    },
    ActivateIdentity {
        address: String,
    },
    RemoveIdentity {
        address: String,
    },
    SetKeychainBridge,

    CreateDestination {
        app_name: String,
        aspect: String,
    },
    LoadDestination {
        identity_hex: String,
        app_name: String,
        aspect: String,
    },
    Announce {
        destination_hash: String,
        app_data: Vec<u8>,
    },
    RequestPath {
        destination_hash: String,
    },
    DropPath {
        destination_hash: String,
    },
    MarkPathUnresponsive {
        destination_hash: String,
    },
    MarkPathResponsive {
        destination_hash: String,
    },

    OpenLink {
        destination_hash: String,
    },
    CloseLink {
        destination_hash: String,
    },
    SendData {
        destination_hash: String,
        data: Vec<u8>,
    },
    SendRequest {
        destination_hash: String,
        path: String,
        data: Vec<u8>,
        timeout_ms: u64,
    },
    RegisterRequestHandler {
        destination_hash: String,
        path: String,
    },
    SendResponse {
        request_id: String,
        data: Vec<u8>,
    },

    GetCapabilities,
    SetLogBridge,
    SetTransportBridge,
    StartNetworkTick {
        interval_ms: u64,
    },
    StopNetworkTick,

    SetLxmfDeliveryIdentity {
        config: LxmfDeliveryConfig,
    },
    AnnounceLxmfDelivery,
    AnnounceLxmfPropagationNode,
    SendLxmfMessage {
        destination_hash: String,
        fields: LxmfMessageFields,
        method: LxmfDeliveryMethod,
        stamp_cost: Option<u8>,
        include_ticket: bool,
        transport_encryption: Option<String>,
    },
    IngestLxmUri {
        uri: String,
    },
    IgnoreDestination {
        destination_hash: String,
    },
    UnignoreDestination {
        destination_hash: String,
    },
    SetLxmfRouterConfig {
        config: RouterConfig,
    },
    SetActivePropagationNode {
        destination_hash: String,
    },
    GenerateTicket {
        destination_hash: String,
    },
    PeerPropagationNode {
        destination_hash: String,
    },
    UnpeerPropagationNode {
        destination_hash: String,
    },

    RequestPropagationSync {
        max_messages: u32,
    },
    CancelPropagationSync,

    StartCall {
        destination_hash: String,
        codec: CodecType,
    },
    AnswerCall {
        call_id: String,
        codec: CodecType,
    },
    DeclineCall {
        call_id: String,
    },
    HangupCall {
        call_id: String,
    },
    SendCallSignal {
        call_id: String,
        signal: String,
    },
    AnnounceCallEndpoint,
    SendAudioFrames {
        call_id: String,
        frames: Vec<Vec<u8>>,
    },
    SetAudioBridge,
    SetAudioPolicy {
        policy: AppAudioPolicy,
    },

    AdvertiseResource {
        link_id: String,
        data: Vec<u8>,
        metadata: Option<Vec<u8>>,
    },
    AcceptResource {
        hash: String,
    },
    CancelResource {
        hash: String,
    },
    SetResourceStrategy {
        link_id: String,
        strategy: String,
    },

    StartDiscovery {
        required_value: u64,
        autoconnect: bool,
    },
    StopDiscovery,
    ConnectDiscoveredInterface {
        transport_id: String,
    },

    StartSharedInstance {
        address: SharedInstanceAddress,
        access: Option<AppSharedInstanceAccessConfig>,
    },
    StopSharedInstance,
    ConnectSharedInstance {
        name: String,
        address: SharedInstanceAddress,
        access_token: Option<Vec<u8>>,
    },

    ClearToast,
}

impl From<AppAction> for reticulum_actor::types::Action {
    fn from(a: AppAction) -> Self {
        match a {
            AppAction::Start {
                transport_enabled,
                identity_address,
            } => reticulum_actor::types::Action::Start {
                transport_enabled,
                identity_address,
            },
            AppAction::Stop => reticulum_actor::types::Action::Stop,

            AppAction::AddInterface {
                name,
                config,
                ifac,
                enabled,
            } => reticulum_actor::types::Action::AddInterface {
                name,
                config: config.into(),
                ifac: ifac.map(Into::into),
                enabled,
            },
            AppAction::RemoveInterface { address } => {
                reticulum_actor::types::Action::RemoveInterface { address }
            }
            AppAction::RenameInterface { address, name } => {
                reticulum_actor::types::Action::RenameInterface { address, name }
            }
            AppAction::RestartInterface { address } => {
                reticulum_actor::types::Action::RestartInterface { address }
            }
            AppAction::SetInterfaceEnabled { address, enabled } => {
                reticulum_actor::types::Action::SetInterfaceEnabled { address, enabled }
            }
            AppAction::SetInterfaceMode { address, mode } => {
                reticulum_actor::types::Action::SetInterfaceMode { address, mode }
            }
            AppAction::SetInterfaceBitrate { address, bitrate } => {
                reticulum_actor::types::Action::SetInterfaceBitrate { address, bitrate }
            }
            AppAction::SetInterfaceIfac { address, ifac } => {
                reticulum_actor::types::Action::SetInterfaceIfac {
                    address,
                    ifac: ifac.into(),
                }
            }

            AppAction::CreateIdentity { name } => {
                reticulum_actor::types::Action::CreateIdentity { name }
            }
            AppAction::ImportIdentity { name, hex } => {
                reticulum_actor::types::Action::ImportIdentity { name, hex }
            }
            AppAction::ImportIdentityFile { name, path } => {
                reticulum_actor::types::Action::ImportIdentityFile { name, path }
            }
            AppAction::ExportIdentity { address, path } => {
                reticulum_actor::types::Action::ExportIdentity { address, path }
            }
            AppAction::ActivateIdentity { address } => {
                reticulum_actor::types::Action::ActivateIdentity { address }
            }
            AppAction::RemoveIdentity { address } => {
                reticulum_actor::types::Action::RemoveIdentity { address }
            }
            AppAction::SetKeychainBridge => reticulum_actor::types::Action::SetKeychainBridge,

            AppAction::CreateDestination { app_name, aspect } => {
                reticulum_actor::types::Action::CreateDestination { app_name, aspect }
            }
            AppAction::LoadDestination {
                identity_hex,
                app_name,
                aspect,
            } => reticulum_actor::types::Action::LoadDestination {
                identity_hex,
                app_name,
                aspect,
            },
            AppAction::Announce {
                destination_hash,
                app_data,
            } => reticulum_actor::types::Action::Announce {
                destination_hash,
                app_data,
            },
            AppAction::RequestPath { destination_hash } => {
                reticulum_actor::types::Action::RequestPath { destination_hash }
            }
            AppAction::DropPath { destination_hash } => {
                reticulum_actor::types::Action::DropPath { destination_hash }
            }
            AppAction::MarkPathUnresponsive { destination_hash } => {
                reticulum_actor::types::Action::MarkPathUnresponsive { destination_hash }
            }
            AppAction::MarkPathResponsive { destination_hash } => {
                reticulum_actor::types::Action::MarkPathResponsive { destination_hash }
            }

            AppAction::OpenLink { destination_hash } => {
                reticulum_actor::types::Action::OpenLink { destination_hash }
            }
            AppAction::CloseLink { destination_hash } => {
                reticulum_actor::types::Action::CloseLink { destination_hash }
            }
            AppAction::SendData {
                destination_hash,
                data,
            } => reticulum_actor::types::Action::SendData {
                destination_hash,
                data,
            },
            AppAction::SendRequest {
                destination_hash,
                path,
                data,
                timeout_ms,
            } => reticulum_actor::types::Action::SendRequest {
                destination_hash,
                path,
                data,
                timeout_ms,
            },
            AppAction::RegisterRequestHandler {
                destination_hash,
                path,
            } => reticulum_actor::types::Action::RegisterRequestHandler {
                destination_hash,
                path,
            },
            AppAction::SendResponse { request_id, data } => {
                reticulum_actor::types::Action::SendResponse { request_id, data }
            }

            AppAction::GetCapabilities => reticulum_actor::types::Action::GetCapabilities,
            AppAction::SetLogBridge => reticulum_actor::types::Action::SetLogBridge,
            AppAction::SetTransportBridge => reticulum_actor::types::Action::SetTransportBridge,
            AppAction::StartNetworkTick { interval_ms } => {
                reticulum_actor::types::Action::StartNetworkTick { interval_ms }
            }
            AppAction::StopNetworkTick => reticulum_actor::types::Action::StopNetworkTick,

            AppAction::SetLxmfDeliveryIdentity { config } => {
                reticulum_actor::types::Action::SetLxmfDeliveryIdentity {
                    config: config.into(),
                }
            }
            AppAction::AnnounceLxmfDelivery => reticulum_actor::types::Action::AnnounceLxmfDelivery,
            AppAction::AnnounceLxmfPropagationNode => {
                reticulum_actor::types::Action::AnnounceLxmfPropagationNode
            }
            AppAction::SendLxmfMessage {
                destination_hash,
                fields,
                method,
                stamp_cost,
                include_ticket,
                transport_encryption,
            } => reticulum_actor::types::Action::SendLxmfMessage {
                destination_hash,
                fields: fields.into(),
                method: method.into(),
                stamp_cost,
                include_ticket,
                transport_encryption,
            },
            AppAction::IngestLxmUri { uri } => reticulum_actor::types::Action::IngestLxmUri { uri },
            AppAction::IgnoreDestination { destination_hash } => {
                reticulum_actor::types::Action::IgnoreDestination { destination_hash }
            }
            AppAction::UnignoreDestination { destination_hash } => {
                reticulum_actor::types::Action::UnignoreDestination { destination_hash }
            }
            AppAction::SetLxmfRouterConfig { config } => {
                reticulum_actor::types::Action::SetLxmfRouterConfig {
                    config: config.into(),
                }
            }
            AppAction::SetActivePropagationNode { destination_hash } => {
                reticulum_actor::types::Action::SetActivePropagationNode { destination_hash }
            }
            AppAction::GenerateTicket { destination_hash } => {
                reticulum_actor::types::Action::GenerateTicket { destination_hash }
            }
            AppAction::PeerPropagationNode { destination_hash } => {
                reticulum_actor::types::Action::PeerPropagationNode { destination_hash }
            }
            AppAction::UnpeerPropagationNode { destination_hash } => {
                reticulum_actor::types::Action::UnpeerPropagationNode { destination_hash }
            }

            AppAction::RequestPropagationSync { max_messages } => {
                reticulum_actor::types::Action::RequestPropagationSync { max_messages }
            }
            AppAction::CancelPropagationSync => {
                reticulum_actor::types::Action::CancelPropagationSync
            }

            AppAction::StartCall {
                destination_hash,
                codec,
            } => reticulum_actor::types::Action::StartCall {
                destination_hash,
                codec: codec.into(),
            },
            AppAction::AnswerCall { call_id, codec } => {
                reticulum_actor::types::Action::AnswerCall {
                    call_id,
                    codec: codec.into(),
                }
            }
            AppAction::DeclineCall { call_id } => {
                reticulum_actor::types::Action::DeclineCall { call_id }
            }
            AppAction::HangupCall { call_id } => {
                reticulum_actor::types::Action::HangupCall { call_id }
            }
            AppAction::SendCallSignal { call_id, signal } => {
                reticulum_actor::types::Action::SendCallSignal { call_id, signal }
            }
            AppAction::AnnounceCallEndpoint => reticulum_actor::types::Action::AnnounceCallEndpoint,
            AppAction::SendAudioFrames { call_id, frames } => {
                reticulum_actor::types::Action::SendAudioFrames { call_id, frames }
            }
            AppAction::SetAudioBridge => reticulum_actor::types::Action::SetAudioBridge,
            AppAction::SetAudioPolicy { policy } => {
                reticulum_actor::types::Action::SetAudioPolicy {
                    policy: policy.into(),
                }
            }

            AppAction::AdvertiseResource {
                link_id,
                data,
                metadata,
            } => reticulum_actor::types::Action::AdvertiseResource {
                link_id,
                data,
                metadata,
            },
            AppAction::AcceptResource { hash } => {
                reticulum_actor::types::Action::AcceptResource { hash }
            }
            AppAction::CancelResource { hash } => {
                reticulum_actor::types::Action::CancelResource { hash }
            }
            AppAction::SetResourceStrategy { link_id, strategy } => {
                reticulum_actor::types::Action::SetResourceStrategy { link_id, strategy }
            }

            AppAction::StartDiscovery {
                required_value,
                autoconnect,
            } => reticulum_actor::types::Action::StartDiscovery {
                required_value,
                autoconnect,
            },
            AppAction::StopDiscovery => reticulum_actor::types::Action::StopDiscovery,
            AppAction::ConnectDiscoveredInterface { transport_id } => {
                reticulum_actor::types::Action::ConnectDiscoveredInterface { transport_id }
            }

            AppAction::StartSharedInstance { address, access } => {
                reticulum_actor::types::Action::StartSharedInstance {
                    address: address.into(),
                    access: access.map(Into::into),
                }
            }
            AppAction::StopSharedInstance => reticulum_actor::types::Action::StopSharedInstance,
            AppAction::ConnectSharedInstance {
                name,
                address,
                access_token,
            } => reticulum_actor::types::Action::ConnectSharedInstance {
                name,
                address: address.into(),
                access_token,
            },

            AppAction::ClearToast => reticulum_actor::types::Action::ClearToast,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Updates                                                                   ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Enum, Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AppUpdate {
    FullState(AppState),

    NodeStatus(NodeStatus),
    NetworkTick(NetworkTick),
    BackendCapabilities(BackendCapabilities),
    Log {
        level: LogLevel,
        message: String,
    },
    Toast(String),

    AnnounceReceived {
        address_hash: String,
        name_hash_hex: String,
        app_data: Vec<u8>,
        hops: Option<u8>,
    },

    InterfaceAdded {
        address: String,
        name: String,
        kind: String,
    },
    InterfaceRemoved {
        address: String,
    },
    InterfaceUpdated {
        address: String,
        online: bool,
        failed: bool,
    },

    PathResolved {
        destination_hash: String,
        hops: u8,
    },
    PathLost {
        destination_hash: String,
    },

    LinkOpened {
        link_id: String,
        destination_hash: String,
    },
    LinkActivated {
        link_id: String,
        destination_hash: String,
    },
    LinkData {
        link_id: String,
        data: Vec<u8>,
    },
    LinkClosed {
        link_id: String,
    },
    DataReceived {
        destination_hash: String,
        data: Vec<u8>,
    },
    RequestReceived {
        request_id: String,
        destination_hash: String,
        path: String,
        data: Vec<u8>,
    },
    ResponseReceived {
        request_id: String,
        data: Vec<u8>,
    },
    RequestFailed {
        request_id: String,
    },

    IdentityCreated {
        address_hash: String,
    },
    KnownDestinationUpdated {
        destination_hash: String,
    },

    MessageReceived {
        hash: String,
        source_hash: String,
        destination_hash: String,
    },
    MessageStateChanged {
        hash: String,
        state: String,
        progress: f64,
    },
    MessageDuplicate {
        hash: String,
    },
    DeliveryReceipt {
        hash: String,
    },
    SendFailed {
        hash: String,
        reason: String,
    },
    PaperMessagePacked {
        hash: String,
        uri: String,
    },

    PropagationTransferChanged {
        state: String,
        progress: f64,
        size: u64,
    },

    CallStateChanged {
        call_id: String,
        state: String,
    },
    IncomingCall {
        call_id: String,
        destination_hash: String,
    },
    CallFrames {
        call_id: String,
        codec: String,
        data: Vec<u8>,
    },
    CallClosed {
        call_id: String,
    },
    AudioWarning {
        call_id: String,
        message: String,
    },

    ResourceProgress {
        hash: String,
        status: String,
        progress: f64,
    },
    ResourceComplete {
        hash: String,
        data: Option<Vec<u8>>,
        metadata: Option<Vec<u8>>,
    },
    ResourceFailed {
        hash: String,
    },

    DiscoveryUpdated {
        interfaces: Vec<DiscoveredInterfaceSummary>,
    },

    SharedInstanceClientConnected {
        address: String,
    },
    SharedInstanceClientDisconnected {
        address: String,
    },
}

impl From<reticulum_actor::types::Update> for AppUpdate {
    fn from(u: reticulum_actor::types::Update) -> Self {
        match u {
            reticulum_actor::types::Update::FullState(s) => AppUpdate::FullState(s.into()),
            reticulum_actor::types::Update::NodeStatus(s) => AppUpdate::NodeStatus(s.into()),
            reticulum_actor::types::Update::NetworkTick(t) => AppUpdate::NetworkTick(t.into()),
            reticulum_actor::types::Update::BackendCapabilities(c) => {
                AppUpdate::BackendCapabilities(c.into())
            }
            reticulum_actor::types::Update::Log { level, message } => AppUpdate::Log {
                level: level.into(),
                message,
            },
            reticulum_actor::types::Update::Toast(m) => AppUpdate::Toast(m),

            reticulum_actor::types::Update::AnnounceReceived {
                address_hash,
                name_hash_hex,
                app_data,
                hops,
            } => AppUpdate::AnnounceReceived {
                address_hash,
                name_hash_hex,
                app_data,
                hops,
            },

            reticulum_actor::types::Update::InterfaceAdded {
                address,
                name,
                kind,
            } => AppUpdate::InterfaceAdded {
                address,
                name,
                kind,
            },
            reticulum_actor::types::Update::InterfaceRemoved { address } => {
                AppUpdate::InterfaceRemoved { address }
            }
            reticulum_actor::types::Update::InterfaceUpdated {
                address,
                online,
                failed,
            } => AppUpdate::InterfaceUpdated {
                address,
                online,
                failed,
            },

            reticulum_actor::types::Update::PathResolved {
                destination_hash,
                hops,
            } => AppUpdate::PathResolved {
                destination_hash,
                hops,
            },
            reticulum_actor::types::Update::PathLost { destination_hash } => {
                AppUpdate::PathLost { destination_hash }
            }

            reticulum_actor::types::Update::LinkOpened {
                link_id,
                destination_hash,
            } => AppUpdate::LinkOpened {
                link_id,
                destination_hash,
            },
            reticulum_actor::types::Update::LinkActivated {
                link_id,
                destination_hash,
            } => AppUpdate::LinkActivated {
                link_id,
                destination_hash,
            },
            reticulum_actor::types::Update::LinkData { link_id, data } => {
                AppUpdate::LinkData { link_id, data }
            }
            reticulum_actor::types::Update::LinkClosed { link_id } => {
                AppUpdate::LinkClosed { link_id }
            }
            reticulum_actor::types::Update::DataReceived {
                destination_hash,
                data,
            } => AppUpdate::DataReceived {
                destination_hash,
                data,
            },
            reticulum_actor::types::Update::RequestReceived {
                request_id,
                destination_hash,
                path,
                data,
            } => AppUpdate::RequestReceived {
                request_id,
                destination_hash,
                path,
                data,
            },
            reticulum_actor::types::Update::ResponseReceived { request_id, data } => {
                AppUpdate::ResponseReceived { request_id, data }
            }
            reticulum_actor::types::Update::RequestFailed { request_id } => {
                AppUpdate::RequestFailed { request_id }
            }

            reticulum_actor::types::Update::IdentityCreated { address_hash } => {
                AppUpdate::IdentityCreated { address_hash }
            }
            reticulum_actor::types::Update::KnownDestinationUpdated { destination_hash } => {
                AppUpdate::KnownDestinationUpdated { destination_hash }
            }

            reticulum_actor::types::Update::MessageReceived {
                hash,
                source_hash,
                destination_hash,
            } => AppUpdate::MessageReceived {
                hash,
                source_hash,
                destination_hash,
            },
            reticulum_actor::types::Update::MessageStateChanged {
                hash,
                state,
                progress,
            } => AppUpdate::MessageStateChanged {
                hash,
                state,
                progress,
            },
            reticulum_actor::types::Update::MessageDuplicate { hash } => {
                AppUpdate::MessageDuplicate { hash }
            }
            reticulum_actor::types::Update::DeliveryReceipt { hash } => {
                AppUpdate::DeliveryReceipt { hash }
            }
            reticulum_actor::types::Update::SendFailed { hash, reason } => {
                AppUpdate::SendFailed { hash, reason }
            }
            reticulum_actor::types::Update::PaperMessagePacked { hash, uri } => {
                AppUpdate::PaperMessagePacked { hash, uri }
            }

            reticulum_actor::types::Update::PropagationTransferChanged {
                state,
                progress,
                size,
            } => AppUpdate::PropagationTransferChanged {
                state,
                progress,
                size,
            },

            reticulum_actor::types::Update::CallStateChanged { call_id, state } => {
                AppUpdate::CallStateChanged { call_id, state }
            }
            reticulum_actor::types::Update::IncomingCall {
                call_id,
                destination_hash,
            } => AppUpdate::IncomingCall {
                call_id,
                destination_hash,
            },
            reticulum_actor::types::Update::CallFrames {
                call_id,
                codec,
                data,
            } => AppUpdate::CallFrames {
                call_id,
                codec,
                data,
            },
            reticulum_actor::types::Update::CallClosed { call_id } => {
                AppUpdate::CallClosed { call_id }
            }
            reticulum_actor::types::Update::AudioWarning { call_id, message } => {
                AppUpdate::AudioWarning { call_id, message }
            }

            reticulum_actor::types::Update::ResourceProgress {
                hash,
                status,
                progress,
            } => AppUpdate::ResourceProgress {
                hash,
                status,
                progress,
            },
            reticulum_actor::types::Update::ResourceComplete {
                hash,
                data,
                metadata,
            } => AppUpdate::ResourceComplete {
                hash,
                data,
                metadata,
            },
            reticulum_actor::types::Update::ResourceFailed { hash } => {
                AppUpdate::ResourceFailed { hash }
            }

            reticulum_actor::types::Update::DiscoveryUpdated { interfaces } => {
                AppUpdate::DiscoveryUpdated {
                    interfaces: interfaces.into_iter().map(Into::into).collect(),
                }
            }

            reticulum_actor::types::Update::SharedInstanceClientConnected { address } => {
                AppUpdate::SharedInstanceClientConnected { address }
            }
            reticulum_actor::types::Update::SharedInstanceClientDisconnected { address } => {
                AppUpdate::SharedInstanceClientDisconnected { address }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Callback interfaces and adapters                                          ║
// ═════════════════════════════════════════════════════════════════════════════

#[uniffi::export(callback_interface)]
pub trait AppReconciler: Send + Sync + 'static {
    fn reconcile(&self, update: AppUpdate);
}

#[uniffi::export(callback_interface)]
pub trait TransportBridge: Send + Sync + 'static {
    fn mtu(&self, interface_kind: String) -> u32;
    fn read_chunk(&self, interface_kind: String) -> Vec<u8>;
    fn write_chunk(&self, interface_kind: String, data: Vec<u8>);
}

struct TransportBridgeAdapter(Box<dyn TransportBridge>);

impl reticulum_actor::types::TransportBridge for TransportBridgeAdapter {
    fn mtu(&self, interface_kind: &str) -> u32 {
        self.0.mtu(interface_kind.to_string())
    }

    fn read_chunk(&self, interface_kind: &str) -> Vec<u8> {
        self.0.read_chunk(interface_kind.to_string())
    }

    fn write_chunk(&self, interface_kind: &str, data: Vec<u8>) {
        self.0.write_chunk(interface_kind.to_string(), data)
    }
}

#[uniffi::export(callback_interface)]
pub trait KeychainBridge: Send + Sync + 'static {
    fn encrypt(&self, identity_address: String, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt(&self, identity_address: String, ciphertext: Vec<u8>) -> Option<Vec<u8>>;
}

struct KeychainBridgeAdapter(Box<dyn KeychainBridge>);

impl reticulum_actor::types::KeychainBridge for KeychainBridgeAdapter {
    fn encrypt(&self, identity_address: &str, plaintext: &[u8]) -> Vec<u8> {
        self.0
            .encrypt(identity_address.to_string(), plaintext.to_vec())
    }

    fn decrypt(&self, identity_address: &str, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.0
            .decrypt(identity_address.to_string(), ciphertext.to_vec())
    }
}

#[uniffi::export(callback_interface)]
pub trait LogBridge: Send + Sync + 'static {
    fn log(&self, level: LogLevel, message: String);
}

struct LogBridgeAdapter(Box<dyn LogBridge>);

impl reticulum_actor::types::LogBridge for LogBridgeAdapter {
    fn log(&self, level: reticulum_actor::types::LogLevel, message: &str) {
        self.0.log(level.into(), message.to_string())
    }
}

#[uniffi::export(callback_interface)]
pub trait AudioBridge: Send + Sync + 'static {
    fn read_frames(&self, codec: String, max_frames: u32) -> Vec<Vec<u8>>;
    fn write_frames(&self, codec: String, frames: Vec<Vec<u8>>);
}

struct AudioBridgeAdapter(Box<dyn AudioBridge>);

impl reticulum_actor::types::AudioBridge for AudioBridgeAdapter {
    fn read_frames(&self, codec: &str, max_frames: u32) -> Vec<Vec<u8>> {
        self.0.read_frames(codec.to_string(), max_frames)
    }

    fn write_frames(&self, codec: &str, frames: Vec<Vec<u8>>) {
        self.0.write_frames(codec.to_string(), frames)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  FFI entry point                                                           ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(uniffi::Object)]
pub struct FfiApp {
    actor: reticulum_actor::App,
    update_rx: Receiver<reticulum_actor::types::Update>,
    listener: Mutex<Option<JoinHandle<()>>>,
    stop_listener: Arc<AtomicBool>,
    /// The thread currently running this app's reconciler loop, if any.
    /// Used to detect `stop_listening` calls made from inside a callback:
    /// joining the current thread would panic or deadlock, so the stop
    /// flag alone must suffice there.
    listener_thread: Arc<Mutex<Option<thread::ThreadId>>>,
}

#[uniffi::export]
impl FfiApp {
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Arc<Self> {
        let (actor, update_rx) = reticulum_actor::App::new(data_dir);

        Arc::new(Self {
            actor,
            update_rx,
            listener: Mutex::new(None),
            stop_listener: Arc::new(AtomicBool::new(false)),
            listener_thread: Arc::new(Mutex::new(None)),
        })
    }

    pub fn state(&self) -> AppState {
        self.actor.state().into()
    }

    pub fn dispatch(&self, action: AppAction) {
        self.actor.dispatch(action.into());
    }

    pub fn listen_for_updates(&self, reconciler: Box<dyn AppReconciler>) {
        let mut listener = self.listener.lock().unwrap_or_else(|e| e.into_inner());
        if listener.as_ref().is_some_and(|h| !h.is_finished()) {
            return;
        }

        self.stop_listener.store(false, Ordering::SeqCst);
        let rx = self.update_rx.clone();
        let stop = self.stop_listener.clone();
        let listener_thread = self.listener_thread.clone();
        *listener = Some(thread::spawn(move || {
            // Record which thread is running the callbacks so
            // `stop_listening` can avoid joining itself, and clear the
            // record on exit so it never goes stale.
            *listener_thread.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(thread::current().id());
            while !stop.load(Ordering::SeqCst) {
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(update) => reconciler.reconcile(update.into()),
                    Err(flume::RecvTimeoutError::Timeout) => continue,
                    Err(flume::RecvTimeoutError::Disconnected) => break,
                }
            }
            *listener_thread.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }));
    }

    pub fn stop_listening(&self) {
        self.stop_listener.store(true, Ordering::SeqCst);
        let handle = self
            .listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(handle) = handle else {
            return;
        };

        // Called from inside a reconciler callback (e.g. an app stopping
        // its own update stream from `reconcile`): joining the current
        // thread would panic or deadlock. The loop re-checks the stop flag
        // on every bounded receive, so the thread exits on its own.
        let listener_thread = *self
            .listener_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if listener_thread.is_some_and(|id| id == thread::current().id()) {
            return;
        }
        let _ = handle.join();
    }

    /// Delegates to `reticulum_actor::App::set_log_bridge` when that method lands.
    pub fn set_log_bridge(&self, bridge: Box<dyn LogBridge>) {
        self.actor
            .set_log_bridge(Arc::new(LogBridgeAdapter(bridge)));
    }

    /// Delegates to `reticulum_actor::App::set_transport_bridge` when that method lands.
    pub fn set_transport_bridge(&self, bridge: Box<dyn TransportBridge>) {
        self.actor
            .set_transport_bridge(Arc::new(TransportBridgeAdapter(bridge)));
    }

    /// Delegates to `reticulum_actor::App::set_keychain_bridge` when that method lands.
    pub fn set_keychain_bridge(&self, bridge: Box<dyn KeychainBridge>) {
        self.actor
            .set_keychain_bridge(Arc::new(KeychainBridgeAdapter(bridge)));
    }

    /// Delegates to `reticulum_actor::App::set_audio_bridge` when that method lands.
    pub fn set_audio_bridge(&self, bridge: Box<dyn AudioBridge>) {
        self.actor
            .set_audio_bridge(Arc::new(AudioBridgeAdapter(bridge)));
    }
}
