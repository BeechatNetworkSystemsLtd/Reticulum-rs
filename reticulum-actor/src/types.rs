//! Public actor types: state, actions, updates, and callback traits.
//!
//! This module defines the full M0–M5 engine surface consumed by the
//! `reticulum-ffi` skin and by headless Rust consumers.  Complex runtime logic
//! lives in `core.rs`; this file is intentionally the single source of truth
//! for the action/update contract.

use std::sync::Arc;

// ═════════════════════════════════════════════════════════════════════════════
// ║  State                                                                    ║
// ═════════════════════════════════════════════════════════════════════════════

/// Full snapshot of the node state emitted after each action or internal event.
#[derive(Clone, Debug)]
pub struct State {
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

impl State {
    pub fn empty() -> Self {
        Self {
            rev: 0,
            status: NodeStatus::Stopped,
            capabilities: BackendCapabilities::default(),
            active_identity: None,
            identities: Vec::new(),
            interfaces: Vec::new(),
            destinations: Vec::new(),
            peers: Vec::new(),
            links: Vec::new(),
            paths: Vec::new(),
            tunnels: Vec::new(),
            known_destinations: Vec::new(),
            messages: Vec::new(),
            calls: Vec::new(),
            propagation: PropagationState::default(),
            resources: Vec::new(),
            discovery: DiscoveryState::default(),
            shared_instance: SharedInstanceState::default(),
            toast: None,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Status & capabilities                                                    ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, PartialEq)]
pub enum NodeStatus {
    Stopped,
    Starting,
    Running { identity_hash: String },
    Error { message: String },
}

/// Runtime capability matrix.  Compile-time feature flags *trim code*, but this
/// record is the authoritative per-platform/runtime report consumed by Paloma.
#[derive(Clone, Debug, Default)]
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

// ═════════════════════════════════════════════════════════════════════════════
// ║  Identities                                                               ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct IdentitySummary {
    pub name: String,
    pub address_hash: String,
    pub public_key_hex: String,
    pub active: bool,
    pub encrypted: bool,
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Interfaces                                                               ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
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
    /// Last reported radio RSSI in dBm (Python `r_stat_rssi`), when the
    /// interface reports radio telemetry.
    pub rssi: Option<i16>,
    /// Last reported radio SNR in dB (Python `r_stat_snr`).
    pub snr: Option<f64>,
    /// Last reported radio link-quality percentage (Python `r_stat_q`).
    pub quality: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct IfacConfig {
    pub netname: Option<String>,
    pub netkey: Option<String>,
    pub size: u32,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub enum SharedInstanceAddress {
    Tcp { port: u16 },
    UnixAbstract { name: String },
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Destinations, peers, links, paths                                        ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct DestinationSummary {
    pub address_hash: String,
    pub app_name: String,
    pub aspect: String,
    pub accepts_links: bool,
    pub ratchets_enabled: bool,
}

#[derive(Clone, Debug)]
pub struct PeerSummary {
    pub address_hash: String,
    pub name_hash_hex: String,
    pub app_data: Vec<u8>,
    pub hops: Option<u8>,
}

#[derive(Clone, Debug)]
pub struct LinkSummary {
    pub id: String,
    pub destination_hash: String,
    pub status: String,
    pub is_outbound: bool,
    pub mdu: u64,
}

#[derive(Clone, Debug)]
pub struct PathSummary {
    pub destination_hash: String,
    pub hops: u8,
    pub via: String,
    pub interface: String,
    pub timestamp: f64,
    pub unresponsive: bool,
}

#[derive(Clone, Debug)]
pub struct TunnelSummary {
    pub destination_hash: String,
    pub interface: String,
    pub hops: u8,
    pub expires: f64,
}

#[derive(Clone, Debug)]
pub struct KnownDestinationSummary {
    pub destination_hash: String,
    pub app_data: Vec<u8>,
    pub retained: bool,
    pub last_seen: f64,
    pub identity_hash: Option<String>,
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  LXMF messaging (M2)                                                      ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct LxmfDeliveryConfig {
    pub display_name: Option<String>,
    pub stamp_cost: Option<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct RouterConfig {
    pub propagation_node: bool,
    pub message_storage_limit: u64,
    pub propagation_transfer_limit: u64,
    pub auto_announce: bool,
}

#[derive(Clone, Debug)]
pub enum LxmfDeliveryMethod {
    Direct,
    Opportunistic,
    Propagated,
    Paper,
}

#[derive(Clone, Debug)]
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

/// Explicit LXMF transport-encryption override
/// (`lxmf::message::TransportEncryption` names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LxmfTransportEncryption {
    /// AES-128 encrypted transport (group destinations).
    Aes128,
    /// Curve25519 encrypted transport (single destinations and links).
    Curve25519,
    /// Unencrypted transport.
    Unencrypted,
}

impl LxmfTransportEncryption {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "aes128" | "aes" | "aes-128" => Ok(Self::Aes128),
            "curve25519" | "curve" | "ec" => Ok(Self::Curve25519),
            "unencrypted" | "none" | "plain" => Ok(Self::Unencrypted),
            _ => Err(format!("Unknown transport encryption: {value}")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LxmfAttachment {
    pub file_name: String,
    pub data: Vec<u8>,
    pub mime_type: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LxmfReaction {
    pub to_message_hash: String,
    pub content: String,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug, Default)]
pub struct PropagationState {
    pub active_node: Option<String>,
    pub sync_state: String,
    pub sync_progress: f64,
    pub sync_size: u64,
    pub entries: Vec<PropagationEntrySummary>,
    pub peers: Vec<PropagationPeerSummary>,
}

#[derive(Clone, Debug)]
pub struct PropagationEntrySummary {
    pub hash: String,
    pub source: String,
    pub destination: String,
    pub received: f64,
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct PropagationPeerSummary {
    pub destination_hash: String,
    pub name: Option<String>,
    pub peering_value: i64,
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  LXST calls (M4)                                                          ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub enum CallState {
    Idle,
    Calling,
    Ringing,
    Established,
    Ended,
}

#[derive(Clone, Debug)]
pub enum CodecType {
    Raw,
    Opus,
    Codec2,
    Null,
}

#[derive(Clone, Debug)]
pub struct CallSummary {
    pub id: String,
    pub destination_hash: String,
    pub state: String,
    pub codec: String,
    pub muted: bool,
    pub speaker: bool,
    pub quality: Option<f64>,
    /// Last reported radio RSSI (dBm) of the call link's interface, when
    /// the interface reports radio telemetry.
    pub rssi: Option<i16>,
    /// Last reported radio SNR (dB) of the call link's interface.
    pub snr: Option<f64>,
    /// Last reported radio link-quality percentage (0–100, `r_stat_q`).
    pub radio_quality: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct AudioFrame {
    pub call_id: String,
    pub codec: String,
    pub data: Vec<u8>,
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Resources, discovery, shared instance (M5)                               ║
// ═════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug)]
pub struct ResourceSummary {
    pub hash: String,
    pub link_id: String,
    pub status: String,
    pub progress: f64,
    pub size: u64,
    pub metadata: Option<Vec<u8>>,
    pub outgoing: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DiscoveryState {
    pub announcing: bool,
    pub listening: bool,
    pub autoconnect: bool,
    pub interfaces: Vec<DiscoveredInterfaceSummary>,
}

#[derive(Clone, Debug)]
pub struct DiscoveredInterfaceSummary {
    pub name: String,
    pub interface_type: String,
    pub address: String,
    pub port: u16,
    pub status: String,
    pub transport_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct SharedInstanceState {
    pub hosting: bool,
    pub address: Option<SharedInstanceAddress>,
    pub clients: Vec<String>,
}

/// Access control for a hosted shared instance
/// (`reticulum::iface::local::SharedInstanceAccessConfig`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedInstanceAccessConfig {
    /// Client names allowed to connect (empty = allow any).
    pub allow: Vec<String>,
    /// Require clients to authenticate with this token.
    pub required_token: Option<Vec<u8>>,
    /// Maximum simultaneously connected clients (None = unlimited).
    pub max_clients: Option<u32>,
}

/// Runtime audio-pump policy for LXST calls: latency warnings, bridge
/// failure fallback and the auto-close quality floor.
#[derive(Clone, Debug)]
pub struct AudioPolicy {
    /// Bridge callback latency (milliseconds) above which
    /// `Update::AudioWarning` is emitted.
    pub warning_latency_ms: u64,
    /// Consecutive bridge failures before the pump falls back to
    /// null-codec mode (the platform bridge is no longer called).
    pub max_consecutive_failures: u32,
    /// Minimum call quality (0.0–1.0). Calls whose blended quality stays
    /// below this for `quality_grace_ticks` network ticks are auto-closed.
    pub min_quality: Option<f64>,
    /// Consecutive low-quality network ticks tolerated before auto-close.
    pub quality_grace_ticks: u32,
}

impl Default for AudioPolicy {
    fn default() -> Self {
        Self {
            warning_latency_ms: 250,
            max_consecutive_failures: 3,
            min_quality: None,
            quality_grace_ticks: 3,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Actions                                                                  ║
// ═════════════════════════════════════════════════════════════════════════════

/// Commands dispatched to the actor thread.
#[derive(Clone, Debug)]
pub enum Action {
    // Lifecycle
    Start {
        transport_enabled: bool,
        identity_address: Option<String>,
    },
    Stop,

    // Interfaces (M1)
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

    // Identities (M1)
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

    // Destinations, announce, path (M1)
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

    // Links & requests (M1)
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

    // Cross-cutting (M1)
    GetCapabilities,
    SetLogBridge,
    SetTransportBridge,
    StartNetworkTick {
        interval_ms: u64,
    },
    StopNetworkTick,

    // LXMF (M2)
    SetLxmfDeliveryIdentity {
        config: LxmfDeliveryConfig,
    },
    AnnounceLxmfDelivery,
    /// Re-announce the propagation-node destination when this node runs as
    /// a propagation node.
    AnnounceLxmfPropagationNode,
    SendLxmfMessage {
        destination_hash: String,
        fields: LxmfMessageFields,
        method: LxmfDeliveryMethod,
        stamp_cost: Option<u8>,
        include_ticket: bool,
        /// Explicit transport-encryption override for this message
        /// (`LxmfTransportEncryption` names). When `None`, the router
        /// derives it from the delivery method and destination type.
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

    // Propagation sync (M3)
    RequestPropagationSync {
        max_messages: u32,
    },
    CancelPropagationSync,

    // LXST (M4)
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
    /// Re-announce the LXST call destination (useful after interfaces were
    /// added; the endpoint announces once at startup).
    AnnounceCallEndpoint,
    SendAudioFrames {
        call_id: String,
        frames: Vec<Vec<u8>>,
    },
    SetAudioBridge,
    /// Configure the audio-pump policy: latency warnings, bridge-failure
    /// fallback and the auto-close quality floor.
    SetAudioPolicy {
        policy: AudioPolicy,
    },

    // Resources (M5)
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

    // Discovery (M5)
    StartDiscovery {
        required_value: u64,
        autoconnect: bool,
    },
    StopDiscovery,
    ConnectDiscoveredInterface {
        transport_id: String,
    },

    // Shared instance (M5)
    StartSharedInstance {
        address: SharedInstanceAddress,
        access: Option<SharedInstanceAccessConfig>,
    },
    StopSharedInstance,
    ConnectSharedInstance {
        name: String,
        address: SharedInstanceAddress,
        /// Token presented to access-controlled shared instances.
        access_token: Option<Vec<u8>>,
    },

    ClearToast,
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Updates                                                                  ║
// ═════════════════════════════════════════════════════════════════════════════

/// Granular and full-state updates emitted by the actor.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Update {
    FullState(State),

    // Lifecycle / network
    NodeStatus(NodeStatus),
    NetworkTick(NetworkTick),
    BackendCapabilities(BackendCapabilities),
    Log {
        level: LogLevel,
        message: String,
    },
    Toast(String),

    // Announce / peers
    AnnounceReceived {
        address_hash: String,
        name_hash_hex: String,
        app_data: Vec<u8>,
        hops: Option<u8>,
    },

    // Interfaces
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

    // Paths
    PathResolved {
        destination_hash: String,
        hops: u8,
    },
    PathLost {
        destination_hash: String,
    },

    // Links / raw data
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

    // Identities / known destinations
    IdentityCreated {
        address_hash: String,
    },
    KnownDestinationUpdated {
        destination_hash: String,
    },

    // LXMF (M2)
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

    // Propagation (M3)
    PropagationTransferChanged {
        state: String,
        progress: f64,
        size: u64,
    },

    // Calls (M4)
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
    /// The audio pump degraded or auto-closed a call: slow platform
    /// callbacks, repeated bridge failures, or sustained low quality.
    AudioWarning {
        call_id: String,
        message: String,
    },

    // Resources (M5)
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

    // Discovery (M5)
    DiscoveryUpdated {
        interfaces: Vec<DiscoveredInterfaceSummary>,
    },

    // Shared instance (M5)
    SharedInstanceClientConnected {
        address: String,
    },
    SharedInstanceClientDisconnected {
        address: String,
    },
}

#[derive(Clone, Debug)]
pub struct NetworkTick {
    pub timestamp_ms: u64,
    pub interfaces: Vec<InterfaceSummary>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

// ═════════════════════════════════════════════════════════════════════════════
// ║  Platform callback traits                                                 ║
// ═════════════════════════════════════════════════════════════════════════════

/// Platform-supplied radio/serial byte bridge.  The actor calls `read_chunk`
/// from the interface worker loop and `write_chunk` when packets need to leave
/// the device.  Empty `read_chunk` results mean "no data available right now".
pub trait TransportBridge: Send + Sync + 'static {
    fn mtu(&self, interface_kind: &str) -> u32;
    fn read_chunk(&self, interface_kind: &str) -> Vec<u8>;
    fn write_chunk(&self, interface_kind: &str, data: Vec<u8>);
}

/// Platform keychain for encrypting/decrypting identity files at rest.
pub trait KeychainBridge: Send + Sync + 'static {
    fn encrypt(&self, identity_address: &str, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt(&self, identity_address: &str, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// Platform log sink.  The actor routes `log` records here when a bridge is
/// registered, in addition to the Rust `log` crate.
pub trait LogBridge: Send + Sync + 'static {
    fn log(&self, level: LogLevel, message: &str);
}

/// Platform audio I/O.  Chunks of 40–80 ms of encoded frames are exchanged in
/// both directions to keep FFI overhead low.
pub trait AudioBridge: Send + Sync + 'static {
    fn read_frames(&self, codec: &str, max_frames: u32) -> Vec<Vec<u8>>;
    fn write_frames(&self, codec: &str, frames: Vec<Vec<u8>>);
}

// Types used by the runtime to store callback objects behind `Arc`.
pub type DynTransportBridge = Arc<dyn TransportBridge>;
pub type DynKeychainBridge = Arc<dyn KeychainBridge>;
pub type DynLogBridge = Arc<dyn LogBridge>;
pub type DynAudioBridge = Arc<dyn AudioBridge>;
