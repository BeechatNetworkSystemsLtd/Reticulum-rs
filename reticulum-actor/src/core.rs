use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flume::{Receiver, Sender};
use lxmf::fields::{
    FieldValue, FIELD_AUDIO, FIELD_CUSTOM_DATA, FIELD_CUSTOM_TYPE, FIELD_FILE_ATTACHMENTS,
    FIELD_ICON_APPEARANCE, FIELD_IMAGE, FIELD_REACTION, FIELD_RENDERER, FIELD_REPLY_QUOTE,
    FIELD_REPLY_TO, FIELD_TELEMETRY,
};
use lxmf::message::{LXMessage, DIRECT, OPPORTUNISTIC, PAPER, PROPAGATED, SENDING};
use lxmf::router::{DeliveryConfig, LxmEvent, LxmRouter};
use lxst::call::{CallEndpoint, CallEvent};
use lxst::network::Signal;
use rand_core::OsRng;
use reticulum::destination::link::{LinkEvent, LinkId, LinkStatus};
use reticulum::destination::{DestinationDesc, DestinationName, SingleInputDestination};
use reticulum::error::RnsError;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::control::InterfaceMode;
use reticulum::iface::local::{LocalClient, LocalServer};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::iface::InterfaceStats;
use reticulum::resource::{ResourceEvent, ResourceOptions, ResourceStatus, ResourceStrategy};
use reticulum::reticulum::Reticulum;
use reticulum::storage::{FsStorage, Storage};
use reticulum::transport::TransportConfig;
use reticulum_discovery::{InterfaceAnnouncer, InterfaceDiscovery, InterfaceInfo};

use crate::bridge::BridgeInterface;
use crate::types::*;

/// A global log fan-out: the `log` crate allows a single logger per
/// process, but several `App`s (e.g. in parallel tests) can each register
/// their own bridge. Sinks whose update channel disconnected are dropped.
struct BridgeLogger {
    sinks: RwLock<Vec<(DynLogBridge, Sender<Update>)>>,
}

static BRIDGE_LOGGER: BridgeLogger = BridgeLogger {
    sinks: RwLock::new(Vec::new()),
};
static LOGGER_INSTALLED: std::sync::Once = std::sync::Once::new();

thread_local! {
    /// Bridge callbacks are foreign code that may legitimately log while
    /// handling a record. Re-entering the fan-out from a callback would
    /// recurse without bound, so nested records are dropped instead.
    static IN_BRIDGE_CALLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl log::Log for BridgeLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        if IN_BRIDGE_CALLBACK.with(std::cell::Cell::get) {
            return;
        }
        let level = match record.level() {
            log::Level::Trace => LogLevel::Trace,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Info => LogLevel::Info,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Error => LogLevel::Error,
        };
        let message = record.args().to_string();

        // Snapshot the live sinks under the lock and invoke the bridge
        // callbacks only after releasing it: the callbacks are foreign
        // code, and a bridge that logs while handling a record would
        // otherwise deadlock trying to re-acquire the same write lock.
        let sinks: Vec<(DynLogBridge, Sender<Update>)> = {
            let mut sinks = self.sinks.write().unwrap_or_else(|e| e.into_inner());
            sinks.retain(|(_, updates)| !updates.is_disconnected());
            sinks.clone()
        };

        IN_BRIDGE_CALLBACK.with(|guard| guard.set(true));
        for (bridge, updates) in sinks.iter() {
            bridge.log(level.clone(), &message);
            let _ = updates.send(Update::Log {
                level: level.clone(),
                message: message.clone(),
            });
        }
        IN_BRIDGE_CALLBACK.with(|guard| guard.set(false));
    }

    fn flush(&self) {}
}

fn install_log_sink(bridge: Option<DynLogBridge>, updates: Sender<Update>) {
    LOGGER_INSTALLED.call_once(|| {
        if log::set_logger(&BRIDGE_LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Trace);
        }
    });
    let mut sinks = BRIDGE_LOGGER
        .sinks
        .write()
        .unwrap_or_else(|e| e.into_inner());
    sinks.retain(|existing| !existing.1.is_disconnected() && !existing.1.same_channel(&updates));
    if let Some(bridge) = bridge {
        sinks.push((bridge, updates));
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum CoreMsg {
    Action(Action),
    Internal(InternalEvent),
    SetLogBridge(DynLogBridge),
    SetTransportBridge(DynTransportBridge),
    SetKeychainBridge(DynKeychainBridge),
    SetAudioBridge(DynAudioBridge),
    Close,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum InternalEvent {
    Announce(AddressHash, Vec<u8>, Vec<u8>),
    LinkActivated(LinkId, AddressHash),
    LinkData(LinkId, AddressHash, Vec<u8>),
    LinkClosed(LinkId, AddressHash),
    Data(AddressHash, Vec<u8>),
    RequestReceived(String, AddressHash, String, Vec<u8>),
    Response(String, Vec<u8>),
    RequestFailed(String),
    PathResult(AddressHash, Option<u8>),
    NetworkTick,
    Lxmf(LxmEvent),
    CallIncoming(LinkId),
    CallSignal(LinkId, Vec<u8>),
    CallFrame(LinkId, lxst::common::AudioFrame),
    CallClosed(LinkId),
    Resource(ResourceEvent),
    InboundLink(LinkId),
}

struct ActiveCallState {
    link_id: LinkId,
    destination_hash: String,
    state: String,
    codec: lxst::codecs::CodecType,
    transmit: tokio::sync::mpsc::Sender<Vec<u8>>,
    audio_pump: Option<tokio::task::JoinHandle<()>>,
    quality: Arc<CallQuality>,
    /// Consecutive network ticks with quality below the policy floor.
    low_quality_ticks: u32,
}

#[derive(Default)]
struct CallQuality {
    attempts: std::sync::atomic::AtomicU64,
    successes: std::sync::atomic::AtomicU64,
    consecutive: std::sync::atomic::AtomicU64,
    /// High-water bridge callback latency in milliseconds.
    max_latency_ms: std::sync::atomic::AtomicU64,
    /// Total latency warnings emitted by the pump.
    warnings: std::sync::atomic::AtomicU64,
    /// Whether the pump degraded to the null-codec fallback.
    degraded: std::sync::atomic::AtomicBool,
}

impl CallQuality {
    fn audio_quality(&self) -> Option<f64> {
        let attempts = self.attempts.load(std::sync::atomic::Ordering::Relaxed);
        let successes = self.successes.load(std::sync::atomic::Ordering::Relaxed);
        let consecutive = self.consecutive.load(std::sync::atomic::Ordering::Relaxed);
        (attempts > 0).then(|| {
            let delivery = successes as f64 / attempts as f64;
            let stability = consecutive as f64 / (consecutive as f64 + 1.0);
            (delivery + stability) / 2.0
        })
    }
}

/// Radio link-quality telemetry of one link interface:
/// `(rssi dBm, snr dB, quality 0-100)`.
type LinkRadioQuality = (Option<i16>, Option<f64>, Option<f64>);

struct DestinationInfo {
    arc: Arc<tokio::sync::Mutex<SingleInputDestination>>,
    app_name: String,
    aspect: String,
}

struct PeerInfo {
    address: AddressHash,
    name_hash: Vec<u8>,
    app_data: Vec<u8>,
}
struct LinkInfo {
    id: LinkId,
    destination: AddressHash,
    status: String,
    outbound: bool,
}

#[derive(Clone)]
struct ConfiguredInterface {
    address: Option<AddressHash>,
    name: String,
    config: InterfaceConfig,
    ifac: Option<IfacConfig>,
    enabled: bool,
    failed: bool,
    mode: String,
    bitrate: u64,
}

pub struct App {
    core_tx: Sender<CoreMsg>,
    shared_state: Arc<RwLock<State>>,
}

impl App {
    pub fn new(data_dir: impl Into<String>) -> (Self, Receiver<Update>) {
        let (update_tx, update_rx) = flume::unbounded();
        let (core_tx, core_rx) = flume::unbounded();
        let shared_state = Arc::new(RwLock::new(State::empty()));
        let state = shared_state.clone();
        let actor_tx = core_tx.clone();
        let data_dir = data_dir.into();
        thread::spawn(move || {
            let mut core = CoreState::new(data_dir, update_tx, state, actor_tx);
            let mut runtime = None;
            while let Ok(msg) = core_rx.recv() {
                match msg {
                    CoreMsg::Close => break,
                    CoreMsg::SetLogBridge(v) => {
                        core.log_bridge = Some(v);
                        core.refresh_capabilities();
                        install_log_sink(core.log_bridge.clone(), core.update_tx.clone());
                    }
                    CoreMsg::SetTransportBridge(v) => {
                        core.transport_bridge = Some(v);
                        core.refresh_capabilities();
                    }
                    CoreMsg::SetKeychainBridge(v) => {
                        core.keychain_bridge = Some(v);
                        core.refresh_capabilities();
                    }
                    CoreMsg::SetAudioBridge(v) => {
                        core.audio_bridge = Some(v);
                        core.refresh_capabilities();
                    }
                    CoreMsg::Action(Action::Start {
                        transport_enabled,
                        identity_address,
                    }) => {
                        if runtime.is_none() {
                            core.status = NodeStatus::Starting;
                            core.send_update(Update::NodeStatus(core.status.clone()));
                            match tokio::runtime::Builder::new_multi_thread()
                                .worker_threads(2)
                                .enable_all()
                                .build()
                            {
                                Ok(rt) => runtime = Some(rt),
                                Err(e) => {
                                    core.status = NodeStatus::Error {
                                        message: e.to_string(),
                                    }
                                }
                            }
                            if let Some(rt) = runtime.as_ref() {
                                if let Err(e) = rt.block_on(
                                    core.start(transport_enabled, identity_address.as_deref()),
                                ) {
                                    core.status = NodeStatus::Error { message: e };
                                }
                            }
                        } else {
                            core.toast("Node is already running".into());
                        }
                    }
                    CoreMsg::Action(Action::Stop) => {
                        if let Some(rt) = runtime.as_ref() {
                            rt.block_on(core.stop());
                        }
                        if let Some(rt) = runtime.take() {
                            rt.shutdown_background();
                        }
                    }
                    CoreMsg::Action(Action::ClearToast) => core.toast = None,
                    CoreMsg::Action(Action::SetLxmfDeliveryIdentity { config })
                        if runtime.is_none() =>
                    {
                        core.lxmf_delivery_config = Some(config)
                    }
                    CoreMsg::Action(Action::SetLxmfRouterConfig { config })
                        if runtime.is_none() =>
                    {
                        core.lxmf_router_config = config
                    }
                    CoreMsg::Action(Action::CreateIdentity { name }) if runtime.is_none() => {
                        let id = PrivateIdentity::new_from_rand(OsRng);
                        if let Err(e) = core.save_identity(&name, &id) {
                            core.toast(e);
                        }
                        let _ = core.load_identity_summaries();
                        core.send_update(Update::IdentityCreated {
                            address_hash: id.address_hash().to_hex_string(),
                        });
                    }
                    CoreMsg::Action(Action::ImportIdentity { name, hex }) if runtime.is_none() => {
                        match hex_decode(&hex)
                            .ok_or("Invalid identity hex".to_string())
                            .and_then(|b| {
                                PrivateIdentity::new_from_bytes(&b).map_err(|e| format!("{e:?}"))
                            }) {
                            Ok(id) => {
                                if let Err(e) = core.save_identity(&name, &id) {
                                    core.toast(e);
                                }
                                let _ = core.load_identity_summaries();
                                core.send_update(Update::IdentityCreated {
                                    address_hash: id.address_hash().to_hex_string(),
                                });
                            }
                            Err(e) => core.toast(e),
                        }
                    }
                    CoreMsg::Action(Action::ActivateIdentity { address }) if runtime.is_none() => {
                        match parse_address(&address) {
                            Ok(a) if core.identities.contains_key(&a) => {
                                core.active_identity = Some(a);
                                if let Err(e) = core.write_active_identity(&a) {
                                    core.toast(e);
                                }
                                for (candidate, summary) in &mut core.identities {
                                    summary.active = *candidate == a;
                                }
                            }
                            Ok(_) => core.toast("Unknown identity".into()),
                            Err(e) => core.toast(e),
                        }
                    }
                    CoreMsg::Action(action) => {
                        if let Some(rt) = runtime.as_ref() {
                            if let Err(e) = rt.block_on(core.handle_action(action)) {
                                core.toast(e);
                            }
                        } else {
                            core.toast("Node is not running".into());
                        }
                    }
                    CoreMsg::Internal(event) => {
                        if let Some(rt) = runtime.as_ref() {
                            rt.block_on(core.handle_internal(event));
                        }
                    }
                }
                let snapshot = runtime
                    .as_ref()
                    .map(|rt| rt.block_on(core.build_state()))
                    .unwrap_or_else(|| core.build_state_offline());
                core.emit(snapshot);
            }
        });
        (
            Self {
                core_tx,
                shared_state,
            },
            update_rx,
        )
    }

    pub fn state(&self) -> State {
        self.shared_state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn dispatch(&self, action: Action) {
        let _ = self.core_tx.send(CoreMsg::Action(action));
    }
    pub fn set_log_bridge(&self, bridge: DynLogBridge) {
        let _ = self.core_tx.send(CoreMsg::SetLogBridge(bridge));
    }
    pub fn set_transport_bridge(&self, bridge: DynTransportBridge) {
        let _ = self.core_tx.send(CoreMsg::SetTransportBridge(bridge));
    }
    pub fn set_keychain_bridge(&self, bridge: DynKeychainBridge) {
        let _ = self.core_tx.send(CoreMsg::SetKeychainBridge(bridge));
    }
    pub fn set_audio_bridge(&self, bridge: DynAudioBridge) {
        let _ = self.core_tx.send(CoreMsg::SetAudioBridge(bridge));
    }
}
impl Drop for App {
    fn drop(&mut self) {
        let _ = self.core_tx.send(CoreMsg::Close);
    }
}

struct CoreState {
    data_dir: PathBuf,
    update_tx: Sender<Update>,
    shared_state: Arc<RwLock<State>>,
    core_tx: Sender<CoreMsg>,
    reticulum: Option<Reticulum>,
    lxmf_router: Option<Arc<LxmRouter>>,
    active_private_identity: Option<PrivateIdentity>,
    lxmf_delivery_config: Option<LxmfDeliveryConfig>,
    lxmf_router_config: RouterConfig,
    messages: HashMap<String, MessageSummary>,
    status: NodeStatus,
    toast: Option<String>,
    capabilities: BackendCapabilities,
    next_rev: u64,
    identities: HashMap<AddressHash, IdentitySummary>,
    destinations: HashMap<AddressHash, DestinationInfo>,
    peers: HashMap<AddressHash, PeerInfo>,
    links: HashMap<AddressHash, LinkInfo>,
    interfaces: Vec<ConfiguredInterface>,
    active_identity: Option<AddressHash>,
    tick_task: Option<tokio::task::JoinHandle<()>>,
    log_bridge: Option<DynLogBridge>,
    transport_bridge: Option<DynTransportBridge>,
    keychain_bridge: Option<DynKeychainBridge>,
    audio_bridge: Option<DynAudioBridge>,
    call_endpoint: Option<Arc<tokio::sync::Mutex<CallEndpoint>>>,
    call_state: HashMap<String, ActiveCallState>,
    incoming_calls: HashMap<String, LinkId>,
    resources: HashMap<String, ResourceSummary>,
    accepted_resources: Arc<std::sync::Mutex<HashSet<String>>>,
    discovery_announcer: Option<Arc<InterfaceAnnouncer>>,
    discovery: Option<Arc<InterfaceDiscovery>>,
    discovery_state: DiscoveryState,
    shared_instance: SharedInstanceState,
    shared_server_address: Option<AddressHash>,
    transport_enabled: bool,
    pending_request_handlers:
        Arc<std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    audio_policy: AudioPolicy,
    /// Default resource strategy applied to inbound links
    /// (`Action::SetResourceStrategy` with an empty link id).
    resource_strategy: ResourceStrategy,
    /// Inbound links seen activated on this transport.
    inbound_links: HashSet<LinkId>,
}

impl CoreState {
    fn new(
        data_dir: String,
        update_tx: Sender<Update>,
        shared_state: Arc<RwLock<State>>,
        core_tx: Sender<CoreMsg>,
    ) -> Self {
        let mut s = Self {
            data_dir: data_dir.into(),
            update_tx,
            shared_state,
            core_tx,
            reticulum: None,
            lxmf_router: None,
            active_private_identity: None,
            lxmf_delivery_config: None,
            lxmf_router_config: RouterConfig::default(),
            messages: HashMap::new(),
            status: NodeStatus::Stopped,
            toast: None,
            capabilities: BackendCapabilities::default(),
            next_rev: 0,
            identities: HashMap::new(),
            destinations: HashMap::new(),
            peers: HashMap::new(),
            links: HashMap::new(),
            interfaces: Vec::new(),
            active_identity: None,
            tick_task: None,
            log_bridge: None,
            transport_bridge: None,
            keychain_bridge: None,
            audio_bridge: None,
            call_endpoint: None,
            call_state: HashMap::new(),
            incoming_calls: HashMap::new(),
            resources: HashMap::new(),
            accepted_resources: Arc::new(std::sync::Mutex::new(HashSet::new())),
            discovery_announcer: None,
            discovery: None,
            discovery_state: DiscoveryState::default(),
            shared_instance: SharedInstanceState::default(),
            shared_server_address: None,
            transport_enabled: false,
            pending_request_handlers: Arc::new(std::sync::Mutex::new(HashMap::new())),
            audio_policy: AudioPolicy::default(),
            resource_strategy: ResourceStrategy::None,
            inbound_links: HashSet::new(),
        };
        s.refresh_capabilities();
        s
    }
    fn refresh_capabilities(&mut self) {
        self.capabilities = BackendCapabilities {
            tcp_client: true,
            tcp_server: true,
            udp: true,
            auto: cfg!(all(feature = "iface-auto", target_os = "linux")),
            rnode: cfg!(feature = "iface-rnode"),
            serial: cfg!(feature = "iface-serial"),
            kiss: cfg!(feature = "iface-serial"),
            ax25: cfg!(feature = "iface-serial"),
            i2p: cfg!(feature = "iface-i2p"),
            pipe: cfg!(feature = "iface-pipe"),
            backbone: cfg!(feature = "iface-backbone"),
            local_client: true,
            local_server: true,
            transport_bridge: self.transport_bridge.is_some(),
            keychain_bridge: self.keychain_bridge.is_some(),
            audio_bridge: self.audio_bridge.is_some(),
            log: self.log_bridge.is_some(),
            lxmf: self.lxmf_router.is_some(),
            propagation: self.lxmf_router.is_some(),
            lxst: self.call_endpoint.is_some(),
            resources: self.reticulum.is_some(),
            discovery: self.discovery.is_some(),
            shared_instance: self.shared_server_address.is_some(),
        };
    }
    fn send_update(&self, u: Update) {
        // Granular updates are delivered immediately; `emit` separately sends
        // the authoritative FullState snapshot after each actor-loop message.
        let _ = self.update_tx.send(u);
    }
    fn toast(&mut self, message: String) {
        self.toast = Some(message.clone());
        self.send_update(Update::Toast(message));
    }
    fn emit(&mut self, mut s: State) {
        s.rev = self.next_rev;
        self.next_rev += 1;
        *self.shared_state.write().unwrap_or_else(|e| e.into_inner()) = s.clone();
        self.send_update(Update::FullState(s));
    }
    fn clear_runtime(&mut self) {
        self.destinations.clear();
        self.peers.clear();
        self.links.clear();
        for i in &mut self.interfaces {
            i.address = None;
            i.failed = false;
        }
    }
    fn stop_tick(&mut self) {
        if let Some(h) = self.tick_task.take() {
            h.abort();
        }
    }

    async fn start(
        &mut self,
        transport_enabled: bool,
        selected: Option<&str>,
    ) -> Result<(), String> {
        self.transport_enabled = transport_enabled;
        install_log_sink(self.log_bridge.clone(), self.update_tx.clone());
        std::fs::create_dir_all(self.identities_dir()).map_err(|e| e.to_string())?;
        self.load_identity_summaries()?;
        let identity = self.select_identity(selected)?;
        let address = *identity.address_hash();
        self.active_identity = Some(address);
        self.write_active_identity(&address)?;
        let storage: Arc<dyn Storage> = Arc::new(FsStorage::new(self.data_dir.to_string_lossy()));
        let config = TransportConfig::new("reticulum-actor", &identity)
            .set_storage(storage)
            .set_retransmit(transport_enabled);
        self.reticulum = Some(Reticulum::new(config));
        self.active_private_identity = Some(identity.clone());
        self.start_lxmf_router().await?;
        self.start_call_endpoint(&identity).await;
        self.start_resource_listener().await;
        self.setup_listeners().await;
        self.refresh_capabilities();
        self.status = NodeStatus::Running {
            identity_hash: address.to_hex_string(),
        };
        self.send_update(Update::NodeStatus(self.status.clone()));
        self.send_update(Update::BackendCapabilities(self.capabilities.clone()));
        Ok(())
    }

    async fn stop(&mut self) {
        self.stop_tick();
        self.stop_m4_m5();
        self.pending_request_handlers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.lxmf_router = None;
        self.active_private_identity = None;
        self.reticulum = None;
        self.status = NodeStatus::Stopped;
        self.clear_runtime();
        self.send_update(Update::NodeStatus(NodeStatus::Stopped));
    }

    async fn start_call_endpoint(&mut self, identity: &PrivateIdentity) {
        let Some(r) = self.reticulum.as_ref() else {
            return;
        };
        let destination = r
            .add_destination(identity.clone(), lxst::call::call_endpoint_name())
            .await;
        let (endpoint, mut events) =
            CallEndpoint::with_destination(r.transport().clone(), destination, identity.clone());
        let endpoint = Arc::new(tokio::sync::Mutex::new(endpoint));
        endpoint.lock().await.announce().await;
        self.call_endpoint = Some(endpoint);
        let tx = self.core_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let internal = match event {
                    CallEvent::IncomingCall(id) => InternalEvent::CallIncoming(id),
                    CallEvent::Signalling(id, signals) => InternalEvent::CallSignal(id, signals),
                    CallEvent::Frame(id, frame) => InternalEvent::CallFrame(id, frame),
                    CallEvent::Closed(id) => InternalEvent::CallClosed(id),
                };
                if tx.send(CoreMsg::Internal(internal)).is_err() {
                    break;
                }
            }
        });
    }

    async fn start_resource_listener(&self) {
        let Some(r) = self.reticulum.as_ref() else {
            return;
        };
        let mut events = r.transport().resource_events().await;
        let tx = self.core_tx.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if tx
                            .send(CoreMsg::Internal(InternalEvent::Resource(event)))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    fn stop_m4_m5(&mut self) {
        self.call_endpoint = None;
        for (_, mut call) in self.call_state.drain() {
            if let Some(pump) = call.audio_pump.take() {
                pump.abort();
            }
        }
        self.incoming_calls.clear();
        self.resources.clear();
        self.discovery = None;
        self.discovery_announcer = None;
        self.discovery_state = DiscoveryState::default();
        self.shared_instance = SharedInstanceState::default();
        self.shared_server_address = None;
        self.refresh_capabilities();
    }

    async fn start_lxmf_router(&mut self) -> Result<(), String> {
        let reticulum = self.reticulum.as_ref().ok_or("Node is not running")?;
        let identity = self
            .active_private_identity
            .clone()
            .ok_or("No active identity")?;
        let delivery_config = self
            .lxmf_delivery_config
            .clone()
            .unwrap_or(LxmfDeliveryConfig {
                display_name: None,
                stamp_cost: None,
            });
        let delivery = Some(DeliveryConfig {
            identity: Some(identity.clone()),
            display_name: delivery_config.display_name,
            stamp_cost: delivery_config.stamp_cost,
        });
        let propagation_node = self.lxmf_router_config.propagation_node;
        let config = lxmf::router::RouterConfig {
            propagation_node,
            propagation_transfer_limit: if self.lxmf_router_config.propagation_transfer_limit > 0 {
                self.lxmf_router_config.propagation_transfer_limit as i64
            } else {
                0
            },
            propagation_sync_limit: if self.lxmf_router_config.message_storage_limit > 0 {
                self.lxmf_router_config.message_storage_limit as i64
            } else {
                0
            },
            ..Default::default()
        };
        let router = LxmRouter::new(
            reticulum.transport().as_ref().clone(),
            identity,
            self.data_dir.join("lxmf"),
            None::<String>,
            delivery,
            config,
        )
        .await;
        let mut events = router.subscribe();
        let tx = self.core_tx.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if tx
                            .send(CoreMsg::Internal(InternalEvent::Lxmf(event)))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        // A propagation node announces itself when enabled (Python
        // `LXMRouter(want_node_announce=True)` announces on start).
        if propagation_node {
            router.announce_propagation_node().await;
        }
        self.lxmf_router = Some(router);
        Ok(())
    }

    fn identities_dir(&self) -> PathBuf {
        self.data_dir.join("identities")
    }
    fn active_path(&self) -> PathBuf {
        self.data_dir.join("active_identity")
    }
    fn identity_bytes(&self, path: &Path, address_hint: Option<&str>) -> Result<Vec<u8>, String> {
        let raw = std::fs::read(path).map_err(|e| e.to_string())?;
        const HEADER: &[u8] = b"reticulum-keychain-v1:";
        if let Some(rest) = raw.strip_prefix(HEADER) {
            let newline = rest
                .iter()
                .position(|b| *b == b'\n')
                .ok_or("Invalid encrypted identity header")?;
            let stored_address =
                std::str::from_utf8(&rest[..newline]).map_err(|e| e.to_string())?;
            if address_hint.is_some_and(|hint| hint != stored_address) {
                return Err("Identity address hint mismatch".into());
            }
            let plain = self
                .keychain_bridge
                .as_ref()
                .and_then(|b| b.decrypt(stored_address, &rest[newline + 1..]))
                .ok_or_else(|| "Unable to decrypt identity".to_string())?;
            return decode_identity_plaintext(plain);
        }
        let text = String::from_utf8_lossy(&raw);
        if let Some(v) = hex_decode(text.trim()) {
            return Ok(v);
        }
        let plain = self
            .keychain_bridge
            .as_ref()
            .and_then(|b| b.decrypt(address_hint.unwrap_or(""), &raw))
            .ok_or_else(|| "Invalid or encrypted identity".to_string())?;
        decode_identity_plaintext(plain)
    }
    fn save_identity(&self, name: &str, id: &PrivateIdentity) -> Result<(), String> {
        validate_name(name)?;
        std::fs::create_dir_all(self.identities_dir()).map_err(|e| e.to_string())?;
        let plain = id.to_hex_string().into_bytes();
        let addr = id.address_hash().to_hex_string();
        let bytes = if let Some(bridge) = &self.keychain_bridge {
            let encrypted = bridge.encrypt(&addr, &plain);
            let mut envelope = format!("reticulum-keychain-v1:{addr}\n").into_bytes();
            envelope.extend(encrypted);
            envelope
        } else {
            plain
        };
        std::fs::write(self.identities_dir().join(name), bytes).map_err(|e| e.to_string())
    }
    fn load_identity_summaries(&mut self) -> Result<(), String> {
        self.identities.clear();
        let active = std::fs::read_to_string(self.active_path()).ok();
        for entry in std::fs::read_dir(self.identities_dir()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry.file_type().map_err(|e| e.to_string())?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Ok(bytes) = self.identity_bytes(&entry.path(), None) {
                if let Ok(id) = PrivateIdentity::new_from_bytes(&bytes) {
                    let address = *id.address_hash();
                    self.identities.insert(
                        address,
                        IdentitySummary {
                            name,
                            address_hash: address.to_hex_string(),
                            public_key_hex: to_hex(&id.as_identity().to_bytes()),
                            active: active.as_deref().map(str::trim)
                                == Some(&address.to_hex_string()),
                            encrypted: std::fs::read(entry.path())
                                .is_ok_and(|b| b.starts_with(b"reticulum-keychain-v1:")),
                        },
                    );
                }
            }
        }
        Ok(())
    }
    fn select_identity(&mut self, requested: Option<&str>) -> Result<PrivateIdentity, String> {
        let requested = requested.map(str::to_owned).or_else(|| {
            std::fs::read_to_string(self.active_path())
                .ok()
                .map(|s| s.trim().into())
        });
        if let Some(address) = requested {
            if let Some((_, summary)) = self
                .identities
                .iter()
                .find(|(a, s)| a.to_hex_string() == address || s.name == address)
            {
                let bytes = self.identity_bytes(
                    &self.identities_dir().join(&summary.name),
                    Some(&summary.address_hash),
                )?;
                return PrivateIdentity::new_from_bytes(&bytes).map_err(|e| format!("{e:?}"));
            }
            return Err(format!("Identity not found: {address}"));
        }
        if let Some(summary) = self
            .identities
            .values()
            .find(|s| s.name == "default")
            .or_else(|| self.identities.values().next())
        {
            let bytes = self.identity_bytes(
                &self.identities_dir().join(&summary.name),
                Some(&summary.address_hash),
            )?;
            return PrivateIdentity::new_from_bytes(&bytes).map_err(|e| format!("{e:?}"));
        }
        let id = PrivateIdentity::new_from_rand(OsRng);
        self.save_identity("default", &id)?;
        self.load_identity_summaries()?;
        Ok(id)
    }
    fn write_active_identity(&self, address: &AddressHash) -> Result<(), String> {
        std::fs::write(self.active_path(), address.to_hex_string()).map_err(|e| e.to_string())
    }

    async fn setup_listeners(&self) {
        let r = self.reticulum.as_ref().unwrap().clone();
        let tx = self.core_tx.clone();
        let mut rx = r.transport().recv_announces().await;
        tokio::spawn(async move {
            while let Ok(e) = rx.recv().await {
                let d = e.destination.lock().await;
                let _ = tx.send(CoreMsg::Internal(InternalEvent::Announce(
                    d.desc.address_hash,
                    d.desc.name.as_name_hash_slice().to_vec(),
                    e.app_data.as_slice().to_vec(),
                )));
            }
        });
        // Track inbound link activations so the configured default
        // resource strategy can be applied to links the app never saw.
        let r = self.reticulum.as_ref().unwrap().clone();
        let tx = self.core_tx.clone();
        let mut rx = r.transport().in_link_events();
        tokio::spawn(async move {
            while let Ok(e) = rx.recv().await {
                if let LinkEvent::Activated = e.event {
                    let _ = tx.send(CoreMsg::Internal(InternalEvent::InboundLink(e.id)));
                }
            }
        });
        let r = self.reticulum.as_ref().unwrap().clone();
        let tx = self.core_tx.clone();
        let mut rx = r.transport().received_data_events();
        tokio::spawn(async move {
            while let Ok(e) = rx.recv().await {
                let _ = tx.send(CoreMsg::Internal(InternalEvent::Data(
                    e.destination,
                    e.data.as_slice().to_vec(),
                )));
            }
        });
    }

    async fn handle_action(&mut self, action: Action) -> Result<(), String> {
        if let Action::ActivateIdentity { address } = &action {
            let a = parse_address(address)?;
            if !self.identities.contains_key(&a) {
                return Err("Unknown identity".into());
            }
            self.write_active_identity(&a)?;
            let transport_enabled = self.transport_enabled;
            let interfaces = std::mem::take(&mut self.interfaces);
            self.stop().await;
            self.start(transport_enabled, Some(address)).await?;
            let reticulum = self
                .reticulum
                .as_ref()
                .ok_or("Node failed to restart")?
                .clone();
            for interface in interfaces {
                self.add_interface(
                    &reticulum,
                    interface.name,
                    interface.config,
                    interface.ifac,
                    interface.enabled,
                )
                .await?;
            }
            return Ok(());
        }
        let r = self
            .reticulum
            .as_ref()
            .ok_or("Node is not running")?
            .clone();
        match action {
            Action::Start { .. } | Action::Stop => {
                return Err("Lifecycle action handled by actor".into());
            }
            Action::AddInterface {
                name,
                config,
                ifac,
                enabled,
            } => self.add_interface(&r, name, config, ifac, enabled).await?,
            Action::RemoveInterface { address } => {
                let a = parse_address(&address)?;
                r.interface_manager().lock().await.stop_iface(&a);
                self.interfaces.retain(|i| i.address != Some(a));
                self.send_update(Update::InterfaceRemoved { address });
            }
            Action::RenameInterface { address, name } => {
                let a = parse_address(&address)?;
                r.interface_manager().lock().await.set_iface_name(&a, &name);
                if let Some(i) = self.interfaces.iter_mut().find(|i| i.address == Some(a)) {
                    i.name = name;
                }
            }
            Action::RestartInterface { address } => {
                let a = parse_address(&address)?;
                let old = self
                    .interfaces
                    .iter()
                    .find(|i| i.address == Some(a))
                    .cloned()
                    .ok_or("Unknown interface")?;
                r.interface_manager().lock().await.stop_iface(&a);
                self.interfaces.retain(|i| i.address != Some(a));
                self.add_interface(&r, old.name, old.config, old.ifac, old.enabled)
                    .await?;
            }
            Action::SetInterfaceEnabled { address, enabled } => {
                let a = parse_address(&address)?;
                let old = self
                    .interfaces
                    .iter()
                    .find(|i| i.address == Some(a))
                    .cloned()
                    .ok_or("Unknown interface")?;
                if !enabled && old.enabled {
                    r.interface_manager().lock().await.stop_iface(&a);
                    if let Some(i) = self.interfaces.iter_mut().find(|i| i.address == Some(a)) {
                        i.enabled = false;
                    }
                } else if enabled && !old.enabled {
                    self.interfaces.retain(|i| i.address != Some(a));
                    self.add_interface(&r, old.name, old.config, old.ifac, true)
                        .await?;
                }
            }
            Action::SetInterfaceMode { address, mode } => {
                let a = parse_address(&address)?;
                let parsed = parse_mode(&mode)?;
                if !r
                    .interface_manager()
                    .lock()
                    .await
                    .set_iface_mode(&a, parsed)
                {
                    return Err("Unknown interface".into());
                }
                if let Some(i) = self.interfaces.iter_mut().find(|i| i.address == Some(a)) {
                    i.mode = mode;
                }
            }
            Action::SetInterfaceBitrate { address, bitrate } => {
                let a = parse_address(&address)?;
                if !r
                    .interface_manager()
                    .lock()
                    .await
                    .set_iface_bitrate(&a, bitrate)
                {
                    return Err("Unknown interface".into());
                }
                if let Some(i) = self.interfaces.iter_mut().find(|i| i.address == Some(a)) {
                    i.bitrate = bitrate;
                }
            }
            Action::SetInterfaceIfac { address, ifac } => {
                let a = parse_address(&address)?;
                r.interface_manager()
                    .lock()
                    .await
                    .set_iface_ifac(
                        &a,
                        ifac.netname.as_deref(),
                        ifac.netkey.as_deref(),
                        ifac.size as usize,
                    )
                    .map_err(|e| format!("{e:?}"))?;
                if let Some(i) = self.interfaces.iter_mut().find(|i| i.address == Some(a)) {
                    i.ifac = Some(ifac);
                }
            }
            Action::CreateIdentity { name } => {
                let id = PrivateIdentity::new_from_rand(OsRng);
                self.save_identity(&name, &id)?;
                self.load_identity_summaries()?;
                self.send_update(Update::IdentityCreated {
                    address_hash: id.address_hash().to_hex_string(),
                });
            }
            Action::ImportIdentity { name, hex } => {
                let b = hex_decode(&hex).ok_or("Invalid identity hex")?;
                let id = PrivateIdentity::new_from_bytes(&b).map_err(|e| format!("{e:?}"))?;
                self.save_identity(&name, &id)?;
                self.load_identity_summaries()?;
                self.send_update(Update::IdentityCreated {
                    address_hash: id.address_hash().to_hex_string(),
                });
            }
            Action::ImportIdentityFile { name, path } => {
                let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
                let b = hex_decode(raw.trim()).ok_or("Invalid identity hex")?;
                let id = PrivateIdentity::new_from_bytes(&b).map_err(|e| format!("{e:?}"))?;
                self.save_identity(&name, &id)?;
                self.load_identity_summaries()?;
                self.send_update(Update::IdentityCreated {
                    address_hash: id.address_hash().to_hex_string(),
                });
            }
            Action::ExportIdentity { address, path } => {
                let a = parse_address(&address)?;
                let s = self.identities.get(&a).ok_or("Unknown identity")?;
                let b =
                    self.identity_bytes(&self.identities_dir().join(&s.name), Some(&address))?;
                std::fs::write(path, to_hex(&b)).map_err(|e| e.to_string())?;
            }
            Action::ActivateIdentity { address } => {
                return Err(format!(
                    "Identity activation was not intercepted: {address}"
                ));
            }
            Action::RemoveIdentity { address } => {
                let a = parse_address(&address)?;
                if self.active_identity == Some(a) {
                    return Err("Cannot remove active identity".into());
                }
                let s = self.identities.remove(&a).ok_or("Unknown identity")?;
                std::fs::remove_file(self.identities_dir().join(s.name))
                    .map_err(|e| e.to_string())?;
            }
            Action::CreateDestination { app_name, aspect } => {
                self.create_destination(&r, PrivateIdentity::new_from_rand(OsRng), app_name, aspect)
                    .await
            }
            Action::LoadDestination {
                identity_hex,
                app_name,
                aspect,
            } => {
                let b = hex_decode(&identity_hex).ok_or("Invalid identity hex")?;
                let id = PrivateIdentity::new_from_bytes(&b).map_err(|e| format!("{e:?}"))?;
                self.create_destination(&r, id, app_name, aspect).await;
            }
            Action::Announce {
                destination_hash,
                app_data,
            } => {
                let a = parse_address(&destination_hash)?;
                let d = &self
                    .destinations
                    .get(&a)
                    .ok_or("Unknown local destination")?
                    .arc;
                r.announce(d, Some(&app_data)).await;
            }
            Action::RequestPath { destination_hash } => {
                let a = parse_address(&destination_hash)?;
                r.request_path(&a).await;
                let tx = self.core_tx.clone();
                let rr = r.clone();
                tokio::spawn(async move {
                    let ok = rr.await_path(&a, Some(Duration::from_secs(10))).await;
                    let hops = if ok { rr.hops_to(&a).await } else { None };
                    let _ = tx.send(CoreMsg::Internal(InternalEvent::PathResult(a, hops)));
                });
            }
            Action::DropPath { destination_hash } => {
                let a = parse_address(&destination_hash)?;
                r.transport().drop_path(&a).await;
                self.send_update(Update::PathLost { destination_hash });
            }
            Action::MarkPathUnresponsive { destination_hash } => {
                r.transport()
                    .mark_path_unresponsive(&parse_address(&destination_hash)?)
                    .await;
            }
            Action::MarkPathResponsive { destination_hash } => {
                r.transport()
                    .mark_path_responsive(&parse_address(&destination_hash)?)
                    .await;
            }
            Action::OpenLink { destination_hash } => {
                self.open_link(&r, parse_address(&destination_hash)?)
                    .await?
            }
            Action::CloseLink { destination_hash } => {
                r.transport()
                    .link_close(parse_address(&destination_hash)?)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
            }
            Action::SendData {
                destination_hash,
                data,
            } => {
                self.send_data(&r, parse_address(&destination_hash)?, data)
                    .await?
            }
            Action::SendRequest {
                destination_hash,
                path,
                data,
                timeout_ms,
            } => {
                let a = parse_address(&destination_hash)?;
                let link = r
                    .transport()
                    .find_out_link(&a)
                    .await
                    .ok_or("No link to destination")?;
                let id = r
                    .transport()
                    .request(&link, &path, &data)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                let rr = r.clone();
                let tx = self.core_tx.clone();
                tokio::spawn(async move {
                    match rr
                        .transport()
                        .await_request_response(id, Duration::from_millis(timeout_ms))
                        .await
                    {
                        Some(data) => {
                            let _ = tx.send(CoreMsg::Internal(InternalEvent::Response(
                                id.to_hex_string(),
                                data,
                            )));
                        }
                        None => {
                            let _ = tx.send(CoreMsg::Internal(InternalEvent::RequestFailed(
                                id.to_hex_string(),
                            )));
                        }
                    }
                });
            }
            Action::RegisterRequestHandler {
                destination_hash,
                path,
            } => {
                let a = parse_address(&destination_hash)?;
                let tx = self.core_tx.clone();
                let pending = self.pending_request_handlers.clone();
                let p = path.clone();
                r.transport()
                    .register_async_request_handler(&a, &path, move |ctx| {
                        let tx = tx.clone();
                        let pending = pending.clone();
                        let p = p.clone();
                        async move {
                            let request_id = ctx.request_id.to_hex_string();
                            let (response_tx, response_rx) = tokio::sync::oneshot::channel();
                            pending
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(request_id.clone(), response_tx);
                            let _ = tx.send(CoreMsg::Internal(InternalEvent::RequestReceived(
                                request_id.clone(),
                                a,
                                p,
                                ctx.data,
                            )));
                            // Responses travel msgpack-wrapped (Python
                            // `umsgpack.packb`).
                            let response = response_rx
                                .await
                                .ok()
                                .map(|data| reticulum::resource::msgpack_bin(&data));
                            pending
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&request_id);
                            response
                        }
                    })
                    .await;
            }
            Action::SendResponse { request_id, data } => {
                let sender = self
                    .pending_request_handlers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&request_id)
                    .ok_or("Unknown or completed request")?;
                sender
                    .send(data)
                    .map_err(|_| "Request is no longer pending")?;
            }
            Action::GetCapabilities => {
                self.send_update(Update::BackendCapabilities(self.capabilities.clone()))
            }
            Action::SetLogBridge => {
                if self.log_bridge.is_none() {
                    return Err("No LogBridge registered on App".into());
                }
                self.refresh_capabilities();
            }
            Action::SetTransportBridge => {
                if self.transport_bridge.is_none() {
                    return Err("No TransportBridge registered on App".into());
                }
                self.refresh_capabilities();
            }
            Action::SetKeychainBridge => {
                if self.keychain_bridge.is_none() {
                    return Err("No KeychainBridge registered on App".into());
                }
                self.refresh_capabilities();
            }
            Action::StartNetworkTick { interval_ms } => {
                self.stop_tick();
                let tx = self.core_tx.clone();
                self.tick_task = Some(tokio::spawn(async move {
                    let mut timer =
                        tokio::time::interval(Duration::from_millis(interval_ms.max(10)));
                    loop {
                        timer.tick().await;
                        if tx
                            .send(CoreMsg::Internal(InternalEvent::NetworkTick))
                            .is_err()
                        {
                            break;
                        }
                    }
                }));
            }
            Action::StopNetworkTick => self.stop_tick(),
            Action::SetLxmfDeliveryIdentity { config } => {
                self.lxmf_delivery_config = Some(config);
                self.start_lxmf_router().await?;
            }
            Action::AnnounceLxmfDelivery => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .announce_delivery()
                    .await;
            }
            Action::AnnounceLxmfPropagationNode => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .announce_propagation_node()
                    .await;
            }
            Action::SendLxmfMessage {
                destination_hash,
                fields,
                method,
                stamp_cost,
                include_ticket,
                transport_encryption,
            } => {
                let router = self
                    .lxmf_router
                    .clone()
                    .ok_or("LXMF router is not running")?;
                let source = self
                    .active_private_identity
                    .clone()
                    .ok_or("No active identity")?;
                let source_hash = router
                    .delivery_destination_hash()
                    .await
                    .unwrap_or_else(|| *source.address_hash());
                let mut message = LXMessage::new(
                    parse_address(&destination_hash)?,
                    source_hash,
                    fields.title.as_deref().unwrap_or("").as_bytes(),
                    fields.text.as_deref().unwrap_or("").as_bytes(),
                );
                message.fields = map_lxmf_fields(&fields)?;
                message.desired_method = Some(match method {
                    LxmfDeliveryMethod::Direct => DIRECT,
                    LxmfDeliveryMethod::Opportunistic => OPPORTUNISTIC,
                    LxmfDeliveryMethod::Propagated => PROPAGATED,
                    LxmfDeliveryMethod::Paper => PAPER,
                });
                message.stamp_cost = stamp_cost;
                message.include_ticket = include_ticket;
                if let Some(value) = &transport_encryption {
                    let encryption = LxmfTransportEncryption::parse(value)?;
                    message.set_transport_encryption(match encryption {
                        LxmfTransportEncryption::Aes128 => {
                            lxmf::message::TransportEncryption::Aes128
                        }
                        LxmfTransportEncryption::Curve25519 => {
                            lxmf::message::TransportEncryption::Curve25519
                        }
                        LxmfTransportEncryption::Unencrypted => {
                            lxmf::message::TransportEncryption::Unencrypted
                        }
                    });
                }
                match message.desired_method {
                    Some(PROPAGATED) => message.pack_propagation(&source, OsRng),
                    Some(PAPER) => message.pack_paper(&source, OsRng),
                    _ => message.pack(&source),
                }
                .map_err(|e| e.to_string())?;
                let hash = message.hash.map(|h| h.to_string()).unwrap_or_default();
                let mut summary = message_summary(&message, fields);
                summary.state = "Sending".into();
                self.messages.insert(hash.clone(), summary);
                self.send_update(Update::MessageStateChanged {
                    hash: hash.clone(),
                    state: "Sending".into(),
                    progress: 0.0,
                });
                if message.desired_method == Some(PAPER) {
                    let uri = message.as_uri().map_err(|e| e.to_string())?;
                    self.send_update(Update::PaperMessagePacked {
                        hash: hash.clone(),
                        uri,
                    });
                }
                router
                    .send(&mut message, &source)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Action::IngestLxmUri { uri } => {
                self.lxmf_router
                    .clone()
                    .ok_or("LXMF router is not running")?
                    .ingest_lxm_uri(&uri, false)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Action::IgnoreDestination { destination_hash } => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .ignore_destination(parse_address(&destination_hash)?)
                    .await;
            }
            Action::UnignoreDestination { destination_hash } => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .unignore_destination(parse_address(&destination_hash)?)
                    .await;
            }
            Action::SetLxmfRouterConfig { config } => {
                self.lxmf_router_config = config;
                self.start_lxmf_router().await?;
            }
            Action::SetActivePropagationNode { destination_hash } => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .set_active_propagation_node(parse_address(&destination_hash)?)
                    .await;
            }
            Action::GenerateTicket { destination_hash } => {
                let destination = parse_address(&destination_hash)?;
                let result = self
                    .lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .generate_ticket(&destination)
                    .await;
                self.toast(match result {
                    Some((expires, ticket)) => {
                        format!("Ticket {} expires at {expires}", to_hex(&ticket))
                    }
                    None => "No ticket generated".into(),
                });
            }
            Action::PeerPropagationNode { destination_hash } => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .peer(
                        parse_address(&destination_hash)?,
                        now_seconds() as i64,
                        lxmf::router::PROPAGATION_LIMIT,
                        None,
                        lxmf::router::PROPAGATION_COST,
                        lxmf::router::PROPAGATION_COST_FLEX,
                        lxmf::router::PEERING_COST,
                        None,
                    )
                    .await;
            }
            Action::UnpeerPropagationNode { destination_hash } => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .unpeer(&parse_address(&destination_hash)?, None)
                    .await;
            }
            Action::RequestPropagationSync { max_messages } => {
                self.lxmf_router
                    .clone()
                    .ok_or("LXMF router is not running")?
                    .request_messages_from_propagation_node(Some(max_messages))
                    .await;
            }
            Action::CancelPropagationSync => {
                self.lxmf_router
                    .as_ref()
                    .ok_or("LXMF router is not running")?
                    .cancel_propagation_node_requests()
                    .await;
            }
            Action::StartCall {
                destination_hash,
                codec,
            } => {
                let destination = parse_address(&destination_hash)?;
                let desc = self
                    .resolve_desc(&r, destination)
                    .await
                    .ok_or("Unknown call destination")?;
                let link = r.transport().link(desc).await;
                let id = *link.lock().await.id();
                self.activate_call(link, destination_hash.clone(), codec, "Calling")
                    .await?;
                self.send_update(Update::CallStateChanged {
                    call_id: id.to_hex_string(),
                    state: "Calling".into(),
                });
            }
            Action::AnswerCall { call_id, codec } => {
                let id = parse_address(&call_id)?;
                if !self.incoming_calls.contains_key(&call_id) {
                    return Err("Unknown incoming call".into());
                }
                let link = r
                    .transport()
                    .find_in_link(&id)
                    .await
                    .ok_or("Incoming call link is unavailable")?;
                self.activate_call(link, String::new(), codec, "Established")
                    .await?;
                self.incoming_calls.remove(&call_id);
                self.send_update(Update::CallStateChanged {
                    call_id,
                    state: "Established".into(),
                });
            }
            Action::DeclineCall { call_id } => {
                let id = parse_address(&call_id)?;
                r.transport()
                    .link_close(id)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                self.incoming_calls.remove(&call_id);
                if let Some(mut call) = self.call_state.remove(&call_id) {
                    if let Some(pump) = call.audio_pump.take() {
                        pump.abort();
                    }
                }
                self.send_update(Update::CallClosed { call_id });
            }
            Action::HangupCall { call_id } => {
                let id = parse_address(&call_id)?;
                r.transport()
                    .link_close(id)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                if let Some(mut call) = self.call_state.remove(&call_id) {
                    if let Some(pump) = call.audio_pump.take() {
                        pump.abort();
                    }
                }
                self.send_update(Update::CallClosed { call_id });
            }
            Action::AnnounceCallEndpoint => {
                let endpoint = self
                    .call_endpoint
                    .as_ref()
                    .ok_or("Call endpoint unavailable")?
                    .clone();
                endpoint.lock().await.announce().await;
            }
            Action::SendCallSignal { call_id, signal } => {
                let signal = parse_signal(&signal)?;
                let call = self.call_state.get(&call_id).ok_or("Unknown active call")?;
                let endpoint = self
                    .call_endpoint
                    .as_ref()
                    .ok_or("Call endpoint unavailable")?;
                let guard = endpoint.lock().await;
                let active = guard.has_active_call();
                drop(guard);
                if !active {
                    return Err("Call is not active".into());
                }
                // Packetizer is owned by the endpoint; signalling is encoded as a
                // one-byte LXST signalling frame through a short-lived packetizer.
                let link = r
                    .transport()
                    .find_in_link(&call.link_id)
                    .await
                    .or(r.transport().find_out_link(&call.link_id).await)
                    .ok_or("Call link unavailable")?;
                let (packetizer, _) = lxst::network::Packetizer::new_for_link(
                    r.transport().clone(),
                    link,
                    call.codec,
                );
                packetizer
                    .send_signal(signal.code())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Action::SendAudioFrames { call_id, frames } => {
                let call = self.call_state.get(&call_id).ok_or("Unknown active call")?;
                for frame in frames {
                    call.transmit
                        .send(frame)
                        .await
                        .map_err(|_| "Call transmit path closed")?;
                }
            }
            Action::SetAudioBridge => {
                if self.audio_bridge.is_none() {
                    return Err("No audio bridge is registered".into());
                }
            }
            Action::SetAudioPolicy { policy } => {
                if let Some(min_quality) = policy.min_quality {
                    if !(0.0..=1.0).contains(&min_quality) {
                        return Err("min_quality must be between 0.0 and 1.0".into());
                    }
                }
                self.audio_policy = policy;
            }
            Action::AdvertiseResource {
                link_id,
                data,
                metadata,
            } => {
                let link = self.find_link(&r, &link_id).await?;
                let options = ResourceOptions {
                    metadata: metadata.clone(),
                    ..ResourceOptions::default()
                };
                let hash = r
                    .transport()
                    .send_resource_with_options(&link, data.clone(), options)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                self.resources.insert(
                    hash.to_string(),
                    ResourceSummary {
                        hash: hash.to_string(),
                        link_id,
                        status: "Advertised".into(),
                        progress: 0.0,
                        size: data.len() as u64,
                        metadata,
                        outgoing: true,
                    },
                );
            }
            Action::AcceptResource { hash } => {
                self.accepted_resources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(hash);
            }
            Action::CancelResource { hash } => {
                let summary = self
                    .resources
                    .get(&hash)
                    .cloned()
                    .ok_or_else(|| format!("Unknown resource: {hash}"))?;
                let link_id = parse_address(&summary.link_id)?;
                let bytes =
                    hex_decode(&hash).ok_or("Invalid resource hash (expected 64 hex chars)")?;
                let resource_hash = reticulum::hash::Hash::new(
                    bytes
                        .try_into()
                        .map_err(|_| "Resource hash must be 32 bytes")?,
                );
                r.transport()
                    .cancel_resource(&link_id, &resource_hash)
                    .await
                    .map_err(|e| format!("{e:?}"))?;
                if let Some(resource) = self.resources.get_mut(&hash) {
                    resource.status = "Failed".into();
                    resource.progress = 0.0;
                }
                self.send_update(Update::ResourceFailed { hash: hash.clone() });
            }
            Action::SetResourceStrategy { link_id, strategy } => {
                let parsed = match strategy.to_ascii_lowercase().as_str() {
                    "all" => ResourceStrategy::All,
                    "app" => ResourceStrategy::App,
                    "none" => ResourceStrategy::None,
                    _ => return Err("Resource strategy must be None, App, or All".into()),
                };
                if link_id.is_empty() {
                    // Empty link id configures the transport-level default
                    // applied to every link without an explicit entry
                    // (inbound links included), plus the accept callback
                    // for already-known inbound links.
                    self.resource_strategy = parsed;
                    r.transport().set_default_resource_strategy(parsed).await;
                    for id in self.inbound_links.clone() {
                        r.transport().set_resource_strategy(id, parsed).await;
                        if parsed == ResourceStrategy::App {
                            let accepted = self.accepted_resources.clone();
                            r.transport()
                                .set_resource_accept_callback(
                                    id,
                                    Arc::new(move |adv| {
                                        accepted
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .contains(&adv.hash.to_string())
                                    }),
                                )
                                .await;
                        }
                    }
                    return Ok(());
                }
                let id = parse_address(&link_id)?;
                r.transport().set_resource_strategy(id, parsed).await;
                if parsed == ResourceStrategy::App {
                    let accepted = self.accepted_resources.clone();
                    r.transport()
                        .set_resource_accept_callback(
                            id,
                            Arc::new(move |adv| {
                                accepted
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .contains(&adv.hash.to_string())
                            }),
                        )
                        .await;
                }
            }
            Action::StartDiscovery {
                required_value,
                autoconnect,
            } => {
                let identity = self
                    .active_private_identity
                    .as_ref()
                    .ok_or("No active identity")?;
                let announcer = InterfaceAnnouncer::start(
                    r.transport(),
                    identity,
                    required_value.min(u32::MAX as u64) as u32,
                    Duration::from_secs(60),
                )
                .await;
                for configured in &self.interfaces {
                    if let InterfaceConfig::TcpServer { bind } = &configured.config {
                        if let Some((host, port)) = split_host_port(bind) {
                            announcer
                                .announce_interface(InterfaceInfo {
                                    interface_type: "TCPServerInterface".into(),
                                    transport: true,
                                    transport_id: *identity.address_hash(),
                                    name: Some(configured.name.clone()),
                                    latitude: None,
                                    longitude: None,
                                    height: None,
                                    reachable_on: Some(host),
                                    port: Some(port),
                                    frequency: None,
                                    bandwidth: None,
                                    spreadingfactor: None,
                                    codingrate: None,
                                    channel: None,
                                    modulation: None,
                                    ifac_netname: configured
                                        .ifac
                                        .as_ref()
                                        .and_then(|v| v.netname.clone()),
                                    ifac_netkey: configured
                                        .ifac
                                        .as_ref()
                                        .and_then(|v| v.netkey.clone()),
                                    transport_impl: None,
                                    transport_vers: None,
                                    operator_lxmf_address: None,
                                })
                                .await;
                        }
                    }
                }
                self.discovery_announcer = Some(announcer);
                let discovery = InterfaceDiscovery::start(
                    r.transport(),
                    required_value.min(u32::MAX as u64) as u32,
                    autoconnect,
                )
                .await;
                self.discovery = Some(discovery);
                self.discovery_state.announcing = true;
                self.discovery_state.listening = true;
                self.discovery_state.autoconnect = autoconnect;
                self.refresh_capabilities();
            }
            Action::StopDiscovery => {
                self.discovery = None;
                self.discovery_announcer = None;
                self.discovery_state = DiscoveryState::default();
                self.send_update(Update::DiscoveryUpdated {
                    interfaces: Vec::new(),
                });
                self.refresh_capabilities();
            }
            Action::ConnectDiscoveredInterface { transport_id } => {
                let discovery = self.discovery.as_ref().ok_or("Discovery is not running")?;
                let entry = discovery
                    .list()
                    .await
                    .into_iter()
                    .find(|entry| entry.info.transport_id.to_hex_string() == transport_id)
                    .ok_or("Discovered interface not found")?;
                let info = entry.info;
                let host = info
                    .reachable_on
                    .ok_or("Discovered interface has no address")?;
                let port = info.port.ok_or("Discovered interface has no port")?;
                let config = match info.interface_type.as_str() {
                    "TCPServerInterface" | "BackboneInterface" => InterfaceConfig::TcpClient {
                        address: endpoint(&host, port),
                    },
                    "LocalServerInterface" => InterfaceConfig::LocalClient {
                        name: info.name.clone().unwrap_or_else(|| transport_id.clone()),
                        address: SharedInstanceAddress::Tcp { port },
                    },
                    _ => {
                        return Err(format!(
                            "Unsupported discovered interface type: {}",
                            info.interface_type
                        ))
                    }
                };
                let ifac = if info.ifac_netname.is_some() || info.ifac_netkey.is_some() {
                    Some(IfacConfig {
                        netname: info.ifac_netname,
                        netkey: info.ifac_netkey,
                        size: 8,
                    })
                } else {
                    None
                };
                let name = info
                    .name
                    .unwrap_or_else(|| format!("Discovered {transport_id}"));
                self.add_interface(&r, name, config, ifac, true).await?;
            }
            Action::StartSharedInstance { address, access } => {
                let mapped = map_shared(address.clone())?;
                let access = access.unwrap_or_default();
                let manager = r.interface_manager();
                let server = LocalServer::new_with_access(
                    mapped,
                    manager.clone(),
                    reticulum::iface::local::SharedInstanceAccessConfig {
                        allow: access.allow,
                        required_token: access.required_token,
                        max_clients: access.max_clients,
                    },
                );
                let id = manager.lock().await.spawn(server, LocalServer::spawn);
                manager.lock().await.set_iface_name(&id, "shared instance");
                self.shared_server_address = Some(id);
                self.shared_instance.hosting = true;
                self.shared_instance.address = Some(address);
                self.refresh_capabilities();
            }
            Action::StopSharedInstance => {
                if let Some(id) = self.shared_server_address.take() {
                    r.interface_manager().lock().await.stop_iface(&id);
                }
                self.shared_instance = SharedInstanceState::default();
                self.refresh_capabilities();
            }
            Action::ConnectSharedInstance {
                name,
                address,
                access_token,
            } => {
                let manager = r.interface_manager();
                let client = match access_token {
                    Some(token) => {
                        LocalClient::new_authenticated(name.clone(), map_shared(address)?, token)
                    }
                    None => LocalClient::new(name.clone(), map_shared(address)?),
                };
                let id = manager.lock().await.spawn(client, LocalClient::spawn);
                manager.lock().await.set_iface_name(&id, &name);
            }
            Action::ClearToast => self.toast = None,
        }
        Ok(())
    }

    async fn create_destination(
        &mut self,
        r: &Reticulum,
        id: PrivateIdentity,
        app: String,
        aspect: String,
    ) {
        let name = DestinationName::new(&app, &aspect);
        let a = name.address_hash_for(&id);
        let arc = r.add_destination(id, name).await;
        self.destinations.insert(
            a,
            DestinationInfo {
                arc,
                app_name: app,
                aspect,
            },
        );
    }

    async fn add_interface(
        &mut self,
        r: &Reticulum,
        name: String,
        config: InterfaceConfig,
        ifac: Option<IfacConfig>,
        enabled: bool,
    ) -> Result<(), String> {
        let mut record = ConfiguredInterface {
            address: None,
            name: name.clone(),
            config: config.clone(),
            ifac: ifac.clone(),
            enabled,
            failed: false,
            mode: "Full".into(),
            bitrate: 0,
        };
        if !enabled {
            self.interfaces.push(record);
            return Ok(());
        }
        let manager = r.interface_manager();
        let mut m = manager.lock().await;
        let (address, kind) = match config {
            InterfaceConfig::TcpClient { address } => (
                m.spawn(TcpClient::new(address), TcpClient::spawn),
                "TcpClient",
            ),
            InterfaceConfig::TcpServer { bind } => (
                m.spawn(TcpServer::new(bind, manager.clone()), TcpServer::spawn),
                "TcpServer",
            ),
            InterfaceConfig::Udp {
                bind,
                forward,
                broadcast,
            } => (
                m.spawn(
                    UdpInterface::new(bind, forward, broadcast),
                    UdpInterface::spawn,
                ),
                "Udp",
            ),
            InterfaceConfig::LocalClient { name, address } => {
                use reticulum::iface::local::LocalClient;
                (
                    m.spawn(
                        LocalClient::new(name, map_shared(address)?),
                        LocalClient::spawn,
                    ),
                    "LocalClient",
                )
            }
            InterfaceConfig::LocalServer { address } => {
                use reticulum::iface::local::LocalServer;
                (
                    m.spawn(
                        LocalServer::new(map_shared(address)?, manager.clone()),
                        LocalServer::spawn,
                    ),
                    "LocalServer",
                )
            }
            c => {
                drop(m);
                return self.add_feature_interface(r, name, c, ifac).await;
            }
        };
        m.set_iface_name(&address, &name);
        if let Some(v) = &ifac {
            m.set_iface_ifac(
                &address,
                v.netname.as_deref(),
                v.netkey.as_deref(),
                v.size as usize,
            )
            .map_err(|e| format!("{e:?}"))?;
        }
        record.address = Some(address);
        self.interfaces.push(record);
        self.send_update(Update::InterfaceAdded {
            address: address.to_hex_string(),
            name,
            kind: kind.into(),
        });
        Ok(())
    }

    async fn add_feature_interface(
        &mut self,
        r: &Reticulum,
        name: String,
        config: InterfaceConfig,
        ifac: Option<IfacConfig>,
    ) -> Result<(), String> {
        let kind = interface_kind(&config).to_string();
        let manager = r.interface_manager();
        #[allow(unused_mut)]
        let mut address: Option<AddressHash> = None;
        match config.clone() {
            #[cfg(all(feature = "iface-auto", target_os = "linux"))]
            InterfaceConfig::Auto { group_id } => {
                use reticulum::iface::auto::{AutoInterface, AutoInterfaceConfig};
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    AutoInterface::new(AutoInterfaceConfig::new(group_id), manager.clone()),
                    AutoInterface::spawn,
                ));
            }
            #[cfg(feature = "iface-serial")]
            InterfaceConfig::Serial { port, speed } => {
                use reticulum::iface::kiss::SerialPortConfig;
                use reticulum::iface::serial::SerialInterface;
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    SerialInterface::new(SerialPortConfig::new(port, speed)),
                    SerialInterface::spawn,
                ));
            }
            #[cfg(feature = "iface-serial")]
            InterfaceConfig::Kiss { port, speed } => {
                use reticulum::iface::kiss::{CsmaParams, KissInterface, SerialPortConfig};
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    KissInterface::new(
                        SerialPortConfig::new(port, speed),
                        CsmaParams::default(),
                        false,
                    ),
                    KissInterface::spawn,
                ));
            }
            #[cfg(feature = "iface-serial")]
            InterfaceConfig::KissAx25 {
                callsign,
                ssid,
                port,
                speed,
            } => {
                use reticulum::iface::kiss::{CsmaParams, KissInterface, SerialPortConfig};
                let mut m = manager.lock().await;
                let kiss = KissInterface::new_ax25(
                    callsign,
                    ssid,
                    SerialPortConfig::new(port, speed),
                    CsmaParams::default(),
                    false,
                )
                .map_err(|e| format!("{e:?}"))?;
                address = Some(m.spawn(kiss, KissInterface::spawn));
            }
            #[cfg(feature = "iface-pipe")]
            InterfaceConfig::Pipe { command } => {
                use reticulum::iface::pipe::PipeInterface;
                let mut m = manager.lock().await;
                address = Some(m.spawn(PipeInterface::new(command), PipeInterface::spawn));
            }
            #[cfg(feature = "iface-i2p")]
            InterfaceConfig::I2pClient {
                sam_addr,
                session_id,
                destination,
            } => {
                use reticulum::iface::i2p::I2pPeer;
                let mut m = manager.lock().await;
                address = Some(
                    m.spawn(
                        I2pPeer::new_initiator(&sam_addr, &session_id, &destination)
                            .with_manager(manager.clone()),
                        I2pPeer::spawn,
                    ),
                );
            }
            #[cfg(feature = "iface-i2p")]
            InterfaceConfig::I2pServer {
                sam_addr,
                session_id,
            } => {
                use reticulum::iface::i2p::I2pServer;
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    I2pServer::new(sam_addr, session_id, manager.clone()),
                    I2pServer::spawn,
                ));
            }
            #[cfg(feature = "iface-rnode")]
            InterfaceConfig::RnodeTcp { address: addr } => {
                use reticulum::iface::rnode::RnodeInterface;
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    RnodeInterface::tcp(addr, default_rnode_config()).with_manager(manager.clone()),
                    RnodeInterface::spawn,
                ));
            }
            #[cfg(all(feature = "iface-rnode", feature = "iface-serial"))]
            InterfaceConfig::RnodeSerial { port, speed } => {
                use reticulum::iface::rnode::RnodeInterface;
                let mut m = manager.lock().await;
                address = Some(
                    m.spawn(
                        RnodeInterface::serial(port, speed, default_rnode_config())
                            .with_manager(manager.clone()),
                        RnodeInterface::spawn,
                    ),
                );
            }
            #[cfg(feature = "iface-rnode")]
            InterfaceConfig::RnodeMulti {
                tcp_addr: Some(addr),
                ..
            } => {
                use reticulum::iface::rnode::RnodeMultiInterface;
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    RnodeMultiInterface::tcp(addr, Vec::new(), manager.clone()),
                    RnodeMultiInterface::spawn,
                ));
            }
            #[cfg(all(feature = "iface-rnode", feature = "iface-serial"))]
            InterfaceConfig::RnodeMulti {
                serial_port: Some(port),
                baudrate,
                ..
            } => {
                use reticulum::iface::rnode::RnodeMultiInterface;
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    RnodeMultiInterface::serial(port, baudrate, Vec::new(), manager.clone()),
                    RnodeMultiInterface::spawn,
                ));
            }
            #[cfg(feature = "iface-backbone")]
            InterfaceConfig::BackboneClient { address: addr } => {
                use reticulum::iface::backbone::BackboneClient;
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    BackboneClient::new(addr).with_manager(manager.clone()),
                    BackboneClient::spawn,
                ));
            }
            #[cfg(feature = "iface-backbone")]
            InterfaceConfig::BackboneServer { bind } => {
                use reticulum::iface::backbone::{BackboneServer, FastFlapTable};
                let table = Arc::new(tokio::sync::Mutex::new(FastFlapTable::new(
                    true,
                    Duration::from_secs(10),
                    3,
                    Duration::from_secs(60),
                )));
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    BackboneServer::new(bind, manager.clone(), table),
                    BackboneServer::spawn,
                ));
            }
            InterfaceConfig::Bridge { kind: bridge_kind } if self.transport_bridge.is_some() => {
                let bridge = self.transport_bridge.clone().expect("bridge checked above");
                let mut m = manager.lock().await;
                address = Some(m.spawn(
                    BridgeInterface::new(bridge_kind, bridge),
                    BridgeInterface::spawn,
                ));
            }
            _ => {}
        }
        let address = address.ok_or_else(|| format!("{kind} is not available on this build"))?;
        let mut m = manager.lock().await;
        m.set_iface_name(&address, &name);
        if let Some(v) = &ifac {
            m.set_iface_ifac(
                &address,
                v.netname.as_deref(),
                v.netkey.as_deref(),
                v.size as usize,
            )
            .map_err(|e| format!("{e:?}"))?;
        }
        drop(m);
        self.interfaces.push(ConfiguredInterface {
            address: Some(address),
            name: name.clone(),
            config,
            ifac,
            enabled: true,
            failed: false,
            mode: "Full".into(),
            bitrate: 0,
        });
        self.send_update(Update::InterfaceAdded {
            address: address.to_hex_string(),
            name,
            kind,
        });
        Ok(())
    }

    /// Resolve a link by its id: inbound links are keyed by id, outbound
    /// links by destination hash, so out-links go through the tracked
    /// link table first.
    async fn find_link(
        &self,
        r: &Reticulum,
        link_id: &str,
    ) -> Result<Arc<tokio::sync::Mutex<reticulum::destination::link::Link>>, String> {
        let id = parse_address(link_id)?;
        if let Some(link) = r.transport().find_in_link(&id).await {
            return Ok(link);
        }
        if let Some(info) = self.links.values().find(|l| l.id == id) {
            if let Some(link) = r.transport().find_out_link(&info.destination).await {
                return Ok(link);
            }
        }
        // Fall back to a direct destination-hash lookup for callers that
        // pass the destination instead of the link id.
        r.transport()
            .find_out_link(&id)
            .await
            .ok_or_else(|| "Unknown link".to_string())
    }

    async fn open_link(&mut self, r: &Reticulum, a: AddressHash) -> Result<(), String> {
        let desc = self.resolve_desc(r, a).await.ok_or("Unknown destination")?;
        let link = r.transport().link(desc).await;
        let id = *link.lock().await.id();
        let mut rx = r.transport().events_for_link(id).await;
        let tx = self.core_tx.clone();
        tokio::spawn(async move {
            while let Ok(e) = rx.recv().await {
                let x = match e.event {
                    LinkEvent::Activated => InternalEvent::LinkActivated(e.id, e.address_hash),
                    LinkEvent::Data(p) => {
                        InternalEvent::LinkData(e.id, e.address_hash, p.as_slice().to_vec())
                    }
                    LinkEvent::Closed => InternalEvent::LinkClosed(e.id, e.address_hash),
                    _ => continue,
                };
                let _ = tx.send(CoreMsg::Internal(x));
            }
        });
        self.links.insert(
            a,
            LinkInfo {
                id,
                destination: a,
                status: "Pending".into(),
                outbound: true,
            },
        );
        self.send_update(Update::LinkOpened {
            link_id: id.to_hex_string(),
            destination_hash: a.to_hex_string(),
        });
        Ok(())
    }
    async fn send_data(&self, r: &Reticulum, a: AddressHash, data: Vec<u8>) -> Result<(), String> {
        if let Some(link) = r.transport().find_out_link(&a).await {
            let l = link.lock().await;
            if l.status() == LinkStatus::Active {
                let p = l.data_packet(&data).map_err(|e| format!("{e:?}"))?;
                r.transport().send_packet(p).await;
                return Ok(());
            }
        }
        match r.transport().send_to_destination(&a, &data).await {
            Ok(_) => Ok(()),
            Err(RnsError::LinkNotReady) => {
                r.request_path(&a).await;
                Err("Destination not known; requested a path".into())
            }
            Err(e) => Err(format!("{e:?}")),
        }
    }
    async fn resolve_desc(&self, r: &Reticulum, a: AddressHash) -> Option<DestinationDesc> {
        if let Some(i) = self.destinations.get(&a) {
            return Some(i.arc.lock().await.desc);
        }
        r.transport()
            .get_out_destination(&a)
            .await
            .and_then(|d| d.try_lock().ok().map(|x| x.desc))
    }

    /// Tear down an active or incoming call: abort the audio pump, close
    /// the link and emit `Update::CallClosed`.
    async fn close_call(&mut self, r: &Reticulum, call_id: &str) {
        if let Ok(id) = parse_address(call_id) {
            let _ = r.transport().link_close(id).await;
        }
        if let Some(mut call) = self.call_state.remove(call_id) {
            if let Some(pump) = call.audio_pump.take() {
                pump.abort();
            }
        }
        self.incoming_calls.remove(call_id);
        self.send_update(Update::CallClosed {
            call_id: call_id.to_string(),
        });
    }

    async fn activate_call(
        &mut self,
        link: Arc<tokio::sync::Mutex<reticulum::destination::link::Link>>,
        destination_hash: String,
        codec: CodecType,
        state: &str,
    ) -> Result<(), String> {
        let endpoint = self
            .call_endpoint
            .as_ref()
            .ok_or("Call endpoint unavailable")?
            .clone();
        let wire_codec = map_codec(&codec);
        let handle = endpoint
            .lock()
            .await
            .answer(link, wire_codec, None, None)
            .await
            .map_err(|e| e.to_string())?;
        let call_id = handle.link_id.to_hex_string();
        let transmit = handle.transmit();
        let quality = Arc::new(CallQuality::default());
        let audio_pump = if let Some(bridge) = self.audio_bridge.clone() {
            let codec_name = wire_codec.name().to_string();
            let quality = quality.clone();
            let transmit = transmit.clone();
            let policy = self.audio_policy.clone();
            let update_tx = self.update_tx.clone();
            let call_id = handle.link_id.to_hex_string();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(60));
                let mut consecutive_failures: u32 = 0;
                // Null-codec fallback state: once the platform bridge fails
                // repeatedly the pump stops calling into it and only keeps
                // the call control path alive.
                let mut null_fallback = false;
                loop {
                    interval.tick().await;
                    if null_fallback {
                        // Degraded: do not call the (failing) platform
                        // bridge; keep the pump alive for teardown.
                        continue;
                    }
                    // Track per-call callback latency: slow platform audio
                    // (JNI/FFI boundary) starves the transmit queue. A tick
                    // whose callback exceeded the warning threshold counts
                    // as a failure; sustained failures degrade the pump.
                    let started = std::time::Instant::now();
                    let frames = bridge.read_frames(&codec_name, 16);
                    let latency = started.elapsed().as_millis() as u64;
                    let previous_max = quality
                        .max_latency_ms
                        .fetch_max(latency, std::sync::atomic::Ordering::Relaxed);
                    let failed = latency > policy.warning_latency_ms;
                    if failed && previous_max <= policy.warning_latency_ms {
                        quality
                            .warnings
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let _ = update_tx.send(Update::AudioWarning {
                            call_id: call_id.clone(),
                            message: format!(
                                "audio bridge callback latency {latency} ms exceeded {} ms",
                                policy.warning_latency_ms
                            ),
                        });
                    }
                    quality
                        .consecutive
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    for frame in frames {
                        quality
                            .attempts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if transmit.send(frame).await.is_err() {
                            quality
                                .consecutive
                                .store(0, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        quality
                            .successes
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    if failed {
                        consecutive_failures += 1;
                    } else {
                        consecutive_failures = 0;
                    }
                    if consecutive_failures >= policy.max_consecutive_failures.max(1) {
                        null_fallback = true;
                        quality
                            .degraded
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        let _ = update_tx.send(Update::AudioWarning {
                            call_id: call_id.clone(),
                            message: format!(
                                "audio bridge failed {consecutive_failures} times in a row;                                  falling back to null codec"
                            ),
                        });
                    }
                }
            }))
        } else {
            None
        };
        self.call_state.insert(
            call_id.clone(),
            ActiveCallState {
                link_id: handle.link_id,
                destination_hash,
                state: state.into(),
                codec: wire_codec,
                transmit: transmit.clone(),
                audio_pump,
                quality,
                low_quality_ticks: 0,
            },
        );
        Ok(())
    }

    async fn handle_internal(&mut self, event: InternalEvent) {
        match event {
            InternalEvent::Announce(a, n, d) => {
                self.peers.insert(
                    a,
                    PeerInfo {
                        address: a,
                        name_hash: n.clone(),
                        app_data: d.clone(),
                    },
                );
                self.send_update(Update::AnnounceReceived {
                    address_hash: a.to_hex_string(),
                    name_hash_hex: to_hex(&n),
                    app_data: d,
                    hops: None,
                });
            }
            InternalEvent::LinkActivated(id, a) => {
                if let Some(l) = self.links.get_mut(&a) {
                    l.id = id;
                    l.status = "Active".into()
                }
                self.send_update(Update::LinkActivated {
                    link_id: id.to_hex_string(),
                    destination_hash: a.to_hex_string(),
                });
            }
            InternalEvent::LinkData(id, a, d) => {
                if let Some(l) = self.links.get_mut(&a) {
                    l.id = id
                }
                self.send_update(Update::LinkData {
                    link_id: id.to_hex_string(),
                    data: d,
                });
            }
            InternalEvent::LinkClosed(id, a) => {
                if let Some(l) = self.links.get_mut(&a) {
                    l.status = "Closed".into()
                }
                self.send_update(Update::LinkClosed {
                    link_id: id.to_hex_string(),
                });
            }
            InternalEvent::Data(a, d) => self.send_update(Update::DataReceived {
                destination_hash: a.to_hex_string(),
                data: d,
            }),
            InternalEvent::RequestReceived(id, a, path, data) => {
                self.send_update(Update::RequestReceived {
                    request_id: id,
                    destination_hash: a.to_hex_string(),
                    path,
                    data,
                })
            }
            InternalEvent::Response(request_id, data) => {
                self.send_update(Update::ResponseReceived { request_id, data })
            }
            InternalEvent::RequestFailed(request_id) => {
                self.send_update(Update::RequestFailed { request_id })
            }
            InternalEvent::PathResult(a, Some(h)) => self.send_update(Update::PathResolved {
                destination_hash: a.to_hex_string(),
                hops: h,
            }),
            InternalEvent::PathResult(a, None) => self.send_update(Update::PathLost {
                destination_hash: a.to_hex_string(),
            }),
            InternalEvent::NetworkTick => {
                if let Some(r) = self.reticulum.clone() {
                    let interfaces = self.interface_summaries(&r).await;
                    self.send_update(Update::NetworkTick(NetworkTick {
                        timestamp_ms: now_ms(),
                        interfaces,
                    }));
                    if let Some(discovery) = &self.discovery {
                        if self.discovery_state.autoconnect {
                            let _ = discovery.connect_discovered().await;
                        }
                        let found: Vec<_> = discovery
                            .list()
                            .await
                            .into_iter()
                            .map(map_discovered)
                            .collect();
                        self.discovery_state.interfaces = found.clone();
                        self.send_update(Update::DiscoveryUpdated { interfaces: found });
                    }
                    // Auto-close calls whose blended quality stays below the
                    // configured floor (audio fallback / radio telemetry).
                    if let Some(min_quality) = self.audio_policy.min_quality {
                        let transport = r.transport().clone();
                        let mut radio: HashMap<LinkId, LinkRadioQuality> = HashMap::new();
                        for call in self.call_state.values() {
                            if let Some(stats) =
                                transport.interface_stats_for_link(call.link_id).await
                            {
                                radio.insert(
                                    call.link_id,
                                    (
                                        stats.rssi,
                                        stats.snr.map(f64::from),
                                        stats.quality.map(f64::from),
                                    ),
                                );
                            }
                        }
                        let summaries = self.call_summaries(&radio);
                        let mut to_close: Vec<(String, f64)> = Vec::new();
                        for summary in &summaries {
                            let Some(quality) = summary.quality else {
                                continue;
                            };
                            if let Some(call) = self.call_state.get_mut(&summary.id) {
                                if quality < min_quality {
                                    call.low_quality_ticks += 1;
                                } else {
                                    call.low_quality_ticks = 0;
                                }
                                if call.low_quality_ticks
                                    >= self.audio_policy.quality_grace_ticks.max(1)
                                {
                                    to_close.push((summary.id.clone(), quality));
                                }
                            }
                        }
                        for (call_id, quality) in to_close {
                            self.send_update(Update::AudioWarning {
                                call_id: call_id.clone(),
                                message: format!(
                                    "call quality {quality:.3} below minimum {min_quality:.3};                                      closing call"
                                ),
                            });
                            self.close_call(&r, &call_id).await;
                        }
                    }
                    if self.shared_instance.hosting {
                        let clients: Vec<String> = r
                            .interface_stats()
                            .await
                            .into_iter()
                            .filter(|s| s.kind == "LocalClient" && s.online)
                            .map(|s| s.name)
                            .collect();
                        eprintln!(
                            "TICK-DBG: hosting clients={clients:?} known={:?}",
                            self.shared_instance.clients
                        );
                        for client in clients
                            .iter()
                            .filter(|c| !self.shared_instance.clients.contains(c))
                        {
                            eprintln!("TICK-DBG: emitting connected for {client}");
                            self.send_update(Update::SharedInstanceClientConnected {
                                address: client.clone(),
                            });
                        }
                        for client in self
                            .shared_instance
                            .clients
                            .iter()
                            .filter(|c| !clients.contains(c))
                        {
                            self.send_update(Update::SharedInstanceClientDisconnected {
                                address: client.clone(),
                            });
                        }
                        self.shared_instance.clients = clients;
                    }
                }
            }
            InternalEvent::Lxmf(event) => self.handle_lxmf_event(event).await,
            InternalEvent::CallIncoming(id) => {
                let call_id = id.to_hex_string();
                self.incoming_calls.insert(call_id.clone(), id);
                self.send_update(Update::IncomingCall {
                    call_id,
                    destination_hash: self
                        .active_identity
                        .map(|a| a.to_hex_string())
                        .unwrap_or_default(),
                });
            }
            InternalEvent::CallSignal(id, signals) => {
                let call_id = id.to_hex_string();
                if let Some(signal) = signals.last().and_then(|v| Signal::from_code(*v)) {
                    let state = signal_state(signal).to_string();
                    if let Some(call) = self.call_state.get_mut(&call_id) {
                        call.state = state.clone();
                    }
                    self.send_update(Update::CallStateChanged { call_id, state });
                }
            }
            InternalEvent::CallFrame(id, frame) => {
                let call_id = id.to_hex_string();
                let codec = self
                    .call_state
                    .get(&call_id)
                    .map(|c| c.codec.name())
                    .unwrap_or("Raw")
                    .to_string();
                let mut data = Vec::with_capacity(frame.samples.len() * 4);
                for sample in frame.samples {
                    data.extend_from_slice(&sample.to_le_bytes());
                }
                if let Some(bridge) = &self.audio_bridge {
                    bridge.write_frames(&codec, vec![data.clone()]);
                    if let Some(call) = self.call_state.get(&call_id) {
                        call.quality
                            .attempts
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        call.quality
                            .successes
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        call.quality
                            .consecutive
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                self.send_update(Update::CallFrames {
                    call_id,
                    codec,
                    data,
                });
            }
            InternalEvent::CallClosed(id) => {
                let call_id = id.to_hex_string();
                if let Some(mut call) = self.call_state.remove(&call_id) {
                    if let Some(pump) = call.audio_pump.take() {
                        pump.abort();
                    }
                }
                self.incoming_calls.remove(&call_id);
                self.send_update(Update::CallClosed { call_id });
            }
            InternalEvent::Resource(event) => self.handle_resource_event(event),
            InternalEvent::InboundLink(id) => {
                if self.inbound_links.insert(id) {
                    // Apply the configured default resource strategy to
                    // links the app never opened itself.
                    if let Some(r) = self.reticulum.clone() {
                        let accepted = self.accepted_resources.clone();
                        r.transport()
                            .set_resource_strategy(id, self.resource_strategy)
                            .await;
                        if self.resource_strategy == ResourceStrategy::App {
                            r.transport()
                                .set_resource_accept_callback(
                                    id,
                                    Arc::new(move |adv| {
                                        accepted
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .contains(&adv.hash.to_string())
                                    }),
                                )
                                .await;
                        }
                    }
                }
            }
        }
    }

    fn handle_resource_event(&mut self, event: ResourceEvent) {
        let hash = event.hash.to_string();
        let status = resource_status_name(event.status).to_string();
        let size = event
            .advertisement
            .as_ref()
            .map(|a| a.data_size as u64)
            .unwrap_or_else(|| {
                event
                    .data
                    .as_ref()
                    .map(|d| d.len() as u64)
                    .unwrap_or_default()
            });
        let outgoing = self
            .resources
            .get(&hash)
            .map(|r| r.outgoing)
            .unwrap_or(false);
        self.resources.insert(
            hash.clone(),
            ResourceSummary {
                hash: hash.clone(),
                link_id: event.link_id.to_hex_string(),
                status: status.clone(),
                progress: event.progress,
                size,
                metadata: event.metadata.clone(),
                outgoing,
            },
        );
        match event.status {
            ResourceStatus::Complete => self.send_update(Update::ResourceComplete {
                hash,
                data: event.data,
                metadata: event.metadata,
            }),
            ResourceStatus::Failed | ResourceStatus::Corrupt | ResourceStatus::Rejected => {
                self.send_update(Update::ResourceFailed { hash })
            }
            _ => self.send_update(Update::ResourceProgress {
                hash,
                status,
                progress: event.progress,
            }),
        }
    }

    async fn handle_lxmf_event(&mut self, event: LxmEvent) {
        match event {
            LxmEvent::Received(message) => {
                let hash = message.hash.map(|h| h.to_string()).unwrap_or_default();
                let source_hash = message.source_hash.to_hex_string();
                let destination_hash = message.destination_hash.to_hex_string();
                let fields = decode_lxmf_fields(&message.fields);
                self.messages
                    .insert(hash.clone(), message_summary(&message, fields));
                self.send_update(Update::MessageReceived {
                    hash,
                    source_hash,
                    destination_hash,
                });
            }
            LxmEvent::Duplicate(message) => {
                self.send_update(Update::MessageDuplicate {
                    hash: message.hash.map(|h| h.to_string()).unwrap_or_default(),
                });
            }
            LxmEvent::DeliveryReceipt { message_hash } => {
                let hash = message_hash.to_string();
                if let Some(message) = self.messages.get_mut(&hash) {
                    message.state = "Delivered".into();
                    message.progress = 1.0;
                }
                self.send_update(Update::DeliveryReceipt { hash: hash.clone() });
                self.send_update(Update::MessageStateChanged {
                    hash,
                    state: "Delivered".into(),
                    progress: 1.0,
                });
            }
            LxmEvent::SendFailed {
                message_hash,
                reason,
            } => {
                let hash = message_hash.to_string();
                if let Some(message) = self.messages.get_mut(&hash) {
                    message.state = "Failed".into();
                }
                self.send_update(Update::SendFailed {
                    hash: hash.clone(),
                    reason: format!("{reason:?}"),
                });
                self.send_update(Update::MessageStateChanged {
                    hash,
                    state: "Failed".into(),
                    progress: 0.0,
                });
            }
            LxmEvent::PropagationTransfer(_) => {
                if let Some(router) = &self.lxmf_router {
                    let transfer = router.propagation_transfer_state().await;
                    self.send_update(Update::PropagationTransferChanged {
                        state: propagation_state_name(transfer.state),
                        progress: transfer.progress,
                        size: transfer.size as u64,
                    });
                }
            }
            LxmEvent::Announce(_) | LxmEvent::PropagationStored { .. } => {}
        }
    }

    async fn interface_summaries(&self, r: &Reticulum) -> Vec<InterfaceSummary> {
        let stats = r.interface_stats().await;
        self.interfaces
            .iter()
            .map(|c| {
                let s = c
                    .address
                    .and_then(|a| stats.iter().find(|s| s.address == a));
                map_interface(c, s)
            })
            .collect()
    }
    async fn build_state(&self) -> State {
        let mut s = self.build_state_offline();
        if let Some(r) = &self.reticulum {
            s.interfaces = self.interface_summaries(r).await;
            // Radio link-quality telemetry for active calls (RNode RSSI /
            // SNR / `q`), blended into `CallSummary::quality`.
            if !self.call_state.is_empty() {
                let mut radio: HashMap<LinkId, LinkRadioQuality> = HashMap::new();
                for call in self.call_state.values() {
                    if let Some(stats) = r.transport().interface_stats_for_link(call.link_id).await
                    {
                        radio.insert(
                            call.link_id,
                            (
                                stats.rssi,
                                stats.snr.map(f64::from),
                                stats.quality.map(f64::from),
                            ),
                        );
                    }
                }
                s.calls = self.call_summaries(&radio);
            }
            s.paths = r
                .path_table()
                .await
                .into_iter()
                .map(|p| PathSummary {
                    destination_hash: p.destination.to_hex_string(),
                    hops: p.hops,
                    via: p.via.to_hex_string(),
                    interface: p.iface.to_hex_string(),
                    timestamp: 0.0,
                    unresponsive: p.unresponsive,
                })
                .collect();
            s.tunnels = r
                .tunnel_table()
                .await
                .into_iter()
                .map(|t| TunnelSummary {
                    destination_hash: t.tunnel_id.to_hex_string(),
                    interface: t.iface.map(|a| a.to_hex_string()).unwrap_or_default(),
                    hops: t.paths.min(u8::MAX as usize) as u8,
                    expires: 0.0,
                })
                .collect();
        }
        if let Some(router) = &self.lxmf_router {
            let peers = router.peers().await;
            s.peers.extend(peers.values().map(|p| PeerSummary {
                address_hash: p.destination_hash.to_hex_string(),
                name_hash_hex: String::new(),
                app_data: Vec::new(),
                hops: None,
            }));
            s.propagation.peers = peers
                .values()
                .map(|p| PropagationPeerSummary {
                    destination_hash: p.destination_hash.to_hex_string(),
                    name: None,
                    peering_value: p.peering_cost.unwrap_or_default(),
                })
                .collect();
            s.propagation.entries = router
                .propagation_entries()
                .await
                .into_iter()
                .map(|(hash, e)| PropagationEntrySummary {
                    hash: hash.to_string(),
                    source: String::new(),
                    destination: e.destination_hash.to_hex_string(),
                    received: e.received,
                    size: e.size as u64,
                })
                .collect();
            let transfer = router.propagation_transfer_state().await;
            s.propagation.active_node = router
                .get_outbound_propagation_node()
                .await
                .map(|a| a.to_hex_string());
            s.propagation.sync_state = propagation_state_name(transfer.state);
            s.propagation.sync_progress = transfer.progress;
            s.propagation.sync_size = transfer.size as u64;
        }
        if let Some(discovery) = &self.discovery {
            if self.discovery_state.autoconnect {
                let _ = discovery.connect_discovered().await;
            }
            s.discovery.interfaces = discovery
                .list()
                .await
                .into_iter()
                .map(map_discovered)
                .collect();
        }
        s
    }
    /// Summaries of active calls with blended quality. `radio` maps link
    /// ids to the link interface's `(rssi, snr, quality)` telemetry; when
    /// an [`AudioBridge`] is active the audio-delivery quality and the
    /// radio link quality are averaged, otherwise whichever exists wins.
    fn call_summaries(&self, radio: &HashMap<LinkId, LinkRadioQuality>) -> Vec<CallSummary> {
        self.call_state
            .iter()
            .map(|(id, call)| {
                let audio = self
                    .audio_bridge
                    .is_some()
                    .then(|| call.quality.audio_quality())
                    .flatten();
                let (rssi, snr, radio_quality) =
                    radio.get(&call.link_id).cloned().unwrap_or_default();
                let quality = match (audio, radio_quality) {
                    (Some(audio), Some(radio_q)) => Some((audio + radio_q / 100.0) / 2.0),
                    (Some(audio), None) => Some(audio),
                    (None, Some(radio_q)) => Some(radio_q / 100.0),
                    (None, None) => None,
                };
                CallSummary {
                    id: id.clone(),
                    destination_hash: call.destination_hash.clone(),
                    state: call.state.clone(),
                    codec: call.codec.name().into(),
                    muted: false,
                    speaker: true,
                    quality,
                    rssi,
                    snr,
                    radio_quality,
                }
            })
            .collect()
    }

    fn build_state_offline(&self) -> State {
        let mut s = State::empty();
        s.status = self.status.clone();
        s.capabilities = self.capabilities.clone();
        s.toast = self.toast.clone();
        s.identities = self.identities.values().cloned().collect();
        s.active_identity = self
            .active_identity
            .and_then(|a| self.identities.get(&a).cloned());
        s.interfaces = self
            .interfaces
            .iter()
            .map(|c| map_interface(c, None))
            .collect();
        s.destinations = self
            .destinations
            .values()
            .filter_map(|i| {
                i.arc.try_lock().ok().map(|d| DestinationSummary {
                    address_hash: d.desc.address_hash.to_hex_string(),
                    app_name: i.app_name.clone(),
                    aspect: i.aspect.clone(),
                    accepts_links: d.accepts_links,
                    ratchets_enabled: d.ratchets.is_some(),
                })
            })
            .collect();
        s.peers = self
            .peers
            .values()
            .map(|p| PeerSummary {
                address_hash: p.address.to_hex_string(),
                name_hash_hex: to_hex(&p.name_hash),
                app_data: p.app_data.clone(),
                hops: None,
            })
            .collect();
        s.links = self
            .links
            .values()
            .map(|l| LinkSummary {
                id: l.id.to_hex_string(),
                destination_hash: l.destination.to_hex_string(),
                status: l.status.clone(),
                is_outbound: l.outbound,
                mdu: 0,
            })
            .collect();
        s.messages = self.messages.values().cloned().collect();
        s.calls = self.call_summaries(&HashMap::new());
        s.resources = self.resources.values().cloned().collect();
        s.discovery = self.discovery_state.clone();
        s.shared_instance = self.shared_instance.clone();
        s
    }
}

fn map_interface(c: &ConfiguredInterface, s: Option<&InterfaceStats>) -> InterfaceSummary {
    InterfaceSummary {
        address: c.address.map(|a| a.to_hex_string()).unwrap_or_default(),
        name: c.name.clone(),
        kind: interface_kind(&c.config).into(),
        enabled: c.enabled,
        online: s.map(|x| x.online).unwrap_or(false),
        failed: c.failed,
        sent: s.map(|x| x.sent).unwrap_or(0),
        received: s.map(|x| x.received).unwrap_or(0),
        tx_bytes: s.map(|x| x.tx_bytes).unwrap_or(0),
        rx_bytes: s.map(|x| x.rx_bytes).unwrap_or(0),
        announces_received: s.map(|x| x.announces_received).unwrap_or(0),
        announces_sent: s.map(|x| x.announces_sent).unwrap_or(0),
        announce_bytes_received: s.map(|x| x.announce_bytes_received).unwrap_or(0),
        announce_bytes_sent: s.map(|x| x.announce_bytes_sent).unwrap_or(0),
        path_requests_received: s.map(|x| x.path_requests_received).unwrap_or(0),
        path_requests_sent: s.map(|x| x.path_requests_sent).unwrap_or(0),
        protocol_violations: s.map(|x| x.protocol_violations).unwrap_or(0),
        ifac_violations: s.map(|x| x.ifac_violations).unwrap_or(0),
        packet_filter_hits: s.map(|x| x.packet_filter_hits).unwrap_or(0),
        mode: c.mode.clone(),
        bitrate: c.bitrate,
        ifac_netname: c.ifac.as_ref().and_then(|x| x.netname.clone()),
        ifac_netkey: c.ifac.as_ref().and_then(|x| x.netkey.clone()),
        rssi: s.and_then(|x| x.rssi),
        snr: s.and_then(|x| x.snr).map(f64::from),
        quality: s.and_then(|x| x.quality).map(f64::from),
    }
}
fn interface_kind(c: &InterfaceConfig) -> &'static str {
    match c {
        InterfaceConfig::TcpClient { .. } => "TcpClient",
        InterfaceConfig::TcpServer { .. } => "TcpServer",
        InterfaceConfig::Udp { .. } => "Udp",
        InterfaceConfig::Auto { .. } => "Auto",
        InterfaceConfig::RnodeTcp { .. } => "RnodeTcp",
        InterfaceConfig::RnodeSerial { .. } => "RnodeSerial",
        InterfaceConfig::RnodeMulti { .. } => "RnodeMulti",
        InterfaceConfig::Serial { .. } => "Serial",
        InterfaceConfig::Kiss { .. } => "Kiss",
        InterfaceConfig::KissAx25 { .. } => "KissAx25",
        InterfaceConfig::I2pClient { .. } => "I2pClient",
        InterfaceConfig::I2pServer { .. } => "I2pServer",
        InterfaceConfig::Pipe { .. } => "Pipe",
        InterfaceConfig::BackboneClient { .. } => "BackboneClient",
        InterfaceConfig::BackboneServer { .. } => "BackboneServer",
        InterfaceConfig::LocalClient { .. } => "LocalClient",
        InterfaceConfig::LocalServer { .. } => "LocalServer",
        InterfaceConfig::Bridge { .. } => "Bridge",
    }
}
fn parse_mode(s: &str) -> Result<InterfaceMode, String> {
    match s.to_ascii_lowercase().as_str() {
        "full" => Ok(InterfaceMode::Full),
        "pointtopoint" | "point_to_point" => Ok(InterfaceMode::PointToPoint),
        "accesspoint" | "access_point" => Ok(InterfaceMode::AccessPoint),
        "roaming" => Ok(InterfaceMode::Roaming),
        "boundary" => Ok(InterfaceMode::Boundary),
        "gateway" => Ok(InterfaceMode::Gateway),
        _ => Err(format!("Invalid interface mode: {s}")),
    }
}
fn map_codec(codec: &CodecType) -> lxst::codecs::CodecType {
    match codec {
        CodecType::Raw => lxst::codecs::CodecType::Raw,
        CodecType::Opus => lxst::codecs::CodecType::Opus,
        CodecType::Codec2 => lxst::codecs::CodecType::Codec2,
        CodecType::Null => lxst::codecs::CodecType::Null,
    }
}
fn parse_signal(signal: &str) -> Result<Signal, String> {
    match signal.to_ascii_lowercase().replace(['_', '-'], "").as_str() {
        "busy" | "statusbusy" => Ok(Signal::StatusBusy),
        "rejected" | "statusrejected" => Ok(Signal::StatusRejected),
        "calling" | "statuscalling" => Ok(Signal::StatusCalling),
        "available" | "statusavailable" => Ok(Signal::StatusAvailable),
        "ringing" | "statusringing" => Ok(Signal::StatusRinging),
        "connecting" | "statusconnecting" => Ok(Signal::StatusConnecting),
        "established" | "statusestablished" => Ok(Signal::StatusEstablished),
        _ => Err(format!("Unknown call signal: {signal}")),
    }
}
fn signal_state(signal: Signal) -> &'static str {
    match signal {
        Signal::StatusCalling => "Calling",
        Signal::StatusRinging => "Ringing",
        Signal::StatusConnecting => "Connecting",
        Signal::StatusEstablished => "Established",
        Signal::StatusRejected => "Rejected",
        Signal::StatusBusy => "Busy",
        Signal::StatusAvailable => "Available",
    }
}
fn resource_status_name(status: ResourceStatus) -> &'static str {
    match status {
        ResourceStatus::None => "None",
        ResourceStatus::Queued => "Queued",
        ResourceStatus::Advertised => "Advertised",
        ResourceStatus::Transferring => "Transferring",
        ResourceStatus::AwaitingProof => "AwaitingProof",
        ResourceStatus::Assembling => "Assembling",
        ResourceStatus::Complete => "Complete",
        ResourceStatus::Failed => "Failed",
        ResourceStatus::Corrupt => "Corrupt",
        ResourceStatus::Rejected => "Rejected",
    }
}
fn map_discovered(entry: reticulum_discovery::DiscoveredInterface) -> DiscoveredInterfaceSummary {
    let status = format!("{:?}", entry.status());
    DiscoveredInterfaceSummary {
        name: entry
            .info
            .name
            .unwrap_or_else(|| entry.info.interface_type.clone()),
        interface_type: entry.info.interface_type,
        address: entry.info.reachable_on.unwrap_or_default(),
        port: entry.info.port.unwrap_or_default(),
        status,
        transport_id: entry.info.transport_id.to_hex_string(),
    }
}
fn split_host_port(bind: &str) -> Option<(String, u16)> {
    let (host, port) = bind.rsplit_once(':')?;
    Some((
        host.trim_matches(['[', ']']).to_string(),
        port.parse().ok()?,
    ))
}
fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn map_shared(
    a: SharedInstanceAddress,
) -> Result<reticulum::iface::local::SharedInstanceAddress, String> {
    match a {
        SharedInstanceAddress::Tcp { port } => {
            Ok(reticulum::iface::local::SharedInstanceAddress::tcp(port))
        }
        SharedInstanceAddress::UnixAbstract { name } => {
            #[cfg(target_os = "linux")]
            {
                Ok(reticulum::iface::local::SharedInstanceAddress::unix_abstract(name))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                Err("Unix abstract sockets are unavailable".into())
            }
        }
    }
}
fn validate_name(s: &str) -> Result<(), String> {
    if s.is_empty() || s.contains('/') || s.contains('\\') || s == "." || s == ".." {
        Err("Invalid identity name".into())
    } else {
        Ok(())
    }
}
fn parse_address(s: &str) -> Result<AddressHash, String> {
    let b = hex_decode(s).ok_or("Invalid address hex")?;
    AddressHash::new_from_raw_slice(&b).ok_or("Address must be 16 bytes".into())
}
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
        .collect::<Result<_, _>>()
        .ok()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn map_lxmf_fields(fields: &LxmfMessageFields) -> Result<lxmf::fields::Fields, String> {
    let mut mapped = lxmf::fields::Fields::new();
    if let Some(v) = &fields.image {
        mapped.insert(FIELD_IMAGE, FieldValue::Bin(v.clone()));
    }
    if let Some(v) = &fields.audio {
        mapped.insert(FIELD_AUDIO, FieldValue::Bin(v.clone()));
    }
    if !fields.files.is_empty() {
        mapped.insert(
            FIELD_FILE_ATTACHMENTS,
            FieldValue::Array(
                fields
                    .files
                    .iter()
                    .map(|f| {
                        FieldValue::Array(vec![
                            FieldValue::Str(f.file_name.clone()),
                            FieldValue::Bin(f.data.clone()),
                        ])
                    })
                    .collect(),
            ),
        );
    }
    if let Some(v) = fields.icon_appearance {
        mapped.insert(FIELD_ICON_APPEARANCE, FieldValue::Int(v as i64));
    }
    if let Some(v) = &fields.telemetry {
        mapped.insert(FIELD_TELEMETRY, FieldValue::Bin(v.clone()));
    }
    if !fields.reactions.is_empty() {
        mapped.insert(
            FIELD_REACTION,
            FieldValue::Array(
                fields
                    .reactions
                    .iter()
                    .map(|r| {
                        FieldValue::Array(vec![
                            FieldValue::Bin(hex_decode(&r.to_message_hash).unwrap_or_default()),
                            FieldValue::Str(r.content.clone()),
                        ])
                    })
                    .collect(),
            ),
        );
    }
    if let Some(v) = &fields.reply_to {
        mapped.insert(
            FIELD_REPLY_TO,
            FieldValue::Bin(hex_decode(v).ok_or("Invalid reply hash")?),
        );
    }
    if let Some(v) = &fields.reply_quote {
        mapped.insert(FIELD_REPLY_QUOTE, FieldValue::Str(v.clone()));
    }
    if let Some(v) = &fields.renderer {
        mapped.insert(FIELD_RENDERER, FieldValue::Str(v.clone()));
    }
    if let Some(v) = &fields.custom_data {
        mapped.insert(FIELD_CUSTOM_DATA, FieldValue::Bin(v.clone()));
    }
    if let Some(v) = fields.custom_type {
        mapped.insert(FIELD_CUSTOM_TYPE, FieldValue::Int(v as i64));
    }
    Ok(mapped)
}
fn decode_lxmf_fields(fields: &lxmf::fields::Fields) -> LxmfMessageFields {
    let bin = |key| match fields.get(key) {
        Some(FieldValue::Bin(value)) => Some(value.clone()),
        _ => None,
    };
    let string = |key| match fields.get(key) {
        Some(FieldValue::Str(value)) => Some(value.clone()),
        _ => None,
    };
    let integer = |key| match fields.get(key) {
        Some(FieldValue::Int(value)) => u32::try_from(*value).ok(),
        _ => None,
    };
    let files = match fields.get(FIELD_FILE_ATTACHMENTS) {
        Some(FieldValue::Array(values)) => values
            .iter()
            .filter_map(|value| match value {
                FieldValue::Array(parts) => match parts.as_slice() {
                    [FieldValue::Str(file_name), FieldValue::Bin(data), rest @ ..] => {
                        let mime_type = rest.first().and_then(|value| match value {
                            FieldValue::Str(value) => Some(value.clone()),
                            _ => None,
                        });
                        Some(LxmfAttachment {
                            file_name: file_name.clone(),
                            data: data.clone(),
                            mime_type,
                        })
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let reactions = match fields.get(FIELD_REACTION) {
        Some(FieldValue::Array(values)) => values
            .iter()
            .filter_map(|value| match value {
                FieldValue::Array(parts) => match parts.as_slice() {
                    [FieldValue::Bin(hash), FieldValue::Str(content), ..] => Some(LxmfReaction {
                        to_message_hash: to_hex(hash),
                        content: content.clone(),
                    }),
                    _ => None,
                },
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    LxmfMessageFields {
        text: None,
        title: None,
        image: bin(FIELD_IMAGE),
        audio: bin(FIELD_AUDIO),
        files,
        icon_appearance: integer(FIELD_ICON_APPEARANCE),
        telemetry: bin(FIELD_TELEMETRY),
        reactions,
        reply_to: bin(FIELD_REPLY_TO).map(|value| to_hex(&value)),
        reply_quote: string(FIELD_REPLY_QUOTE),
        renderer: string(FIELD_RENDERER),
        custom_data: bin(FIELD_CUSTOM_DATA),
        custom_type: integer(FIELD_CUSTOM_TYPE),
    }
}
fn message_summary(message: &LXMessage, fields: LxmfMessageFields) -> MessageSummary {
    MessageSummary {
        hash: message.hash.map(|h| h.to_string()).unwrap_or_default(),
        source_hash: message.source_hash.to_hex_string(),
        destination_hash: message.destination_hash.to_hex_string(),
        title: String::from_utf8(message.title.clone()).ok(),
        content: String::from_utf8(message.content.clone()).ok(),
        state: message_state_name(message.state),
        method: message_method_name(message.method),
        timestamp: message.timestamp.unwrap_or_default(),
        progress: message.progress as f64,
        fields,
    }
}

fn decode_identity_plaintext(plain: Vec<u8>) -> Result<Vec<u8>, String> {
    if let Ok(text) = std::str::from_utf8(&plain) {
        if let Some(decoded) = hex_decode(text.trim()) {
            return Ok(decoded);
        }
    }
    Ok(plain)
}
fn message_state_name(state: u8) -> String {
    match state {
        lxmf::message::GENERATING => "Generating",
        lxmf::message::OUTBOUND => "Outbound",
        SENDING => "Sending",
        lxmf::message::SENT => "Sent",
        lxmf::message::DELIVERED => "Delivered",
        lxmf::message::REJECTED => "Rejected",
        lxmf::message::CANCELLED => "Cancelled",
        lxmf::message::FAILED => "Failed",
        _ => "Unknown",
    }
    .into()
}
fn message_method_name(method: u8) -> String {
    match method {
        OPPORTUNISTIC => "Opportunistic",
        DIRECT => "Direct",
        PROPAGATED => "Propagated",
        PAPER => "Paper",
        _ => "Unknown",
    }
    .into()
}
fn propagation_state_name(state: u8) -> String {
    match state {
        lxmf::router::PR_IDLE => "Idle",
        lxmf::router::PR_PATH_REQUESTED => "PathRequested",
        lxmf::router::PR_LINK_ESTABLISHING => "LinkEstablishing",
        lxmf::router::PR_LINK_ESTABLISHED => "LinkEstablished",
        lxmf::router::PR_REQUEST_SENT => "RequestSent",
        lxmf::router::PR_RECEIVING => "Receiving",
        lxmf::router::PR_RESPONSE_RECEIVED => "ResponseReceived",
        lxmf::router::PR_COMPLETE => "Complete",
        lxmf::router::PR_NO_PATH => "NoPath",
        lxmf::router::PR_LINK_FAILED => "LinkFailed",
        lxmf::router::PR_TRANSFER_FAILED => "TransferFailed",
        lxmf::router::PR_NO_IDENTITY_RCVD => "NoIdentity",
        lxmf::router::PR_NO_ACCESS => "NoAccess",
        _ => "Failed",
    }
    .into()
}
#[cfg(feature = "iface-rnode")]
fn default_rnode_config() -> reticulum::iface::rnode::RnodeRadioConfig {
    reticulum::iface::rnode::RnodeRadioConfig {
        frequency: 915_000_000,
        bandwidth: 125_000,
        txpower: 14,
        spreadingfactor: 7,
        codingrate: 5,
        st_alock: None,
        lt_alock: None,
    }
}
