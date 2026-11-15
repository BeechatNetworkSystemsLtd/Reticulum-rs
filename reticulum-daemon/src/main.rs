use std::path::{Path, PathBuf};

use clap::Parser;
use rand_core::OsRng;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::IfaceControlParams;
use reticulum::iface::Interface;
use reticulum::iface::InterfaceContext;
use reticulum::iface::InterfaceManager;
use reticulum::iface::InterfaceMode;
use reticulum::iface::local::LocalServer;
use reticulum::iface::local::SharedInstanceAddress;
use reticulum::iface::tcp_client::INITIAL_CONNECT_TIMEOUT;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_client::TcpOptions;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::storage::FsStorage;
use reticulum::transport::TransportConfig;
use tokio::signal;

#[cfg(feature = "iface-auto")]
use reticulum::iface::auto::AutoInterface;
#[cfg(feature = "iface-auto")]
use reticulum::iface::auto::AutoInterfaceConfig;
#[cfg(feature = "iface-auto")]
use reticulum::iface::auto::DiscoveryScope;
#[cfg(feature = "iface-auto")]
use reticulum::iface::auto::MulticastAddressType;
#[cfg(feature = "iface-serial")]
use reticulum::iface::kiss::CsmaParams;
#[cfg(feature = "iface-serial")]
use reticulum::iface::kiss::KissInterface;
#[cfg(feature = "iface-serial")]
use reticulum::iface::kiss::SerialPortConfig;
#[cfg(feature = "iface-pipe")]
use reticulum::iface::pipe::PipeInterface;
#[cfg(feature = "iface-serial")]
use reticulum::iface::serial::SerialInterface;
#[cfg(all(not(target_os = "android"), feature = "iface-serial"))]
use reticulum::iface::weave::WeaveInterface;

use reticulum_daemon::config::{Config, InterfaceConfig};

/// File the daemon identity is persisted to (hex format, see
/// `reticulum_utils::common::save_private_identity`), relative to the config
/// directory. Python stores the transport identity under
/// `storage/identities` in raw-key format; we keep the daemon identity at
/// the config-dir root in hex so `rn id -i <configdir>/identity` can inspect
/// it.
const IDENTITY_FILE: &str = "identity";

/// Parse identity hashes (Python validates `len(hexhash) == 32`).
fn parse_identity_hashes(values: &[String], what: &str) -> Result<Vec<AddressHash>, String> {
    values
        .iter()
        .map(|value| {
            if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!("invalid identity hash for {what}: {value}"));
            }
            AddressHash::new_from_hex_string(value)
                .map_err(|_| format!("invalid identity hash for {what}: {value}"))
        })
        .collect()
}

fn parse_management_allowed(values: &[String]) -> Result<Vec<AddressHash>, String> {
    parse_identity_hashes(values, "remote management")
}

/// Resolve Python and native RNode endpoints consistently: an explicit TCP
/// setting wins; otherwise a port with a tcp:// prefix is a TCP target and
/// every other port value is a serial path.
#[cfg(feature = "iface-rnode")]
fn rnode_endpoint<'a>(
    tcp: &'a Option<String>,
    port: &'a Option<String>,
) -> (Option<&'a str>, Option<&'a str>) {
    if let Some(tcp) = tcp.as_deref() {
        return (Some(tcp), None);
    }
    match port.as_deref() {
        Some(port) if port.starts_with("tcp://") => (Some(&port[6..]), None),
        Some(port) => (None, Some(port)),
        None => (None, None),
    }
}

/// Reticulum-rs daemon
#[derive(Parser)]
#[clap(version)]
#[clap(args_conflicts_with_subcommands = true)]
pub struct Command {
    /// Reticulum config directory
    #[arg(short, long)]
    pub config_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub convert_config: Option<Subcommand>,
}

#[derive(clap::Subcommand)]
pub enum Subcommand {
    /// Convert a Python Reticulum config file to TOML
    ConvertConfig {
        /// Path to the Python Reticulum config file
        config_file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cmd = Command::parse();
    if let Some(subcommand) = cmd.convert_config {
        match subcommand {
            Subcommand::ConvertConfig { config_file } => {
                return reticulum_daemon::config::migrate_config(&config_file);
            }
        }
    }

    let (config, config_path) = Config::load(cmd.config_dir.as_deref())?;
    let mut logger = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(format!("{:?}", config.logging.loglevel)),
    );
    if !config.logging.logtimestamps {
        logger.format_timestamp(None);
    }
    logger.init();
    let config = std::sync::Arc::new(config);

    // Register before interface startup. A SIGTERM during bind would
    // otherwise terminate the process before the handler exists.
    #[cfg(unix)]
    let mut sigterm = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
        Ok(term) => Some(term),
        Err(err) => {
            log::warn!("could not listen for SIGTERM: {err}");
            None
        }
    };

    log::info!("Configuration loaded from: {}", config_path.display());
    log::info!("Reticulum daemon starting");

    // Load (or create + persist) the daemon identity so the instance — and
    // every destination derived from it — stays stable across restarts
    // (Phase 7.4). The daemon announces nothing by default.
    let identity_path = config_path.join(IDENTITY_FILE);
    let (persisted, created) =
        reticulum_utils::common::load_or_create_private_identity(&identity_path)
            .map_err(|err| format!("could not load daemon identity: {err}"))?;
    log::info!(
        "{} daemon identity {} at {}",
        if created { "Generated" } else { "Loaded" },
        reticulum_utils::common::prettyhexrep(persisted.address_hash().as_slice()),
        identity_path.display()
    );
    // Default authkey is the persisted key at storage/transport_identity
    // (Python `Identity.to_file` raw bytes), including when the running
    // transport identity below is ephemeral. An explicit rpc_key overrides
    // it. Do not hash config_dir/identity.
    let transport_identity_path = config_path.join("storage").join("transport_identity");
    let (transport_identity, transport_identity_created) =
        match reticulum_utils::common::load_private_identity(&transport_identity_path) {
            Ok(identity) => (identity, false),
            Err(reticulum_utils::common::IdentityLoadError::Io(err))
                if err.kind() == std::io::ErrorKind::NotFound =>
            {
                let identity = PrivateIdentity::new_from_rand(OsRng);
                if let Some(parent) = transport_identity_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                write_raw_identity(&transport_identity_path, &identity)?;
                (identity, true)
            }
            Err(err) => return Err(format!("could not load transport identity: {err}").into()),
        };
    if transport_identity_created {
        log::info!(
            "Generated transport identity {} at {}",
            reticulum_utils::common::prettyhexrep(transport_identity.address_hash().as_slice()),
            transport_identity_path.display()
        );
    }
    let rpc_authkey = reticulum_utils::rpc::authkey(
        config.reticulum.rpc_key.as_deref(),
        Some(&transport_identity),
    );
    // Python replaces the running transport identity with a fresh one when
    // transport is off and `static_transport_identity` is not set. The file
    // above stays the persisted identity either way.
    let identity =
        if config.reticulum.enable_transport || config.reticulum.static_transport_identity {
            persisted
        } else {
            let ephemeral = PrivateIdentity::new_from_rand(OsRng);
            log::info!(
                "Initialized ephemeral transport identity {}",
                reticulum_utils::common::prettyhexrep(ephemeral.address_hash().as_slice())
            );
            ephemeral
        };
    let network_identity = match config.reticulum.network_identity.as_deref() {
        Some(path) => Some(load_network_identity(path)?),
        None => None,
    };

    let instance_name = config
        .reticulum
        .instance_name
        .clone()
        .unwrap_or_else(|| "rns-daemon".to_string());
    log::info!("Instance name: {instance_name}");

    let blackhole_sources =
        parse_identity_hashes(&config.reticulum.blackhole_sources, "blackhole source")?;
    let transport = std::sync::Arc::new(
        apply_daemon_transport(
            TransportConfig::new(&instance_name, &identity),
            &config.reticulum,
            blackhole_sources,
            config_path.join("storage").to_string_lossy().into_owned(),
        )
        .build(),
    );
    let started = std::time::Instant::now();
    transport
        .load_known_destinations()
        .await
        .map_err(|error| format!("could not load known destinations: {error:?}"))?;

    let iface_manager = transport.iface_manager();
    let mut control_listener: Option<reticulum_daemon::rpc::BoundControl> = None;

    // Local shared instance (Python `Reticulum.__start_local_interface`):
    // TCP on 127.0.0.1:shared_instance_port (`shared_instance_type = tcp`)
    // or the abstract unix domain socket `\0rns/<instance_name>` on
    // platforms supporting them.
    if config.reticulum.share_instance {
        #[cfg(target_os = "linux")]
        let instance_name = config
            .reticulum
            .instance_name
            .clone()
            .unwrap_or_else(|| "default".to_string());

        let address = if config
            .reticulum
            .shared_instance_type
            .eq_ignore_ascii_case("tcp")
        {
            SharedInstanceAddress::tcp(config.reticulum.shared_instance_port)
        } else {
            #[cfg(target_os = "linux")]
            {
                SharedInstanceAddress::unix_abstract(instance_name.clone())
            }
            #[cfg(not(target_os = "linux"))]
            {
                SharedInstanceAddress::tcp(config.reticulum.shared_instance_port)
            }
        };

        log::info!("Starting shared instance interface: LocalServer on {address:?}");
        let server = LocalServer::new(address, iface_manager.clone());
        let mut manager = iface_manager.lock().await;
        let context = manager.open(server);
        let server_address = context.channel.address;
        if let Some(bitrate) = config.reticulum.force_shared_instance_bitrate {
            manager.set_iface_bitrate(&server_address, bitrate);
        }
        manager.launch(context, LocalServer::spawn);
        drop(manager);

        // Python binds `("127.0.0.1", local_control_port)` or
        // `\0rns/<instance_name>/rpc` when the shared instance uses
        // domain sockets. The accept loop starts after probe setup.
        let control_port = config.reticulum.instance_control_port;
        let domain = !config
            .reticulum
            .shared_instance_type
            .eq_ignore_ascii_case("tcp")
            && cfg!(target_os = "linux");
        if domain {
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                use std::os::unix::net::SocketAddr as UnixSocketAddr;
                let bound = (|| -> std::io::Result<tokio::net::UnixListener> {
                    let socket_address = UnixSocketAddr::from_abstract_name(
                        format!("rns/{instance_name}/rpc").as_bytes(),
                    )?;
                    let listener = std::os::unix::net::UnixListener::bind_addr(&socket_address)?;
                    listener.set_nonblocking(true)?;
                    tokio::net::UnixListener::from_std(listener)
                })();
                match bound {
                    Ok(listener) => {
                        log::info!(
                            "Shared instance control listening on \\0rns/{instance_name}/rpc"
                        );
                        control_listener =
                            Some(reticulum_daemon::rpc::BoundControl::Unix(listener));
                    }
                    Err(error) => {
                        log::error!(
                            "could not bind shared instance control \\0rns/{instance_name}/rpc: {error}"
                        );
                    }
                }
            }
        } else {
            match tokio::net::TcpListener::bind(("127.0.0.1", control_port)).await {
                Ok(listener) => {
                    log::info!("Shared instance control listening on 127.0.0.1:{control_port}");
                    control_listener = Some(reticulum_daemon::rpc::BoundControl::Tcp(listener));
                }
                Err(error) => {
                    log::error!(
                        "could not bind shared instance control 127.0.0.1:{control_port}: {error}"
                    );
                }
            }
        }
    }

    let mut live_i2p_reachable: Vec<(String, std::sync::Arc<std::sync::RwLock<Option<String>>>)> =
        Vec::new();

    for iface in &config.interfaces {
        start_configured_interface(
            &iface_manager,
            iface,
            &config.reticulum,
            false,
            &mut live_i2p_reachable,
        )
        .await
        .map_err(std::io::Error::other)?;
    }

    // Network interface discovery (Python RNS/Discovery.py).
    let discoverable: Vec<_> = config
        .interfaces
        .iter()
        .filter(|iface| iface.discoverable)
        .collect();
    let autoconnect_max = config.reticulum.autoconnect_discovered_interfaces;
    let listen_for_discovery =
        !discoverable.is_empty() || config.reticulum.discover_interfaces || autoconnect_max > 0;

    if !discoverable.is_empty() {
        let announcer_identity = network_identity
            .clone()
            .unwrap_or_else(|| transport.identity_private());
        let announcer = reticulum_discovery::InterfaceAnnouncer::start(
            &transport,
            &announcer_identity,
            reticulum_discovery::DEFAULT_STAMP_VALUE,
            reticulum_discovery::ANNOUNCER_INTERVAL,
        )
        .await;

        let transport_id = transport.identity_hash().await;
        for iface in &discoverable {
            let info = discovery_info_for(iface, &config, transport_id);
            if let Some(info) = info {
                if iface.discovery_encrypt && network_identity.is_none() {
                    log::error!(
                        "Interface '{}': discovery encryption requested without a network identity",
                        iface.name
                    );
                    continue;
                }
                let minutes = iface.discovery_announce_interval_minutes.unwrap_or(6 * 60);
                let interval = std::time::Duration::from_secs(minutes.max(5) * 60);
                let stamp = iface.discovery_stamp_value.filter(|value| *value > 0);
                let encrypt_to = if iface.discovery_encrypt {
                    network_identity.clone()
                } else {
                    None
                };
                log::info!(
                    "Announcing interface '{}' as discoverable {}",
                    iface.name,
                    info.interface_type
                );
                announcer
                    .announce_interface_configured(info, interval, stamp, encrypt_to)
                    .await;
                #[cfg(feature = "iface-i2p")]
                if let Some((_, slot)) = live_i2p_reachable
                    .iter()
                    .find(|(name, _)| name == &iface.name)
                {
                    announcer.attach_live_reachable(slot.clone()).await;
                }
            } else {
                log::warn!(
                    "Interface '{}' is discoverable but its type has no discovery mapping yet",
                    iface.name
                );
            }
        }
    }

    if listen_for_discovery {
        let required = config
            .reticulum
            .required_discovery_value
            .filter(|value| *value > 0)
            .unwrap_or(reticulum_discovery::DEFAULT_STAMP_VALUE);
        let policy = reticulum_discovery::AutoconnectPolicy {
            allow_unverified: config.reticulum.autoconnect_unverified_implementations,
            ..reticulum_discovery::AutoconnectPolicy::default()
        };
        let discovery = reticulum_discovery::InterfaceDiscovery::start_with(
            &transport,
            required,
            autoconnect_max > 0,
            reticulum_discovery::DiscoveryOptions {
                policy,
                storage_path: Some(config_path.join("storage")),
                network_identity: network_identity.clone(),
            },
        )
        .await;
        if autoconnect_max > 0 {
            discovery
                .set_max_autoconnected(autoconnect_max as usize)
                .await;
        }
        let sources = parse_identity_hashes(
            &config.reticulum.interface_discovery_sources,
            "interface discovery source",
        )?;
        if !sources.is_empty() {
            discovery.set_interface_sources(sources).await;
        }
        if autoconnect_max > 0 {
            let attach = autoconnect_attach(&config.reticulum);
            tokio::spawn(async move {
                loop {
                    discovery.connect_discovered_with(&attach).await;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            });
        }
    }

    // Management destinations (Python Transport.start: probe and remote
    // management destinations when enabled in the configuration).
    let probe_hash = if config.reticulum.probe_destination {
        let destination = transport.enable_probe_destination().await;
        Some(destination.lock().await.desc.address_hash)
    } else {
        None
    };

    if config.reticulum.publish_blackhole {
        transport.enable_blackhole_publishing().await;
        log::info!(
            "Enabled blackhole list publishing for transport identity {}",
            transport.identity_hash().await.to_hex_string()
        );
    }

    if !config.reticulum.blackhole_sources.is_empty() {
        // Python `Reticulum.__blackhole_sources` enables the updater.
        let sources =
            parse_identity_hashes(&config.reticulum.blackhole_sources, "blackhole source")?;
        let _updater = reticulum_discovery::BlackholeUpdater::start(
            &transport,
            sources,
            config.reticulum.blackhole_update_every(),
        )
        .await;
        log::info!(
            "Enabled blackhole updater for {} source(s)",
            config.reticulum.blackhole_sources.len()
        );
    }

    if config.reticulum.remote_management {
        let allowed = parse_management_allowed(&config.reticulum.remote_management_allowed)?;
        for allowed in allowed {
            transport.remote_management_allow(allowed).await;
        }
        let destination = transport.enable_remote_management().await;
        log::info!(
            "Remote management enabled on {}",
            destination.lock().await.desc.address_hash
        );
    }

    if let Some(listener) = control_listener {
        let (manage_tx, mut manage_rx) =
            tokio::sync::mpsc::channel::<reticulum_daemon::rpc::ManageRequest>(8);
        let manage_transport = std::sync::Arc::clone(&transport);
        let manage_config_dir = config_path.clone();
        tokio::spawn(async move {
            let mut attached_i2p = Vec::new();
            while let Some(request) = manage_rx.recv().await {
                let result = apply_manage(
                    &manage_transport,
                    &manage_config_dir,
                    request.op,
                    &mut attached_i2p,
                )
                .await;
                let _ = request.reply.send(result);
            }
        });
        let state = std::sync::Arc::new(reticulum_daemon::rpc::RpcState {
            transport: std::sync::Arc::clone(&transport),
            authkey: rpc_authkey,
            manage: Some(manage_tx),
            transport_enabled: config.reticulum.enable_transport,
            network_identity: network_identity
                .as_ref()
                .map(|identity| *identity.address_hash()),
            probe_hash,
            started,
        });
        tokio::spawn(async move {
            reticulum_daemon::rpc::serve(listener, state).await;
        });
    }

    log::info!("Reticulum instance running, interfaces initialized");

    // Clean shutdown on SIGINT (Ctrl-C), and SIGTERM where available
    // (not on Windows).
    #[cfg(unix)]
    {
        let sigterm = async {
            match sigterm.as_mut() {
                Some(term) => term.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = signal::ctrl_c() => {},
            _ = sigterm => {},
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.ok();
    }

    log::info!("Shutdown signal received, cleaning up");
    drop(transport);
    Ok(())
}

async fn apply_manage(
    transport: &std::sync::Arc<reticulum::transport::Transport>,
    config_dir: &std::path::Path,
    op: reticulum_daemon::rpc::ManageOp,
    live_i2p_reachable: &mut Vec<(String, std::sync::Arc<std::sync::RwLock<Option<String>>>)>,
) -> Option<bool> {
    let config = match Config::from_file(config_dir) {
        Ok(config) => config,
        Err(err) => {
            log::error!("Could not read configuration for interface management: {err}");
            return None;
        }
    };
    if !config.reticulum.enable_interface_management {
        return Some(false);
    }
    match op {
        reticulum_daemon::rpc::ManageOp::Detach(name) => detach_named(transport, &name).await,
        reticulum_daemon::rpc::ManageOp::Attach(name) => {
            attach_named(transport, &config, &name, live_i2p_reachable).await
        }
        reticulum_daemon::rpc::ManageOp::Reload(name) => {
            if !interface_present(transport, &name).await {
                return None;
            }
            if detach_named(transport, &name).await != Some(true) {
                return Some(false);
            }
            if attach_named(transport, &config, &name, live_i2p_reachable).await == Some(true) {
                Some(true)
            } else {
                Some(false)
            }
        }
    }
}

async fn interface_present(
    transport: &std::sync::Arc<reticulum::transport::Transport>,
    name: &str,
) -> bool {
    transport
        .iface_manager()
        .lock()
        .await
        .stats()
        .iter()
        .any(|stat| stat.name == name)
}

async fn detach_named(
    transport: &std::sync::Arc<reticulum::transport::Transport>,
    name: &str,
) -> Option<bool> {
    let manager = transport.iface_manager();
    let mut manager = manager.lock().await;
    let stat = manager.stats().into_iter().find(|stat| stat.name == name)?;
    if stat.kind == "LocalClient" || stat.kind == "LocalServer" || stat.kind.starts_with("I2p") {
        return Some(false);
    }
    let kind = stat.kind.clone();
    let waiter = manager.stop_iface(&stat.address);
    drop(manager);
    if matches!(
        kind.as_str(),
        "TcpServer" | "BackboneServer" | "AutoInterface"
    ) && let Some(mut waiter) = waiter
    {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            waiter.wait_for(|done| *done),
        )
        .await;
    }
    Some(true)
}

async fn attach_named(
    transport: &std::sync::Arc<reticulum::transport::Transport>,
    config: &Config,
    name: &str,
    live_i2p_reachable: &mut Vec<(String, std::sync::Arc<std::sync::RwLock<Option<String>>>)>,
) -> Option<bool> {
    if interface_present(transport, name).await {
        log::warn!("Attempt to attach existing interface \"{name}\"");
        return Some(false);
    }
    let Some(iface) = config.interfaces.iter().find(|iface| iface.name == name) else {
        log::error!("Cannot attach interface \"{name}\", no configuration entry exists");
        return None;
    };
    if let Err(error) = start_configured_interface(
        &transport.iface_manager(),
        iface,
        &config.reticulum,
        true,
        live_i2p_reachable,
    )
    .await
    {
        log::error!("{error}");
        return Some(false);
    }
    if interface_present(transport, name).await {
        log::info!("Interface \"{name}\" was attached");
        Some(true)
    } else {
        Some(false)
    }
}

#[cfg_attr(not(feature = "iface-i2p"), allow(unused_variables, clippy::ptr_arg))]
async fn start_configured_interface(
    iface_manager: &std::sync::Arc<tokio::sync::Mutex<InterfaceManager>>,
    iface: &reticulum_daemon::config::NamedInterface,
    reticulum: &reticulum_daemon::config::ReticulumConfig,
    force: bool,
    live_i2p_reachable: &mut Vec<(String, std::sync::Arc<std::sync::RwLock<Option<String>>>)>,
) -> Result<(), String> {
    let enabled = match &iface.config {
        InterfaceConfig::TCPServerInterface { enabled, .. } => *enabled,
        InterfaceConfig::TCPClientInterface { enabled, .. } => *enabled,
        InterfaceConfig::UDPInterface { enabled, .. } => *enabled,
        InterfaceConfig::AutoInterface { enabled, .. } => *enabled,
        InterfaceConfig::I2PInterface { enabled, .. } => *enabled,
        InterfaceConfig::BackboneInterface { enabled, .. } => *enabled,
        InterfaceConfig::BackboneClientInterface { enabled, .. } => *enabled,
        InterfaceConfig::RNodeInterface { enabled, .. } => *enabled,
        InterfaceConfig::RNodeMultiInterface { enabled, .. } => *enabled,
        InterfaceConfig::BLEInterface { enabled, .. } => *enabled,
        InterfaceConfig::KISSInterface { enabled, .. } => *enabled,
        InterfaceConfig::AX25KISSInterface { enabled, .. } => *enabled,
        InterfaceConfig::SerialInterface { enabled, .. } => *enabled,
        InterfaceConfig::PipeInterface { enabled, .. } => *enabled,
        InterfaceConfig::LocalInterface { enabled, .. } => *enabled,
        InterfaceConfig::WeaveInterface { enabled, .. } => *enabled,
        InterfaceConfig::Unsupported => iface.configured_enabled,
    };

    if !force && !enabled {
        return Ok(());
    }

    match &iface.config {
        InterfaceConfig::TCPServerInterface {
            bind_host,
            bind_port,
            ..
        } => {
            let addr = format!("{}:{}", bind_host.trim_end_matches(':'), bind_port);
            log::info!(
                "Enabling interface '{}': TCP Server on {}",
                iface.name,
                addr
            );
            match TcpServer::with_options(addr, iface_manager.clone(), tcp_options(iface, false)) {
                Ok(server) => {
                    launch_configured(
                        iface_manager,
                        server,
                        None,
                        TcpServer::spawn,
                        iface,
                        reticulum,
                    )
                    .await;
                }
                Err(error) => {
                    log::error!(
                        "Interface '{}' has an invalid TCP configuration: {error:?}",
                        iface.name
                    );
                }
            }
        }
        InterfaceConfig::TCPClientInterface {
            target_host,
            target_port,
            ..
        } => {
            let addr = format!("{}:{}", target_host.trim_end_matches(':'), target_port);
            log::info!(
                "Enabling interface '{}': TCP Client to {}",
                iface.name,
                addr
            );
            match TcpClient::with_options(addr, tcp_options(iface, true)) {
                Ok(client) => {
                    launch_configured(
                        iface_manager,
                        client,
                        None,
                        TcpClient::spawn,
                        iface,
                        reticulum,
                    )
                    .await;
                }
                Err(error) => {
                    log::error!(
                        "Interface '{}' has an invalid TCP configuration: {error:?}",
                        iface.name
                    );
                }
            }
        }
        InterfaceConfig::UDPInterface {
            listen_ip,
            listen_port,
            forward_ip,
            forward_port,
            port,
            ..
        } => {
            if iface.device.is_some() {
                log::warn!(
                    "Interface '{}': UDP device is not applied; set listen_ip and forward_ip",
                    iface.name
                );
            }
            let listen_port = listen_port.or(*port);
            let forward_port = forward_port.or(*port);
            if let (Some(listen_port), Some(forward_port)) = (listen_port, forward_port) {
                let bind_addr = format!("{}:{}", listen_ip, listen_port);
                let forward_addr = format!("{}:{}", forward_ip, forward_port);
                log::info!(
                    "Enabling interface '{}': UDP {}→{}",
                    iface.name,
                    bind_addr,
                    forward_addr
                );
                launch_configured(
                    iface_manager,
                    UdpInterface::new(bind_addr, Some(forward_addr), false),
                    None,
                    UdpInterface::spawn,
                    iface,
                    reticulum,
                )
                .await;
            } else {
                log::error!(
                    "Interface '{}' (UDP) needs listen_port and forward_port, or port",
                    iface.name
                );
            }
        }
        InterfaceConfig::AutoInterface {
            group_id,
            discovery_port,
            data_port,
            discovery_scope,
            multicast_address_type,
            devices,
            ignored_devices,
            ..
        } => {
            #[cfg(feature = "iface-auto")]
            {
                let mut auto_config = AutoInterfaceConfig {
                    group_id: group_id.clone(),
                    discovery_port: *discovery_port,
                    data_port: *data_port,
                    ..AutoInterfaceConfig::default()
                };

                if let Some(scope) = discovery_scope {
                    auto_config.discovery_scope = DiscoveryScope::parse(&scope);
                }
                if let Some(address_type) = multicast_address_type {
                    auto_config.multicast_address_type = MulticastAddressType::parse(&address_type);
                }
                if let Some(devices) = devices {
                    auto_config.devices = devices
                        .split(',')
                        .map(str::trim)
                        .filter(|device| !device.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                if let Some(ignored) = ignored_devices {
                    auto_config.ignored_devices = ignored
                        .split(',')
                        .map(str::trim)
                        .filter(|device| !device.is_empty())
                        .map(str::to_string)
                        .collect();
                }

                log::info!(
                    "Enabling interface '{}': AutoInterface group '{}' on discovery port {}",
                    iface.name,
                    auto_config.group_id,
                    auto_config.discovery_port
                );
                launch_configured(
                    iface_manager,
                    AutoInterface::new(auto_config, iface_manager.clone()),
                    Some(&iface.name),
                    AutoInterface::spawn,
                    iface,
                    reticulum,
                )
                .await;
            }

            #[cfg(not(feature = "iface-auto"))]
            {
                let _ = (
                    group_id,
                    discovery_port,
                    data_port,
                    discovery_scope,
                    multicast_address_type,
                    devices,
                    ignored_devices,
                );
                log::warn!(
                    "Interface '{}' type 'AutoInterface' requires building the daemon with --features iface-auto",
                    iface.name
                );
            }
        }
        InterfaceConfig::I2PInterface {
            peers,
            connectable,
            sam_address,
            ..
        } => {
            #[cfg(feature = "iface-i2p")]
            {
                let sam_addr = sam_address
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:7656".to_string());

                if *connectable {
                    log::info!(
                        "Enabling interface '{}': I2P server (connectable) via SAM {}",
                        iface.name,
                        sam_addr
                    );
                    let session_id = format!("{}-{}", iface.name, std::process::id());
                    let server = reticulum::iface::i2p::I2pServer::new(
                        sam_addr.clone(),
                        session_id,
                        iface_manager.clone(),
                    );
                    // Read at announce time, after the SAM session exists.
                    let b32_slot = server.b32_slot.clone();
                    launch_configured(
                        iface_manager,
                        server,
                        Some(&iface.name),
                        reticulum::iface::i2p::I2pServer::spawn,
                        iface,
                        reticulum,
                    )
                    .await;
                    if iface.discoverable {
                        live_i2p_reachable.push((iface.name.clone(), b32_slot));
                    }
                }

                for (index, peer) in peers.iter().enumerate() {
                    log::info!(
                        "Enabling interface '{}': I2P peer {index} via SAM {}",
                        iface.name,
                        sam_addr
                    );
                    let session_id = format!("{}-{}-{index}", iface.name, std::process::id());
                    let peer_name = format!("{}-peer-{index}", iface.name);
                    launch_configured(
                        iface_manager,
                        reticulum::iface::i2p::I2pPeer::new_initiator(&sam_addr, &session_id, peer)
                            .with_manager(iface_manager.clone()),
                        Some(&peer_name),
                        reticulum::iface::i2p::I2pPeer::spawn,
                        iface,
                        reticulum,
                    )
                    .await;
                }

                if !*connectable && peers.is_empty() {
                    log::warn!(
                        "Interface '{}' (I2P) has neither connectable = yes nor peers",
                        iface.name
                    );
                }
            }

            #[cfg(not(feature = "iface-i2p"))]
            {
                let _ = (peers, connectable, sam_address);
                log::warn!(
                    "Interface '{}' type 'I2PInterface' requires building the daemon with --features iface-i2p",
                    iface.name
                );
            }
        }
        InterfaceConfig::BackboneInterface {
            listen_ip,
            bind_port,
            block_fast_flapping,
            fast_flapping_threshold,
            fast_flapping_grace,
            fast_flapping_block_time,
            ..
        } => {
            let addr = format!("{}:{}", listen_ip.trim_end_matches(':'), bind_port);

            let table = reticulum::iface::backbone::FastFlapTable::new(
                *block_fast_flapping,
                fast_flapping_threshold
                    .map(|seconds| std::time::Duration::from_secs_f64(seconds.max(0.1)))
                    .unwrap_or(reticulum::iface::backbone::FAST_FLAP_THRESHOLD),
                fast_flapping_grace.unwrap_or(reticulum::iface::backbone::FAST_FLAP_GRACE),
                fast_flapping_block_time
                    .map(|minutes| std::time::Duration::from_secs_f64(minutes.max(0.1) * 60.0))
                    .unwrap_or(reticulum::iface::backbone::FAST_FLAP_EXPIRY),
            );

            log::info!(
                "Enabling interface '{}': Backbone server on {}",
                iface.name,
                addr
            );
            launch_configured(
                iface_manager,
                reticulum::iface::backbone::BackboneServer::new(
                    addr,
                    iface_manager.clone(),
                    std::sync::Arc::new(tokio::sync::Mutex::new(table)),
                ),
                Some(&iface.name),
                reticulum::iface::backbone::BackboneServer::spawn,
                iface,
                reticulum,
            )
            .await;
        }
        InterfaceConfig::BackboneClientInterface {
            target_ip,
            target_port,
            ..
        } => {
            let addr = format!("{}:{}", target_ip.trim_end_matches(':'), target_port);
            log::info!(
                "Enabling interface '{}': Backbone client to {}",
                iface.name,
                addr
            );
            launch_configured(
                iface_manager,
                reticulum::iface::backbone::BackboneClient::new(addr)
                    .with_manager(iface_manager.clone()),
                Some(&iface.name),
                reticulum::iface::backbone::BackboneClient::spawn,
                iface,
                reticulum,
            )
            .await;
        }
        InterfaceConfig::RNodeInterface {
            port,
            tcp,
            speed,
            frequency,
            bandwidth,
            txpower,
            spreadingfactor,
            codingrate,
            st_alock,
            lt_alock,
            flow_control,
            ..
        } => {
            #[cfg(feature = "iface-rnode")]
            {
                let radio = reticulum::iface::rnode::RnodeRadioConfig {
                    frequency: *frequency,
                    bandwidth: *bandwidth,
                    txpower: *txpower,
                    spreadingfactor: *spreadingfactor,
                    codingrate: *codingrate,
                    st_alock: *st_alock,
                    lt_alock: *lt_alock,
                };

                let (tcp, port) = rnode_endpoint(tcp, port);
                if let Some(port) = port {
                    if reticulum::iface::rnode::parse_ble_target(port).is_some() {
                        #[cfg(feature = "iface-rnode-ble")]
                        {
                            log::info!(
                                "Enabling interface '{}': RNode over BLE {port} at {frequency} Hz",
                                iface.name
                            );
                            let mut interface =
                                reticulum::iface::rnode::RnodeInterface::ble(port, radio)
                                    .with_flow_control(*flow_control)
                                    .with_manager(iface_manager.clone());
                            if let (Some(interval), Some(callsign)) =
                                (iface.id_interval, iface.id_callsign.as_deref())
                            {
                                interface = interface.with_beacon(interval, callsign.as_bytes());
                            }
                            launch_configured(
                                iface_manager,
                                interface,
                                Some(&iface.name),
                                reticulum::iface::rnode::RnodeInterface::spawn,
                                iface,
                                reticulum,
                            )
                            .await;
                            return Ok(());
                        }
                        #[cfg(not(feature = "iface-rnode-ble"))]
                        {
                            log::error!(
                                "Interface '{}' type 'RNodeInterface' BLE requires building the daemon with --features iface-rnode-ble",
                                iface.name
                            );
                            return Ok(());
                        }
                    }
                }
                let interface = if let Some(tcp) = tcp {
                    log::info!(
                        "Enabling interface '{}': RNode over TCP {tcp} at {frequency} Hz",
                        iface.name
                    );
                    Some(reticulum::iface::rnode::RnodeInterface::tcp(tcp, radio))
                } else if let Some(port) = port {
                    log::info!(
                        "Enabling interface '{}': RNode on {port} at {speed} baud, {frequency} Hz",
                        iface.name
                    );
                    #[cfg(feature = "iface-serial")]
                    {
                        Some(reticulum::iface::rnode::RnodeInterface::serial(
                            port, *speed, radio,
                        ))
                    }
                    #[cfg(not(feature = "iface-serial"))]
                    {
                        log::warn!(
                            "Interface '{}' RNode serial mode requires building with --features iface-serial",
                            iface.name
                        );
                        None
                    }
                } else {
                    log::error!(
                        "Interface '{}' (RNode) needs a port or tcp target",
                        iface.name
                    );
                    None
                };

                if let Some(mut interface) = interface {
                    interface = interface
                        .with_flow_control(*flow_control)
                        .with_manager(iface_manager.clone());
                    if let (Some(interval), Some(callsign)) =
                        (iface.id_interval, iface.id_callsign.as_deref())
                    {
                        interface = interface.with_beacon(interval, callsign.as_bytes());
                    }
                    launch_configured(
                        iface_manager,
                        interface,
                        Some(&iface.name),
                        reticulum::iface::rnode::RnodeInterface::spawn,
                        iface,
                        reticulum,
                    )
                    .await;
                }
            }

            #[cfg(not(feature = "iface-rnode"))]
            {
                let _ = (
                    port,
                    tcp,
                    speed,
                    frequency,
                    bandwidth,
                    txpower,
                    spreadingfactor,
                    codingrate,
                    st_alock,
                    lt_alock,
                    flow_control,
                );
                log::warn!(
                    "Interface '{}' type 'RNodeInterface' requires building the daemon with --features iface-rnode",
                    iface.name
                );
            }
        }
        InterfaceConfig::RNodeMultiInterface {
            port,
            tcp,
            speed,
            subinterfaces,
            ..
        } => {
            #[cfg(feature = "iface-rnode")]
            {
                use reticulum::iface::rnode::{RnodeMultiInterface, RnodeVport};

                let vports: Vec<RnodeVport> = subinterfaces
                    .iter()
                    .map(|sub| RnodeVport {
                        index: sub.vport,
                        config: reticulum::iface::rnode::RnodeRadioConfig {
                            frequency: sub.frequency,
                            bandwidth: sub.bandwidth,
                            txpower: sub.txpower,
                            spreadingfactor: sub.spreadingfactor,
                            codingrate: sub.codingrate,
                            st_alock: sub.st_alock,
                            lt_alock: sub.lt_alock,
                        },
                    })
                    .collect();

                let (tcp, port) = rnode_endpoint(tcp, port);
                if port.is_some_and(|port| {
                    reticulum::iface::rnode::parse_ble_target(port).is_some()
                }) {
                    log::error!(
                        "Interface '{}' type 'RNodeMultiInterface' BLE is not supported",
                        iface.name
                    );
                    return Ok(());
                }
                let interface = if let Some(tcp) = tcp {
                    log::info!(
                        "Enabling interface '{}': RNodeMulti over TCP {tcp} with {} virtual ports",
                        iface.name,
                        vports.len()
                    );
                    Some(RnodeMultiInterface::tcp(tcp, vports, iface_manager.clone()))
                } else if let Some(port) = port {
                    log::info!(
                        "Enabling interface '{}': RNodeMulti on {port} at {speed} baud with {} virtual ports",
                        iface.name,
                        vports.len()
                    );
                    #[cfg(feature = "iface-serial")]
                    {
                        Some(RnodeMultiInterface::serial(
                            port,
                            *speed,
                            vports,
                            iface_manager.clone(),
                        ))
                    }
                    #[cfg(not(feature = "iface-serial"))]
                    {
                        log::warn!(
                            "Interface '{}' RNodeMulti serial mode requires building with --features iface-serial",
                            iface.name
                        );
                        None
                    }
                } else {
                    log::error!(
                        "Interface '{}' (RNodeMulti) needs a port or tcp target",
                        iface.name
                    );
                    None
                };

                if let Some(mut interface) = interface {
                    if let (Some(interval), Some(callsign)) =
                        (iface.id_interval, iface.id_callsign.as_deref())
                    {
                        interface = interface.with_beacon(interval, callsign.as_bytes());
                    }
                    for sub in subinterfaces {
                        if !sub.outgoing {
                            interface = interface.with_receive_only(sub.vport);
                        }
                    }
                    launch_configured(
                        iface_manager,
                        interface,
                        Some(&iface.name),
                        RnodeMultiInterface::spawn,
                        iface,
                        reticulum,
                    )
                    .await;
                }
            }

            #[cfg(not(feature = "iface-rnode"))]
            {
                let _ = (port, tcp, speed, subinterfaces);
                log::warn!(
                    "Interface '{}' type 'RNodeMultiInterface' requires building the daemon with --features iface-rnode",
                    iface.name
                );
            }
        }
        InterfaceConfig::BLEInterface { .. } => {
            log::warn!(
                "Interface '{}' type 'BLEInterface' is not yet supported",
                iface.name
            );
        }
        InterfaceConfig::KISSInterface {
            port,
            speed,
            databits,
            parity,
            stopbits,
            preamble,
            txtail,
            persistence,
            slottime,
            flow_control,
            ..
        } => {
            #[cfg(feature = "iface-serial")]
            {
                let serial = SerialPortConfig::new(port.clone(), *speed).with_format(
                    *databits,
                    parity.clone(),
                    *stopbits,
                );
                let csma = CsmaParams::new(*preamble, *txtail, *persistence, *slottime);

                log::info!(
                    "Enabling interface '{}': KISS on {port} at {speed} baud (csma preamble={preamble} txtail={txtail} persistence={persistence} slottime={slottime})",
                    iface.name
                );
                let mut kiss = KissInterface::new(serial, csma, *flow_control);
                if let (Some(interval), Some(callsign)) =
                    (iface.id_interval, iface.id_callsign.as_deref())
                {
                    kiss = kiss.with_beacon(interval, callsign.as_bytes());
                }
                launch_configured(
                    iface_manager,
                    kiss,
                    Some(&iface.name),
                    KissInterface::spawn,
                    iface,
                    reticulum,
                )
                .await;
            }

            #[cfg(not(feature = "iface-serial"))]
            {
                let _ = (
                    speed,
                    databits,
                    parity,
                    stopbits,
                    preamble,
                    txtail,
                    persistence,
                    slottime,
                    flow_control,
                );
                log::warn!(
                    "Interface '{}' type 'KISSInterface' on port {port} requires building the daemon with --features iface-serial",
                    iface.name
                );
            }
        }
        InterfaceConfig::SerialInterface {
            port,
            speed,
            databits,
            parity,
            stopbits,
            ..
        } => {
            #[cfg(feature = "iface-serial")]
            {
                let serial = SerialPortConfig::new(port.clone(), *speed).with_format(
                    *databits,
                    parity.clone(),
                    *stopbits,
                );

                log::info!(
                    "Enabling interface '{}': Serial (HDLC) on {port} at {speed} baud",
                    iface.name
                );
                launch_configured(
                    iface_manager,
                    SerialInterface::new(serial),
                    Some(&iface.name),
                    SerialInterface::spawn,
                    iface,
                    reticulum,
                )
                .await;
            }

            #[cfg(not(feature = "iface-serial"))]
            {
                let _ = (speed, databits, parity, stopbits);
                log::warn!(
                    "Interface '{}' type 'SerialInterface' on port {port} requires building the daemon with --features iface-serial",
                    iface.name
                );
            }
        }
        InterfaceConfig::PipeInterface {
            command,
            respawn_delay,
            ..
        } => {
            #[cfg(feature = "iface-pipe")]
            {
                let respawn_delay =
                    std::time::Duration::from_secs_f64(respawn_delay.max(0.0) as f64);

                log::info!(
                    "Enabling interface '{}': Pipe command '{command}' (respawn delay {respawn_delay:?})",
                    iface.name
                );
                launch_configured(
                    iface_manager,
                    PipeInterface::new(command).with_respawn_delay(respawn_delay),
                    Some(&iface.name),
                    PipeInterface::spawn,
                    iface,
                    reticulum,
                )
                .await;
            }

            #[cfg(not(feature = "iface-pipe"))]
            {
                let _ = respawn_delay;
                log::warn!(
                    "Interface '{}' type 'PipeInterface' (command '{command}') requires building the daemon with --features iface-pipe",
                    iface.name
                );
            }
        }
        InterfaceConfig::LocalInterface {
            listen_ip,
            listen_port,
            ..
        } => {
            // A local shared-instance listener declared as an interface
            // (Python handles this via [reticulum] share_instance; the
            // daemon also accepts it explicitly here).
            if listen_ip == "127.0.0.1" {
                log::info!(
                    "Enabling interface '{}': Local shared instance on 127.0.0.1:{listen_port}",
                    iface.name
                );
                launch_configured(
                    iface_manager,
                    LocalServer::new(
                        SharedInstanceAddress::tcp(*listen_port),
                        iface_manager.clone(),
                    ),
                    Some(&iface.name),
                    LocalServer::spawn,
                    iface,
                    reticulum,
                )
                .await;
            } else {
                log::warn!(
                    "Interface '{}' type 'LocalInterface': shared instances always listen on 127.0.0.1 (got {listen_ip})",
                    iface.name
                );
            }
        }
        InterfaceConfig::AX25KISSInterface {
            callsign,
            ssid,
            port,
            speed,
            databits,
            parity,
            stopbits,
            preamble,
            txtail,
            persistence,
            slottime,
            flow_control,
            ..
        } => {
            #[cfg(feature = "iface-serial")]
            {
                let serial = SerialPortConfig::new(port.clone(), *speed).with_format(
                    *databits,
                    parity.clone(),
                    *stopbits,
                );
                let csma = CsmaParams::new(*preamble, *txtail, *persistence, *slottime);

                match KissInterface::new_ax25(callsign.clone(), *ssid, serial, csma, *flow_control)
                {
                    Ok(interface) => {
                        log::info!(
                            "Enabling interface '{}': AX.25 KISS {callsign}-{ssid} on {port} at {speed} baud",
                            iface.name
                        );
                        launch_configured(
                            iface_manager,
                            interface,
                            Some(&iface.name),
                            KissInterface::spawn,
                            iface,
                            reticulum,
                        )
                        .await;
                    }
                    Err(_) => {
                        log::error!(
                            "Interface '{}': invalid callsign '{callsign}' or ssid {ssid}, not enabling",
                            iface.name
                        );
                    }
                }
            }

            #[cfg(not(feature = "iface-serial"))]
            {
                let _ = (
                    callsign,
                    ssid,
                    speed,
                    databits,
                    parity,
                    stopbits,
                    preamble,
                    txtail,
                    persistence,
                    slottime,
                    flow_control,
                );
                log::warn!(
                    "Interface '{}' type 'AX25KISSInterface' on port {port} requires building the daemon with --features iface-serial",
                    iface.name
                );
            }
        }
        InterfaceConfig::WeaveInterface { port, .. } => {
            #[cfg(target_os = "android")]
            {
                log::error!(
                    "Interface '{}' type 'WeaveInterface' on port {port}: Weave USB serial is not supported",
                    iface.name
                );
            }
            #[cfg(all(not(target_os = "android"), feature = "iface-serial"))]
            {
                log::info!("Enabling interface '{}': Weave on {port}", iface.name);
                launch_configured(
                    iface_manager,
                    WeaveInterface::new(port.clone(), iface_manager.clone()),
                    None,
                    WeaveInterface::spawn,
                    iface,
                    reticulum,
                )
                .await;
            }
            #[cfg(all(not(target_os = "android"), not(feature = "iface-serial")))]
            {
                log::warn!(
                    "Interface '{}' type 'WeaveInterface' on port {port} requires building the daemon with --features iface-serial",
                    iface.name
                );
            }
        }
        InterfaceConfig::Unsupported => {
            let type_name = if iface.configured_type.is_empty() {
                "unknown".to_string()
            } else {
                iface.configured_type.clone()
            };
            if let Some(factory) =
                reticulum_daemon::config::interface_factory(&iface.configured_type)
            {
                factory(iface.clone(), iface_manager.clone())
                    .await
                    .map_err(|error| {
                        format!("Interface '{}' type '{type_name}': {error}", iface.name)
                    })?;
            } else {
                return Err(format!(
                    "Interface '{}' type '{type_name}' is not supported",
                    iface.name
                ));
            }
        }
    }
    Ok(())
}

fn apply_daemon_transport(
    builder: TransportConfig,
    config: &reticulum_daemon::config::ReticulumConfig,
    blackhole_sources: Vec<AddressHash>,
    storage_path: String,
) -> TransportConfig {
    builder
        .set_retransmit(config.enable_transport)
        .set_implicit_proof(config.use_implicit_proof)
        .set_local_hops_delta(config.local_hops_delta)
        .set_link_mtu_discovery(config.link_mtu_discovery.unwrap_or(true))
        .set_inbound_queue_length(
            reticulum::transport::TrafficClass::Data,
            config.qlen_in_data.unwrap_or(0),
        )
        .set_inbound_queue_length(
            reticulum::transport::TrafficClass::Announce,
            config.qlen_in_announce.unwrap_or(0),
        )
        .set_inbound_queue_length(
            reticulum::transport::TrafficClass::PathRequest,
            config.qlen_in_pr.unwrap_or(0),
        )
        .set_inbound_queue_length(
            reticulum::transport::TrafficClass::IngressLimited,
            config.qlen_in_il.unwrap_or(0),
        )
        .set_blackhole_publish(config.publish_blackhole)
        .set_blackhole_sources(blackhole_sources)
        .set_storage(std::sync::Arc::new(FsStorage::new(storage_path)))
}

/// Open an interface, publish its control state, then start the worker.
async fn launch_configured<T, F, R>(
    iface_manager: &std::sync::Arc<tokio::sync::Mutex<InterfaceManager>>,
    inner: T,
    name: Option<&str>,
    worker: F,
    iface: &reticulum_daemon::config::NamedInterface,
    config: &reticulum_daemon::config::ReticulumConfig,
) -> AddressHash
where
    T: Interface,
    F: FnOnce(InterfaceContext<T>) -> R,
    R: std::future::Future<Output = ()> + Send + 'static,
    R::Output: Send + 'static,
{
    let context = {
        let mut manager = iface_manager.lock().await;
        let context = manager.open(inner);
        let address = context.channel.address;
        // Detach looks the interface up by its configuration name.
        let label = name.unwrap_or(iface.name.as_str());
        if !label.is_empty() {
            manager.set_iface_name(&address, label);
        }
        context
    };
    let address = context.channel.address;
    configure_iface(iface_manager, &address, iface, config).await;
    iface_manager.lock().await.launch(context, worker)
}

/// Apply per-interface common options before the worker can accept
/// (Python `Reticulum._add_interface` / `interface_post_init`).
async fn configure_iface(
    iface_manager: &std::sync::Arc<tokio::sync::Mutex<reticulum::iface::InterfaceManager>>,
    address: &reticulum::hash::AddressHash,
    iface: &reticulum_daemon::config::NamedInterface,
    config: &reticulum_daemon::config::ReticulumConfig,
) {
    let manager = iface_manager.lock().await;

    let parsed = iface.mode.as_deref().and_then(InterfaceMode::from_name);
    if iface.mode.is_some() && parsed.is_none() && !iface.discoverable {
        log::warn!(
            "Interface '{}' has unknown mode '{}', keeping default",
            iface.name,
            iface.mode.as_deref().unwrap_or("")
        );
    }
    let mode = if iface.discoverable
        && !matches!(
            parsed,
            Some(InterfaceMode::Gateway | InterfaceMode::AccessPoint | InterfaceMode::Internal)
        ) {
        let corrected = match &iface.config {
            reticulum_daemon::config::InterfaceConfig::RNodeInterface { .. }
            | reticulum_daemon::config::InterfaceConfig::RNodeMultiInterface { .. } => {
                InterfaceMode::AccessPoint
            }
            _ => InterfaceMode::Gateway,
        };
        if !iface.ignore_config_warnings {
            let label = if corrected == InterfaceMode::AccessPoint {
                "AP"
            } else {
                "gateway"
            };
            log::info!(
                "Discovery enabled on interface {} without gateway, internal or AP mode. Auto-configured to {label} mode.",
                iface.name
            );
        }
        Some(corrected)
    } else {
        parsed
    };
    if let Some(mode) = mode {
        manager.set_iface_mode(address, mode);
    }

    let bitrate = match iface.bitrate {
        Some(bitrate) if bitrate >= 5 => Some(bitrate),
        Some(bitrate) => {
            log::warn!(
                "Interface '{}' bitrate {bitrate} is below the minimum of 5, ignoring",
                iface.name
            );
            None
        }
        None => None,
    };
    if let Some(bitrate) = bitrate {
        manager.set_iface_bitrate(address, bitrate);
    } else if matches!(
        &iface.config,
        reticulum_daemon::config::InterfaceConfig::WeaveInterface { .. }
    ) {
        manager.set_iface_bitrate(address, reticulum::iface::weave::BITRATE_GUESS);
    }

    let gravity = iface.gravity.or(config.default_gravity).unwrap_or(0);
    let params = control_params(config, iface);
    let rate = announce_rate_limits(config, iface);
    let cap = iface.announce_cap_fraction();
    manager.with_control(address, |control| {
        control.gravity = gravity;
        control.announce_cap = cap;
        control.ingress_control = iface.ingress_control.unwrap_or(true);
        if let Some(egress) = iface.egress_control.or(config.egress_control) {
            control.egress_control = egress;
        }
        control.recursive_prs = iface.recursive_prs;
        if let Some(from_internal) = iface.announces_from_internal {
            control.announces_from_internal = from_internal;
        }
        if let Some(to_internal) = iface.announces_to_internal {
            control.announces_to_internal = Some(to_internal);
        }
        if let Some((target, grace, penalty)) = rate {
            control.announce_rate_target = Some(target);
            control.announce_rate_grace = Some(grace);
            control.announce_rate_penalty = Some(penalty);
        }
    });
    manager.with_control(address, |control| control.set_params(params));

    let netname = meaningful_ifac(iface.networkname.as_deref());
    let netkey = meaningful_ifac(iface.passphrase.as_deref());
    if netname.is_none() && iface.networkname.as_deref() == Some("None") {
        log::warn!(
            "Interface '{}': ambiguous IFAC network name \"None\" is ignored",
            iface.name
        );
    }
    if netkey.is_none() && iface.passphrase.as_deref() == Some("None") {
        log::warn!(
            "Interface '{}': ambiguous IFAC passphrase \"None\" is ignored",
            iface.name
        );
    }
    if netname.is_some() || netkey.is_some() {
        let type_default = match &iface.config {
            reticulum_daemon::config::InterfaceConfig::SerialInterface { .. }
            | reticulum_daemon::config::InterfaceConfig::KISSInterface { .. }
            | reticulum_daemon::config::InterfaceConfig::AX25KISSInterface { .. }
            | reticulum_daemon::config::InterfaceConfig::RNodeInterface { .. }
            | reticulum_daemon::config::InterfaceConfig::RNodeMultiInterface { .. }
            | reticulum_daemon::config::InterfaceConfig::PipeInterface { .. } => {
                reticulum::iface::ifac::SERIAL_FAMILY_IFAC_SIZE
            }
            reticulum_daemon::config::InterfaceConfig::WeaveInterface { .. } => {
                reticulum::iface::ifac::DEFAULT_IFAC_SIZE
            }
            _ => reticulum::iface::ifac::DEFAULT_IFAC_SIZE,
        };
        let size = match iface.ifac_size {
            Some(bits) if bits >= reticulum::iface::ifac::IFAC_MIN_SIZE * 8 => bits / 8,
            _ => type_default,
        };

        if let Err(error) = manager.set_iface_ifac(address, netname, netkey, size) {
            log::error!(
                "Interface '{}' has an invalid IFAC configuration: {error:?}",
                iface.name
            );
        }

        log::info!(
            "Interface '{}' is access-code protected (ifac size {size} bytes)",
            iface.name
        );
    }
}

/// Build the discovery description of a discoverable interface
/// (Python `InterfaceAnnouncer.get_interface_announce_data`).
fn discovery_info_for(
    iface: &reticulum_daemon::config::NamedInterface,
    config: &reticulum_daemon::config::Config,
    transport_id: reticulum::hash::AddressHash,
) -> Option<reticulum_discovery::InterfaceInfo> {
    use reticulum_daemon::config::InterfaceConfig;

    let mut frequency = iface.discovery_frequency;
    let mut bandwidth = iface.discovery_bandwidth;
    let mut spreadingfactor = None;
    let mut codingrate = None;
    let modulation = iface.discovery_modulation.clone();
    let mut reachable_on = None;
    let mut port = None;

    let interface_type = match &iface.config {
        InterfaceConfig::BackboneInterface { bind_port, .. } => {
            reachable_on = iface.reachable_on.clone();
            port = Some(*bind_port);
            "BackboneInterface"
        }
        InterfaceConfig::TCPServerInterface { bind_port, .. } => {
            reachable_on = iface.reachable_on.clone();
            port = Some(*bind_port);
            "TCPServerInterface"
        }
        InterfaceConfig::TCPClientInterface { .. } => {
            if !iface.kiss_framing {
                log::error!(
                    "Interface '{}': TCP client discovery requires kiss_framing",
                    iface.name
                );
                return None;
            }
            "TCPClientInterface"
        }
        InterfaceConfig::RNodeInterface {
            frequency: radio_frequency,
            bandwidth: radio_bandwidth,
            spreadingfactor: sf,
            codingrate: cr,
            ..
        } => {
            frequency = Some(*radio_frequency);
            bandwidth = Some(u64::from(*radio_bandwidth));
            spreadingfactor = Some(*sf);
            codingrate = Some(cr.to_string());
            "RNodeInterface"
        }
        InterfaceConfig::I2PInterface { .. } => {
            // `reachable_on` is the live SAM b32, filled at announce time.
            "I2PInterface"
        }
        InterfaceConfig::KISSInterface { .. } => "KISSInterface",
        InterfaceConfig::WeaveInterface { .. } => "WeaveInterface",
        _ => return None,
    };

    if matches!(interface_type, "BackboneInterface" | "TCPServerInterface")
        && reachable_on
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .is_none()
    {
        log::error!(
            "Interface '{}': discovery requires reachable_on for {interface_type}",
            iface.name
        );
        return None;
    }

    let (ifac_netname, ifac_netkey) = if iface.publish_ifac {
        let netname = meaningful_ifac(iface.networkname.as_deref()).map(str::to_string);
        let netkey = meaningful_ifac(iface.passphrase.as_deref()).map(str::to_string);
        if netname.is_none() && netkey.is_none() {
            log::warn!(
                "Interface '{}': IFAC publishing is enabled but no network name or passphrase is set",
                iface.name
            );
        }
        (netname, netkey)
    } else {
        (None, None)
    };

    Some(reticulum_discovery::InterfaceInfo {
        interface_type: interface_type.to_string(),
        transport: config.reticulum.enable_transport,
        transport_id,
        name: iface.discovery_name.clone(),
        latitude: iface.latitude,
        longitude: iface.longitude,
        height: iface.height,
        reachable_on,
        port,
        frequency,
        bandwidth,
        spreadingfactor,
        codingrate,
        channel: None,
        modulation,
        ifac_netname,
        ifac_netkey,
        transport_impl: None,
        transport_vers: None,
        operator_lxmf_address: iface
            .discovery_lxmf_address
            .as_deref()
            .filter(|hex| hex.len() == 32)
            .and_then(|hex| AddressHash::new_from_hex_string(hex).ok()),
    })
}

fn meaningful_ifac(value: Option<&str>) -> Option<&str> {
    match value {
        Some(text) if !text.is_empty() && text != "None" => Some(text),
        _ => None,
    }
}

fn tcp_options(iface: &reticulum_daemon::config::NamedInterface, client: bool) -> TcpOptions {
    let mut options = TcpOptions {
        kiss_framing: iface.kiss_framing,
        prefer_ipv6: iface.prefer_ipv6,
        device: iface.device.clone(),
        fixed_mtu: iface.fixed_mtu,
        max_reconnect_tries: iface.max_reconnect_tries,
        connect_timeout: iface.connect_timeout,
    };
    if client && options.connect_timeout.is_none() {
        options.connect_timeout = Some(INITIAL_CONNECT_TIMEOUT);
    }
    options
}

fn control_params(
    config: &reticulum_daemon::config::ReticulumConfig,
    iface: &reticulum_daemon::config::NamedInterface,
) -> IfaceControlParams {
    let mut params = IfaceControlParams::default();
    if let Some(value) = config.ic_max_held_announces.filter(|value| *value > 0) {
        params.ic_max_held_announces = value as usize;
    }
    if let Some(value) = config.ic_burst_hold.filter(|value| *value > 0.0) {
        params.ic_burst_hold = std::time::Duration::from_secs_f64(value);
    }
    if let Some(value) = config.ic_burst_freq_new.filter(|value| *value > 0.0) {
        params.ic_burst_freq_new = value;
    }
    if let Some(value) = config.ic_burst_freq.filter(|value| *value > 0.0) {
        params.ic_burst_freq = value;
    }
    if let Some(value) = config.ic_pr_burst_freq_new.filter(|value| *value > 0.0) {
        params.ic_pr_burst_freq_new = value;
    }
    if let Some(value) = config.ic_pr_burst_freq.filter(|value| *value > 0.0) {
        params.ic_pr_burst_freq = value;
    }
    if let Some(value) = config.ec_pr_freq.filter(|value| *value > 0.0) {
        params.ec_pr_freq = value;
    }
    if let Some(value) = config.ic_new_time.filter(|value| *value > 0.0) {
        params.ic_new_time = std::time::Duration::from_secs_f64(value);
    }
    if let Some(value) = config.ic_burst_penalty.filter(|value| *value > 0.0) {
        params.ic_burst_penalty = std::time::Duration::from_secs_f64(value);
    }
    if let Some(value) = config.ic_held_release_interval.filter(|value| *value > 0.0) {
        params.ic_held_release_interval = std::time::Duration::from_secs_f64(value);
    }

    if let Some(value) = iface.ic_max_held_announces {
        params.ic_max_held_announces = value.max(0) as usize;
    }
    if let Some(value) = iface.ic_burst_hold {
        params.ic_burst_hold = finite_secs(value);
    }
    if let Some(value) = iface.ic_burst_freq_new {
        params.ic_burst_freq_new = value.max(0.0);
    }
    if let Some(value) = iface.ic_burst_freq {
        params.ic_burst_freq = value.max(0.0);
    }
    if let Some(value) = iface.ic_pr_burst_freq_new {
        params.ic_pr_burst_freq_new = value.max(0.0);
    }
    if let Some(value) = iface.ic_pr_burst_freq {
        params.ic_pr_burst_freq = value.max(0.0);
    }
    if let Some(value) = iface.ec_pr_freq {
        params.ec_pr_freq = value.max(0.0);
    }
    if let Some(value) = iface.ic_new_time {
        params.ic_new_time = finite_secs(value);
    }
    if let Some(value) = iface.ic_burst_penalty {
        params.ic_burst_penalty = finite_secs(value);
    }
    if let Some(value) = iface.ic_held_release_interval {
        params.ic_held_release_interval = finite_secs(value);
    }
    params
}

fn finite_secs(value: f64) -> std::time::Duration {
    let seconds = if value.is_finite() && value > 0.0 {
        value
    } else {
        0.0
    };
    std::time::Duration::from_secs_f64(seconds)
}

/// Python fills a missing announce rate only when transport is enabled.
/// A configured target with a missing grace or penalty uses 0.
fn announce_rate_limits(
    config: &reticulum_daemon::config::ReticulumConfig,
    iface: &reticulum_daemon::config::NamedInterface,
) -> Option<(std::time::Duration, u32, std::time::Duration)> {
    let mut target = iface.announce_rate_target.filter(|value| *value > 0);
    let mut grace = iface.announce_rate_grace.filter(|value| *value >= 0);
    let mut penalty = iface.announce_rate_penalty.filter(|value| *value >= 0);
    if target.is_some() && grace.is_none() {
        grace = Some(0);
    }
    if target.is_some() && penalty.is_none() {
        penalty = Some(0);
    }
    if config.enable_transport {
        if target.is_none() {
            target = Some(match config.default_ar_target {
                Some(value) if value > 0 => value,
                _ => 3600,
            });
        }
        if penalty.is_none() {
            penalty = Some(
                config
                    .default_ar_penalty
                    .filter(|value| *value > 0)
                    .unwrap_or(0),
            );
        }
        if grace.is_none() {
            grace = Some(
                config
                    .default_ar_grace
                    .filter(|value| *value > 0)
                    .unwrap_or(5),
            );
        }
    }
    target.map(|target| {
        (
            std::time::Duration::from_secs(target as u64),
            grace.unwrap_or(0) as u32,
            std::time::Duration::from_secs(penalty.unwrap_or(0) as u64),
        )
    })
}

fn autoconnect_attach(
    config: &reticulum_daemon::config::ReticulumConfig,
) -> reticulum_discovery::AutoconnectAttach {
    let mode = config
        .autoconnect_interface_mode
        .as_deref()
        .and_then(InterfaceMode::from_name)
        .or(config.enable_transport.then_some(InterfaceMode::Gateway));
    let rate = if config.enable_transport {
        announce_rate_limits(config, &reticulum_daemon::config::NamedInterface::default())
    } else {
        None
    };
    reticulum_discovery::AutoconnectAttach {
        mode,
        gravity: config.autoconnect_interface_gravity,
        announces_to_internal: config.autoconnect_announces_to_internal.then_some(true),
        bitrate: Some(5_000_000),
        announce_rate_target: rate.map(|rate| rate.0),
        announce_rate_grace: rate.map(|rate| rate.1),
        announce_rate_penalty: rate.map(|rate| rate.2),
    }
}

fn load_network_identity(path: &str) -> Result<PrivateIdentity, String> {
    let path = expand_user_path(path);
    if path.is_file() {
        return reticulum_utils::common::load_private_identity(&path).map_err(|err| {
            format!(
                "could not load network identity from {}: {err}",
                path.display()
            )
        });
    }
    let identity = PrivateIdentity::new_from_rand(OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("could not create {}: {err}", parent.display()))?;
    }
    write_raw_identity(&path, &identity).map_err(|err| {
        format!(
            "could not save network identity to {}: {err}",
            path.display()
        )
    })?;
    log::info!(
        "Network identity generated and persisted to {}",
        path.display()
    );
    Ok(identity)
}

fn expand_user_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    } else if path == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    PathBuf::from(path)
}

fn write_raw_identity(path: &Path, identity: &PrivateIdentity) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&identity.to_bytes())?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, identity.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_management_allowed;

    #[test]
    fn management_hashes_are_all_validated_before_use() {
        let valid = vec!["00112233445566778899aabbccddeeff".to_string()];
        assert_eq!(parse_management_allowed(&valid).unwrap().len(), 1);
        assert!(parse_management_allowed(&[]).unwrap().is_empty());
        assert!(
            parse_management_allowed(&[valid[0].clone(), "not-a-valid-hash".to_string(),]).is_err()
        );
    }

    #[cfg(feature = "iface-rnode")]
    #[test]
    fn rnode_endpoints_normalize_python_and_native_forms() {
        use super::rnode_endpoint;

        let tcp = Some("native.example:7633".to_string());
        let serial = Some("/dev/ttyUSB0".to_string());
        assert_eq!(
            rnode_endpoint(&tcp, &serial),
            (Some("native.example:7633"), None)
        );

        let tcp = None;
        let migrated = Some("tcp://127.0.0.1:7633".to_string());
        assert_eq!(
            rnode_endpoint(&tcp, &migrated),
            (Some("127.0.0.1:7633"), None)
        );

        let serial = Some("/dev/ttyACM0".to_string());
        assert_eq!(rnode_endpoint(&tcp, &serial), (None, Some("/dev/ttyACM0")));
    }

    #[tokio::test]
    async fn configure_path_publishes_control_on_the_receiving_peer() {
        use std::time::Duration;

        use super::apply_daemon_transport;
        use super::launch_configured;
        use super::tcp_options;
        use rand_core::OsRng;
        use reticulum::identity::PrivateIdentity;
        use reticulum::iface::InterfaceMode;
        use reticulum::iface::control::ANNOUNCE_CAP;
        use reticulum::iface::tcp_server::TcpServer;
        use reticulum::iface::udp::UdpInterface;
        use reticulum::transport::TransportConfig;
        use reticulum_daemon::config::InterfaceConfig;
        use reticulum_daemon::config::NamedInterface;
        use reticulum_daemon::config::ReticulumConfig;

        let config = ReticulumConfig {
            qlen_in_data: Some(0),
            qlen_in_announce: Some(32),
            default_gravity: Some(7),
            ..ReticulumConfig::default()
        };

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let transport = apply_daemon_transport(
            TransportConfig::new("configure-path", &identity),
            &config,
            Vec::new(),
            std::env::temp_dir()
                .join("rns-configure-path")
                .to_string_lossy()
                .into_owned(),
        )
        .build();
        let lengths = transport.inbound_queue_lengths().await;
        assert_eq!(
            lengths[reticulum::transport::TrafficClass::Data as usize],
            reticulum::transport::INBOUND_QUEUE_LENGTHS[0],
            "qlen 0 leaves the data queue at the class default"
        );
        assert_eq!(
            lengths[reticulum::transport::TrafficClass::Announce as usize],
            32
        );

        let manager = transport.iface_manager();
        let fresh_cap = {
            let mut manager = manager.lock().await;
            let fresh = manager.open(UdpInterface::new("127.0.0.1:9", None, false));
            let address = fresh.channel.address;
            drop(fresh);
            manager.with_control(&address, |control| control.announce_cap)
        };
        // The control-state cap is the fraction itself (PR "Announce cap
        // fraction"): ANNOUNCE_CAP is already 0.02 and must not be divided
        // by 100 again.
        assert_eq!(fresh_cap, Some(ANNOUNCE_CAP));

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let iface = NamedInterface {
            name: "uplink".to_string(),
            mode: Some("gw".to_string()),
            bitrate: Some(50_000),
            announce_cap: Some(25.0),
            gravity: Some(3),
            announce_rate_target: Some(120),
            announce_rate_grace: Some(2),
            announce_rate_penalty: Some(30),
            ingress_control: Some(false),
            egress_control: Some(true),
            recursive_prs: true,
            announces_from_internal: Some(false),
            announces_to_internal: Some(true),
            ic_max_held_announces: Some(9),
            config: InterfaceConfig::TCPServerInterface {
                enabled: true,
                bind_host: "127.0.0.1".to_string(),
                bind_port: port,
            },
            ..NamedInterface::default()
        };

        let server = TcpServer::with_options(
            format!("127.0.0.1:{port}"),
            manager.clone(),
            tcp_options(&iface, false),
        )
        .expect("tcp options");
        launch_configured(&manager, server, None, TcpServer::spawn, &iface, &config).await;

        let mut stream = None;
        for _ in 0..50 {
            if let Ok(connected) = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await
            {
                stream = Some(connected);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let stream = stream.expect("connect");
        let mut peer = None;
        for _ in 0..50 {
            let stats = manager.lock().await.stats();
            if let Some(stat) = stats.iter().find(|stat| stat.kind == "TcpClient") {
                peer = Some(stat.address);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let peer = peer.expect("spawned tcp peer");
        let control = manager
            .lock()
            .await
            .with_control(&peer, |control| {
                (
                    control.mode,
                    control.gravity,
                    control.bitrate,
                    control.announce_cap,
                    control.announce_rate_target,
                    control.announce_rate_grace,
                    control.announce_rate_penalty,
                    control.ingress_control,
                    control.egress_control,
                    control.recursive_prs,
                    control.announces_from_internal,
                    control.announces_to_internal,
                    control.params().ic_max_held_announces,
                )
            })
            .expect("peer control");
        assert_eq!(control.0, InterfaceMode::Gateway);
        assert_eq!(control.1, 3);
        assert_eq!(control.2, 50_000);
        assert_eq!(control.3, 0.25);
        assert_eq!(control.4, Some(Duration::from_secs(120)));
        assert_eq!(control.5, Some(2));
        assert_eq!(control.6, Some(Duration::from_secs(30)));
        assert!(!control.7);
        assert!(control.8);
        assert!(control.9);
        assert!(!control.10);
        assert_eq!(control.11, Some(true));
        assert_eq!(control.12, 9);
        drop(stream);
    }

    fn unsupported_iface(
        name: &str,
        type_name: &str,
        enabled: bool,
    ) -> reticulum_daemon::config::NamedInterface {
        use reticulum_daemon::config::InterfaceConfig;
        reticulum_daemon::config::NamedInterface {
            name: name.to_string(),
            config: InterfaceConfig::Unsupported,
            configured_type: type_name.to_string(),
            configured_enabled: enabled,
            ..reticulum_daemon::config::NamedInterface::default()
        }
    }

    #[tokio::test]
    async fn unknown_interface_type_fails_startup_with_its_name() {
        use super::start_configured_interface;
        use reticulum::iface::InterfaceManager;
        use reticulum_daemon::config::ReticulumConfig;

        let manager = std::sync::Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(4)));
        let iface = unsupported_iface("future", "SomeNewInterfaceType", true);
        let error = start_configured_interface(
            &manager,
            &iface,
            &ReticulumConfig::default(),
            false,
            &mut Vec::new(),
        )
        .await
        .expect_err("enabled unknown type");
        assert!(error.contains("SomeNewInterfaceType"), "{error}");
    }

    #[tokio::test]
    async fn disabled_unknown_interface_is_skipped() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use super::start_configured_interface;
        use reticulum::iface::InterfaceManager;
        use reticulum_daemon::config::ReticulumConfig;
        use reticulum_daemon::config::register_interface_factory;

        let called = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&called);
        register_interface_factory("Pr26DisabledUnknown", move |_, _| {
            let flag = std::sync::Arc::clone(&flag);
            async move {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }
        });

        let manager = std::sync::Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(4)));
        let iface = unsupported_iface("quiet", "Pr26DisabledUnknown", false);
        start_configured_interface(
            &manager,
            &iface,
            &ReticulumConfig::default(),
            false,
            &mut Vec::new(),
        )
        .await
        .expect("disabled unknown type is skipped");
        assert!(!called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn registered_factory_handles_unknown_type_without_a_match_arm() {
        use std::sync::atomic::{AtomicBool, Ordering};

        use super::start_configured_interface;
        use reticulum::iface::InterfaceManager;
        use reticulum_daemon::config::ReticulumConfig;
        use reticulum_daemon::config::register_interface_factory;

        let called = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&called);
        register_interface_factory("Pr26FactoryProbe", move |iface, _| {
            let flag = std::sync::Arc::clone(&flag);
            async move {
                assert_eq!(iface.configured_type, "Pr26FactoryProbe");
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }
        });

        let manager = std::sync::Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(4)));
        let iface = unsupported_iface("probe", "Pr26FactoryProbe", true);
        start_configured_interface(
            &manager,
            &iface,
            &ReticulumConfig::default(),
            false,
            &mut Vec::new(),
        )
        .await
        .expect("factory handles the type");
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn weave_ifac_default_is_16_and_bitrate_guess_is_250k() {
        use super::configure_iface;
        use reticulum::iface::InterfaceManager;
        use reticulum::iface::udp::UdpInterface;
        use reticulum_daemon::config::InterfaceConfig;
        use reticulum_daemon::config::NamedInterface;
        use reticulum_daemon::config::ReticulumConfig;

        let manager = std::sync::Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(4)));

        async fn open_udp(
            manager: &std::sync::Arc<tokio::sync::Mutex<InterfaceManager>>,
        ) -> reticulum::hash::AddressHash {
            let mut guard = manager.lock().await;
            let context = guard.open(UdpInterface::new("127.0.0.1:9", None, false));
            context.channel.address
        }

        let weave_address = open_udp(&manager).await;
        let weave = NamedInterface {
            name: "weave".to_string(),
            networkname: Some("net".to_string()),
            config: InterfaceConfig::WeaveInterface {
                enabled: true,
                port: "/dev/weave0".to_string(),
            },
            ..NamedInterface::default()
        };
        configure_iface(
            &manager,
            &weave_address,
            &weave,
            &ReticulumConfig::default(),
        )
        .await;
        let ifac_size = manager
            .lock()
            .await
            .with_iface_ifac(&weave_address, |slot| {
                slot.read().expect("ifac lock").as_ref().map(|key| key.size)
            })
            .unwrap();
        let bitrate = manager
            .lock()
            .await
            .with_control(&weave_address, |control| control.bitrate)
            .unwrap();
        assert_eq!(ifac_size, Some(16));
        assert_eq!(bitrate, reticulum::iface::weave::BITRATE_GUESS);

        let explicit_address = open_udp(&manager).await;
        let explicit = NamedInterface {
            name: "weave-fast".to_string(),
            bitrate: Some(100_000),
            networkname: Some("net".to_string()),
            config: InterfaceConfig::WeaveInterface {
                enabled: true,
                port: "/dev/weave1".to_string(),
            },
            ..NamedInterface::default()
        };
        configure_iface(
            &manager,
            &explicit_address,
            &explicit,
            &ReticulumConfig::default(),
        )
        .await;
        let bitrate = manager
            .lock()
            .await
            .with_control(&explicit_address, |control| control.bitrate)
            .unwrap();
        assert_eq!(bitrate, 100_000);

        let low_address = open_udp(&manager).await;
        let low = NamedInterface {
            name: "weave-low".to_string(),
            bitrate: Some(4),
            config: InterfaceConfig::WeaveInterface {
                enabled: true,
                port: "/dev/weave-low".to_string(),
            },
            ..NamedInterface::default()
        };
        configure_iface(&manager, &low_address, &low, &ReticulumConfig::default()).await;
        let bitrate = manager
            .lock()
            .await
            .with_control(&low_address, |control| control.bitrate)
            .unwrap();
        assert_eq!(bitrate, reticulum::iface::weave::BITRATE_GUESS);

        let floor_address = open_udp(&manager).await;
        let floor = NamedInterface {
            name: "weave-floor".to_string(),
            bitrate: Some(5),
            config: InterfaceConfig::WeaveInterface {
                enabled: true,
                port: "/dev/weave-floor".to_string(),
            },
            ..NamedInterface::default()
        };
        configure_iface(
            &manager,
            &floor_address,
            &floor,
            &ReticulumConfig::default(),
        )
        .await;
        let bitrate = manager
            .lock()
            .await
            .with_control(&floor_address, |control| control.bitrate)
            .unwrap();
        assert_eq!(bitrate, 5);

        let serial_address = open_udp(&manager).await;
        let serial = NamedInterface {
            name: "serial".to_string(),
            networkname: Some("net".to_string()),
            config: InterfaceConfig::SerialInterface {
                enabled: true,
                port: "/dev/ttyUSB0".to_string(),
                speed: 9600,
                databits: 8,
                parity: "N".to_string(),
                stopbits: 1,
            },
            ..NamedInterface::default()
        };
        configure_iface(
            &manager,
            &serial_address,
            &serial,
            &ReticulumConfig::default(),
        )
        .await;
        let ifac_size = manager
            .lock()
            .await
            .with_iface_ifac(&serial_address, |slot| {
                slot.read().expect("ifac lock").as_ref().map(|key| key.size)
            })
            .unwrap();
        let bitrate = manager
            .lock()
            .await
            .with_control(&serial_address, |control| control.bitrate)
            .unwrap();
        assert_eq!(ifac_size, Some(8));
        assert_eq!(bitrate, 62_500);

        let slow_address = open_udp(&manager).await;
        let slow = NamedInterface {
            name: "serial-slow".to_string(),
            bitrate: Some(1),
            config: InterfaceConfig::SerialInterface {
                enabled: true,
                port: "/dev/ttyUSB1".to_string(),
                speed: 9600,
                databits: 8,
                parity: "N".to_string(),
                stopbits: 1,
            },
            ..NamedInterface::default()
        };
        configure_iface(&manager, &slow_address, &slow, &ReticulumConfig::default()).await;
        let bitrate = manager
            .lock()
            .await
            .with_control(&slow_address, |control| control.bitrate)
            .unwrap();
        assert_eq!(bitrate, 62_500);
    }
}
