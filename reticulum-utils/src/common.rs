//! Shared plumbing for the `rn*` tools: config-directory handling, identity
//! file persistence, transport construction from a config directory and
//! formatting helpers.
//!
//! Python reference: `RNS.Reticulum` (config dir + storage layout),
//! `RNS.Utilities/*` (`--config` option, `RNS.prettyhexrep`).

use std::fs;
use std::path::{Path, PathBuf};

use rand_core::OsRng;
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::local::{LocalClient, SharedInstanceAddress};
use reticulum::iface::tcp_client::TcpClient;
use reticulum::iface::tcp_server::TcpServer;
use reticulum::iface::udp::UdpInterface;
use reticulum::transport::{Transport, TransportConfig};

/// Format a hash like Python `RNS.prettyhexrep`: `<aabbcc...>`.
pub fn prettyhexrep(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2 + 2);
    out.push('<');
    for byte in bytes {
        out.push_str(&format!("{byte:0>2x}"));
    }
    out.push('>');
    out
}

/// Seconds since the unix epoch.
pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

/// Python `RNS.prettytime` (not verbose, not compact).
pub fn pretty_time(seconds: f64) -> String {
    let mut time = seconds.max(0.0);
    let days = (time / 86_400.0) as u64;
    time %= 86_400.0;
    let hours = (time / 3_600.0) as u64;
    time %= 3_600.0;
    let minutes = (time / 60.0) as u64;
    time %= 60.0;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if time > 0.0 {
        // Python `str(round(seconds, 2))`, so a whole second is `1.0`.
        parts.push(format!("{}s", round_seconds(time)));
    }
    match parts.len() {
        0 => "0s".to_string(),
        1 => parts.remove(0),
        _ => {
            let last = parts.pop().unwrap_or_default();
            format!("{} and {last}", parts.join(", "))
        }
    }
}

fn round_seconds(value: f64) -> String {
    let rounded = (value * 100.0).round() / 100.0;
    let mut text = format!("{rounded:.2}");
    if text.ends_with('0') && !text.ends_with(".0") {
        text.pop();
    }
    text
}

/// Numeric msgpack value as `f64` (int, uint, or float).
pub(crate) fn as_f64(value: &rmpv::Value) -> Option<f64> {
    value.as_f64().or_else(|| {
        value
            .as_i64()
            .map(|item| item as f64)
            .or_else(|| value.as_u64().map(|item| item as f64))
    })
}

/// Msgpack value as JSON. Byte strings become bare hex, matching
/// `RNS.hexrep(..., delimit=False)` in the Python utilities' `--json` output.
pub fn msgpack_json(value: &rmpv::Value) -> String {
    serde_json::to_string(&msgpack_json_value(value)).unwrap_or_else(|_| "null".to_string())
}

fn msgpack_json_value(value: &rmpv::Value) -> serde_json::Value {
    match value {
        rmpv::Value::Nil => serde_json::Value::Null,
        rmpv::Value::Boolean(item) => serde_json::Value::Bool(*item),
        rmpv::Value::Integer(item) => {
            if let Some(number) = item.as_i64() {
                serde_json::Value::from(number)
            } else if let Some(number) = item.as_u64() {
                serde_json::Value::from(number)
            } else {
                serde_json::Value::Null
            }
        }
        rmpv::Value::F32(item) => serde_json::json!(*item as f64),
        rmpv::Value::F64(item) => serde_json::Number::from_f64(*item)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        rmpv::Value::String(item) => {
            serde_json::Value::String(item.as_str().unwrap_or("").to_string())
        }
        rmpv::Value::Binary(item) => serde_json::Value::String(hex_bytes(item)),
        rmpv::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(msgpack_json_value).collect())
        }
        rmpv::Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (key, item) in entries {
                let name = match key {
                    rmpv::Value::String(text) => text.as_str().unwrap_or("").to_string(),
                    rmpv::Value::Binary(bytes) => hex_bytes(bytes),
                    other => msgpack_json_value(other).to_string(),
                };
                map.insert(name, msgpack_json_value(item));
            }
            serde_json::Value::Object(map)
        }
        rmpv::Value::Ext(_, data) => serde_json::Value::String(hex_bytes(data)),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Parse a `<hex>`, bare hex or `/<hex>` string into an address hash.
pub fn parse_hash(input: &str) -> Result<AddressHash, String> {
    let cleaned: String = input
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim_start_matches('/')
        .to_lowercase();
    if cleaned.len() != 32 {
        return Err(format!(
            "Invalid hash entered, must be 32 hexadecimal characters (16 bytes), got {} characters",
            cleaned.len()
        ));
    }
    AddressHash::new_from_hex_string(&cleaned)
        .map_err(|_| "Invalid hash entered. Check your input.".to_string())
}

/// Serialize an `rmpv::Value` tree to msgpack bytes.
pub(crate) fn rmpv_to_bytes(value: &rmpv::Value) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = rmpv::encode::write_value(&mut out, value);
    out
}

/// Resolve the configuration directory: explicit argument, else
/// `$RETICULUM_CONFIG_DIR`, else `~/.reticulum`
/// (Python: `RNS.Reticulum(configdir=...)` default).
pub fn resolve_config_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Ok(env_dir) = std::env::var("RETICULUM_CONFIG_DIR") {
        if !env_dir.is_empty() {
            return PathBuf::from(env_dir);
        }
    }
    dirs_home().join(".reticulum")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ---------------------------------------------------------------------------
// Identity files (Phase 1.1 / 7.4)
// ---------------------------------------------------------------------------

/// Error loading an identity file.
#[derive(Debug)]
pub enum IdentityLoadError {
    Io(std::io::Error),
    /// The file content is neither a hex string nor 64 raw key bytes.
    Invalid,
}

impl std::fmt::Display for IdentityLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "could not read identity file: {err}"),
            Self::Invalid => write!(
                f,
                "invalid identity file (expected 128 hex characters or 64 raw key bytes)"
            ),
        }
    }
}

impl std::error::Error for IdentityLoadError {}

/// Save a private identity to `path` as a hex string
/// (`PrivateIdentity::to_hex_string`, 128 hex characters).
///
/// Note: Python `Identity.to_file` writes the same 64 key bytes *raw*;
/// [`load_private_identity`] accepts both formats.
pub fn save_private_identity(path: &Path, identity: &PrivateIdentity) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        use std::io::Write;
        file.write_all(identity.to_hex_string().as_bytes())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, identity.to_hex_string())
    }
}

/// Load a private identity from `path`.
///
/// Two formats are accepted:
///  * hex string (128 characters, `PrivateIdentity::to_hex_string`)
///  * raw 64 bytes (Python `Identity.to_file` output:
///    X25519 private key ‖ Ed25519 signing key, same order as the hex form)
pub fn load_private_identity(path: &Path) -> Result<PrivateIdentity, IdentityLoadError> {
    let bytes = fs::read(path).map_err(IdentityLoadError::Io)?;
    // Hex files are ASCII; Python `Identity.to_file` files are raw binary.
    let as_text = String::from_utf8(bytes.clone()).ok();
    if let Some(text) = as_text {
        let text = text.trim().to_string();
        if text.len() == 128 {
            return PrivateIdentity::new_from_hex_string(&text)
                .map_err(|_| IdentityLoadError::Invalid);
        }
    }
    identity_from_raw_keys(&bytes).ok_or(IdentityLoadError::Invalid)
}

/// Build a [`PrivateIdentity`] from 64 raw key bytes
/// (X25519 private key ‖ Ed25519 signing key), the layout Python
/// `Identity.to_file` writes.
pub fn identity_from_raw_keys(bytes: &[u8]) -> Option<PrivateIdentity> {
    if bytes.len() != 64 {
        return None;
    }
    let mut hex_string = String::with_capacity(128);
    for byte in bytes {
        hex_string.push_str(&format!("{byte:0>2x}"));
    }
    PrivateIdentity::new_from_hex_string(&hex_string).ok()
}

/// Load the identity at `path`, creating (and persisting) a new one when the
/// file does not exist yet. Returns the identity and whether it was created.
pub fn load_or_create_private_identity(
    path: &Path,
) -> Result<(PrivateIdentity, bool), IdentityLoadError> {
    if path.exists() {
        return load_private_identity(path).map(|identity| (identity, false));
    }
    let identity = PrivateIdentity::new_from_rand(OsRng);
    save_private_identity(path, &identity).map_err(IdentityLoadError::Io)?;
    Ok((identity, true))
}

// ---------------------------------------------------------------------------
// Transport construction from a config directory
// ---------------------------------------------------------------------------

/// Options for [`build_tool_transport`].
pub struct ToolTransportOptions<'a> {
    /// Config directory (usually from `--config`).
    pub config_dir: &'a Path,
    /// Instance name used in logs (Python `instance_name`).
    pub instance_name: &'a str,
    /// Enable transport (routing) mode.
    pub enable_transport: bool,
    /// Bind a UDP loopback interface on `bind_port` forwarding to
    /// `forward_port`. Used when the config directory has no usable
    /// interfaces (e.g. ad-hoc `rn cp` runs between two machines).
    pub udp_loopback: Option<(u16, u16)>,
}

/// A parsed `[[interfaces]]` entry from the config file.
#[derive(Debug)]
pub struct ConfiguredInterface {
    pub name: String,
    pub kind: InterfaceKind,
    pub enabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InterfaceKind {
    TcpServer {
        bind_host: String,
        bind_port: u16,
    },
    TcpClient {
        target_host: String,
        target_port: u16,
    },
    Udp {
        listen_ip: String,
        listen_port: u16,
        forward_ip: String,
        forward_port: u16,
    },
    Unsupported(String),
}

/// Read `config.toml` (or `config`) from `config_dir` and list the
/// `[[interfaces]]` entries. Unknown-but-parseable entries are returned as
/// [`InterfaceKind::Unsupported`]; a missing or unparseable config yields an
/// empty list (the tools work fine without one).
pub fn read_configured_interfaces(config_dir: &Path) -> Vec<ConfiguredInterface> {
    let Some(content) = read_config_file(config_dir) else {
        return vec![];
    };
    let Ok(value) = toml::from_str::<toml::Value>(&content) else {
        log::warn!(
            "Could not parse {} as TOML; no interfaces from config",
            config_config_path(config_dir).display()
        );
        return vec![];
    };
    let Some(entries) = value.get("interfaces").and_then(|v| v.as_array()) else {
        return vec![];
    };

    let mut out = Vec::new();
    for entry in entries {
        let table = match entry.as_table() {
            Some(table) => table,
            None => continue,
        };
        let name = table
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed")
            .to_string();
        let enabled = table
            .get("enabled")
            .or_else(|| table.get("interface_enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let kind_str = table.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let get = |key: &str| {
            table
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let get_u16 = |key: &str| {
            table
                .get(key)
                .and_then(|v| v.as_integer())
                .and_then(|v| u16::try_from(v).ok())
        };

        let listen_host = {
            let host = get("listen_ip");
            if host.is_empty() {
                get("bind_host")
            } else {
                host
            }
        };
        let kind = match kind_str {
            "TCPServerInterface" => match get_u16("listen_port").or_else(|| get_u16("bind_port")) {
                Some(port) => InterfaceKind::TcpServer {
                    bind_host: listen_host,
                    bind_port: port,
                },
                None => InterfaceKind::Unsupported(kind_str.to_string()),
            },
            "TCPClientInterface" => match get_u16("target_port") {
                Some(port) => InterfaceKind::TcpClient {
                    target_host: get("target_host"),
                    target_port: port,
                },
                _ => InterfaceKind::Unsupported(kind_str.to_string()),
            },
            "UDPInterface" => match (get_u16("listen_port"), get_u16("forward_port")) {
                (Some(listen_port), Some(forward_port)) => InterfaceKind::Udp {
                    listen_ip: get("listen_ip"),
                    listen_port,
                    forward_ip: get("forward_ip"),
                    forward_port,
                },
                _ => InterfaceKind::Unsupported(kind_str.to_string()),
            },
            other => InterfaceKind::Unsupported(other.to_string()),
        };
        out.push(ConfiguredInterface {
            name,
            kind,
            enabled,
        });
    }
    out
}

/// `[reticulum] interface_discovery_sources` from the config file: the
/// network-identity hashes interface discovery accepts (Python
/// `Reticulum.interface_discovery_sources`). A missing, unparseable, or
/// empty option yields an empty set, which disables filtering.
pub fn interface_discovery_sources(config_dir: &Path) -> std::collections::HashSet<AddressHash> {
    let mut sources = std::collections::HashSet::new();
    let Some(raw) = read_config_file(config_dir)
        .and_then(|content| toml::from_str::<toml::Value>(&content).ok())
        .and_then(|value| {
            value
                .get("reticulum")?
                .get("interface_discovery_sources")
                .cloned()
        })
    else {
        return sources;
    };
    let items: Vec<String> = match &raw {
        toml::Value::Array(list) => list
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        toml::Value::String(text) => text.split(',').map(str::to_string).collect(),
        _ => Vec::new(),
    };
    for item in items {
        let trimmed = item.trim();
        if trimmed.len() == 32 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            if let Ok(hash) = AddressHash::new_from_hex_string(trimmed) {
                sources.insert(hash);
            }
        }
    }
    sources
}

fn config_config_path(config_dir: &Path) -> PathBuf {
    let toml_path = config_dir.join("config.toml");
    if toml_path.exists() {
        toml_path
    } else {
        config_dir.join("config")
    }
}

fn read_config_file(config_dir: &Path) -> Option<String> {
    let path = config_config_path(config_dir);
    if !path.exists() {
        return None;
    }
    let content = fs::read_to_string(&path).ok()?;
    if toml::from_str::<toml::Value>(&content).is_err() {
        log::warn!(
            "Config at {} is not valid TOML (Python-format configs must be converted with \
             `rs-rnsd convert-config` first); continuing without configured interfaces",
            path.display()
        );
        return None;
    }
    Some(content)
}

/// Build a transport for a tool run.
///
/// A reachable shared instance is attached and configured interfaces are
/// left down. Otherwise the interfaces from `config_dir` (or
/// `udp_loopback`) are opened. If the probe succeeds but the local client
/// never comes online, configured interfaces are opened instead.
pub async fn build_tool_transport(options: ToolTransportOptions<'_>) -> Transport {
    match build_tool_transport_inner(options, false).await {
        Ok(transport) => transport,
        Err(_) => unreachable!("shared instance was not required"),
    }
}

/// [`build_tool_transport`], returning an error when no shared instance is
/// reachable. A probe that succeeds but whose client never comes online
/// still falls back to configured interfaces.
pub async fn build_tool_transport_requiring_shared(
    options: ToolTransportOptions<'_>,
) -> Result<Transport, String> {
    build_tool_transport_inner(options, true).await
}

async fn build_tool_transport_inner(
    options: ToolTransportOptions<'_>,
    require_shared_instance: bool,
) -> Result<Transport, String> {
    let settings = shared_settings(options.config_dir);
    let reachable = if settings.share {
        shared_instance_reachable(&settings).await
    } else {
        false
    };
    if require_shared_instance && !reachable {
        return Err(
            "No shared instance available, but application that started Reticulum required it"
                .to_string(),
        );
    }

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let mut attached_shared = false;
    // Python clears transport only after the shared client is connected.
    // A failed attach must keep the configured flag.
    let transport = TransportConfig::new(options.instance_name, &identity)
        .set_retransmit(options.enable_transport)
        .build();

    if reachable {
        let address = shared_data_address(&settings);
        log::info!("Connected to locally available Reticulum instance via {address:?}");
        let manager = transport.iface_manager();
        let mut manager = manager.lock().await;
        let attached = manager.spawn(
            LocalClient::new("Local shared instance", address),
            LocalClient::spawn,
        );
        manager.set_iface_name(&attached, "Local shared instance");
        drop(manager);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if transport
                .iface_manager()
                .lock()
                .await
                .connected_to_shared_instance()
            {
                attached_shared = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if attached_shared {
            transport.set_retransmit(false).await;
            return Ok(transport);
        }
        let waiter = transport.iface_manager().lock().await.stop_iface(&attached);
        if let Some(mut waiter) = waiter {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                waiter.wait_for(|done| *done),
            )
            .await;
        }
        transport.set_retransmit(options.enable_transport).await;
    }

    let interfaces = read_configured_interfaces(options.config_dir);
    let mut spawned = 0usize;
    for iface in &interfaces {
        if !iface.enabled {
            log::debug!("Interface '{}' disabled in config", iface.name);
            continue;
        }
        // Interfaces are spawned below without holding the manager lock
        // across awaits of the loop body.
        match &iface.kind {
            InterfaceKind::TcpServer {
                bind_host,
                bind_port,
            } => {
                let addr = format!("{}:{}", bind_host.trim_end_matches(':'), bind_port);
                log::info!(
                    "Enabling interface '{}': TCP Server on {}",
                    iface.name,
                    addr
                );
                transport.iface_manager().lock().await.spawn(
                    TcpServer::new(addr, transport.iface_manager()),
                    TcpServer::spawn,
                );
                spawned += 1;
            }
            InterfaceKind::TcpClient {
                target_host,
                target_port,
            } => {
                let addr = format!("{}:{}", target_host.trim_end_matches(':'), target_port);
                log::info!(
                    "Enabling interface '{}': TCP Client to {}",
                    iface.name,
                    addr
                );
                transport
                    .iface_manager()
                    .lock()
                    .await
                    .spawn(TcpClient::new(addr), TcpClient::spawn);
                spawned += 1;
            }
            InterfaceKind::Udp {
                listen_ip,
                listen_port,
                forward_ip,
                forward_port,
            } => {
                let bind_addr = format!("{}:{}", listen_ip, listen_port);
                let forward_addr = format!("{}:{}", forward_ip, forward_port);
                log::info!(
                    "Enabling interface '{}': UDP {}→{}",
                    iface.name,
                    bind_addr,
                    forward_addr
                );
                transport.iface_manager().lock().await.spawn(
                    UdpInterface::new(bind_addr, Some(forward_addr), false),
                    UdpInterface::spawn,
                );
                spawned += 1;
            }
            InterfaceKind::Unsupported(kind) => {
                log::warn!(
                    "Interface '{}' of type '{}' is not supported yet, skipping",
                    iface.name,
                    kind
                );
            }
        }
    }

    if spawned == 0 {
        if let Some((bind_port, forward_port)) = options.udp_loopback {
            log::info!(
                "No configured interfaces, using UDP loopback 127.0.0.1:{bind_port}→127.0.0.1:{forward_port}"
            );
            transport.iface_manager().lock().await.spawn(
                UdpInterface::new(
                    format!("127.0.0.1:{bind_port}"),
                    Some(format!("127.0.0.1:{forward_port}")),
                    false,
                ),
                UdpInterface::spawn,
            );
        }
    }

    Ok(transport)
}

/// One msgpack RPC against the shared instance described by `config_dir`.
pub async fn shared_rpc(config_dir: &Path, request: rmpv::Value) -> Result<rmpv::Value, String> {
    let settings = shared_settings(config_dir);
    let addr = match &settings.abstract_name {
        #[cfg(target_os = "linux")]
        Some(name) => crate::rpc::ControlAddr::Abstract(name.clone()),
        _ => crate::rpc::ControlAddr::Tcp(settings.control_port),
    };
    crate::rpc::call(&addr, &settings.authkey, &request).await
}

struct SharedSettings {
    share: bool,
    data_port: u16,
    control_port: u16,
    /// Set when the control and data sockets are Linux abstract names.
    abstract_name: Option<String>,
    authkey: Vec<u8>,
}

fn shared_settings(config_dir: &Path) -> SharedSettings {
    let table = read_config_file(config_dir)
        .and_then(|content| toml::from_str::<toml::Value>(&content).ok())
        .and_then(|value| {
            value
                .get("reticulum")
                .and_then(|item| item.as_table())
                .cloned()
        });
    let share = table
        .as_ref()
        .and_then(|table| table.get("share_instance"))
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let data_port = table
        .as_ref()
        .and_then(|table| table.get("shared_instance_port"))
        .and_then(|value| value.as_integer())
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(37428);
    let control_port = table
        .as_ref()
        .and_then(|table| table.get("instance_control_port"))
        .and_then(|value| value.as_integer())
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(37429);
    let instance_name = table
        .as_ref()
        .and_then(|table| table.get("instance_name"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("default")
        .to_string();
    let instance_type = table
        .as_ref()
        .and_then(|table| table.get("shared_instance_type"))
        .and_then(|value| value.as_str())
        .unwrap_or("domain");
    let abstract_name = if !instance_type.eq_ignore_ascii_case("tcp") && cfg!(target_os = "linux") {
        Some(instance_name.clone())
    } else {
        None
    };
    let configured = table
        .as_ref()
        .and_then(|table| table.get("rpc_key"))
        .and_then(|value| value.as_str());
    let authkey = tool_authkey(config_dir, configured);
    SharedSettings {
        share,
        data_port,
        control_port,
        abstract_name,
        authkey,
    }
}

fn tool_authkey(config_dir: &Path, configured: Option<&str>) -> Vec<u8> {
    // Python hashes `storage/transport_identity`. Do not use `identity`
    // when that file is present; the daemon identity is a different key.
    let transport_path = config_dir.join("storage").join("transport_identity");
    let identity = match load_private_identity(&transport_path) {
        Ok(identity) => Some(identity),
        Err(_) if transport_path.exists() => None,
        Err(_) => load_private_identity(&config_dir.join("identity")).ok(),
    };
    crate::rpc::authkey(configured, identity.as_ref())
}

fn shared_data_address(settings: &SharedSettings) -> SharedInstanceAddress {
    match &settings.abstract_name {
        #[cfg(target_os = "linux")]
        Some(name) => SharedInstanceAddress::unix_abstract(name.clone()),
        _ => SharedInstanceAddress::tcp(settings.data_port),
    }
}

async fn shared_instance_reachable(settings: &SharedSettings) -> bool {
    if let Some(name) = &settings.abstract_name {
        #[cfg(target_os = "linux")]
        {
            return abstract_reachable(name);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = name;
            return false;
        }
    }
    tokio::time::timeout(
        std::time::Duration::from_millis(200),
        tokio::net::TcpStream::connect(("127.0.0.1", settings.data_port)),
    )
    .await
    .ok()
    .and_then(|result| result.ok())
    .is_some()
}

#[cfg(target_os = "linux")]
fn abstract_reachable(name: &str) -> bool {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr as UnixSocketAddr;

    let Ok(socket_address) = UnixSocketAddr::from_abstract_name(format!("rns/{name}").as_bytes())
    else {
        return false;
    };
    std::os::unix::net::UnixStream::connect_addr(&socket_address).is_ok()
}

// ---------------------------------------------------------------------------
// Interface stats (rnstatus)
// ---------------------------------------------------------------------------

/// Fetch interface stats for a transport
/// (`Transport::interface_stats`, Phase 5.9: names, kinds, counters and
/// online state — the data source for `rnstatus`).
pub async fn interface_stats(transport: &Transport) -> Vec<reticulum::iface::InterfaceStats> {
    transport.interface_stats().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use reticulum::iface::local::LocalServer;
    use std::sync::Arc;

    fn write_shared_config(dir: &Path, body: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("config.toml"), body).unwrap();
    }

    #[tokio::test]
    async fn require_shared_instance_fails_when_nothing_is_listening() {
        let dir = std::env::temp_dir().join(format!("rns-require-{}", std::process::id()));
        write_shared_config(
            &dir,
            // No listener can own port zero; a released ephemeral port can be reused.
            "[reticulum]\nshare_instance = true\nshared_instance_type = \"tcp\"\nshared_instance_port = 0\n",
        );
        let err = build_tool_transport_requiring_shared(ToolTransportOptions {
            config_dir: &dir,
            instance_name: "require-test",
            enable_transport: false,
            udp_loopback: Some((9, 9)),
        })
        .await;
        let Err(err) = err else {
            panic!("closed port should fail");
        };
        assert!(err.contains("No shared instance available"));

        write_shared_config(
            &dir,
            "[reticulum]\nshare_instance = false\nshared_instance_type = \"tcp\"\n",
        );
        let err = build_tool_transport_requiring_shared(ToolTransportOptions {
            config_dir: &dir,
            instance_name: "require-test",
            enable_transport: false,
            udp_loopback: None,
        })
        .await;
        let Err(err) = err else {
            panic!("sharing disabled should fail");
        };
        assert!(err.contains("No shared instance available"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn attaches_when_a_shared_instance_is_listening() {
        let dir = std::env::temp_dir().join(format!("rns-attach-{}", std::process::id()));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        write_shared_config(
            &dir,
            &format!(
                "[reticulum]\nshare_instance = true\nshared_instance_type = \"tcp\"\nshared_instance_port = {port}\n"
            ),
        );

        let identity = PrivateIdentity::new_from_rand(OsRng);
        let server = Arc::new(TransportConfig::new("shared-test", &identity).build());
        let manager = server.iface_manager();
        {
            let mut guard = manager.lock().await;
            let local = LocalServer::new(SharedInstanceAddress::tcp(port), manager.clone());
            let context = guard.open(local);
            guard.launch(context, LocalServer::spawn);
        }

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            if tokio::time::Instant::now() >= deadline {
                panic!("shared instance did not accept connections");
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let transport = build_tool_transport(ToolTransportOptions {
            config_dir: &dir,
            instance_name: "attach-test",
            enable_transport: false,
            udp_loopback: Some((9, 9)),
        })
        .await;
        let stats = transport.iface_manager().lock().await.stats();
        assert!(stats
            .iter()
            .any(|stat| stat.kind == "LocalClient" && stat.name == "Local shared instance"));
        assert!(stats.iter().all(|stat| stat.kind != "UdpInterface"));
        assert!(transport
            .iface_manager()
            .lock()
            .await
            .connected_to_shared_instance());
        let _ = fs::remove_dir_all(dir);
    }
}
