//! Reticulum network interface discovery — Python `RNS/Discovery.py`
//! parity (Phase 6.6).
//!
//! * [`InterfaceAnnouncer`] periodically announces discoverable interfaces
//!   on the fixed SINGLE destination `rnstransport.discovery.interface`,
//!   with an LXMF work-function stamp over the packed interface
//!   description (Python `InterfaceAnnouncer`)
//! * [`InterfaceDiscovery`] listens for those announces, validates the
//!   stamps (required value), and can auto-connect. A storage path writes
//!   the table under `{path}/discovery/interfaces`. The default policy
//!   matches Python: only `BackboneInterface` peers whose wire
//!   implementation is `RNS` at version 1.5.2 or newer
//! * [`BlackholeUpdater`] pulls blackhole lists from configured sources
//!   over links to their `rnstransport.info.blackhole` `/list` handlers
//!   (Python `Discovery.BlackholeUpdater`)
//!
//! Location and `reachable_on` values are taken from the interface
//! record. External programs are not executed.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use tokio::sync::{Mutex, RwLock};

use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::hash::{AddressHash, Hash};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::backbone::BackboneClient;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::Transport;

/// LXMF stamp expand rounds used by interface discovery
/// (Python `InterfaceAnnouncer.WORKBLOCK_EXPAND_ROUNDS`).
pub const WORKBLOCK_EXPAND_ROUNDS: usize = 20;

/// Default required stamp value for accepting discovery announces
/// (Python `InterfaceAnnouncer.DEFAULT_STAMP_VALUE`).
pub const DEFAULT_STAMP_VALUE: u32 = 16;

/// Default announcer job interval in seconds
/// (Python `InterfaceAnnouncer.JOB_INTERVAL`).
pub const ANNOUNCER_INTERVAL: Duration = Duration::from_secs(60);

/// Default discovery announce interval per interface
/// (Python `Interface.discovery_announce_interval`).
pub const DISCOVERY_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(60 * 30);

/// Interface types the announcer will pack
/// (Python `InterfaceAnnouncer.DISCOVERABLE_INTERFACE_TYPES`).
/// `TCPClientInterface` is packed on the wire as `KISSInterface`.
pub const DISCOVERABLE_TYPES: [&str; 7] = [
    "BackboneInterface",
    "TCPServerInterface",
    "TCPClientInterface",
    "RNodeInterface",
    "WeaveInterface",
    "I2PInterface",
    "KISSInterface",
];

/// Interface types the listener retains
/// (Python `InterfaceDiscovery.DISCOVERABLE_TYPES`).
pub const RETAINED_TYPES: [&str; 6] = [
    "BackboneInterface",
    "TCPServerInterface",
    "I2PInterface",
    "RNodeInterface",
    "WeaveInterface",
    "KISSInterface",
];

/// Python `InterfaceDiscovery.THRESHOLD_UNKNOWN` (24 hours).
const THRESHOLD_UNKNOWN: Duration = Duration::from_secs(24 * 60 * 60);
/// Python `InterfaceDiscovery.THRESHOLD_STALE` (3 days).
const THRESHOLD_STALE: Duration = Duration::from_secs(3 * 24 * 60 * 60);
/// Python `InterfaceDiscovery.THRESHOLD_REMOVE` (7 days).
const THRESHOLD_REMOVE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Flag bit: encrypted payload (Python `FLAG_ENCRYPTED`).
pub const FLAG_ENCRYPTED: u8 = 0x02;

/// The fixed discovery destination name
/// (Python `Destination(..., APP_NAME, "discovery", "interface")`).
pub fn discovery_destination_name() -> DestinationName {
    DestinationName::new("rnstransport", "discovery.interface")
}

/// Whether the string is a valid IPv4/IPv6 literal
/// (Python `Discovery.is_ip_address`).
fn is_ip_address(address: &str) -> bool {
    use std::net::IpAddr;
    address.parse::<IpAddr>().is_ok()
}

/// Whether the string is a valid (non-numeric-TLD) hostname
/// (Python `Discovery.is_hostname`).
fn is_hostname(hostname: &str) -> bool {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }
    let components: Vec<&str> = hostname.split('.').collect();
    // A trailing all-numeric label is not a hostname
    // (Python `re.match(r"[0-9]+$", ...)`).
    if components
        .last()
        .map(|c| !c.is_empty() && c.chars().all(|b| b.is_ascii_digit()))
        == Some(true)
    {
        return false;
    }
    let allowed = |label: &str| {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    components.iter().all(|c| allowed(c))
}

/// Whether the string is a `.onion` address (Python 1.5.0
/// `is_onion_address`).
fn is_onion_address(address: &str) -> bool {
    address.to_ascii_lowercase().ends_with(".onion")
}

/// IP addresses that must never be auto-connected
/// (Python 1.5.0 `INVALID_IP_ADDRESSES`).
const INVALID_IP_ADDRESSES: [&str; 2] = ["127.0.0.1", "0.0.0.0"];

fn is_invalid_ip_address(address: &str) -> bool {
    INVALID_IP_ADDRESSES.contains(&address)
}

/// Python `InterfaceAnnouncer.sanitize`: drop CR/LF and surrounding space.
fn sanitize_text(value: &str) -> String {
    value.replace(['\n', '\r'], "").trim().to_string()
}

fn cleaned_ifac(value: &Option<String>) -> Option<String> {
    let sanitized = sanitize_text(value.as_deref()?);
    if sanitized.is_empty() || sanitized == "None" {
        None
    } else {
        Some(sanitized)
    }
}

/// Python `InterfaceAnnounceHandler.sanitize_name`.
fn sanitize_name(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let mut name: String = name.chars().filter(|c| c.is_ascii()).collect();
    name = name.trim().to_string();
    for width in [5usize, 3, 2] {
        name = name.replace(&" ".repeat(width), " ");
    }
    let alphanumeric = |c: char| c.is_ascii_alphanumeric();
    while name.chars().next().is_some_and(|c| !alphanumeric(c)) {
        name.remove(0);
    }
    while name
        .chars()
        .last()
        .is_some_and(|c| !alphanumeric(c) && c != ')')
    {
        name.pop();
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn display_name(info: &InterfaceInfo) -> String {
    info.name
        .as_deref()
        .and_then(sanitize_name)
        .unwrap_or_else(|| format!("Discovered {}", info.interface_type))
}

/// Python `version_tuple`: leading digit runs per dotted component.
fn version_tuple(version: &str) -> Option<Vec<u64>> {
    let mut components = Vec::new();
    for component in version.trim().split('.') {
        let digits: String = component
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if digits.is_empty() {
            break;
        }
        components.push(digits.parse::<u64>().ok()?);
    }
    if components.is_empty() {
        None
    } else {
        Some(components)
    }
}

fn sequential_name(name: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(name) {
        return name.to_string();
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{name} ({n})");
        if !taken.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

fn system_from_unix(unix: f64) -> SystemTime {
    if !unix.is_finite() || unix <= 0.0 {
        return UNIX_EPOCH;
    }
    UNIX_EPOCH + Duration::from_secs_f64(unix)
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// Discovery information wire keys (Python `RNS/Discovery.py`). The
// announce payload is a msgpack map with these short INTEGER keys, not
// string keys.
pub const KEY_INTERFACE_TYPE: u64 = 0x00;
pub const KEY_TRANSPORT: u64 = 0x01;
pub const KEY_REACHABLE_ON: u64 = 0x02;
pub const KEY_LATITUDE: u64 = 0x03;
pub const KEY_LONGITUDE: u64 = 0x04;
pub const KEY_HEIGHT: u64 = 0x05;
pub const KEY_PORT: u64 = 0x06;
pub const KEY_IFAC_NETNAME: u64 = 0x07;
pub const KEY_IFAC_NETKEY: u64 = 0x08;
pub const KEY_FREQUENCY: u64 = 0x09;
pub const KEY_BANDWIDTH: u64 = 0x0A;
pub const KEY_SPREADINGFACTOR: u64 = 0x0B;
pub const KEY_CODINGRATE: u64 = 0x0C;
pub const KEY_MODULATION: u64 = 0x0D;
pub const KEY_CHANNEL: u64 = 0x0E;
pub const KEY_OP_ADDR: u64 = 0xF0;
pub const KEY_TRANSPORT_VERS: u64 = 0xFC;
pub const KEY_TRANSPORT_IMPL: u64 = 0xFD;
pub const KEY_TRANSPORT_ID: u64 = 0xFE;
pub const KEY_NAME: u64 = 0xFF;

/// Wire implementation identifier (Python `IMPLEMENTATION_NAME = "RNS"`).
/// Library logs identify this stack as reticulum-rs; the wire field does not.
pub const IMPLEMENTATION_NAME: &str = "RNS";

/// Wire implementation version (Python `RNS.__version__` 1.5.5).
/// Autoconnect rejects anything below 1.5.2.
pub const IMPLEMENTATION_VERSION: &str = "1.5.5";

/// One announced, discoverable interface (Python discovery `info` map).
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface type (`DISCOVERABLE_TYPES`).
    pub interface_type: String,
    /// Whether the announcing node has transport enabled.
    pub transport: bool,
    /// Truncated hash of the announcing transport instance.
    pub transport_id: AddressHash,
    /// Human-readable name of the interface.
    pub name: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub height: Option<f64>,
    /// Reachable host for connectable types (IP or hostname).
    pub reachable_on: Option<String>,
    /// Reachable port for connectable types.
    pub port: Option<u16>,
    /// Optional radio parameters (RNode/KISS/Weave).
    pub frequency: Option<u64>,
    pub bandwidth: Option<u64>,
    pub spreadingfactor: Option<u8>,
    pub codingrate: Option<String>,
    pub channel: Option<u64>,
    pub modulation: Option<String>,
    /// IFAC credentials published alongside the interface.
    pub ifac_netname: Option<String>,
    pub ifac_netkey: Option<String>,
    /// Implementation identifier (Python `TRANSPORT_IMPL`, required
    /// since RNS 1.5.0).
    pub transport_impl: Option<String>,
    /// Implementation version (Python `TRANSPORT_VERS`).
    pub transport_vers: Option<String>,
    /// Operator LXMF address (Python `OP_ADDR`, 16-byte truncated hash).
    pub operator_lxmf_address: Option<AddressHash>,
}

impl InterfaceInfo {
    /// Pack the description as msgpack with Python's short integer
    /// keys, in `get_interface_announce_data` field order.
    pub fn pack(&self) -> Vec<u8> {
        encode_wire(self)
    }

    /// Unpack a description (Python `InterfaceAnnounceHandler` field
    /// validation). The wire format is a msgpack map with short
    /// integer keys; malformed entries are rejected like Python's
    /// `ValueError` handling.
    pub fn unpack(packed: &[u8]) -> Option<Self> {
        let mut cursor = std::io::Cursor::new(packed);
        let value = rmpv::decode::read_value(&mut cursor).ok()?;
        let rmpv::Value::Map(entries) = value else {
            return None;
        };

        let mut fields: HashMap<u64, rmpv::Value> = HashMap::new();
        for (key, value) in entries {
            fields.insert(key.as_u64()?, value);
        }

        let interface_type = fields.get(&KEY_INTERFACE_TYPE)?.as_str()?.to_string();
        if !DISCOVERABLE_TYPES.contains(&interface_type.as_str()) {
            return None;
        }

        let transport = match fields.get(&KEY_TRANSPORT)? {
            rmpv::Value::Boolean(value) => *value,
            _ => return None,
        };

        let transport_id_bytes = match fields.get(&KEY_TRANSPORT_ID)? {
            rmpv::Value::Binary(bytes) => bytes,
            _ => return None,
        };
        // The field carries a ready-made 16-byte address hash; copy it
        // (re-hashing produces an unrelated address).
        let transport_id = AddressHash::new_from_raw_slice(transport_id_bytes)?;

        // Latitude/longitude/height are required keys. Python accepts
        // only nil or float (integers are rejected).
        let float_field = |key: &u64| -> Option<Option<f64>> {
            match fields.get(key)? {
                rmpv::Value::Nil => Some(None),
                rmpv::Value::F64(value) => Some(Some(*value)),
                rmpv::Value::F32(value) => Some(Some(*value as f64)),
                _ => None,
            }
        };
        let latitude = float_field(&KEY_LATITUDE)?;
        let longitude = float_field(&KEY_LONGITUDE)?;
        let height = float_field(&KEY_HEIGHT)?;

        let str_field = |key: &u64| -> Option<Option<String>> {
            match fields.get(key) {
                None => Some(None),
                Some(rmpv::Value::Nil) => Some(None),
                Some(rmpv::Value::String(value)) => Some(Some(value.as_str()?.to_string())),
                _ => None,
            }
        };
        // NAME is a required key (nil is allowed).
        if !fields.contains_key(&KEY_NAME) {
            return None;
        }
        let name = str_field(&KEY_NAME)?;
        let reachable_on = str_field(&KEY_REACHABLE_ON)?.map(|host| sanitize_text(&host));
        if let Some(host) = &reachable_on {
            if host.is_empty() || !(is_ip_address(host) || is_hostname(host)) {
                return None;
            }
        }

        let u64_field = |key: &u64| fields.get(key).and_then(|v| v.as_u64());
        // Python packs RNode coding rate and Weave modulation as ints.
        let text_or_int = |key: &u64| -> Option<Option<String>> {
            match fields.get(key) {
                None => Some(None),
                Some(rmpv::Value::Nil) => Some(None),
                Some(rmpv::Value::String(value)) => Some(Some(value.as_str()?.to_string())),
                Some(value) => Some(Some(value.as_u64()?.to_string())),
            }
        };

        // Operator LXMF address: nil or a 16-byte binary
        // (Python rejects other shapes entirely).
        let operator_lxmf_address = match fields.get(&KEY_OP_ADDR) {
            None => None,
            Some(rmpv::Value::Nil) => None,
            Some(rmpv::Value::Binary(bytes)) if bytes.len() == 16 => {
                Some(AddressHash::new_from_raw_slice(bytes)?)
            }
            _ => return None,
        };

        Some(Self {
            interface_type,
            transport,
            transport_id,
            transport_impl: str_field(&KEY_TRANSPORT_IMPL)?.filter(|s| !s.is_empty()),
            transport_vers: str_field(&KEY_TRANSPORT_VERS)?.filter(|s| !s.is_empty()),
            name,
            latitude,
            longitude,
            height,
            reachable_on,
            port: match fields.get(&KEY_PORT) {
                None | Some(rmpv::Value::Nil) => None,
                Some(value) => Some(u16::try_from(value.as_u64()?).ok()?),
            },
            frequency: u64_field(&KEY_FREQUENCY),
            bandwidth: u64_field(&KEY_BANDWIDTH),
            spreadingfactor: match fields.get(&KEY_SPREADINGFACTOR) {
                None | Some(rmpv::Value::Nil) => None,
                Some(value) => Some(u8::try_from(value.as_u64()?).ok()?),
            },
            codingrate: text_or_int(&KEY_CODINGRATE)?,
            channel: u64_field(&KEY_CHANNEL),
            modulation: text_or_int(&KEY_MODULATION)?,
            ifac_netname: cleaned_ifac(&str_field(&KEY_IFAC_NETNAME)?),
            ifac_netkey: cleaned_ifac(&str_field(&KEY_IFAC_NETKEY)?),
            operator_lxmf_address,
        })
    }

    /// Hash identifying this interface description
    /// (Python `infohash = full_hash(packed)`).
    pub fn info_hash(&self) -> Hash {
        Hash::new_from_slice(&self.pack())
    }
}

enum WireValue {
    Nil,
    Bool(bool),
    Uint(u64),
    Float(f64),
    Str(String),
    Bin(Vec<u8>),
}

fn push_uint_or_str(fields: &mut Vec<(u64, WireValue)>, key: u64, value: &str) {
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(number) = value.parse::<u64>() {
            fields.push((key, WireValue::Uint(number)));
            return;
        }
    }
    fields.push((key, WireValue::Str(value.to_string())));
}

fn push_optional_text(fields: &mut Vec<(u64, WireValue)>, key: u64, value: &Option<String>) {
    match value
        .as_deref()
        .map(sanitize_text)
        .filter(|s| !s.is_empty())
    {
        Some(text) => push_uint_or_str(fields, key, &text),
        None => fields.push((key, WireValue::Nil)),
    }
}

fn encode_wire(info: &InterfaceInfo) -> Vec<u8> {
    use rmp::encode as mp;

    let wire_type = if matches!(
        info.interface_type.as_str(),
        "KISSInterface" | "TCPClientInterface"
    ) {
        "KISSInterface"
    } else {
        info.interface_type.as_str()
    };

    let mut fields = vec![
        (KEY_INTERFACE_TYPE, WireValue::Str(wire_type.to_string())),
        (KEY_TRANSPORT, WireValue::Bool(info.transport)),
        (
            KEY_TRANSPORT_ID,
            WireValue::Bin(info.transport_id.as_slice().to_vec()),
        ),
        (
            KEY_TRANSPORT_IMPL,
            WireValue::Str(
                info.transport_impl
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| IMPLEMENTATION_NAME.to_string()),
            ),
        ),
        (
            KEY_TRANSPORT_VERS,
            WireValue::Str(
                info.transport_vers
                    .clone()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| IMPLEMENTATION_VERSION.to_string()),
            ),
        ),
    ];
    match info.name.as_deref() {
        Some(name) => fields.push((KEY_NAME, WireValue::Str(sanitize_text(name)))),
        None => fields.push((KEY_NAME, WireValue::Nil)),
    }
    for (key, value) in [
        (KEY_LATITUDE, info.latitude),
        (KEY_LONGITUDE, info.longitude),
        (KEY_HEIGHT, info.height),
    ] {
        match value {
            Some(value) => fields.push((key, WireValue::Float(value))),
            None => fields.push((key, WireValue::Nil)),
        }
    }
    if let Some(address) = info.operator_lxmf_address {
        fields.push((KEY_OP_ADDR, WireValue::Bin(address.as_slice().to_vec())));
    }

    match info.interface_type.as_str() {
        "BackboneInterface" | "TCPServerInterface" => {
            match info
                .reachable_on
                .as_deref()
                .map(sanitize_text)
                .filter(|host| !host.is_empty())
            {
                Some(host) => fields.push((KEY_REACHABLE_ON, WireValue::Str(host))),
                None => fields.push((KEY_REACHABLE_ON, WireValue::Nil)),
            }
            match info.port {
                Some(port) => fields.push((KEY_PORT, WireValue::Uint(port as u64))),
                None => fields.push((KEY_PORT, WireValue::Nil)),
            }
        }
        "I2PInterface" => {
            if let Some(host) = info
                .reachable_on
                .as_deref()
                .map(sanitize_text)
                .filter(|host| !host.is_empty())
            {
                fields.push((KEY_REACHABLE_ON, WireValue::Str(host)));
            }
        }
        "RNodeInterface" => {
            for (key, value) in [
                (KEY_FREQUENCY, info.frequency),
                (KEY_BANDWIDTH, info.bandwidth),
            ] {
                match value {
                    Some(value) => fields.push((key, WireValue::Uint(value))),
                    None => fields.push((key, WireValue::Nil)),
                }
            }
            match info.spreadingfactor {
                Some(value) => fields.push((KEY_SPREADINGFACTOR, WireValue::Uint(value as u64))),
                None => fields.push((KEY_SPREADINGFACTOR, WireValue::Nil)),
            }
            push_optional_text(&mut fields, KEY_CODINGRATE, &info.codingrate);
        }
        "WeaveInterface" => {
            for (key, value) in [
                (KEY_FREQUENCY, info.frequency),
                (KEY_BANDWIDTH, info.bandwidth),
                (KEY_CHANNEL, info.channel),
            ] {
                match value {
                    Some(value) => fields.push((key, WireValue::Uint(value))),
                    None => fields.push((key, WireValue::Nil)),
                }
            }
            push_optional_text(&mut fields, KEY_MODULATION, &info.modulation);
        }
        "KISSInterface" | "TCPClientInterface" => {
            for (key, value) in [
                (KEY_FREQUENCY, info.frequency),
                (KEY_BANDWIDTH, info.bandwidth),
            ] {
                match value {
                    Some(value) => fields.push((key, WireValue::Uint(value))),
                    None => fields.push((key, WireValue::Nil)),
                }
            }
            push_optional_text(&mut fields, KEY_MODULATION, &info.modulation);
        }
        _ => {
            if let Some(host) = info
                .reachable_on
                .as_deref()
                .map(sanitize_text)
                .filter(|host| !host.is_empty())
            {
                fields.push((KEY_REACHABLE_ON, WireValue::Str(host)));
            }
            if let Some(port) = info.port {
                fields.push((KEY_PORT, WireValue::Uint(port as u64)));
            }
            for (key, value) in [
                (KEY_FREQUENCY, info.frequency),
                (KEY_BANDWIDTH, info.bandwidth),
                (KEY_CHANNEL, info.channel),
            ] {
                if let Some(value) = value {
                    fields.push((key, WireValue::Uint(value)));
                }
            }
            if let Some(value) = info.spreadingfactor {
                fields.push((KEY_SPREADINGFACTOR, WireValue::Uint(value as u64)));
            }
            if let Some(value) = info.codingrate.as_deref() {
                push_uint_or_str(&mut fields, KEY_CODINGRATE, value);
            }
            if let Some(value) = info.modulation.as_deref() {
                push_uint_or_str(&mut fields, KEY_MODULATION, value);
            }
        }
    }

    if let Some(netname) = cleaned_ifac(&info.ifac_netname) {
        fields.push((KEY_IFAC_NETNAME, WireValue::Str(netname)));
    }
    if let Some(netkey) = cleaned_ifac(&info.ifac_netkey) {
        fields.push((KEY_IFAC_NETKEY, WireValue::Str(netkey)));
    }

    let mut out = Vec::new();
    mp::write_map_len(&mut out, fields.len() as u32).ok();
    for (key, value) in fields {
        mp::write_uint(&mut out, key).ok();
        match value {
            WireValue::Nil => {
                mp::write_nil(&mut out).ok();
            }
            WireValue::Bool(value) => {
                mp::write_bool(&mut out, value).ok();
            }
            WireValue::Uint(value) => {
                mp::write_uint(&mut out, value).ok();
            }
            WireValue::Float(value) => {
                mp::write_f64(&mut out, value).ok();
            }
            WireValue::Str(value) => {
                mp::write_str(&mut out, &value).ok();
            }
            WireValue::Bin(value) => {
                mp::write_bin(&mut out, &value).ok();
            }
        }
    }
    out
}

fn announce_bytes(info: &InterfaceInfo) -> Option<Vec<u8>> {
    if !DISCOVERABLE_TYPES.contains(&info.interface_type.as_str()) {
        return None;
    }
    if matches!(
        info.interface_type.as_str(),
        "BackboneInterface" | "TCPServerInterface"
    ) {
        let host = sanitize_text(info.reachable_on.as_deref()?);
        if host.is_empty() || !(is_ip_address(&host) || is_hostname(&host)) || info.port.is_none() {
            return None;
        }
    }
    Some(encode_wire(info))
}

/// Build the discovery announce payload for one interface:
/// `flags || packed_info || stamp`. The flag byte is clear.
/// Encrypted announces use [`build_discovery_payload_for_identity`].
pub fn build_discovery_payload(info: &InterfaceInfo, stamp_value: u32) -> Option<Vec<u8>> {
    build_discovery_payload_for_identity(info, stamp_value, None)
}

/// Build an announce, encrypting `packed || stamp` when `network_identity`
/// is set (Python `discovery_encrypt`).
pub fn build_discovery_payload_for_identity(
    info: &InterfaceInfo,
    stamp_value: u32,
    network_identity: Option<&PrivateIdentity>,
) -> Option<Vec<u8>> {
    let packed = announce_bytes(info)?;
    let info_hash = Hash::new_from_slice(&packed);

    let workblock =
        lxmf::stamper::stamp_workblock_with_rounds(info_hash.as_slice(), WORKBLOCK_EXPAND_ROUNDS);
    let mut rng = OsRng;
    let (stamp, value) =
        lxmf::stamper::generate_stamp_against_workblock(&workblock, stamp_value, &mut rng);
    let stamp = stamp?;

    let mut plain = packed;
    plain.extend_from_slice(&stamp);
    let (flags, body) = if let Some(identity) = network_identity {
        let mut out = vec![0u8; plain.len() + 128];
        let encrypted = identity
            .as_identity()
            .encrypt(OsRng, &plain, None, &mut out)
            .ok()?
            .to_vec();
        (FLAG_ENCRYPTED, encrypted)
    } else {
        (0u8, plain)
    };

    let mut payload = Vec::with_capacity(1 + body.len());
    payload.push(flags);
    payload.extend_from_slice(&body);
    let _ = value;
    Some(payload)
}

/// Validate a received discovery announce payload and extract the
/// interface description (Python `InterfaceAnnounceHandler
/// .received_announce`). Encrypted payloads are rejected here; pass the
/// network identity to [`validate_discovery_payload_for_identity`].
pub fn validate_discovery_payload(
    payload: &[u8],
    required_value: u32,
) -> Option<(InterfaceInfo, u64)> {
    validate_discovery_payload_for_identity(payload, required_value, None)
}

/// Validate an announce, decrypting it when `FLAG_ENCRYPTED` is set.
pub fn validate_discovery_payload_for_identity(
    payload: &[u8],
    required_value: u32,
    network_identity: Option<&PrivateIdentity>,
) -> Option<(InterfaceInfo, u64)> {
    if payload.len() <= lxmf::stamper::STAMP_SIZE + 1 {
        return None;
    }

    let flags = payload[0];
    let body = if flags & FLAG_ENCRYPTED != 0 {
        let identity = network_identity?;
        let mut out = vec![0u8; payload.len()];
        identity
            .decrypt(&payload[1..], &[], &mut out)
            .ok()?
            .to_vec()
    } else {
        payload[1..].to_vec()
    };
    if body.len() <= lxmf::stamper::STAMP_SIZE {
        return None;
    }

    let stamp = &body[body.len() - lxmf::stamper::STAMP_SIZE..];
    let packed = &body[..body.len() - lxmf::stamper::STAMP_SIZE];

    let info_hash = Hash::new_from_slice(packed);
    let workblock =
        lxmf::stamper::stamp_workblock_with_rounds(info_hash.as_slice(), WORKBLOCK_EXPAND_ROUNDS);
    let value = lxmf::stamper::stamp_value(&workblock, stamp);
    if !lxmf::stamper::stamp_valid(stamp, required_value, &workblock) {
        return None;
    }

    Some((InterfaceInfo::unpack(packed)?, value))
}

/// Status of a discovered interface
/// (Python `THRESHOLD_*` based statuses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveredStatus {
    Available,
    Unknown,
    Stale,
}

impl DiscoveredStatus {
    fn from_age(age: Duration) -> Self {
        if age > THRESHOLD_STALE {
            Self::Stale
        } else if age > THRESHOLD_UNKNOWN {
            Self::Unknown
        } else {
            Self::Available
        }
    }
}

/// A tracked discovered interface (Python persisted `info` record).
#[derive(Debug, Clone)]
pub struct DiscoveredInterface {
    pub info: InterfaceInfo,
    /// Hash of the announcing network identity.
    pub network_id: Hash,
    /// Stamp value of the accepted announce.
    pub value: u64,
    pub hops: u8,
    pub discovered: tokio::time::Instant,
    pub last_heard: tokio::time::Instant,
    pub heard_count: usize,
    /// Unix `discovered` and `last_heard` stored in the discovery directory.
    /// Age checks use these values, including after load.
    recorded_unix: Option<(f64, f64)>,
}

impl DiscoveredInterface {
    fn heard_age(&self) -> Duration {
        if let Some((_, last_heard)) = self.recorded_unix {
            return SystemTime::now()
                .duration_since(system_from_unix(last_heard))
                .unwrap_or_default();
        }
        self.last_heard.elapsed()
    }

    pub fn status(&self) -> DiscoveredStatus {
        DiscoveredStatus::from_age(self.heard_age())
    }

    /// Endpoint hash for duplicate detection (Python `endpoint_hash`):
    /// SHA-256 of `reachable_on` plus `:port` when a port is present.
    pub fn endpoint_hash(&self) -> Hash {
        let mut specifier = String::new();
        if let Some(host) = &self.info.reachable_on {
            specifier.push_str(host);
        }
        if let Some(port) = self.info.port {
            specifier.push(':');
            specifier.push_str(&port.to_string());
        }
        Hash::new_from_slice(specifier.as_bytes())
    }
}

fn discovery_file_id(info: &InterfaceInfo) -> String {
    let material = format!(
        "{}{}",
        info.transport_id.to_hex_string(),
        display_name(info)
    );
    let hash = Hash::new_from_slice(material.as_bytes());
    hash.as_slice()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn discovery_dir(storage: &Path) -> PathBuf {
    storage.join("discovery").join("interfaces")
}

fn write_stored(entry: &DiscoveredInterface) -> Vec<u8> {
    use rmp::encode as mp;
    let now_unix = unix_now();
    let (discovered_unix, last_heard_unix) = entry.recorded_unix.unwrap_or((now_unix, now_unix));
    let mut fields: Vec<(&str, WireValue)> = vec![
        ("type", WireValue::Str(entry.info.interface_type.clone())),
        (
            "impl_name",
            match &entry.info.transport_impl {
                Some(value) => WireValue::Str(value.clone()),
                None => WireValue::Nil,
            },
        ),
        (
            "version",
            match &entry.info.transport_vers {
                Some(value) => WireValue::Str(value.clone()),
                None => WireValue::Nil,
            },
        ),
        ("transport", WireValue::Bool(entry.info.transport)),
        (
            "name",
            WireValue::Str(entry.info.name.clone().unwrap_or_default()),
        ),
        (
            "transport_id",
            WireValue::Bin(entry.info.transport_id.as_slice().to_vec()),
        ),
        (
            "network_id",
            WireValue::Bin(entry.network_id.as_slice().to_vec()),
        ),
        ("hops", WireValue::Uint(entry.hops as u64)),
        ("value", WireValue::Uint(entry.value)),
        ("heard_count", WireValue::Uint(entry.heard_count as u64)),
        ("discovered", WireValue::Float(discovered_unix)),
        ("last_heard", WireValue::Float(last_heard_unix)),
    ];
    if let Some(host) = &entry.info.reachable_on {
        fields.push(("reachable_on", WireValue::Str(host.clone())));
    }
    if let Some(port) = entry.info.port {
        fields.push(("port", WireValue::Uint(port as u64)));
    }
    for (key, value) in [
        ("latitude", entry.info.latitude),
        ("longitude", entry.info.longitude),
        ("height", entry.info.height),
    ] {
        match value {
            Some(value) => fields.push((key, WireValue::Float(value))),
            None => fields.push((key, WireValue::Nil)),
        }
    }
    if let Some(value) = entry.info.frequency {
        fields.push(("frequency", WireValue::Uint(value)));
    }
    if let Some(value) = entry.info.bandwidth {
        fields.push(("bandwidth", WireValue::Uint(value)));
    }
    if let Some(value) = entry.info.spreadingfactor {
        fields.push(("spreadingfactor", WireValue::Uint(value as u64)));
    }
    if let Some(value) = &entry.info.codingrate {
        fields.push(("codingrate", WireValue::Str(value.clone())));
    }
    if let Some(value) = entry.info.channel {
        fields.push(("channel", WireValue::Uint(value)));
    }
    if let Some(value) = &entry.info.modulation {
        fields.push(("modulation", WireValue::Str(value.clone())));
    }
    if let Some(value) = &entry.info.ifac_netname {
        fields.push(("ifac_netname", WireValue::Str(value.clone())));
    }
    if let Some(value) = &entry.info.ifac_netkey {
        fields.push(("ifac_netkey", WireValue::Str(value.clone())));
    }
    if let Some(address) = entry.info.operator_lxmf_address {
        fields.push(("operator", WireValue::Bin(address.as_slice().to_vec())));
    }

    let mut out = Vec::new();
    mp::write_map_len(&mut out, fields.len() as u32).ok();
    for (key, value) in fields {
        mp::write_str(&mut out, key).ok();
        match value {
            WireValue::Nil => {
                mp::write_nil(&mut out).ok();
            }
            WireValue::Bool(value) => {
                mp::write_bool(&mut out, value).ok();
            }
            WireValue::Uint(value) => {
                mp::write_uint(&mut out, value).ok();
            }
            WireValue::Float(value) => {
                mp::write_f64(&mut out, value).ok();
            }
            WireValue::Str(value) => {
                mp::write_str(&mut out, &value).ok();
            }
            WireValue::Bin(value) => {
                mp::write_bin(&mut out, &value).ok();
            }
        }
    }
    out
}

fn read_stored(bytes: &[u8]) -> Option<DiscoveredInterface> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    let mut fields: HashMap<String, rmpv::Value> = HashMap::new();
    for (key, value) in entries {
        if let Some(key) = key.as_str() {
            fields.insert(key.to_string(), value);
        }
    }
    let interface_type = fields.get("type")?.as_str()?.to_string();
    if !RETAINED_TYPES.contains(&interface_type.as_str()) {
        return None;
    }
    let transport_id = match fields.get("transport_id")? {
        rmpv::Value::Binary(bytes) => AddressHash::new_from_raw_slice(bytes)?,
        rmpv::Value::String(text) => AddressHash::new_from_hex_string(text.as_str()?).ok()?,
        _ => return None,
    };
    let network_id = match fields.get("network_id")? {
        rmpv::Value::Binary(bytes) if bytes.len() == 32 => {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(bytes);
            Hash::new(hash)
        }
        rmpv::Value::String(text) => {
            let text = text.as_str()?;
            if text.len() != 64 {
                return None;
            }
            let mut hash = [0u8; 32];
            for i in 0..32 {
                hash[i] = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
            }
            Hash::new(hash)
        }
        _ => return None,
    };
    let str_opt = |key: &str| -> Option<String> {
        match fields.get(key) {
            Some(rmpv::Value::String(value)) => value.as_str().map(|s| s.to_string()),
            _ => None,
        }
    };
    let float_opt = |key: &str| -> Option<f64> {
        match fields.get(key) {
            Some(rmpv::Value::F64(value)) => Some(*value),
            Some(rmpv::Value::F32(value)) => Some(*value as f64),
            _ => None,
        }
    };
    let now_unix = unix_now();
    let discovered_unix = float_opt("discovered").unwrap_or(now_unix);
    let last_heard_unix = float_opt("last_heard").unwrap_or(discovered_unix);
    let instant_at = |unix: f64| {
        let age = SystemTime::now()
            .duration_since(system_from_unix(unix))
            .unwrap_or_default();
        tokio::time::Instant::now()
            .checked_sub(age)
            .unwrap_or_else(tokio::time::Instant::now)
    };
    let name = str_opt("name")
        .and_then(|name| sanitize_name(&name))
        .unwrap_or_else(|| format!("Discovered {interface_type}"));
    Some(DiscoveredInterface {
        info: InterfaceInfo {
            interface_type,
            transport: matches!(fields.get("transport"), Some(rmpv::Value::Boolean(true))),
            transport_id,
            name: Some(name),
            latitude: float_opt("latitude"),
            longitude: float_opt("longitude"),
            height: float_opt("height"),
            reachable_on: str_opt("reachable_on"),
            port: fields
                .get("port")
                .and_then(|v| v.as_u64())
                .and_then(|p| u16::try_from(p).ok()),
            frequency: fields.get("frequency").and_then(|v| v.as_u64()),
            bandwidth: fields.get("bandwidth").and_then(|v| v.as_u64()),
            spreadingfactor: fields
                .get("spreadingfactor")
                .and_then(|v| v.as_u64())
                .and_then(|v| u8::try_from(v).ok()),
            codingrate: str_opt("codingrate"),
            channel: fields.get("channel").and_then(|v| v.as_u64()),
            modulation: str_opt("modulation"),
            ifac_netname: cleaned_ifac(&str_opt("ifac_netname")),
            ifac_netkey: cleaned_ifac(&str_opt("ifac_netkey")),
            transport_impl: str_opt("impl_name").filter(|s| !s.is_empty()),
            transport_vers: str_opt("version").filter(|s| !s.is_empty()),
            operator_lxmf_address: match fields.get("operator") {
                Some(rmpv::Value::Binary(bytes)) => AddressHash::new_from_raw_slice(bytes),
                _ => None,
            },
        },
        network_id,
        value: fields.get("value").and_then(|v| v.as_u64()).unwrap_or(0),
        hops: fields
            .get("hops")
            .and_then(|v| v.as_u64())
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(u8::MAX),
        discovered: instant_at(discovered_unix),
        last_heard: instant_at(last_heard_unix),
        heard_count: fields
            .get("heard_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize,
        recorded_unix: Some((discovered_unix, last_heard_unix)),
    })
}

fn persist_entry(storage: &Path, entry: &DiscoveredInterface) {
    let dir = discovery_dir(storage);
    if let Err(error) = std::fs::create_dir_all(&dir) {
        log::error!("discovery: could not create {}: {error}", dir.display());
        return;
    }
    let path = dir.join(discovery_file_id(&entry.info));
    if let Err(error) = std::fs::write(&path, write_stored(entry)) {
        log::error!("discovery: could not persist {}: {error}", path.display());
    }
}

fn load_entries(storage: &Path) -> Vec<DiscoveredInterface> {
    let dir = discovery_dir(storage);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut loaded = Vec::new();
    for entry in entries.flatten() {
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        if let Some(discovered) = read_stored(&bytes) {
            loaded.push(discovered);
        }
    }
    loaded
}

fn remove_entry_file(storage: &Path, info: &InterfaceInfo) {
    let path = discovery_dir(storage).join(discovery_file_id(info));
    let _ = std::fs::remove_file(path);
}

struct QueuedAnnounce {
    entry: AnnouncedInterface,
    encrypt_to: Option<PrivateIdentity>,
    /// Live `reachable_on` read at announce time. `None` keeps the
    /// address stored on [`InterfaceInfo`].
    reachable: Option<Arc<std::sync::RwLock<Option<String>>>>,
}

/// The interface announcer: periodically announces one due discoverable
/// interface on the shared discovery destination
/// (Python `InterfaceAnnouncer`).
pub struct InterfaceAnnouncer {
    transport: Arc<Transport>,
    destination: Arc<Mutex<SingleInputDestination>>,
    interfaces: RwLock<Vec<QueuedAnnounce>>,
    stamp_value: u32,
    interval: Duration,
}

/// Registration of one local discoverable interface.
#[derive(Debug, Clone)]
pub struct AnnouncedInterface {
    pub info: InterfaceInfo,
    pub announce_interval: Duration,
    pub last_announced: Option<tokio::time::Instant>,
    /// `None` uses the announcer's stamp. Set per interface when the
    /// config supplies `discovery_stamp_value`.
    stamp_value: Option<u32>,
}

impl InterfaceAnnouncer {
    /// Create the discovery destination on the transport and start the
    /// announcer job.
    pub async fn start(
        transport: &Arc<Transport>,
        identity: &PrivateIdentity,
        stamp_value: u32,
        interval: Duration,
    ) -> Arc<Self> {
        let destination = transport
            .add_destination(identity.clone(), discovery_destination_name())
            .await;

        let announcer = Arc::new(Self {
            transport: transport.clone(),
            destination,
            interfaces: RwLock::new(Vec::new()),
            stamp_value,
            interval,
        });

        let runner = announcer.clone();
        tokio::spawn(async move { runner.job().await });

        announcer
    }

    /// Register a local interface for discovery announces.
    /// Interval is [`DISCOVERY_ANNOUNCE_INTERVAL`] and the stamp is the
    /// announcer's stamp.
    pub async fn announce_interface(&self, info: InterfaceInfo) {
        self.queue(info, None, DISCOVERY_ANNOUNCE_INTERVAL, None)
            .await;
    }

    /// Register an interface whose announces are encrypted to `identity`
    /// (Python `discovery_encrypt` with the network identity).
    pub async fn announce_encrypted_interface(
        &self,
        info: InterfaceInfo,
        identity: PrivateIdentity,
    ) {
        self.queue(info, Some(identity), DISCOVERY_ANNOUNCE_INTERVAL, None)
            .await;
    }

    /// Register an interface with its own announce interval and stamp.
    /// `stamp_value` of `None` uses the announcer stamp. `encrypt_to`
    /// encrypts the payload the same way as
    /// [`Self::announce_encrypted_interface`].
    pub async fn announce_interface_configured(
        &self,
        info: InterfaceInfo,
        interval: Duration,
        stamp_value: Option<u32>,
        encrypt_to: Option<PrivateIdentity>,
    ) {
        self.queue(info, encrypt_to, interval, stamp_value).await;
    }

    async fn queue(
        &self,
        info: InterfaceInfo,
        encrypt_to: Option<PrivateIdentity>,
        interval: Duration,
        stamp_value: Option<u32>,
    ) {
        self.interfaces.write().await.push(QueuedAnnounce {
            entry: AnnouncedInterface {
                info,
                announce_interval: interval,
                last_announced: None,
                stamp_value,
            },
            encrypt_to,
            reachable: None,
        });
    }

    /// Attach a live `reachable_on` source to the interface most recently
    /// queued. Empty or missing values leave `reachable_on` unset, so a
    /// dropped session does not keep a stale address.
    pub async fn attach_live_reachable(&self, slot: Arc<std::sync::RwLock<Option<String>>>) {
        let mut interfaces = self.interfaces.write().await;
        if let Some(queued) = interfaces.last_mut() {
            queued.reachable = Some(slot);
        }
    }

    async fn job(self: Arc<Self>) {
        loop {
            let fallback_stamp = self.stamp_value;
            let due = {
                let mut interfaces = self.interfaces.write().await;
                let now = tokio::time::Instant::now();
                let mut selected: Option<usize> = None;

                for (index, queued) in interfaces.iter().enumerate() {
                    let due = match queued.entry.last_announced {
                        Some(at) => now - at > queued.entry.announce_interval,
                        None => true,
                    };
                    if due {
                        // announce the most overdue interface
                        let candidate_last = queued.entry.last_announced;
                        let better = match selected {
                            None => true,
                            Some(current) => {
                                let other = interfaces[current].entry.last_announced;
                                candidate_last < other
                            }
                        };
                        if better {
                            selected = Some(index);
                        }
                    }
                }

                selected.map(|index| {
                    interfaces[index].entry.last_announced = Some(now);
                    let mut info = interfaces[index].entry.info.clone();
                    if let Some(slot) = &interfaces[index].reachable {
                        let host = slot
                            .read()
                            .ok()
                            .and_then(|guard| guard.clone())
                            .filter(|host| !host.is_empty());
                        info.reachable_on = host;
                    }
                    (
                        info,
                        interfaces[index].encrypt_to.clone(),
                        interfaces[index]
                            .entry
                            .stamp_value
                            .unwrap_or(fallback_stamp),
                    )
                })
            };

            let Some((info, encrypt_to, stamp_value)) = due else {
                // Nothing due: poll again after the interval.
                tokio::time::sleep(self.interval).await;
                continue;
            };

            match build_discovery_payload_for_identity(&info, stamp_value, encrypt_to.as_ref()) {
                Some(payload) => {
                    log::debug!(
                        "reticulum-rs discovery: announcing interface {} ({} bytes)",
                        info.name.as_deref().unwrap_or(&info.interface_type),
                        payload.len()
                    );
                    self.transport
                        .send_announce(&self.destination, Some(&payload))
                        .await;
                }
                None => log::error!("discovery: could not generate announce payload"),
            }
        }
    }
}

/// Which discovered peers `connect_discovered` will dial.
/// The default matches Python: `BackboneInterface` from `RNS` >= 1.5.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoconnectPolicy {
    pub types: Vec<String>,
    pub implementations: Vec<String>,
    pub min_version: String,
    /// Skip the implementation and version checks
    /// (Python `autoconnect_unverified_implementations`).
    pub allow_unverified: bool,
}

impl Default for AutoconnectPolicy {
    fn default() -> Self {
        Self {
            types: vec!["BackboneInterface".to_string()],
            implementations: vec![IMPLEMENTATION_NAME.to_string()],
            min_version: "1.5.2".to_string(),
            allow_unverified: false,
        }
    }
}

impl AutoconnectPolicy {
    pub fn allows(&self, info: &InterfaceInfo) -> bool {
        if !self.types.iter().any(|kind| kind == &info.interface_type) {
            return false;
        }
        if self.allow_unverified {
            return true;
        }
        let Some(name) = info
            .transport_impl
            .as_deref()
            .filter(|name| !name.is_empty())
        else {
            return false;
        };
        if !self
            .implementations
            .iter()
            .any(|implementation| implementation == name)
        {
            return false;
        }
        match (
            info.transport_vers.as_deref().and_then(version_tuple),
            version_tuple(&self.min_version),
        ) {
            (Some(version), Some(min)) => version >= min,
            _ => false,
        }
    }
}

/// Settings applied to an interface spawned by
/// [`InterfaceDiscovery::connect_discovered_with`]. `None` leaves the
/// constructor value in place, which is what
/// [`InterfaceDiscovery::connect_discovered`] does.
#[derive(Debug, Clone, Copy, Default)]
pub struct AutoconnectAttach {
    pub mode: Option<reticulum::iface::InterfaceMode>,
    pub gravity: Option<i64>,
    pub announces_to_internal: Option<bool>,
    pub bitrate: Option<u64>,
    pub announce_rate_target: Option<Duration>,
    pub announce_rate_grace: Option<u32>,
    pub announce_rate_penalty: Option<Duration>,
}

/// Optional discovery listener settings. [`InterfaceDiscovery::start`]
/// uses [`Default`].
#[derive(Default)]
pub struct DiscoveryOptions {
    pub policy: AutoconnectPolicy,
    pub storage_path: Option<PathBuf>,
    pub network_identity: Option<PrivateIdentity>,
}

/// The interface discovery listener: validates announces, keeps the
/// discovered table, and optionally auto-connects (Python `InterfaceDiscovery`).
pub struct InterfaceDiscovery {
    transport: Arc<Transport>,
    required_value: u32,
    discovered: RwLock<Vec<DiscoveredInterface>>,
    autoconnect: RwLock<bool>,
    max_autoconnected: RwLock<usize>,
    /// Empty means every announcer is accepted
    /// (Python `interface_discovery_sources`).
    allowed_sources: RwLock<Vec<AddressHash>>,
    policy: RwLock<AutoconnectPolicy>,
    storage_path: RwLock<Option<PathBuf>>,
    network_identity: RwLock<Option<PrivateIdentity>>,
    connected: RwLock<HashSet<Hash>>,
}

impl InterfaceDiscovery {
    /// Start listening for discovery announces on the transport.
    pub async fn start(
        transport: &Arc<Transport>,
        required_value: u32,
        autoconnect: bool,
    ) -> Arc<Self> {
        Self::start_with(
            transport,
            required_value,
            autoconnect,
            DiscoveryOptions::default(),
        )
        .await
    }

    /// Start listening with a storage directory, network identity, or
    /// autoconnect policy.
    pub async fn start_with(
        transport: &Arc<Transport>,
        required_value: u32,
        autoconnect: bool,
        options: DiscoveryOptions,
    ) -> Arc<Self> {
        let discovered = options
            .storage_path
            .as_deref()
            .map(load_entries)
            .unwrap_or_default();
        let discovery = Arc::new(Self {
            transport: transport.clone(),
            required_value,
            discovered: RwLock::new(discovered),
            autoconnect: RwLock::new(autoconnect),
            max_autoconnected: RwLock::new(8),
            allowed_sources: RwLock::new(Vec::new()),
            policy: RwLock::new(options.policy),
            storage_path: RwLock::new(options.storage_path),
            network_identity: RwLock::new(options.network_identity),
            connected: RwLock::new(HashSet::new()),
        });

        let runner = discovery.clone();
        tokio::spawn(async move { runner.listen().await });

        discovery
    }

    pub async fn set_autoconnect_policy(&self, policy: AutoconnectPolicy) {
        *self.policy.write().await = policy;
    }

    /// Cap on simultaneously auto-connected peers. The default is 8.
    /// Python `autoconnect_discovered_interfaces` is this maximum.
    pub async fn set_max_autoconnected(&self, max: usize) {
        *self.max_autoconnected.write().await = max;
    }

    /// Allow-list of announcer identity hashes. Empty accepts every source.
    pub async fn set_interface_sources(&self, sources: Vec<AddressHash>) {
        *self.allowed_sources.write().await = sources;
    }

    /// Identity used to decrypt announces with [`FLAG_ENCRYPTED`] set.
    pub async fn set_network_identity(&self, identity: PrivateIdentity) {
        *self.network_identity.write().await = Some(identity);
    }

    /// Persist discovered interfaces under `{path}/discovery/interfaces`.
    pub async fn set_storage_path(&self, path: PathBuf) {
        let loaded = load_entries(&path);
        let mut table = self.discovered.write().await;
        for entry in loaded {
            let id = discovery_file_id(&entry.info);
            if table
                .iter()
                .all(|existing| discovery_file_id(&existing.info) != id)
            {
                table.push(entry);
            }
        }
        drop(table);
        *self.storage_path.write().await = Some(path);
    }

    async fn listen(self: Arc<Self>) {
        let mut announces = self
            .transport
            .subscribe_announces("rnstransport", &["discovery.interface"])
            .await;

        loop {
            let Ok(event) = announces.recv().await else {
                return;
            };

            let payload = event.app_data.as_slice().to_vec();
            if payload.is_empty() {
                continue;
            }

            let (network_id, announcer, address_hash) = {
                let destination = event.destination.lock().await;
                (
                    Hash::new_from_slice(destination.desc.identity.to_bytes().as_slice()),
                    destination.desc.identity.address_hash,
                    destination.desc.address_hash,
                )
            };

            {
                let allowed = self.allowed_sources.read().await;
                if !allowed.is_empty() && !allowed.contains(&announcer) {
                    log::debug!("discovery: ignoring announce from a non-authorized identity");
                    continue;
                }
            }

            let hops = self
                .transport
                .hops_to(&address_hash)
                .await
                .unwrap_or(u8::MAX);

            let identity = self.network_identity.read().await.clone();
            let Some((mut info, value)) = validate_discovery_payload_for_identity(
                &payload,
                self.required_value,
                identity.as_ref(),
            ) else {
                log::debug!("discovery: ignoring announce with insufficient stamp value");
                continue;
            };

            info.ifac_netname = cleaned_ifac(&info.ifac_netname);
            info.ifac_netkey = cleaned_ifac(&info.ifac_netkey);
            info.name = Some(display_name(&info));
            if !RETAINED_TYPES.contains(&info.interface_type.as_str()) {
                continue;
            }

            {
                let blackholes = self.transport.blackholes();
                let blackholes = blackholes.read().await;
                if blackholes.is_blackholed(&announcer)
                    || blackholes.is_blackholed(&info.transport_id)
                {
                    log::debug!("discovery: ignoring announce from a blackholed identity");
                    continue;
                }
            }

            let file_id = discovery_file_id(&info);
            let mut table = self.discovered.write().await;
            let stored = match table
                .iter_mut()
                .find(|entry| discovery_file_id(&entry.info) == file_id)
            {
                Some(entry) => {
                    let discovered_at = entry.discovered;
                    let discovered_unix = entry
                        .recorded_unix
                        .map(|(at, _)| at)
                        .unwrap_or_else(unix_now);
                    let heard_count = entry.heard_count + 1;
                    entry.info = info;
                    entry.network_id = network_id;
                    entry.value = value;
                    entry.hops = hops;
                    entry.discovered = discovered_at;
                    entry.last_heard = tokio::time::Instant::now();
                    entry.recorded_unix = Some((discovered_unix, unix_now()));
                    entry.heard_count = heard_count;
                    entry.clone()
                }
                None => {
                    log::debug!(
                        "discovery: discovered {} (stamp value {value})",
                        info.name.as_deref().unwrap_or(&info.interface_type)
                    );
                    let now = tokio::time::Instant::now();
                    let now_unix = unix_now();
                    let entry = DiscoveredInterface {
                        info,
                        network_id,
                        value,
                        hops,
                        discovered: now,
                        last_heard: now,
                        heard_count: 0,
                        recorded_unix: Some((now_unix, now_unix)),
                    };
                    table.push(entry.clone());
                    entry
                }
            };
            drop(table);
            if let Some(storage) = self.storage_path.read().await.clone() {
                persist_entry(&storage, &stored);
            }
        }
    }

    /// Snapshot of the discovered interfaces (Python
    /// `list_discovered_interfaces`), expired entries removed.
    pub async fn list(&self) -> Vec<DiscoveredInterface> {
        let storage = self.storage_path.read().await.clone();
        let mut table = self.discovered.write().await;
        let before = table.len();
        let mut removed = Vec::new();
        let blackholes = self.transport.blackholes();
        let blackholes = blackholes.read().await;
        table.retain(|entry| {
            let age = entry.heard_age();
            let host_ok = match entry.info.reachable_on.as_deref() {
                Some(host) => !host.is_empty() && (is_ip_address(host) || is_hostname(host)),
                None => true,
            };
            let keep = age < THRESHOLD_REMOVE
                && host_ok
                && RETAINED_TYPES.contains(&entry.info.interface_type.as_str())
                && !blackholes.is_blackholed(&entry.info.transport_id);
            if !keep {
                removed.push(entry.info.clone());
            }
            keep
        });
        drop(blackholes);
        let dropped = before - table.len();
        if dropped > 0 {
            log::debug!("discovery: removed {dropped} stale discovered interfaces");
        }
        if let Some(storage) = &storage {
            for info in &removed {
                remove_entry_file(storage, info);
            }
        }
        table.sort_by(|a, b| {
            match b.status() {
                DiscoveredStatus::Available => 1000u16,
                DiscoveredStatus::Unknown => 100,
                DiscoveredStatus::Stale => 0,
            }
            .cmp(&match a.status() {
                DiscoveredStatus::Available => 1000,
                DiscoveredStatus::Unknown => 100,
                DiscoveredStatus::Stale => 0,
            })
            .then(b.value.cmp(&a.value))
            .then(a.heard_age().cmp(&b.heard_age()))
        });
        table.clone()
    }

    /// Connect discovered interfaces allowed by the autoconnect policy.
    /// The default policy is backbone-only and refuses peers below
    /// version 1.5.2 or with an implementation name other than `RNS`.
    /// Transport peers that `list` has not removed are dialed, including
    /// unknown and stale ones.
    ///
    /// Spawned interfaces keep their constructor mode, gravity and bitrate.
    /// [`Self::connect_discovered_with`] applies optional attach settings.
    pub async fn connect_discovered(&self) -> usize {
        self.connect_discovered_with(&AutoconnectAttach::default())
            .await
    }

    /// [`Self::connect_discovered`] plus settings Python applies inside
    /// `autoconnect()` (mode, gravity, bitrate, announce rate,
    /// `announces_to_internal`). Fields left `None` are not written.
    pub async fn connect_discovered_with(&self, attach: &AutoconnectAttach) -> usize {
        if !*self.autoconnect.read().await {
            return 0;
        }

        let policy = self.policy.read().await.clone();
        let max = *self.max_autoconnected.read().await;
        let table = self.list().await;
        let mut connected_now = 0;
        let mut endpoints = self.connected.write().await;
        let mut taken = {
            let manager = self.transport.iface_manager();
            let manager = manager.lock().await;
            manager
                .stats()
                .iter()
                .map(|stat| stat.name.clone())
                .collect::<HashSet<_>>()
        };

        for entry in table {
            if endpoints.len() >= max {
                break;
            }
            if !entry.info.transport {
                continue;
            }
            if !policy.allows(&entry.info) {
                let implementation = match (
                    entry.info.transport_impl.as_deref(),
                    entry.info.transport_vers.as_deref(),
                ) {
                    (Some(name), Some(version)) => format!("{name} {version}"),
                    _ => "unknown implementation".to_string(),
                };
                log::debug!(
                    "discovery: not auto-connecting {} ({implementation})",
                    entry
                        .info
                        .name
                        .as_deref()
                        .unwrap_or(&entry.info.interface_type)
                );
                continue;
            }
            if entry.info.interface_type == "I2PInterface" {
                log::debug!(
                    "reticulum-rs discovery: auto-connecting discovered I2P interfaces is not implemented"
                );
                return connected_now;
            }
            let Some(host) = entry.info.reachable_on.clone() else {
                continue;
            };
            let Some(port) = entry.info.port else {
                continue;
            };
            let ipv6 = host.parse::<std::net::Ipv6Addr>().ok();
            // Python `is_ygg_ipv6`: network 200::/7.
            let ygg = ipv6
                .as_ref()
                .is_some_and(|ip| ip.octets()[0] & 0xfe == 0x02);
            if is_invalid_ip_address(&host) || is_onion_address(&host) || ygg {
                log::debug!("discovery: not auto-connecting to {host}");
                continue;
            }

            let endpoint = entry.endpoint_hash();
            let address = if ipv6.is_some() {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            let exists = endpoints.contains(&endpoint) || {
                let manager = self.transport.iface_manager();
                let manager = manager.lock().await;
                manager.stats().iter().any(|stat| {
                    matches!(stat.kind.as_str(), "TcpClient" | "BackboneClient")
                        && (stat.name == address || stat.name.contains(&address))
                })
            };
            if exists {
                continue;
            }

            if !matches!(
                entry.info.interface_type.as_str(),
                "BackboneInterface" | "TCPServerInterface"
            ) {
                continue;
            }
            let interface_name =
                sequential_name(entry.info.name.as_deref().unwrap_or(&address), &taken);
            taken.insert(interface_name.clone());

            let manager = self.transport.iface_manager();
            let mut manager = manager.lock().await;
            let ifac_address = match entry.info.interface_type.as_str() {
                "BackboneInterface" => {
                    manager.spawn(BackboneClient::new(address.clone()), BackboneClient::spawn)
                }
                _ => manager.spawn(TcpClient::new(address.clone()), TcpClient::spawn),
            };
            manager.set_iface_name(&ifac_address, &interface_name);
            let netname = cleaned_ifac(&entry.info.ifac_netname);
            let netkey = cleaned_ifac(&entry.info.ifac_netkey);
            if netname.is_some() || netkey.is_some() {
                let _ = manager.set_iface_ifac(
                    &ifac_address,
                    netname.as_deref(),
                    netkey.as_deref(),
                    16,
                );
            }
            manager.with_control(&ifac_address, |control| {
                if let Some(mode) = attach.mode {
                    control.mode = mode;
                }
                if let Some(gravity) = attach.gravity {
                    control.gravity = gravity;
                }
                if let Some(to_internal) = attach.announces_to_internal {
                    control.announces_to_internal = Some(to_internal);
                }
                if let Some(bitrate) = attach.bitrate {
                    control.bitrate = bitrate;
                }
                if let Some(target) = attach.announce_rate_target {
                    control.announce_rate_target = Some(target);
                    control.announce_rate_grace = Some(attach.announce_rate_grace.unwrap_or(0));
                    control.announce_rate_penalty = attach.announce_rate_penalty;
                }
            });
            drop(manager);

            log::info!("reticulum-rs discovery: auto-connected to {address} as {interface_name}");
            endpoints.insert(endpoint);
            connected_now += 1;
        }

        connected_now
    }

    /// The discovered-interface table length.
    pub async fn discovered_count(&self) -> usize {
        self.discovered.read().await.len()
    }
}

/// Blackhole list updater: links to the
/// `rnstransport.info.blackhole` destinations of configured source
/// identities, requests `/list` and merges the reported identities into
/// the local blackhole table (Python `Discovery.BlackholeUpdater`).
pub struct BlackholeUpdater {
    transport: Arc<Transport>,
    /// Configured source identities (Python `Reticulum.blackhole_sources`,
    /// 16-byte truncated identity hashes).
    sources: RwLock<Vec<reticulum::hash::AddressHash>>,
    /// Update interval (Python `blackhole_update_interval`).
    interval: Duration,
}

/// Python `Destination.hash_from_name_and_identity` for a source known
/// only by its truncated identity hash.
struct SourceIdentity(reticulum::hash::AddressHash);

impl reticulum::identity::HashIdentity for SourceIdentity {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl BlackholeUpdater {
    pub async fn start(
        transport: &Arc<Transport>,
        sources: Vec<reticulum::hash::AddressHash>,
        interval: Duration,
    ) -> Arc<Self> {
        let updater = Arc::new(Self {
            transport: transport.clone(),
            sources: RwLock::new(sources),
            interval,
        });

        let runner = updater.clone();
        tokio::spawn(async move { runner.job().await });

        updater
    }

    async fn job(self: Arc<Self>) {
        // Python `BlackholeUpdater.INITIAL_WAIT` (20s) before the first round.
        tokio::time::sleep(Duration::from_secs(20)).await;

        loop {
            let sources = self.sources.read().await.clone();
            for source in sources {
                let name =
                    reticulum::destination::DestinationName::new("rnstransport", "info.blackhole");
                let destination_hash = name.address_hash_for(&SourceIdentity(source));

                if !self
                    .transport
                    .await_path(&destination_hash, Some(Duration::from_secs(25)), None)
                    .await
                {
                    log::debug!(
                        "blackhole updater: no path available for source {source}, retrying later"
                    );
                    continue;
                }

                let Some(identity) = self.transport.recall(&destination_hash).await else {
                    log::debug!("blackhole updater: no known path for source {source}");
                    continue;
                };

                let desc = reticulum::destination::DestinationDesc {
                    identity,
                    address_hash: destination_hash,
                    name,
                };

                if let Err(error) = self.update_from(desc).await {
                    log::debug!("blackhole updater: {error:?}");
                }
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    async fn update_from(
        &self,
        desc: reticulum::destination::DestinationDesc,
    ) -> Result<(), reticulum::error::RnsError> {
        let publisher = desc.identity.address_hash;

        // Subscribe BEFORE creating the link: the activation event can
        // fire (and be dropped by the broadcast channel) before a
        // subscription created afterwards exists.
        let mut events = self.transport.out_link_events();
        let link = self.transport.link(desc).await;

        // Wait for activation.
        let activated = tokio::time::timeout(Duration::from_secs(10), events.recv()).await;
        match activated {
            Ok(Ok(_)) => {}
            _ => {
                let _ = self.transport.link_close(*link.lock().await.id()).await;
                return Err(reticulum::error::RnsError::LinkNotReady);
            }
        }

        let rid = self.transport.request(&link, "/list", &[]).await?;
        let response = self
            .transport
            .await_request_response(rid, Duration::from_secs(10))
            .await;

        let _ = self.transport.link_close(*link.lock().await.id()).await;

        let Some(response) = response else {
            return Err(reticulum::error::RnsError::LinkNotReady);
        };

        let own = self.transport.identity_hash().await;
        let blackholes = self.transport.blackholes();
        let added = blackholes
            .write()
            .await
            .merge_table(&response, publisher, own);

        if added > 0 {
            log::debug!("blackhole updater: merged {added} blackholed identities");

            // Persist the fetched list under the publisher's identity so a
            // restart restores it (Python `Discovery.BlackholeUpdater`
            // writes `blackhole/<hex identity>` with the raw response,
            // only when new entries were added).
            self.transport
                .persist_blackhole_source(&publisher, &response)
                .await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod addr_tests {
    #[test]
    fn ip_and_hostname_checks() {
        assert!(super::is_ip_address("127.0.0.1"));
        assert!(super::is_ip_address("::1"));
        assert!(!super::is_ip_address("node.example"));
        assert!(super::is_hostname("node.example"));
        assert!(!super::is_hostname("127.0.0.1"));
        assert!(!super::is_hostname("bad_host")); // underscore invalid
        assert!(super::is_onion_address("abc123.onion"));
        assert!(super::is_invalid_ip_address("127.0.0.1"));
        assert!(!super::is_invalid_ip_address("10.0.0.1"));
        assert!("200::1"
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.octets()[0] & 0xfe == 0x02));
        assert!("201::1"
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.octets()[0] & 0xfe == 0x02));
        assert!(!"2001::1"
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.octets()[0] & 0xfe == 0x02));
        assert!(!"gw.example"
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.octets()[0] & 0xfe == 0x02));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_pack_unpack_roundtrip() {
        let info = InterfaceInfo {
            interface_type: "TCPServerInterface".to_string(),
            transport: true,
            transport_id: AddressHash::new_from_slice(&[7u8; 16]),
            name: Some("node".to_string()),
            latitude: Some(55.5),
            longitude: Some(12.5),
            height: None,
            reachable_on: Some("127.0.0.1".to_string()),
            port: Some(4434),
            frequency: Some(868_000_000),
            bandwidth: Some(125_000),
            spreadingfactor: Some(9),
            codingrate: Some("5/6".to_string()),
            channel: None,
            modulation: Some("lora".to_string()),
            ifac_netname: None,
            ifac_netkey: None,
            transport_impl: None,
            transport_vers: None,
            operator_lxmf_address: None,
        };

        let packed = info.pack();
        let unpacked = InterfaceInfo::unpack(&packed).expect("unpack");
        assert_eq!(unpacked.interface_type, info.interface_type);
        assert_eq!(unpacked.port, Some(4434));
        assert_eq!(unpacked.reachable_on.as_deref(), Some("127.0.0.1"));
        assert_eq!(unpacked.name.as_deref(), Some("node"));
        assert_eq!(unpacked.transport_impl.as_deref(), Some("RNS"));
        assert_eq!(unpacked.transport_vers.as_deref(), Some("1.5.5"));
        // Radio fields are not part of a TCP server announce.
        assert_eq!(unpacked.frequency, None);
        assert_eq!(unpacked.modulation, None);
    }

    fn blank(interface_type: &str) -> InterfaceInfo {
        InterfaceInfo {
            interface_type: interface_type.to_string(),
            transport: true,
            transport_id: AddressHash::new([0x11; 16]),
            name: Some("node".to_string()),
            latitude: None,
            longitude: None,
            height: None,
            reachable_on: None,
            port: None,
            frequency: None,
            bandwidth: None,
            spreadingfactor: None,
            codingrate: None,
            channel: None,
            modulation: None,
            ifac_netname: None,
            ifac_netkey: None,
            transport_impl: None,
            transport_vers: None,
            operator_lxmf_address: None,
        }
    }

    #[test]
    fn tcp_client_is_packed_as_kiss() {
        let mut kiss = blank("KISSInterface");
        kiss.frequency = Some(145_000_000);
        kiss.bandwidth = Some(9_600);
        kiss.modulation = Some("AFSK".to_string());
        let mut client = kiss.clone();
        client.interface_type = "TCPClientInterface".to_string();
        assert_eq!(client.pack(), kiss.pack());
        let unpacked = InterfaceInfo::unpack(&client.pack()).unwrap();
        assert_eq!(unpacked.interface_type, "KISSInterface");
    }

    #[test]
    fn ifac_none_string_is_dropped() {
        let mut info = blank("BackboneInterface");
        info.reachable_on = Some("gw.example".to_string());
        info.port = Some(4242);
        info.ifac_netname = Some(" None \n".to_string());
        info.ifac_netkey = Some("secret".to_string());
        let unpacked = InterfaceInfo::unpack(&info.pack()).unwrap();
        assert_eq!(unpacked.ifac_netname, None);
        assert_eq!(unpacked.ifac_netkey.as_deref(), Some("secret"));

        info.ifac_netname = Some("Nona".to_string());
        let mut packed = info.pack();
        let pos = packed
            .windows(4)
            .position(|window| window == b"Nona")
            .unwrap();
        packed[pos..pos + 4].copy_from_slice(b"None");
        let unpacked = InterfaceInfo::unpack(&packed).unwrap();
        assert_eq!(unpacked.ifac_netname, None);
    }

    #[test]
    fn autoconnect_policy_matches_python_gate() {
        let policy = AutoconnectPolicy::default();
        let mut info = blank("BackboneInterface");
        info.transport_impl = Some("RNS".to_string());
        info.transport_vers = Some("1.5.2".to_string());
        assert!(policy.allows(&info));
        info.transport_vers = Some("1.5.1".to_string());
        assert!(!policy.allows(&info));
        info.transport_vers = Some("1.6".to_string());
        assert!(policy.allows(&info));
        info.transport_vers = Some("1.5".to_string());
        assert!(!policy.allows(&info));
        info.transport_impl = Some("reticulum-rs".to_string());
        info.transport_vers = Some("1.5.5".to_string());
        assert!(!policy.allows(&info));
        info.transport_impl = Some("RNS".to_string());
        info.interface_type = "TCPServerInterface".to_string();
        assert!(!policy.allows(&info));
        let tcp = AutoconnectPolicy {
            types: vec!["TCPServerInterface".to_string()],
            ..AutoconnectPolicy::default()
        };
        assert!(tcp.allows(&info));
        assert_eq!(version_tuple("1.5.2rc1").as_deref(), Some(&[1, 5, 2][..]));
        assert_eq!(sequential_name("node", &HashSet::new()), "node");
        let taken = HashSet::from(["node".to_string(), "node (2)".to_string()]);
        assert_eq!(sequential_name("node", &taken), "node (3)");
    }

    #[test]
    fn encrypted_flag_roundtrips_only_with_the_network_identity() {
        let mut info = blank("BackboneInterface");
        info.reachable_on = Some("gw.example".to_string());
        info.port = Some(4242);
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let payload = build_discovery_payload_for_identity(&info, 0, Some(&identity)).unwrap();
        assert_eq!(payload[0] & FLAG_ENCRYPTED, FLAG_ENCRYPTED);
        assert!(validate_discovery_payload(&payload, 0).is_none());
        let (unpacked, _) =
            validate_discovery_payload_for_identity(&payload, 0, Some(&identity)).unwrap();
        assert_eq!(unpacked.interface_type, "BackboneInterface");
        assert_eq!(unpacked.port, Some(4242));
        let other = PrivateIdentity::new_from_rand(OsRng);
        assert!(validate_discovery_payload_for_identity(&payload, 0, Some(&other)).is_none());
    }

    #[test]
    fn persisted_record_roundtrips_under_the_discovery_directory() {
        let dir =
            std::env::temp_dir().join(format!("reticulum-rs-discovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut info = blank("RNodeInterface");
        info.frequency = Some(868_000_000);
        info.bandwidth = Some(125_000);
        info.spreadingfactor = Some(8);
        info.codingrate = Some("5".to_string());
        info.ifac_netname = Some("None".to_string());
        let now = tokio::time::Instant::now();
        let heard = unix_now() - (4 * 24 * 60 * 60) as f64;
        let entry = DiscoveredInterface {
            info,
            network_id: Hash::new([0x22; 32]),
            value: 4,
            hops: 1,
            discovered: now,
            last_heard: now,
            heard_count: 0,
            recorded_unix: Some((heard, heard)),
        };
        persist_entry(&dir, &entry);
        let path = discovery_dir(&dir).join(discovery_file_id(&entry.info));
        assert!(path.is_file(), "missing {}", path.display());
        let loaded = load_entries(&dir);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].info.interface_type, "RNodeInterface");
        assert_eq!(loaded[0].info.frequency, Some(868_000_000));
        assert_eq!(loaded[0].info.codingrate.as_deref(), Some("5"));
        assert_eq!(loaded[0].info.ifac_netname, None);
        assert_eq!(loaded[0].value, 4);
        assert_eq!(loaded[0].status(), DiscoveredStatus::Stale);
        assert!(loaded[0].heard_age() < THRESHOLD_REMOVE);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
