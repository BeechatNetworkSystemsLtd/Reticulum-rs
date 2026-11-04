//! AutoInterface, a port of `RNS/Interfaces/AutoInterface.py`:
//! IPv6 link-local multicast peer discovery and direct UDP unicast data.
//!
//! * Discovery group address derived from `group_id` (default
//!   `"reticulum"`): `sha256(group_id)` split into 7 groups,
//!   `"ff" + <temporary|permanent> + <scope> + ":0:" + "{:02x}"...` -
//!   see [`mcast_discovery_address`].
//! * Discovery port 29716 (`DEFAULT_DISCOVERY_PORT`); unicast discovery
//!   on `discovery_port + 1`; data on `DEFAULT_DATA_PORT` 42671.
//! * Peer beacons are `sha256(group_id || link_local_address_string)`
//!   sent to the multicast group every `ANNOUNCE_INTERVAL` (1.6s) plus
//!   reverse-unicast beacons every `reverse_peering_interval` (~5.2s);
//!   received beacons are authenticated by recomputing the token over the
//!   *source address string* (`discovery_handler`).
//! * Data path is direct UDP unicast to the peer's link-local address on
//!   the data port (`AutoInterfacePeer`), with the Python `mif_deque`
//!   duplicate suppression for peers reachable over several interfaces.
//!
//! Local IPv6 addresses come from `/proc/net/if_inet6` on Linux and
//! Android, `getifaddrs` on Apple and the BSDs, and `GetAdaptersAddresses`
//! on Windows. Adoption and peer timing do not depend on that source.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::buffer::InputBuffer;
use crate::buffer::OutputBuffer;
use crate::hash::Hash;
use crate::iface::RxMessage;
use crate::packet::Packet;
use crate::serde::Serialize;

use super::Interface;
use super::InterfaceContext;
use super::InterfaceManager;

/// `AutoInterface.DEFAULT_DISCOVERY_PORT`
pub const DEFAULT_DISCOVERY_PORT: u16 = 29716;
/// `AutoInterface.DEFAULT_DATA_PORT`
pub const DEFAULT_DATA_PORT: u16 = 42671;
/// `AutoInterface.DEFAULT_GROUP_ID`
pub const DEFAULT_GROUP_ID: &str = "reticulum";

/// `AutoInterface.HW_MTU`
pub const HW_MTU: usize = 1196;

/// `AutoInterface.PEERING_TIMEOUT`
pub const PEERING_TIMEOUT: Duration = Duration::from_secs(22);
/// `AutoInterface.ANNOUNCE_INTERVAL`
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_millis(1600);
/// `AutoInterface.PEER_JOB_INTERVAL`
pub const PEER_JOB_INTERVAL: Duration = Duration::from_secs(4);
/// `AutoInterface.MCAST_ECHO_TIMEOUT`
pub const MCAST_ECHO_TIMEOUT: Duration = Duration::from_millis(6500);

/// `AutoInterface.MULTI_IF_DEQUE_LEN`
const MULTI_IF_DEQUE_LEN: usize = 48;
/// `AutoInterface.MULTI_IF_DEQUE_TTL`
const MULTI_IF_DEQUE_TTL: Duration = Duration::from_millis(750);

/// Interface names never adopted (`AutoInterface.ALL_IGNORE_IFS`)
const ALL_IGNORE_IFS: &[&str] = &["lo0"];

/// Skipped on Apple unless listed in `devices` (`DARWIN_IGNORE_IFS`).
#[cfg(any(target_vendor = "apple", test))]
const DARWIN_IGNORE_IFS: &[&str] = &["awdl0", "llw0", "lo0", "en5"];

/// Skipped on Android unless listed in `devices` (`ANDROID_IGNORE_IFS`).
#[cfg(any(target_os = "android", test))]
const ANDROID_IGNORE_IFS: &[&str] = &[
    "dummy0", "lo", "tun0", "rmnet0", "rmnet1", "rmnet2", "rmnet3", "rmnet4", "rmnet5", "rmnet6",
    "rmnet7",
];

/// `discovery_scope` configuration (`AutoInterface.SCOPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiscoveryScope {
    #[default]
    Link,
    Admin,
    Site,
    Organisation,
    Global,
}

impl DiscoveryScope {
    fn id(self) -> char {
        match self {
            Self::Link => '2',
            Self::Admin => '4',
            Self::Site => '5',
            Self::Organisation => '8',
            Self::Global => 'e',
        }
    }

    /// Parse a configuration value like Python's constructor.
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "admin" => Self::Admin,
            "site" => Self::Site,
            "organisation" | "organization" => Self::Organisation,
            "global" => Self::Global,
            _ => Self::Link,
        }
    }
}

/// `multicast_address_type` configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MulticastAddressType {
    #[default]
    Temporary,
    Permanent,
}

impl MulticastAddressType {
    fn id(self) -> char {
        match self {
            Self::Temporary => '1',
            Self::Permanent => '0',
        }
    }

    /// Parse a configuration value like Python's constructor.
    pub fn parse(value: &str) -> Self {
        match value.to_lowercase().as_str() {
            "permanent" => Self::Permanent,
            _ => Self::Temporary,
        }
    }
}

/// Derive the multicast discovery address for a `group_id` exactly like
/// `AutoInterface.__init__`:
///
/// ```text
/// g  = sha256(group_id)
/// gt = "0" + 7x ":" + "{:02x}".format(g[i+1] + (g[i] << 8)) for i in 0,2,..12
/// mcast_discovery_address = "ff" + type + scope + ":" + gt
/// ```
pub fn mcast_discovery_address(
    group_id: &str,
    scope: DiscoveryScope,
    address_type: MulticastAddressType,
) -> String {
    let group_hash = Hash::new_from_slice(group_id.as_bytes()).to_bytes();

    let mut address = String::from("ff");
    address.push(address_type.id());
    address.push(scope.id());
    address.push(':');

    address.push('0');
    // six groups from g[2..14] (Python g[3]+(g[2]<<8), g[5]+(g[4]<<8), ...)
    for i in (2..14).step_by(2) {
        let group = u16::from(group_hash[i + 1]) + (u16::from(group_hash[i]) << 8);
        address.push_str(&format!(":{group:02x}"));
    }

    address
}

/// The discovery/peering token for a link-local address:
/// `sha256(group_id || link_local_address_string)` (`peer_announce`).
pub fn discovery_token(group_id: &str, link_local_addr: &Ipv6Addr) -> [u8; 32] {
    let mut data = Vec::with_capacity(group_id.len() + 46);
    data.extend_from_slice(group_id.as_bytes());
    data.extend_from_slice(link_local_addr.to_string().as_bytes());

    Hash::new_from_slice(&data).to_bytes()
}

/// Verify a received discovery datagram against its source address
/// (`discovery_handler`): the first `HASHLENGTH/8` bytes must equal the
/// token computed over `group_id` and the source address string.
pub fn verify_discovery_token(group_id: &str, src: &Ipv6Addr, data: &[u8]) -> bool {
    if data.len() < 32 {
        return false;
    }

    discovery_token(group_id, src) == data[..32]
}

/// A kernel interface with an adopted IPv6 link-local address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLocalIface {
    pub name: String,
    pub ifindex: u32,
    pub link_local: Ipv6Addr,
}

/// Enumerate suitable interfaces with IPv6 link-local addresses.
///
/// Reads the platform address list and keeps the last `fe80::` address of
/// each interface (Python overwrites `adopted_interfaces[ifname]`), honouring
/// `devices`, `ignored_devices`, and `adopt`.
pub fn suitable_interfaces(
    devices: &[String],
    ignored_devices: &[String],
    adopt: Option<Ipv6Addr>,
) -> Vec<LinkLocalIface> {
    select_interfaces(&platform_addresses(), devices, ignored_devices, adopt).adopted
}

/// Parse the 32 hexadecimal characters of `/proc/net/if_inet6` into an
/// `Ipv6Addr` (yielding the same compressed string form Python gets from
/// `netinfo.ifaddresses`).
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_expanded_ipv6(hex: &str) -> Result<Ipv6Addr, ()> {
    if hex.len() != 32 {
        return Err(());
    }
    let value = u128::from_str_radix(hex, 16).map_err(|_| ())?;
    Ok(Ipv6Addr::from(value.to_be_bytes()))
}

/// One IPv6 address reported by a platform enumerator, before adoption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedAddr {
    pub name: String,
    pub ifindex: u32,
    pub addr: Ipv6Addr,
}

/// Adopted interfaces plus every descoped link-local kept for echo checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedInterfaces {
    pub adopted: Vec<LinkLocalIface>,
    /// Every descoped `fe80::` address, not only the last one per interface.
    pub own_addresses: Vec<Ipv6Addr>,
}

/// Adopt link-locals from `addrs` the way `AutoInterface.__init__` scans
/// `netinfo` output: drop non-`fe80` addresses, descope embedded zone ids,
/// apply ignore and allow lists, and keep the last address on each interface.
pub fn select_interfaces(
    addrs: &[ObservedAddr],
    devices: &[String],
    ignored_devices: &[String],
    adopt: Option<Ipv6Addr>,
) -> SelectedInterfaces {
    select_with_skips(
        addrs,
        devices,
        ignored_devices,
        adopt,
        platform_skip_unless_allowed(),
    )
}

fn select_with_skips(
    addrs: &[ObservedAddr],
    devices: &[String],
    ignored_devices: &[String],
    adopt: Option<Ipv6Addr>,
    skip_unless_allowed: &[&str],
) -> SelectedInterfaces {
    let mut order: Vec<&str> = Vec::new();
    for addr in addrs {
        if !order.contains(&addr.name.as_str()) {
            order.push(addr.name.as_str());
        }
    }

    let mut adopted = Vec::new();
    let mut own_addresses = Vec::new();
    for name in order {
        let allowed = devices.iter().any(|device| device == name);
        if ALL_IGNORE_IFS.contains(&name)
            || ignored_devices.iter().any(|item| item == name)
            || (skip_unless_allowed.contains(&name) && !allowed)
            || (!devices.is_empty() && !allowed)
        {
            continue;
        }

        let mut chosen: Option<LinkLocalIface> = None;
        for addr in addrs.iter().filter(|addr| addr.name == name) {
            let Some(link_local) = descope_linklocal(addr.addr) else {
                continue;
            };
            if let Some(want) = adopt {
                if link_local != want {
                    continue;
                }
            }
            own_addresses.push(link_local);
            chosen = Some(LinkLocalIface {
                name: name.to_string(),
                ifindex: addr.ifindex,
                link_local,
            });
        }
        if let Some(chosen) = chosen {
            adopted.push(chosen);
        }
    }

    if adopt.is_some() && !adopted.is_empty() {
        adopted.truncate(1);
    }

    SelectedInterfaces {
        adopted,
        own_addresses,
    }
}

fn platform_skip_unless_allowed() -> &'static [&'static str] {
    #[cfg(target_vendor = "apple")]
    {
        DARWIN_IGNORE_IFS
    }
    #[cfg(target_os = "android")]
    {
        ANDROID_IGNORE_IFS
    }
    #[cfg(not(any(target_vendor = "apple", target_os = "android")))]
    {
        &[]
    }
}

/// `AutoInterface.descope_linklocal`: rewrite an embedded scope in the
/// second group (`fe80:<scope>::` -> `fe80::`). `None` when the address
/// is not a `fe80::/16` link-local.
fn descope_linklocal(addr: Ipv6Addr) -> Option<Ipv6Addr> {
    let text = addr.to_string();
    if !text.starts_with("fe80:") {
        return None;
    }
    let rest = &text["fe80:".len()..];
    let hex_len = rest
        .bytes()
        .take_while(|byte| byte.is_ascii_hexdigit())
        .count();
    let rewritten = if rest[hex_len..].starts_with("::") {
        let mut out = String::from("fe80::");
        out.push_str(&rest[hex_len + 2..]);
        out
    } else {
        text
    };
    rewritten.parse().ok()
}

fn platform_addresses() -> Vec<ObservedAddr> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_proc_addresses()
    }
    #[cfg(any(
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        apple_addresses()
    }
    #[cfg(windows)]
    {
        windows_addresses()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        windows
    )))]
    {
        Vec::new()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_proc_addresses() -> Vec<ObservedAddr> {
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(proc) => parse_proc_if_inet6(&proc),
        Err(err) => {
            log::warn!("auto: couldn't read /proc/net/if_inet6: {err}");
            Vec::new()
        }
    }
}

/// `/proc/net/if_inet6` rows whose scope is link-local (`0x20`).
/// The interface index column is hexadecimal.
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn parse_proc_if_inet6(proc: &str) -> Vec<ObservedAddr> {
    let mut found = Vec::new();
    for line in proc.lines() {
        let mut fields = line.split_whitespace();
        let (Some(address), Some(ifindex), Some(_prefix), Some(scope), Some(_flags), Some(name)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if scope != "20" {
            continue;
        }
        let Ok(addr) = parse_expanded_ipv6(address) else {
            continue;
        };
        let Ok(ifindex) = u32::from_str_radix(ifindex, 16) else {
            continue;
        };
        found.push(ObservedAddr {
            name: name.to_string(),
            ifindex,
            addr,
        });
    }
    found
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    test
))]
#[repr(C)]
struct AppleIfAddrs {
    ifa_next: *mut AppleIfAddrs,
    ifa_name: *mut std::ffi::c_char,
    ifa_flags: u32,
    ifa_addr: *mut AppleSockAddr,
    ifa_netmask: *mut AppleSockAddr,
    ifa_dstaddr: *mut AppleSockAddr,
    ifa_data: *mut std::ffi::c_void,
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    test
))]
#[repr(C)]
struct AppleSockAddr {
    sa_len: u8,
    sa_family: u8,
    sa_data: [u8; 14],
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    test
))]
#[repr(C)]
struct AppleSockAddrIn6 {
    sin6_len: u8,
    sin6_family: u8,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    windows,
    test
))]
fn ipv6_family() -> i32 {
    i32::from(socket2::Domain::IPV6)
}

/// Walk a `getifaddrs` list. `index_of` is `if_nametoindex`.
/// The `sa_len` sockaddr matches Apple, FreeBSD, NetBSD, and OpenBSD.
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    test
))]
fn collect_apple(
    mut cur: *mut AppleIfAddrs,
    mut index_of: impl FnMut(*const std::ffi::c_char) -> u32,
) -> Vec<ObservedAddr> {
    let mut found = Vec::new();
    while !cur.is_null() {
        // SAFETY: `cur` is the head of a live getifaddrs (or test) list.
        unsafe {
            let ifa = &*cur;
            if !ifa.ifa_addr.is_null() && !ifa.ifa_name.is_null() {
                let family = i32::from((*ifa.ifa_addr).sa_family);
                if family == ipv6_family() {
                    let in6 = &*(ifa.ifa_addr as *const AppleSockAddrIn6);
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .into_owned();
                    found.push(ObservedAddr {
                        name,
                        ifindex: index_of(ifa.ifa_name),
                        addr: Ipv6Addr::from(in6.sin6_addr),
                    });
                }
            }
            cur = ifa.ifa_next;
        }
    }
    found
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
fn apple_addresses() -> Vec<ObservedAddr> {
    extern "C" {
        fn getifaddrs(ifap: *mut *mut AppleIfAddrs) -> i32;
        fn freeifaddrs(ifa: *mut AppleIfAddrs);
        fn if_nametoindex(name: *const std::ffi::c_char) -> u32;
    }

    // SAFETY: getifaddrs writes a list that freeifaddrs releases.
    unsafe {
        let mut head: *mut AppleIfAddrs = std::ptr::null_mut();
        if getifaddrs(&mut head) != 0 {
            log::warn!(
                "auto: getifaddrs failed: {}",
                std::io::Error::last_os_error()
            );
            return Vec::new();
        }
        let found = collect_apple(head, |name| if_nametoindex(name));
        freeifaddrs(head);
        found
    }
}

#[cfg(any(windows, test))]
#[repr(C)]
struct WinAdapter {
    length: u32,
    if_index: u32,
    next: *mut WinAdapter,
    adapter_name: *mut std::ffi::c_char,
    first_unicast: *mut WinUnicast,
}

#[cfg(any(windows, test))]
#[repr(C)]
struct WinUnicast {
    length: u32,
    flags: u32,
    next: *mut WinUnicast,
    address: WinSocketAddress,
}

#[cfg(any(windows, test))]
#[repr(C)]
struct WinSocketAddress {
    sockaddr: *mut WinSockAddr,
    length: i32,
}

#[cfg(any(windows, test))]
#[repr(C)]
struct WinSockAddr {
    family: u16,
    data: [u8; 14],
}

#[cfg(any(windows, test))]
#[repr(C)]
struct WinSockAddrIn6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    addr: [u8; 16],
    scope_id: u32,
}

/// Walk a `GetAdaptersAddresses` list. Adapter names are the GUID strings
/// Python stores (`AdapterName`), and the index is `IfIndex`.
#[cfg(any(windows, test))]
fn collect_windows(mut cur: *mut WinAdapter) -> Vec<ObservedAddr> {
    let mut found = Vec::new();
    while !cur.is_null() {
        // SAFETY: `cur` points at a live adapter list (or a test list).
        unsafe {
            let adapter = &*cur;
            if !adapter.adapter_name.is_null() {
                let name = std::ffi::CStr::from_ptr(adapter.adapter_name)
                    .to_string_lossy()
                    .into_owned();
                let mut uni = adapter.first_unicast;
                while !uni.is_null() {
                    let entry = &*uni;
                    let sock = entry.address.sockaddr;
                    if !sock.is_null() && i32::from((*sock).family) == ipv6_family() {
                        let in6 = &*(sock as *const WinSockAddrIn6);
                        found.push(ObservedAddr {
                            name: name.clone(),
                            ifindex: adapter.if_index,
                            addr: Ipv6Addr::from(in6.addr),
                        });
                    }
                    uni = entry.next;
                }
            }
            cur = adapter.next;
        }
    }
    found
}

#[cfg(windows)]
fn windows_addresses() -> Vec<ObservedAddr> {
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *const core::ffi::c_void,
            adapters: *mut u8,
            size: *mut u32,
        ) -> u32;
    }

    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let mut size: u32 = 15 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..8 {
        buf.resize(size.div_ceil(8) as usize + 1, 0);
        // SAFETY: `buf` is writable and 8-aligned for the adapter structs.
        let rc = unsafe {
            GetAdaptersAddresses(
                0,
                0,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut u8,
                &mut size,
            )
        };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != 0 {
            log::warn!("auto: GetAdaptersAddresses failed: {rc}");
            return Vec::new();
        }
        return collect_windows(buf.as_mut_ptr() as *mut WinAdapter);
    }
    log::warn!("auto: GetAdaptersAddresses buffer stayed too small");
    Vec::new()
}

/// Outcome of a verified discovery beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// Source is one of our own link-locals.
    Echo,
    /// Known peer; `last_heard` was updated.
    Refresh,
    /// Not one of our addresses and not yet tracked.
    New,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedPeer {
    ifname: String,
    last_heard: Instant,
    last_outbound: Instant,
}

/// Peer timing shared by the socket loop and tests that feed a fake address list.
#[derive(Debug, Clone)]
pub struct DiscoveryState {
    own_addresses: Vec<Ipv6Addr>,
    peers: HashMap<Ipv6Addr, TrackedPeer>,
}

impl DiscoveryState {
    pub fn new(own_addresses: Vec<Ipv6Addr>) -> Self {
        Self {
            own_addresses,
            peers: HashMap::new(),
        }
    }

    /// Classify a beacon whose token already matched `src`.
    pub fn observe(&mut self, src: Ipv6Addr, now: Instant) -> DiscoveryEvent {
        if self.own_addresses.contains(&src) {
            return DiscoveryEvent::Echo;
        }
        if let Some(peer) = self.peers.get_mut(&src) {
            peer.last_heard = now;
            return DiscoveryEvent::Refresh;
        }
        DiscoveryEvent::New
    }

    pub fn insert(&mut self, addr: Ipv6Addr, ifname: impl Into<String>, now: Instant) {
        let ifname = ifname.into();
        self.peers.insert(
            addr,
            TrackedPeer {
                ifname,
                last_heard: now,
                last_outbound: now,
            },
        );
    }

    /// Peers with `now > last_heard + timeout` (Python's strict `>`).
    pub fn expire(&mut self, now: Instant, timeout: Duration) -> Vec<(Ipv6Addr, String)> {
        let stale: Vec<Ipv6Addr> = self
            .peers
            .iter()
            .filter(|(_, peer)| now > peer.last_heard + timeout)
            .map(|(addr, _)| *addr)
            .collect();
        let mut removed = Vec::with_capacity(stale.len());
        for addr in stale {
            if let Some(peer) = self.peers.remove(&addr) {
                removed.push((addr, peer.ifname));
            }
        }
        removed
    }

    /// Peers due a reverse unicast beacon. Updates `last_outbound`.
    pub fn take_reverse(&mut self, now: Instant, interval: Duration) -> Vec<(Ipv6Addr, String)> {
        let mut due = Vec::new();
        for (addr, peer) in self.peers.iter_mut() {
            if now > peer.last_outbound + interval {
                peer.last_outbound = now;
                due.push((*addr, peer.ifname.clone()));
            }
        }
        due
    }
}

/// Duplicate suppression for data arriving over several interfaces
/// (`mif_deque` / `mif_deque_times` in `AutoInterfacePeer.process_incoming`).
#[derive(Debug, Default)]
struct MultiIfDeque {
    entries: VecDeque<(Hash, tokio::time::Instant)>,
}

impl MultiIfDeque {
    /// Returns `true` when the data is new (and records it).
    fn check(&mut self, data: &[u8]) -> bool {
        let hash = Hash::new_from_slice(data);
        let now = tokio::time::Instant::now();

        let hit = self
            .entries
            .iter()
            .any(|(entry, time)| *entry == hash && now < *time + MULTI_IF_DEQUE_TTL);

        if hit {
            return false;
        }

        self.entries.push_back((hash, now));
        while self.entries.len() > MULTI_IF_DEQUE_LEN {
            self.entries.pop_front();
        }

        true
    }
}

/// AutoInterface configuration (Python constructor options).
#[derive(Debug, Clone)]
pub struct AutoInterfaceConfig {
    pub group_id: String,
    pub discovery_port: u16,
    pub data_port: u16,
    pub discovery_scope: DiscoveryScope,
    pub multicast_address_type: MulticastAddressType,
    /// Allow-list of interface names (`devices`); empty adopts every
    /// suitable interface.
    pub devices: Vec<String>,
    /// Deny-list of interface names (`ignored_devices`).
    pub ignored_devices: Vec<String>,
    /// Restrict to one specific link-local address (test hook for hosts
    /// with several `fe80::` addresses on one interface).
    pub adopt: Option<Ipv6Addr>,
}

impl Default for AutoInterfaceConfig {
    fn default() -> Self {
        Self {
            group_id: DEFAULT_GROUP_ID.to_string(),
            discovery_port: DEFAULT_DISCOVERY_PORT,
            data_port: DEFAULT_DATA_PORT,
            discovery_scope: DiscoveryScope::default(),
            multicast_address_type: MulticastAddressType::default(),
            devices: Vec::new(),
            ignored_devices: Vec::new(),
            adopt: None,
        }
    }
}

impl AutoInterfaceConfig {
    pub fn new(group_id: impl Into<String>) -> Self {
        Self {
            group_id: group_id.into(),
            ..Self::default()
        }
    }

    pub fn discovery_address(&self) -> String {
        mcast_discovery_address(
            &self.group_id,
            self.discovery_scope,
            self.multicast_address_type,
        )
    }

    pub fn unicast_discovery_port(&self) -> u16 {
        self.discovery_port + 1
    }
}

enum AutoEvent {
    Discovery {
        data: Vec<u8>,
        src: SocketAddrV6,
        ifname: String,
    },
    Data {
        data: Vec<u8>,
        src: SocketAddrV6,
    },
}

struct PeerEntry {
    address: super::AddressHash,
    data_tx: mpsc::Sender<Vec<u8>>,
}

/// One peered remote AutoInterface (`AutoInterfacePeer`): sends datagrams
/// directly to the peer's link-local data port and receives its datagrams
/// through the parent data sockets.
pub struct AutoPeer {
    peer_addr: SocketAddrV6,
    socket: Arc<UdpSocket>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl AutoPeer {
    pub fn new(
        peer_addr: SocketAddrV6,
        socket: Arc<UdpSocket>,
        data_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            peer_addr,
            socket,
            data_rx: Some(data_rx),
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let iface_stop = context.channel.stop.clone();
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let channel_ifac = context.channel.ifac.clone();

        let peer_addr = context.inner.lock().unwrap().peer_addr;
        let socket = context.inner.lock().unwrap().socket.clone();

        let (rx_channel, mut tx_channel) = context.channel.split();

        let mut data_rx = context
            .inner
            .lock()
            .unwrap()
            .data_rx
            .take()
            .expect("auto peer data channel already consumed");

        stats.set_online(true);

        loop {
            enum Event {
                Tx(Box<super::TxMessage>),
                Rx(Vec<u8>),
            }

            let event = tokio::select! {
                _ = context.cancel.cancelled() => break,
                _ = iface_stop.cancelled() => break,
                message = tx_channel.recv() => match message {
                    Some(message) => Event::Tx(Box::new(message)),
                    None => break,
                },
                datagram = data_rx.recv() => match datagram {
                    Some(datagram) => Event::Rx(datagram),
                    None => break,
                },
            };

            match event {
                Event::Tx(message) => {
                    let packet = message.packet;
                    let mut buffer = [0u8; 2048];
                    let mut output = OutputBuffer::new(&mut buffer[..]);
                    if packet.serialize(&mut output).is_ok() {
                        let ifac = channel_ifac.read().expect("ifac lock").clone();
                        let wire = crate::iface::ifac::encode(output.as_slice(), ifac.as_deref());
                        if socket.send_to(&wire, peer_addr).await.is_ok() {
                            stats.count_tx(wire.len());
                        }
                    }
                }
                Event::Rx(datagram) => {
                    let plain = {
                        let ifac = channel_ifac.read().expect("ifac lock").clone();
                        match crate::iface::ifac::decode_inbound(
                            &datagram,
                            ifac.as_deref(),
                            Some(&stats),
                        ) {
                            Some(plain) => plain,
                            None => {
                                log::debug!(
                                    "auto_interface: dropping packet with invalid access code"
                                );
                                continue;
                            }
                        }
                    };
                    match Packet::deserialize(&mut InputBuffer::new(&plain[..])) {
                        Ok(packet) => {
                            stats.count_rx(datagram.len());
                            let _ = rx_channel
                                .send(RxMessage {
                                    address: iface_address,
                                    packet: Box::new(packet),
                                })
                                .await;
                        }
                        Err(_) => log::debug!("auto: couldn't decode packet from {peer_addr}"),
                    }
                }
            }
        }

        stats.set_online(false);
        iface_stop.cancel();
    }
}

impl Interface for AutoPeer {
    fn mtu() -> usize {
        HW_MTU
    }
}

/// The AutoInterface itself: discovery sockets, beacon job and peer
/// management. Spawned into the [`InterfaceManager`] for statistics; the
/// actual data interfaces are [`AutoPeer`]s spawned per discovered peer.
pub struct AutoInterface {
    config: AutoInterfaceConfig,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl AutoInterface {
    pub fn new(
        config: AutoInterfaceConfig,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            config,
            iface_manager,
        }
    }

    pub fn config(&self) -> &AutoInterfaceConfig {
        &self.config
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let cancel = context.cancel.clone();
        let iface_stop = context.channel.stop.clone();
        let exited = context.channel.exited.clone();
        let stats = context.channel.stats.clone();

        let config = context.inner.lock().unwrap().config.clone();
        let iface_manager = context.inner.lock().unwrap().iface_manager.clone();

        // The parent AutoInterface's access code: all traffic is carried by
        // spawned AutoPeer interfaces, so each peer must inherit it or the
        // configured networkname/passphrase protection silently applies to
        // nothing (Python AutoPeer copies the parent's ifac_* attributes).
        let parent_ifac = context.channel.ifac.read().expect("ifac lock").clone();
        let parent = context.channel.address;

        // The AutoInterface itself never carries data (Python
        // `process_outgoing` is a pass); drain manager tx messages, peers
        // are separate interfaces.
        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));
        let drain_stop = iface_stop.clone();
        let drain_task = tokio::spawn(async move {
            loop {
                let mut tx_channel = tx_channel.lock().await;
                tokio::select! {
                    _ = drain_stop.cancelled() => break,
                    message = tx_channel.recv() => match message {
                        Some(_) => {}
                        None => break,
                    },
                }
            }
        });
        let mut rx_tasks = Vec::new();
        let mut beacon_tasks = Vec::new();

        let selected = select_interfaces(
            &platform_addresses(),
            &config.devices,
            &config.ignored_devices,
            config.adopt,
        );
        let ifaces = selected.adopted;

        if ifaces.is_empty() {
            log::warn!(
                "auto: could not autoconfigure, no suitable interfaces with IPv6 link-local addresses"
            );
            drain_task.abort();
            let _ = exited.send(true);
            return;
        }

        let discovery_address: Ipv6Addr = config
            .discovery_address()
            .parse()
            .expect("valid multicast discovery address");

        let mut discovery = DiscoveryState::new(selected.own_addresses);
        let mut peers: HashMap<Ipv6Addr, PeerEntry> = HashMap::new();
        let mut mif_deque = MultiIfDeque::default();

        let (event_tx, mut event_rx) = mpsc::channel::<AutoEvent>(64);

        let mut beacon_sockets: Vec<(String, u32, Arc<UdpSocket>)> = Vec::new();

        for iface in &ifaces {
            log::info!(
                "auto: selecting link-local address {} for interface {}",
                iface.link_local,
                iface.name
            );

            let scope = SocketAddrV6::new(iface.link_local, 0, 0, iface.ifindex);

            // multicast discovery socket bound to the group address
            // (Python binds mcast_discovery_address%ifname:discovery_port;
            // Windows binds the unspecified address)
            let mcast_bind = if cfg!(windows) {
                SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, config.discovery_port, 0, 0)
            } else {
                SocketAddrV6::new(
                    discovery_address,
                    config.discovery_port,
                    0,
                    if config.discovery_scope == DiscoveryScope::Link {
                        iface.ifindex
                    } else {
                        0
                    },
                )
            };
            let mcast_socket =
                match udp6_bind(&mcast_bind, true, Some((discovery_address, iface.ifindex))) {
                    Ok(socket) => socket,
                    Err(err) => {
                        log::warn!(
                            "auto: couldn't bind multicast discovery socket on {}: {err}",
                            iface.name
                        );
                        continue;
                    }
                };

            rx_tasks.push(spawn_rx_loop(
                cancel.clone(),
                iface_stop.clone(),
                mcast_socket,
                iface.name.clone(),
                AutoLoopKind::Discovery,
                event_tx.clone(),
            ));

            // unicast discovery socket on discovery_port + 1
            // (Windows binds the unspecified address; see AutoInterface.py)
            let unicast_bind = if cfg!(windows) {
                SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, config.unicast_discovery_port(), 0, 0)
            } else {
                SocketAddrV6::new(
                    iface.link_local,
                    config.unicast_discovery_port(),
                    0,
                    iface.ifindex,
                )
            };
            match udp6_bind(&unicast_bind, false, None) {
                Ok(socket) => {
                    rx_tasks.push(spawn_rx_loop(
                        cancel.clone(),
                        iface_stop.clone(),
                        socket,
                        iface.name.clone(),
                        AutoLoopKind::Discovery,
                        event_tx.clone(),
                    ));
                }
                Err(err) => {
                    log::warn!(
                        "auto: couldn't bind unicast discovery socket on {}: {err}",
                        iface.name
                    );
                }
            }

            // data socket on the data port
            let data_bind = SocketAddrV6::new(iface.link_local, config.data_port, 0, iface.ifindex);
            match udp6_bind(&data_bind, false, None) {
                Ok(socket) => {
                    rx_tasks.push(spawn_rx_loop(
                        cancel.clone(),
                        iface_stop.clone(),
                        socket,
                        iface.name.clone(),
                        AutoLoopKind::Data,
                        event_tx.clone(),
                    ));
                }
                Err(err) => {
                    log::warn!("auto: couldn't bind data socket on {}: {err}", iface.name);
                }
            }

            // shared outbound socket for beacons and peer data
            let beacon_socket = match udp6_bind(&scope, false, None) {
                Ok(socket) => socket,
                Err(err) => {
                    log::warn!(
                        "auto: couldn't bind outbound socket on {}: {err}",
                        iface.name
                    );
                    continue;
                }
            };
            set_multicast_if(&beacon_socket, iface.ifindex);
            beacon_sockets.push((iface.name.clone(), iface.ifindex, beacon_socket));
        }

        if beacon_sockets.is_empty() {
            log::warn!("auto: could not configure any interface");
            drain_task.abort();
            for task in rx_tasks {
                task.abort();
                let _ = task.await;
            }
            let _ = exited.send(true);
            return;
        }

        // peer beacons: hash this interface's adopted link-local at send
        // time. Index is not a key: Windows IfIndex is 0 for every
        // IPv6-only adapter.
        for (ifname, ifindex, socket) in &beacon_sockets {
            let cancel = cancel.clone();
            let iface_stop = iface_stop.clone();
            let Some(link_local) = ifaces
                .iter()
                .find(|iface| iface.name == *ifname)
                .map(|iface| iface.link_local)
            else {
                continue;
            };
            let group_id = config.group_id.clone();
            let socket = socket.clone();
            let destination =
                SocketAddrV6::new(discovery_address, config.discovery_port, 0, *ifindex);

            beacon_tasks.push(tokio::spawn(async move {
                loop {
                    let token = discovery_token(&group_id, &link_local);
                    let _ = socket.send_to(&token, destination).await;

                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = iface_stop.cancelled() => break,
                        _ = tokio::time::sleep(ANNOUNCE_INTERVAL) => {}
                    }
                }
            }));
        }

        let reverse_peering_interval =
            Duration::from_secs_f64(ANNOUNCE_INTERVAL.as_secs_f64() * 3.25);

        // Parked outside `select!`. A sleep built inside the select is
        // dropped whenever a beacon arrives, so the 4s job would never run.
        let mut peer_jobs = peer_job_interval();
        peer_jobs.tick().await;

        stats.set_online(true);
        log::info!(
            "auto: discovering peers for {:.2} seconds...",
            ANNOUNCE_INTERVAL.as_secs_f64() * 1.2
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = iface_stop.cancelled() => break,

                event = event_rx.recv() => {
                    let Some(event) = event else { break };

                    match event {
                        AutoEvent::Discovery { data, src, ifname } => {
                            if verify_discovery_token(&config.group_id, src.ip(), &data) {
                                let src_addr = *src.ip();
                                let now = Instant::now();
                                match discovery.observe(src_addr, now) {
                                    DiscoveryEvent::Echo => {
                                        log::debug!("auto: multicast echo on {ifname}");
                                    }
                                    DiscoveryEvent::Refresh => {}
                                    DiscoveryEvent::New => {
                                        if Self::add_peer(
                                            &config,
                                            &iface_manager,
                                            &beacon_sockets,
                                            &mut peers,
                                            src_addr,
                                            &ifname,
                                            parent,
                                            &parent_ifac,
                                        )
                                        .await
                                        {
                                            discovery.insert(src_addr, ifname, now);
                                        }
                                    }
                                }
                            } else {
                                log::debug!(
                                    "auto: received peering packet on {ifname} from {}, but authentication hash was incorrect",
                                    src.ip()
                                );
                            }
                        }
                        AutoEvent::Data { data, src } => {
                            let src_addr = *src.ip();

                            if let Some(peer) = peers.get(&src_addr) {
                                if mif_deque.check(&data) {
                                    discovery.observe(src_addr, Instant::now());
                                    let _ = peer.data_tx.send(data).await;
                                }
                            }
                        }
                    }
                }

                _ = peer_jobs.tick() => {
                    let now = Instant::now();

                    for (addr, ifname) in discovery.expire(now, peering_timeout()) {
                        if let Some(peer) = peers.remove(&addr) {
                            log::debug!("auto: removed peer {addr} on {ifname}");
                            iface_manager.lock().await.stop_iface(&peer.address);
                        }
                    }

                    // reverse peering packets (reverse_announce): our own
                    // discovery token, unicast to the peer
                    for (addr, ifname) in discovery.take_reverse(now, reverse_peering_interval) {
                        let Some(link_local) = ifaces
                            .iter()
                            .find(|iface| iface.name == ifname)
                            .map(|iface| iface.link_local)
                        else {
                            continue;
                        };
                        let Some((_, ifindex, socket)) = beacon_sockets
                            .iter()
                            .find(|(name, _, _)| *name == ifname)
                        else {
                            continue;
                        };
                        let token = discovery_token(&config.group_id, &link_local);
                        let destination = SocketAddrV6::new(
                            addr,
                            config.unicast_discovery_port(),
                            0,
                            *ifindex,
                        );
                        let _ = socket.send_to(&token, destination).await;
                    }
                }
            }
        }

        stats.set_online(false);
        for (_, peer) in peers.drain() {
            iface_manager.lock().await.stop_iface(&peer.address);
        }

        drain_task.abort();
        for task in beacon_tasks {
            task.abort();
            let _ = task.await;
        }
        for task in rx_tasks {
            task.abort();
            let _ = task.await;
        }
        drop(beacon_sockets);
        let _ = exited.send(true);
    }

    // Args mirror the spawn-loop state it mutates; a struct would just rename them.
    #[allow(clippy::too_many_arguments)]
    async fn add_peer(
        config: &AutoInterfaceConfig,
        iface_manager: &Arc<tokio::sync::Mutex<InterfaceManager>>,
        beacon_sockets: &[(String, u32, Arc<UdpSocket>)],
        peers: &mut HashMap<Ipv6Addr, PeerEntry>,
        addr: Ipv6Addr,
        ifname: &str,
        parent: crate::hash::AddressHash,
        parent_ifac: &Option<Arc<crate::iface::ifac::IfacKey>>,
    ) -> bool {
        let Some((_, ifindex, socket)) = beacon_sockets.iter().find(|(name, _, _)| name == ifname)
        else {
            return false;
        };

        let peer_addr = SocketAddrV6::new(addr, config.data_port, 0, *ifindex);

        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);

        let peer = AutoPeer::new(peer_addr, socket.clone(), data_rx);

        let name = format!("AutoPeer[{ifname}/{addr}]");
        let mut manager = iface_manager.lock().await;
        let peer_context = manager.open_named(name, peer);
        if let Some(key) = parent_ifac.clone() {
            *peer_context.channel.ifac.write().expect("ifac lock") = Some(key);
        }
        let address = peer_context.channel.address;
        manager.copy_spawned_control(&parent, &address);
        manager.note_spawned(&parent, &address);
        manager.launch(peer_context, AutoPeer::spawn);
        drop(manager);

        peers.insert(addr, PeerEntry { address, data_tx });

        log::debug!("auto: added peer {addr} on {ifname}");
        true
    }
}

/// Peer-job clock. The first tick completes immediately; callers skip it.
/// Other `select!` branches cannot restart this wait.
fn peer_job_interval() -> tokio::time::Interval {
    let mut jobs = tokio::time::interval(PEER_JOB_INTERVAL);
    jobs.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    jobs
}

fn peering_timeout() -> Duration {
    #[cfg(target_os = "android")]
    {
        Duration::from_secs_f64(PEERING_TIMEOUT.as_secs_f64() * 1.25)
    }
    #[cfg(not(target_os = "android"))]
    {
        PEERING_TIMEOUT
    }
}

impl Interface for AutoInterface {
    fn mtu() -> usize {
        HW_MTU
    }
}

enum AutoLoopKind {
    Discovery,
    Data,
}

fn spawn_rx_loop(
    cancel: tokio_util::sync::CancellationToken,
    stop: tokio_util::sync::CancellationToken,
    socket: Arc<UdpSocket>,
    ifname: String,
    kind: AutoLoopKind,
    event_tx: mpsc::Sender<AutoEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; HW_MTU + 128];

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = stop.cancelled() => break,
                result = socket.recv_from(&mut buffer) => match result {
                    Ok((size, SocketAddr::V6(src))) => {
                        let event = match kind {
                            AutoLoopKind::Discovery => AutoEvent::Discovery {
                                data: buffer[..size].to_vec(),
                                src,
                                ifname: ifname.clone(),
                            },
                            AutoLoopKind::Data => AutoEvent::Data {
                                data: buffer[..size].to_vec(),
                                src,
                            },
                        };

                        if event_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        log::debug!("auto: socket error on {ifname}: {err}");
                        break;
                    }
                }
            }
        }
    })
}

/// Create a tokio UDP socket bound to `addr` (IPv6), optionally joining a
/// multicast group on `interface` first.
fn udp6_bind(
    addr: &SocketAddrV6,
    reuse_port: bool,
    join: Option<(Ipv6Addr, u32)>,
) -> Result<Arc<UdpSocket>, std::io::Error> {
    use socket2::{Domain, Protocol, SockAddr, Socket as RawSocket, Type};

    let socket = RawSocket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    socket.set_nonblocking(true)?;

    socket.bind(&SockAddr::from(*addr))?;

    if let Some((group, ifindex)) = join {
        socket.join_multicast_v6(&group, ifindex)?;
    }

    let socket: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(socket)?;

    Ok(Arc::new(socket))
}

/// Set `IPV6_MULTICAST_IF` on a tokio socket (beacon transmissions).
fn set_multicast_if(socket: &UdpSocket, ifindex: u32) {
    use socket2::SockRef;

    if let Err(err) = SockRef::from(socket).set_multicast_if_v6(ifindex) {
        log::warn!("auto: couldn't set multicast interface {ifindex}: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcast_address_matches_python_reference() {
        // Python AutoInterface with group "reticulum" (defaults):
        //   ff12:0:d70b:fb1c:16e4:5e39:485e:31e1
        assert_eq!(
            mcast_discovery_address(
                "reticulum",
                DiscoveryScope::Link,
                MulticastAddressType::Temporary
            ),
            "ff12:0:d70b:fb1c:16e4:5e39:485e:31e1"
        );

        // group "rstest":
        //   ff12:0:5113:b862:4c6f:e1fa:8d3c:c5f6
        assert_eq!(
            mcast_discovery_address(
                "rstest",
                DiscoveryScope::Link,
                MulticastAddressType::Temporary
            ),
            "ff12:0:5113:b862:4c6f:e1fa:8d3c:c5f6"
        );

        // permanent/site scope: ff05:0:5113:b862:4c6f:e1fa:8d3c:c5f6
        assert_eq!(
            mcast_discovery_address(
                "rstest",
                DiscoveryScope::Site,
                MulticastAddressType::Permanent
            ),
            "ff05:0:5113:b862:4c6f:e1fa:8d3c:c5f6"
        );
    }

    #[test]
    fn discovery_token_matches_python_reference() {
        // Python: RNS.Identity.full_hash(b"reticulum"+b"fe80::1")
        let expected: [u8; 32] = [
            0x97, 0xb2, 0x55, 0x76, 0x74, 0x9e, 0xa9, 0x36, 0xb0, 0xd8, 0xa8, 0x53, 0x6f, 0xfa,
            0xf4, 0x42, 0xd1, 0x57, 0xcf, 0x47, 0xd4, 0x60, 0xdc, 0xf1, 0x3c, 0x48, 0xb7, 0xbd,
            0x18, 0xb6, 0xc1, 0x63,
        ];
        let addr: Ipv6Addr = "fe80::1".parse().unwrap();
        assert_eq!(discovery_token("reticulum", &addr), expected);

        // Python: RNS.Identity.full_hash(b"rstest"+b"fe80::2")
        let expected: [u8; 32] = [
            0x50, 0x3c, 0x85, 0x3b, 0xdf, 0x31, 0xda, 0xc7, 0xda, 0x54, 0xfa, 0x3f, 0xec, 0x30,
            0x88, 0x82, 0x1d, 0x63, 0xda, 0x08, 0x6e, 0x0b, 0x88, 0xa6, 0xba, 0xa5, 0x22, 0x78,
            0xcd, 0x79, 0x74, 0x0d,
        ];
        let addr: Ipv6Addr = "fe80::2".parse().unwrap();
        assert_eq!(discovery_token("rstest", &addr), expected);
    }

    #[test]
    fn verify_token_rejects_forged_beacons() {
        let addr: Ipv6Addr = "fe80::42".parse().unwrap();
        let token = discovery_token("reticulum", &addr);

        assert!(verify_discovery_token("reticulum", &addr, &token));
        // wrong source address
        let other: Ipv6Addr = "fe80::43".parse().unwrap();
        assert!(!verify_discovery_token("reticulum", &other, &token));
        // wrong group id
        assert!(!verify_discovery_token("other", &addr, &token));
        // short data
        assert!(!verify_discovery_token("reticulum", &addr, &token[..16]));
    }

    #[test]
    fn parse_expanded_ipv6_from_proc() {
        let addr = parse_expanded_ipv6("fe800000000000000000000000000001").unwrap();
        assert_eq!(addr.to_string(), "fe80::1");

        assert!(parse_expanded_ipv6("fe8000000000000000000000000000").is_err());
    }

    #[test]
    fn mif_deque_suppresses_duplicates() {
        let mut deque = MultiIfDeque::default();

        assert!(deque.check(b"packet"));
        assert!(!deque.check(b"packet"));
        assert!(deque.check(b"other"));
        assert!(!deque.check(b"other"));
    }

    fn obs(name: &str, ifindex: u32, addr: &str) -> ObservedAddr {
        ObservedAddr {
            name: name.to_string(),
            ifindex,
            addr: addr.parse().unwrap(),
        }
    }

    #[test]
    fn proc_rows_keep_link_scope_and_hex_index() {
        let rows = "\
fe80000000000000000000000000000a 0a 40 20 80 eth0
20010db8000000000000000000000001 0a 40 00 00 eth0
fe800000000000000000000000000001 01 40 20 80 lo
not-a-row
";
        let found = parse_proc_if_inet6(rows);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].name, "eth0");
        assert_eq!(found[0].ifindex, 0x0a);
        assert_eq!(found[0].addr, "fe80::a".parse::<Ipv6Addr>().unwrap());
        assert_eq!(found[1].name, "lo");
    }

    #[test]
    fn select_fake_addresses_matches_python_scan() {
        let addrs = vec![
            obs("lo0", 1, "fe80::1"),
            obs("eth0", 2, "2001:db8::1"),
            obs("eth0", 2, "fe80::10"),
            obs("eth0", 2, "fe80::11"),
            obs("eth1", 3, "fe80:4::5"),
            obs("wlan0", 4, "fe80::30"),
        ];
        let selected = select_interfaces(&addrs, &[], &["wlan0".into()], None);
        let names: Vec<_> = selected
            .adopted
            .iter()
            .map(|iface| iface.name.as_str())
            .collect();
        assert_eq!(names, vec!["eth0", "eth1"]);
        assert_eq!(
            selected.adopted[0].link_local,
            "fe80::11".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            selected.adopted[1].link_local,
            "fe80::5".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            selected.own_addresses,
            vec![
                "fe80::10".parse::<Ipv6Addr>().unwrap(),
                "fe80::11".parse::<Ipv6Addr>().unwrap(),
                "fe80::5".parse::<Ipv6Addr>().unwrap(),
            ]
        );

        let allowed = select_interfaces(&addrs, &["eth1".into()], &[], None);
        assert_eq!(allowed.adopted.len(), 1);
        assert_eq!(allowed.adopted[0].name, "eth1");

        let adopted = select_interfaces(&addrs, &[], &[], Some("fe80::10".parse().unwrap()));
        assert_eq!(adopted.adopted.len(), 1);
        assert_eq!(
            adopted.adopted[0].link_local,
            "fe80::10".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            adopted.own_addresses,
            vec!["fe80::10".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn platform_ignore_lists_yield_unless_allowed() {
        let addrs = vec![
            obs("awdl0", 1, "fe80::1"),
            obs("en0", 2, "fe80::2"),
            obs("lo0", 3, "fe80::3"),
            obs("lo", 4, "fe80::4"),
        ];
        let darwin = select_with_skips(&addrs, &[], &[], None, DARWIN_IGNORE_IFS);
        assert_eq!(
            darwin
                .adopted
                .iter()
                .map(|iface| iface.name.as_str())
                .collect::<Vec<_>>(),
            vec!["en0", "lo"]
        );
        let allowed = select_with_skips(&addrs, &["awdl0".into()], &[], None, DARWIN_IGNORE_IFS);
        assert!(allowed.adopted.iter().any(|iface| iface.name == "awdl0"));
        assert!(allowed.adopted.iter().all(|iface| iface.name != "lo0"));

        let android = select_with_skips(&addrs, &[], &[], None, ANDROID_IGNORE_IFS);
        assert!(android.adopted.iter().all(|iface| iface.name != "lo"));
        let android_lo = select_with_skips(&addrs, &["lo".into()], &[], None, ANDROID_IGNORE_IFS);
        assert!(android_lo.adopted.iter().any(|iface| iface.name == "lo"));
    }

    #[test]
    fn discovery_state_machine_with_fake_source() {
        let addrs = vec![obs("eth0", 2, "fe80::10"), obs("eth0", 2, "fe80::11")];
        let selected = select_interfaces(&addrs, &["eth0".into()], &[], None);
        let mut state = DiscoveryState::new(selected.own_addresses);
        let start = Instant::now();
        let own = selected.adopted[0].link_local;
        assert_eq!(state.observe(own, start), DiscoveryEvent::Echo);
        // secondary address is still ours, not a peer
        assert_eq!(
            state.observe("fe80::10".parse().unwrap(), start),
            DiscoveryEvent::Echo
        );

        let peer: Ipv6Addr = "fe80::99".parse().unwrap();
        assert_eq!(state.observe(peer, start), DiscoveryEvent::New);
        state.insert(peer, "eth0", start);
        let heard = start + Duration::from_secs(1);
        assert_eq!(state.observe(peer, heard), DiscoveryEvent::Refresh);

        let interval = Duration::from_secs_f64(ANNOUNCE_INTERVAL.as_secs_f64() * 3.25);
        assert!(state.take_reverse(start + interval, interval).is_empty());
        let due = state.take_reverse(start + interval + Duration::from_nanos(1), interval);
        assert_eq!(due, vec![(peer, "eth0".to_string())]);
        assert!(state
            .take_reverse(start + interval + Duration::from_nanos(1), interval)
            .is_empty());

        assert!(state
            .expire(heard + PEERING_TIMEOUT, PEERING_TIMEOUT)
            .is_empty());
        let removed = state.expire(
            heard + PEERING_TIMEOUT + Duration::from_nanos(1),
            PEERING_TIMEOUT,
        );
        assert_eq!(removed, vec![(peer, "eth0".to_string())]);
        assert_eq!(state.observe(peer, heard), DiscoveryEvent::New);
    }

    #[tokio::test(start_paused = true)]
    async fn reverse_beacon_becomes_due_while_events_arrive() {
        let mut jobs = peer_job_interval();
        jobs.tick().await;

        let peer: Ipv6Addr = "fe80::99".parse().unwrap();
        let started = Instant::now();
        let mut state = DiscoveryState::new(vec!["fe80::1".parse().unwrap()]);
        state.insert(peer, "eth0", started);

        let (tx, mut rx) = mpsc::channel::<()>(8);
        let feeder = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if tx.send(()).await.is_err() {
                    break;
                }
            }
        });

        let reverse_after = Duration::from_secs_f64(ANNOUNCE_INTERVAL.as_secs_f64() * 3.25);
        let clock = tokio::time::Instant::now();
        let mut due = Vec::new();
        let mut events = 0u32;
        for _ in 0..40 {
            tokio::select! {
                event = rx.recv() => {
                    if event.is_none() {
                        break;
                    }
                    events += 1;
                    state.observe(peer, started + clock.elapsed());
                }
                _ = jobs.tick() => {
                    due = state.take_reverse(started + clock.elapsed(), reverse_after);
                    if !due.is_empty() {
                        break;
                    }
                }
            }
        }
        feeder.abort();

        assert!(
            events > 4,
            "traffic should arrive more often than the 4s job, got {events}"
        );
        assert_eq!(due, vec![(peer, "eth0".to_string())]);
    }

    #[test]
    fn apple_and_windows_walkers_read_link_locals() {
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut v6 = AppleSockAddrIn6 {
            sin6_len: std::mem::size_of::<AppleSockAddrIn6>() as u8,
            sin6_family: ipv6_family() as u8,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: link_local.octets(),
            sin6_scope_id: 4,
        };
        let mut v4 = AppleSockAddr {
            sa_len: 16,
            sa_family: 2,
            sa_data: [0; 14],
        };
        let en0 = std::ffi::CString::new("en0").unwrap();
        let lo0 = std::ffi::CString::new("lo0").unwrap();
        let mut v4_ifa = AppleIfAddrs {
            ifa_next: std::ptr::null_mut(),
            ifa_name: lo0.as_ptr() as *mut _,
            ifa_flags: 0,
            ifa_addr: &mut v4,
            ifa_netmask: std::ptr::null_mut(),
            ifa_dstaddr: std::ptr::null_mut(),
            ifa_data: std::ptr::null_mut(),
        };
        let mut v6_ifa = AppleIfAddrs {
            ifa_next: &mut v4_ifa,
            ifa_name: en0.as_ptr() as *mut _,
            ifa_flags: 0,
            ifa_addr: &mut v6 as *mut AppleSockAddrIn6 as *mut AppleSockAddr,
            ifa_netmask: std::ptr::null_mut(),
            ifa_dstaddr: std::ptr::null_mut(),
            ifa_data: std::ptr::null_mut(),
        };
        let apple = collect_apple(&mut v6_ifa, |_| 9);
        assert_eq!(apple.len(), 1);
        assert_eq!(apple[0].name, "en0");
        assert_eq!(apple[0].ifindex, 9);
        assert_eq!(apple[0].addr, link_local);

        let mut win_ip = WinSockAddrIn6 {
            family: ipv6_family() as u16,
            port: 0,
            flowinfo: 0,
            addr: link_local.octets(),
            scope_id: 1,
        };
        let mut win_v4 = WinSockAddr {
            family: 2,
            data: [0; 14],
        };
        let guid = std::ffi::CString::new("{GUID}").unwrap();
        let mut v4_uni = WinUnicast {
            length: 0,
            flags: 0,
            next: std::ptr::null_mut(),
            address: WinSocketAddress {
                sockaddr: &mut win_v4,
                length: 16,
            },
        };
        let mut v6_uni = WinUnicast {
            length: 0,
            flags: 0,
            next: &mut v4_uni,
            address: WinSocketAddress {
                sockaddr: &mut win_ip as *mut WinSockAddrIn6 as *mut WinSockAddr,
                length: std::mem::size_of::<WinSockAddrIn6>() as i32,
            },
        };
        let mut adapter = WinAdapter {
            length: 0,
            if_index: 12,
            next: std::ptr::null_mut(),
            adapter_name: guid.as_ptr() as *mut _,
            first_unicast: &mut v6_uni,
        };
        let windows = collect_windows(&mut adapter);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, "{GUID}");
        assert_eq!(windows[0].ifindex, 12);
        assert_eq!(windows[0].addr, link_local);

        // Prefix offsets of IP_ADAPTER_ADDRESSES / ifaddrs, not the tail fields.
        assert_eq!(std::mem::offset_of!(WinAdapter, next), 8);
        assert_eq!(std::mem::offset_of!(WinUnicast, next), 8);
        assert_eq!(std::mem::offset_of!(AppleSockAddrIn6, sin6_addr), 8);
        if cfg!(target_pointer_width = "64") {
            assert_eq!(std::mem::offset_of!(WinAdapter, first_unicast), 24);
            assert_eq!(std::mem::offset_of!(WinUnicast, address), 16);
            assert_eq!(std::mem::offset_of!(AppleIfAddrs, ifa_addr), 24);
        }
    }
}
