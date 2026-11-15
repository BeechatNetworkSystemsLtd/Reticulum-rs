//! `rnstatus` — instance status utility (`RNS/Utilities/rnstatus.py`).
//!
//! The column report ([`collect`] / [`StatusReport::render`]) is the local
//! snapshot used by the integration tests. Operator output for a running
//! daemon comes from [`fetch_status`] over the shared-instance RPC, and
//! from [`remote_status`] over a management link.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::Transport;
use serde::Serialize;

use crate::common::as_f64;

/// Human-readable byte size (Python `RNS.prettysize`).
pub fn pretty_size(num: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
    let mut value = num as f64;
    let mut unit = 0;
    while value.abs() >= 1000.0 && unit < units.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value:.0} {}", units[unit])
    } else {
        format!("{value:.2} {}", units[unit])
    }
}

/// One row of the interface table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IfaceRow {
    pub name: String,
    pub kind: String,
    pub status: &'static str,
    pub mode: &'static str,
    pub bitrate: String,
    pub tx: String,
    pub rx: String,
    /// Announces sent/received (Python 1.5.0 `rnstatus` traffic stats).
    pub announces: String,
    /// Path requests sent/received.
    pub path_requests: String,
    /// Protocol violations / IFAC violations / filter hits.
    pub violations: String,
}

/// Snapshot of everything `rnstatus` displays.
#[derive(Debug, Clone)]
pub struct StatusReport {
    pub instance_name: String,
    pub identity_hash: String,
    /// Inbound queue pressure: total, per-class heights, per-class drops
    /// (Python 1.5.0 `rnstatus` queue pressure statistics).
    pub queue_pressure: (usize, [usize; 4], [u64; 4]),
    pub interfaces: Vec<IfaceRow>,
    pub paths: Vec<crate::rnpath::PathResult>,
    pub link_counts: reticulum::transport::LinkCounts,
    pub transport_enabled: bool,
    /// Shared-instance active link count. `None` for a local report.
    pub active_links: Option<usize>,
}

#[derive(Serialize)]
struct LinkCountsJson {
    link_table: usize,
    inbound: usize,
    outbound: usize,
}

#[derive(Serialize)]
struct StatusJson<'a> {
    instance_name: &'a str,
    transport_id: &'a str,
    interfaces: &'a [IfaceRow],
    paths: Vec<PathEntryJson>,
    link_counts: LinkCountsJson,
}

#[derive(Serialize)]
struct PathEntryJson {
    hash: String,
    hops: u8,
    via: String,
    interface: String,
}

impl StatusReport {
    pub fn render(&self) -> String {
        let mut out = String::new();

        // Interface table, mirroring the Python column set
        // (Name, Status, Mode, Bitrate, TX, RX, ...).
        out.push_str(&format!(
            "{:<34} {:<12} {:<7} {:<8} {:<12} {:<10} {:<10} {:<20} {:<8} {:<16}\n",
            "Name",
            "Type",
            "Status",
            "Mode",
            "Bitrate",
            "TX",
            "RX",
            "Announces",
            "PRs",
            "Violations"
        ));
        out.push_str(&"-".repeat(150));
        out.push('\n');
        for iface in &self.interfaces {
            out.push_str(&format!(
                "{:<34} {:<12} {:<7} {:<8} {:<12} {:<10} {:<10} {:<20} {:<8} {:<16}\n",
                iface.name,
                iface.kind,
                iface.status,
                iface.mode,
                iface.bitrate,
                iface.tx,
                iface.rx,
                iface.announces,
                iface.path_requests,
                iface.violations
            ));
        }
        if self.interfaces.is_empty() {
            out.push_str("(no interfaces)\n");
        }

        out.push_str(&format!(
            "Inbound queue pressure: {} items (data {}, announce {}, PR {}, IL {}), dropped {}\n",
            self.queue_pressure.0,
            self.queue_pressure.1[0],
            self.queue_pressure.1[1],
            self.queue_pressure.1[2],
            self.queue_pressure.1[3],
            self.queue_pressure.2.iter().sum::<u64>(),
        ));

        out.push('\n');
        if self.transport_enabled {
            out.push_str(&format!(
                " Transport Instance {} running\n",
                self.identity_hash
            ));
        } else if self.active_links.is_none() {
            out.push_str(&format!(
                " Standalone instance {} (transport mode disabled)\n",
                self.identity_hash
            ));
        }

        let counts = &self.link_counts;
        let plural = if counts.link_table == 1 { "y" } else { "ies" };
        if let Some(active) = self.active_links {
            out.push_str(&format!(
                " {} entr{} in link table ({} active)\n",
                counts.link_table, plural, active
            ));
        } else {
            out.push_str(&format!(
                " {} entr{} in link table ({} inbound / {} outbound active links)\n",
                counts.link_table, plural, counts.inbound, counts.outbound
            ));
        }

        out.push('\n');
        out.push_str(&format!(" Path table ({} entries):\n", self.paths.len()));
        if self.paths.is_empty() {
            out.push_str("   No information available\n");
        } else {
            out.push_str("  ");
            out.push_str(&crate::rnpath::render_table(&self.paths).replace('\n', "\n  "));
        }
        out
    }

    pub fn to_json(&self) -> String {
        let json = StatusJson {
            instance_name: &self.instance_name,
            transport_id: &self.identity_hash,
            interfaces: &self.interfaces,
            paths: self
                .paths
                .iter()
                .map(|entry| PathEntryJson {
                    hash: crate::common::prettyhexrep(entry.destination.as_slice()),
                    hops: entry.hops,
                    via: crate::common::prettyhexrep(entry.via.as_slice()),
                    interface: entry.on_interface(),
                })
                .collect(),
            link_counts: LinkCountsJson {
                link_table: self.link_counts.link_table,
                inbound: self.link_counts.inbound,
                outbound: self.link_counts.outbound,
            },
        };
        serde_json::to_string_pretty(&json).unwrap_or_default()
    }
}

/// Collect the status report for a local transport.
///
/// `transport_enabled` should reflect whether the instance routes for others
/// (Python only prints "Transport Instance … running" when it does).
pub async fn collect(transport: &Transport, transport_enabled: bool) -> StatusReport {
    let interfaces = crate::common::interface_stats(transport)
        .await
        .into_iter()
        .map(|stats| IfaceRow {
            name: stats.name,
            kind: stats.kind,
            status: if stats.online { "Up" } else { "Down" },
            // Interface modes and configured bitrates are not tracked yet.
            mode: "Full",
            bitrate: "Unknown".to_string(),
            tx: pretty_size(stats.tx_bytes),
            rx: pretty_size(stats.rx_bytes),
            announces: format!(
                "{}/{} ({}/{})",
                stats.announces_sent,
                stats.announces_received,
                pretty_size(stats.announce_bytes_sent),
                pretty_size(stats.announce_bytes_received),
            ),
            path_requests: format!(
                "{}/{}",
                stats.path_requests_sent, stats.path_requests_received
            ),
            violations: format!(
                "{}/{} (filter {})",
                stats.protocol_violations, stats.ifac_violations, stats.packet_filter_hits
            ),
        })
        .collect();

    StatusReport {
        instance_name: transport.instance_name().await,
        identity_hash: crate::common::prettyhexrep(transport.identity_hash().await.as_slice()),
        queue_pressure: transport.inbound_queue_snapshot().await,
        interfaces,
        paths: crate::rnpath::path_table(transport, None, None).await,
        link_counts: transport.link_counts().await,
        transport_enabled,
        active_links: None,
    }
}

/// Status of a reachable shared instance. Callers that required the shared
/// instance use this instead of the local transport snapshot.
pub async fn collect_shared(
    config_dir: &std::path::Path,
    _transport: &Transport,
) -> Result<StatusReport, String> {
    let stats = crate::common::shared_rpc(config_dir, get_request("interface_stats", None)).await?;
    let paths = crate::common::shared_rpc(
        config_dir,
        get_request("path_table", Some(("max_hops", rmpv::Value::Nil))),
    )
    .await?;
    let link_count = crate::common::shared_rpc(config_dir, get_request("link_count", None)).await?;
    let active =
        crate::common::shared_rpc(config_dir, get_request("active_link_count", None)).await?;

    let interfaces = map_field(&stats, "interfaces")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "interface stats are missing interfaces".to_string())?
        .iter()
        .filter_map(iface_row)
        .collect();

    let transport_id = map_field(&stats, "transport_id").and_then(|value| value.as_slice());
    let identity_hash = match transport_id {
        Some(bytes) => crate::common::prettyhexrep(bytes),
        None => String::new(),
    };

    Ok(StatusReport {
        instance_name: String::new(),
        identity_hash,
        queue_pressure: (
            field_usize(&stats, "rxqt"),
            [
                field_usize(&stats, "rxqd"),
                field_usize(&stats, "rxqa"),
                field_usize(&stats, "rxqp"),
                field_usize(&stats, "rxqil"),
            ],
            [
                field_u64(&stats, "rxqdd"),
                field_u64(&stats, "rxqad"),
                field_u64(&stats, "rxqpd"),
                field_u64(&stats, "rxqild"),
            ],
        ),
        interfaces,
        paths: crate::rnpath::paths_from_rpc(&paths)?,
        link_counts: reticulum::transport::LinkCounts {
            link_table: value_usize(&link_count),
            inbound: 0,
            outbound: 0,
        },
        transport_enabled: transport_id.is_some(),
        active_links: Some(value_usize(&active)),
    })
}

fn get_request(path: &str, extra: Option<(&str, rmpv::Value)>) -> rmpv::Value {
    let mut map = vec![(
        rmpv::Value::from("get"),
        rmpv::Value::from(path.to_string()),
    )];
    if let Some((key, value)) = extra {
        map.push((rmpv::Value::from(key), value));
    }
    rmpv::Value::Map(map)
}

fn iface_row(value: &rmpv::Value) -> Option<IfaceRow> {
    let name = field_str(value, "name")?;
    let kind = field_str(value, "type").unwrap_or_default();
    let online = map_field(value, "status").and_then(|item| item.as_bool()) == Some(true);
    let mode = mode_label(field_u64(value, "mode"));
    let bitrate = field_u64(value, "bitrate");
    Some(IfaceRow {
        name,
        kind,
        status: if online { "Up" } else { "Down" },
        mode,
        bitrate: if bitrate == 0 {
            "Unknown".to_string()
        } else {
            bitrate.to_string()
        },
        tx: pretty_size(field_u64(value, "txb")),
        rx: pretty_size(field_u64(value, "rxb")),
        announces: format!(
            "{}/{} ({}/{})",
            field_u64(value, "atxc"),
            field_u64(value, "arxc"),
            pretty_size(field_u64(value, "atxb")),
            pretty_size(field_u64(value, "arxb")),
        ),
        path_requests: format!("{}/{}", field_u64(value, "ptxc"), field_u64(value, "prxc")),
        violations: format!(
            "{}/{} (filter {})",
            field_u64(value, "protocol_violations"),
            field_u64(value, "ifac_violations"),
            field_u64(value, "packet_filter_hits")
        ),
    })
}

fn mode_label(mode: u64) -> &'static str {
    match mode {
        0x02 => "PtP",
        0x03 => "AP",
        0x04 => "Roaming",
        0x05 => "Boundary",
        0x06 => "Gateway",
        0x07 => "Internal",
        _ => "Full",
    }
}

fn map_field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn field_str(value: &rmpv::Value, key: &str) -> Option<String> {
    map_field(value, key).and_then(|item| item.as_str().map(str::to_string))
}

fn field_u64(value: &rmpv::Value, key: &str) -> u64 {
    map_field(value, key).and_then(value_u64).unwrap_or(0)
}

fn field_usize(value: &rmpv::Value, key: &str) -> usize {
    field_u64(value, key) as usize
}

fn value_usize(value: &rmpv::Value) -> usize {
    value_u64(value).unwrap_or(0) as usize
}

fn value_u64(value: &rmpv::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|item| u64::try_from(item).ok()))
}

/// Which parts of a daemon status report to print.
#[derive(Debug, Clone, Default)]
pub struct StatusView {
    pub show_all: bool,
    pub link_stats: bool,
    pub totals: bool,
    pub pps: bool,
    pub queues: bool,
    pub profiling: bool,
    pub discovered_only: bool,
    /// Python `-D` (`config_entries`): the detail view instead of the
    /// `-d` summary table.
    pub config_entries: bool,
    pub show_stale: bool,
    pub show_unknown: bool,
    pub json: bool,
    pub name_filter: Option<String>,
}

/// Status of the shared instance described by `config_dir`.
pub async fn fetch_status(config_dir: &Path, view: &StatusView) -> Result<String, String> {
    let stats = crate::common::shared_rpc(config_dir, get_request("interface_stats", None)).await?;
    if !stats.is_map() {
        return Err("Could not get RNS status".to_string());
    }
    if view.discovered_only {
        return Ok(render_discovered(config_dir, &stats, view).await);
    }
    let (link_count, active) = if view.link_stats {
        let links = crate::common::shared_rpc(config_dir, get_request("link_count", None)).await?;
        let active =
            crate::common::shared_rpc(config_dir, get_request("active_link_count", None)).await?;
        (Some(value_usize(&links)), Some(value_usize(&active)))
    } else {
        (None, None)
    };
    let profiling = if view.profiling {
        Some(crate::common::shared_rpc(config_dir, get_request("profiling_results", None)).await?)
    } else {
        None
    };
    if view.json {
        return Ok(crate::common::msgpack_json(&stats));
    }
    Ok(render_report(
        &stats,
        view,
        link_count,
        active,
        profiling.as_ref(),
    ))
}

/// Attach, detach, or reload one interface (`manage` RPC).
pub async fn manage_interface(
    config_dir: &Path,
    action: &str,
    name: &str,
) -> Result<String, String> {
    let value = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("manage"),
                rmpv::Value::from(format!("{action}_interface")),
            ),
            (
                rmpv::Value::from("name"),
                rmpv::Value::from(name.to_string()),
            ),
        ]),
    )
    .await?;
    let past = match action {
        "attach" => "attached",
        "detach" => "detached",
        "reload" => "reloaded",
        other => other,
    };
    match value.as_bool() {
        Some(true) => Ok(format!("Interface {name} was {past}")),
        Some(false) => Err(format!("Could not {action} interface {name}")),
        None if value.is_nil() => Err(format!("The interface {name} does not exist")),
        None => Err(format!("Unknown error while {action}ing interface {name}")),
    }
}

/// Status of a remote transport over `rnstransport.remote.management`.
pub async fn remote_status(
    transport: &Transport,
    identity_hash: &AddressHash,
    identity: &PrivateIdentity,
    view: &StatusView,
    timeout: Duration,
) -> Result<String, String> {
    let destination =
        crate::rnpath::named_destination("rnstransport", "remote.management", identity_hash);
    let mut payload = Vec::new();
    rmpv::encode::write_value(
        &mut payload,
        &rmpv::Value::Array(vec![
            rmpv::Value::Boolean(view.link_stats),
            rmpv::Value::Boolean(view.profiling),
        ]),
    )
    .map_err(|err| err.to_string())?;
    // JSON is Python `no_output`: the document must not be prefixed by
    // path and link progress lines.
    let bytes = crate::rnpath::remote_exchange(
        transport,
        &destination,
        Some(identity),
        "/status",
        &payload,
        timeout,
        !view.json,
    )
    .await?;
    let mut cursor = bytes.as_slice();
    let value = rmpv::decode::read_value(&mut cursor).map_err(|err| err.to_string())?;
    let (stats, link_count, profiling) = split_remote_status(&value).ok_or_else(|| {
        format!(
            "Could not get RNS status from remote transport instance {}",
            crate::common::prettyhexrep(identity_hash.as_slice())
        )
    })?;
    if view.json {
        return Ok(crate::common::msgpack_json(&stats));
    }
    let link_count = if view.link_stats { link_count } else { None };
    Ok(render_report(
        &stats,
        view,
        link_count,
        None,
        profiling.as_ref(),
    ))
}

fn split_remote_status(
    value: &rmpv::Value,
) -> Option<(rmpv::Value, Option<usize>, Option<rmpv::Value>)> {
    let items = value.as_array()?;
    let stats = match items.first()? {
        item if item.is_map() => item.clone(),
        item if item.as_array().is_some() => {
            rmpv::Value::Map(vec![(rmpv::Value::from("interfaces"), item.clone())])
        }
        _ => return None,
    };
    let link_count = items.get(1).and_then(value_u64).map(|count| count as usize);
    let profiling = items.get(2).cloned().filter(|item| !item.is_nil());
    Some((stats, link_count, profiling))
}

fn render_report(
    stats: &rmpv::Value,
    view: &StatusView,
    link_count: Option<usize>,
    active: Option<usize>,
    profiling: Option<&rmpv::Value>,
) -> String {
    let mut out = String::new();
    if let Some(interfaces) = map_field(stats, "interfaces").and_then(|value| value.as_array()) {
        for iface in interfaces {
            if let Some(block) = render_interface(iface, view) {
                out.push('\n');
                out.push_str(&block);
            }
        }
    }
    let transport_id = map_field(stats, "transport_id").and_then(|value| value.as_slice());
    let lstr = link_summary(link_count, active, transport_id.is_some(), view.link_stats);
    if view.totals {
        out.push_str(&render_totals(stats, view.pps));
    }
    if view.queues {
        out.push_str(&render_queues(stats));
    }
    if let Some(profiling) = profiling
        .filter(|value| value.is_map() && !value.as_map().is_some_and(|rows| rows.is_empty()))
    {
        out.push_str("\n Profiling    :\n");
        out.push_str(&format_profiling(profiling));
    }
    if let Some(bytes) = transport_id {
        out.push_str(&format!(
            "\n Transport Instance {} running\n",
            crate::common::prettyhexrep(bytes)
        ));
        if let Some(network) = map_field(stats, "network_id").and_then(|value| value.as_slice()) {
            out.push_str(&format!(
                " Network Identity   {}\n",
                crate::common::prettyhexrep(network)
            ));
        }
        if let Some(probe) = map_field(stats, "probe_responder").and_then(|value| value.as_slice())
        {
            out.push_str(&format!(
                " Probe responder at {} active\n",
                crate::common::prettyhexrep(probe)
            ));
        }
        if let Some(uptime) = map_field(stats, "transport_uptime").and_then(as_f64) {
            out.push_str(&format!(
                " Uptime is {}{lstr}\n",
                crate::common::pretty_time(uptime)
            ));
        }
    } else if !lstr.is_empty() {
        out.push('\n');
        out.push_str(&lstr);
        out.push('\n');
    }
    out.push('\n');
    out
}

fn link_summary(
    link_count: Option<usize>,
    active: Option<usize>,
    transport: bool,
    enabled: bool,
) -> String {
    if !enabled {
        return String::new();
    }
    let Some(count) = link_count else {
        return String::new();
    };
    let plural = if count == 1 { "y" } else { "ies" };
    let mut text = if transport {
        format!(", {count} entr{plural} in link table")
    } else {
        format!(" {count} entr{plural} in link table")
    };
    if let Some(active) = active.filter(|count| *count > 0) {
        text = format!("{text} ({active} active)");
    }
    text
}

fn render_interface(iface: &rmpv::Value, view: &StatusView) -> Option<String> {
    let name = field_str(iface, "name")?;
    if hidden_interface(&name, iface, view.show_all) {
        return None;
    }
    if let Some(filter) = &view.name_filter {
        if !name.to_lowercase().contains(&filter.to_lowercase()) {
            return None;
        }
    }
    let mut out = format!(" {name}\n");
    out.push_str(&format!("    Status    : {}\n", status_text(iface)));
    if let Some(clients) = clients_line(&name, iface) {
        out.push_str(&format!("    {clients}\n"));
    }
    if show_mode(&name) {
        out.push_str(&format!("    Mode      : {}\n", mode_text(iface)));
    }
    if map_field(iface, "txdrp").is_some_and(truthy) {
        let drops = field_u64(iface, "txdrp");
        out.push_str(&format!(
            "    TX Drops  : {drops} ({})\n",
            pretty_size(field_u64(iface, "txdrb"))
        ));
    }
    if let Some(bitrate) = map_field(iface, "bitrate").filter(|value| !value.is_nil()) {
        let mtu = match map_field(iface, "mtu") {
            Some(value) if !value.is_nil() => display_num(value),
            Some(_) => "None".to_string(),
            None => String::new(),
        };
        if mtu.is_empty() {
            out.push_str(&format!(
                "    Rate      : {}\n",
                speed_str(as_f64(bitrate).unwrap_or(0.0))
            ));
        } else {
            out.push_str(&format!(
                "    Rate      : {}, MTU {mtu}\n",
                speed_str(as_f64(bitrate).unwrap_or(0.0))
            ));
        }
    }
    if let (Some(short), Some(long)) = (
        map_field(iface, "airtime_short"),
        map_field(iface, "airtime_long"),
    ) {
        out.push_str(&format!(
            "    Airtime   : {}% (15s), {}% (1h)\n",
            display_num(short),
            display_num(long)
        ));
    }
    if let (Some(short), Some(long)) = (
        map_field(iface, "channel_load_short"),
        map_field(iface, "channel_load_long"),
    ) {
        out.push_str(&format!(
            "    Ch. Load  : {}% (15s), {}% (1h)\n",
            display_num(short),
            display_num(long)
        ));
    }
    let violations = field_u64(iface, "protocol_violations");
    let ifac = field_u64(iface, "ifac_violations");
    if map_field(iface, "protocol_violations").is_some() && (violations > 0 || ifac > 0) {
        let pv = if violations > 0 {
            format!("{violations} protocol")
        } else {
            String::new()
        };
        let joiner = if violations > 0 && ifac > 0 { ", " } else { "" };
        let iv = if ifac > 0 {
            format!("{ifac} IFAC")
        } else {
            String::new()
        };
        out.push_str(&format!("    Violatns. : {pv}{joiner}{iv}\n"));
    }
    if map_field(iface, "packet_filter_hits").is_some_and(truthy) {
        out.push_str(&format!(
            "    Flt. Hits : {}\n",
            field_u64(iface, "packet_filter_hits")
        ));
    }
    out.push_str(&traffic_lines(iface));
    Some(out)
}

fn status_text(iface: &rmpv::Value) -> String {
    let up = match map_field(iface, "status") {
        Some(value) => match value.as_bool() {
            Some(up) => up,
            None => {
                let text = value.as_str().unwrap_or("");
                text.eq_ignore_ascii_case("online")
                    || text.eq_ignore_ascii_case("up")
                    || text.eq_ignore_ascii_case("true")
            }
        },
        None => false,
    };
    let mut text = if up {
        "Up".to_string()
    } else {
        "Down".to_string()
    };
    if let Some(gravity) = map_field(iface, "gravity").filter(|value| truthy(value)) {
        text.push_str(&format!(", gravity {}", display_num(gravity)));
    }
    text
}

fn clients_line(name: &str, iface: &rmpv::Value) -> Option<String> {
    let clients = map_field(iface, "clients")?;
    if clients.is_nil() {
        return None;
    }
    let count = value_u64(clients).unwrap_or(0);
    if name.starts_with("Shared Instance[") {
        let count = count.saturating_sub(1);
        let spec = if count == 1 { " program" } else { " programs" };
        Some(format!("Serving   : {count}{spec}"))
    } else {
        Some(format!("Clients   : {count}"))
    }
}

fn show_mode(name: &str) -> bool {
    !(name.starts_with("Shared Instance[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("LocalInterface["))
}

fn mode_text(iface: &rmpv::Value) -> String {
    let mut text = match field_u64(iface, "mode") {
        0x02 => "Point-to-Point",
        0x03 => "Access Point",
        0x04 => "Roaming",
        0x05 => "Boundary",
        0x06 => "Gateway",
        0x07 => "Internal",
        _ => "Full",
    }
    .to_string();
    if map_field(iface, "announces_to_internal").and_then(|value| value.as_bool()) == Some(true) {
        text.push_str(" (a>i)");
    }
    text
}

fn hidden_interface(name: &str, iface: &rmpv::Value, show_all: bool) -> bool {
    if show_all {
        return false;
    }
    if name.starts_with("LocalInterface[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("BackboneInterface[Client on")
        || name.starts_with("AutoInterfacePeer[")
        || name.starts_with("WeaveInterfacePeer[")
        || name.starts_with("I2PInterfacePeer[Connected peer")
    {
        return true;
    }
    name.starts_with("I2PInterface[")
        && map_field(iface, "i2p_connectable").and_then(|value| value.as_bool()) == Some(false)
}

fn traffic_lines(iface: &rmpv::Value) -> String {
    let mut tx = format!("↑{}", pretty_size(field_u64(iface, "txb")));
    let mut rx = format!("↓{}", pretty_size(field_u64(iface, "rxb")));
    let width = tx.chars().count().max(rx.chars().count()).max(10);
    pad_to(&mut tx, width);
    pad_to(&mut rx, width);
    if map_field(iface, "rxs").is_some() && map_field(iface, "txs").is_some() {
        tx.push_str(&format!(
            "  {}",
            pretty_speed(field_u64(iface, "txs") as f64)
        ));
        rx.push_str(&format!(
            "  {}",
            pretty_speed(field_u64(iface, "rxs") as f64)
        ));
    }
    if map_field(iface, "txbuffered").is_some_and(truthy) {
        let stalled =
            if map_field(iface, "txstalled").and_then(|value| value.as_bool()) == Some(true) {
                ", stalled"
            } else {
                ""
            };
        tx.push_str(&format!(
            " ({} waiting{stalled})",
            pretty_size(field_u64(iface, "txbuffered"))
        ));
    }
    format!("    Traffic   : {tx}\n                {rx}\n")
}

fn render_totals(stats: &rmpv::Value, pps: bool) -> String {
    let mut tx = format!("↑{}", pretty_size(field_u64(stats, "txb")));
    let mut rx = format!("↓{}", pretty_size(field_u64(stats, "rxb")));
    let width = tx.chars().count().max(rx.chars().count());
    pad_to(&mut tx, width);
    pad_to(&mut rx, width);
    tx.push_str(&format!(
        "  {}",
        pretty_speed(field_u64(stats, "txs") as f64)
    ));
    rx.push_str(&format!(
        "  {}",
        pretty_speed(field_u64(stats, "rxs") as f64)
    ));
    if pps {
        tx.push_str(&format!(
            ", {}",
            pretty_unit(field_u64(stats, "txpps") as f64, "pps")
        ));
        rx.push_str(&format!(
            ", {}",
            pretty_unit(field_u64(stats, "rxpps") as f64, "pps")
        ));
    }
    format!("\n Totals       : {tx}\n                {rx}\n")
}

fn render_queues(stats: &rmpv::Value) -> String {
    format!(
        "\n Qu. Pressure : {}\n                {}\n                {}\n                {}\n                {}\n",
        queue_line(stats, "tqpressure", "total", "rxqt", "rxqtd"),
        queue_line(stats, "dqpressure", "data", "rxqd", "rxqdd"),
        queue_line(stats, "aqpressure", "announce", "rxqa", "rxqad"),
        queue_line(stats, "pqpressure", "path request", "rxqp", "rxqpd"),
        queue_line(stats, "ilqpressure", "ingress limiter", "rxqil", "rxqild"),
    )
}

fn queue_line(stats: &rmpv::Value, pressure: &str, label: &str, pkts: &str, drops: &str) -> String {
    let fraction = map_field(stats, pressure).and_then(as_f64).unwrap_or(0.0) * 100.0;
    let dropped = field_u64(stats, drops);
    let dropped = if dropped > 0 {
        format!(", {dropped} dropped")
    } else {
        String::new()
    };
    format!(
        "{fraction:.1}% {label}, {} pkts{dropped}",
        field_u64(stats, pkts)
    )
}

/// Local discovery list. Used when `-d` is set together with `-R`: Python
/// prints discovery and returns without opening a management link.
pub async fn local_discovery(config_dir: &Path, view: &StatusView) -> String {
    render_discovered(config_dir, &rmpv::Value::Map(Vec::new()), view).await
}

async fn render_discovered(config_dir: &Path, stats: &rmpv::Value, view: &StatusView) -> String {
    let entries = discovery_entries(config_dir, stats).await;
    if view.json {
        return crate::common::msgpack_json(&rmpv::Value::Array(entries));
    }
    let now = crate::common::unix_now();
    if view.config_entries {
        return render_discovery_details(&entries, view, now);
    }
    let mut out = format!(
        "\n{:<25} {:<10}   {:<10} {:<12} {:<7} {:<16} {:<15}\n",
        "Name", "Type", "Status", "Last Heard", "Value", "Running", "Location"
    );
    out.push_str(&"-".repeat(110));
    out.push('\n');
    for entry in entries {
        if let Some(line) = discovery_row(&entry, view, now) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

const DISCOVERABLE_TYPES: &[&str] = &[
    "BackboneInterface",
    "TCPServerInterface",
    "I2PInterface",
    "RNodeInterface",
    "WeaveInterface",
    "KISSInterface",
];
const DISCOVERY_UNKNOWN_SECS: f64 = 24.0 * 60.0 * 60.0;
const DISCOVERY_STALE_SECS: f64 = 3.0 * 24.0 * 60.0 * 60.0;
const DISCOVERY_REMOVE_SECS: f64 = 7.0 * 24.0 * 60.0 * 60.0;

async fn discovery_entries(config_dir: &Path, stats: &rmpv::Value) -> Vec<rmpv::Value> {
    if let Some(rows) = map_field(stats, "discovered").and_then(|value| value.as_array()) {
        if !rows.is_empty() {
            return rows.clone();
        }
    }
    // A down shared instance has no blacklist to apply. Treat that as empty
    // rather than failing the disk listing.
    let blackholed = blackholed_hashes(config_dir).await;
    let sources = crate::common::interface_discovery_sources(config_dir);
    read_discovery_files(config_dir, crate::common::unix_now(), &blackholed, &sources)
}

async fn blackholed_hashes(config_dir: &Path) -> HashSet<AddressHash> {
    let Ok(value) = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("get"),
            rmpv::Value::from("blackholed_identities"),
        )]),
    )
    .await
    else {
        return HashSet::new();
    };
    let Some(rows) = value.as_map() else {
        return HashSet::new();
    };
    rows.iter()
        .filter_map(|(key, _)| key.as_slice().and_then(AddressHash::new_from_raw_slice))
        .collect()
}

enum DiskFate {
    Keep,
    Remove,
    Skip,
}

fn read_discovery_files(
    config_dir: &Path,
    now: f64,
    blackholed: &HashSet<AddressHash>,
    sources: &HashSet<AddressHash>,
) -> Vec<rmpv::Value> {
    let dir = config_dir
        .join("storage")
        .join("discovery")
        .join("interfaces");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut kept = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                log::warn!(
                    "Error while loading discovered interface data from {}: {err}",
                    path.display()
                );
                continue;
            }
        };
        let mut value = match rmpv::decode::read_value(&mut bytes.as_slice()) {
            Ok(value) if value.is_map() => value,
            _ => {
                log::warn!("The interface data file {} may be corrupt", path.display());
                continue;
            }
        };
        match classify_discovery(&mut value, now, blackholed, sources) {
            DiskFate::Keep => kept.push(value),
            DiskFate::Remove => {
                let _ = std::fs::remove_file(&path);
            }
            DiskFate::Skip => {
                log::warn!(
                    "Error while loading discovered interface data from {}",
                    path.display()
                );
            }
        }
    }
    kept.sort_by(|left, right| {
        let code = |row: &rmpv::Value| -> i64 {
            match map_field(row, "status").and_then(|value| value.as_str()) {
                Some("available") => 1000,
                Some("unknown") => 100,
                _ => 0,
            }
        };
        let number =
            |row: &rmpv::Value, key: &str| map_field(row, key).and_then(as_f64).unwrap_or(0.0);
        code(right)
            .cmp(&code(left))
            .then(number(right, "value").total_cmp(&number(left, "value")))
            .then(number(right, "last_heard").total_cmp(&number(left, "last_heard")))
    });
    kept
}

/// Apply the discovery monitor's removal rules and recompute `status`
/// from `last_heard`. A stored status string is not trusted.
fn classify_discovery(
    value: &mut rmpv::Value,
    now: f64,
    blackholed: &HashSet<AddressHash>,
    sources: &HashSet<AddressHash>,
) -> DiskFate {
    for key in ["ifac_netname", "ifac_netkey"] {
        if map_field(value, key).and_then(|item| item.as_str()) == Some("None") {
            map_remove(value, key);
        }
    }
    let Some(heard) = map_field(value, "last_heard").and_then(as_f64) else {
        return DiskFate::Skip;
    };
    let age = now - heard;
    if age > DISCOVERY_REMOVE_SECS {
        return DiskFate::Remove;
    }
    if !map_field(value, "transport_id").is_some_and(truthy)
        || !map_field(value, "network_id").is_some_and(truthy)
    {
        return DiskFate::Remove;
    }
    if !sources.is_empty() {
        // Python `list_discovered_interfaces`: with a non-empty
        // `interface_discovery_sources`, a file whose decoded network
        // id is not in the set is unlinked. `bytes.fromhex` raising on
        // a non-hex value keeps the file through the loader's warning
        // path.
        match map_field(value, "network_id").and_then(|field| in_discovery_sources(field, sources))
        {
            Some(true) => {}
            Some(false) => return DiskFate::Remove,
            None => return DiskFate::Skip,
        }
    }
    let discoverable = map_field(value, "type")
        .and_then(|item| item.as_str())
        .is_some_and(|kind| DISCOVERABLE_TYPES.contains(&kind));
    if !discoverable {
        return DiskFate::Remove;
    }
    for key in ["network_id", "transport_id"] {
        match identity_blackholed(value, key, blackholed) {
            Ok(true) => return DiskFate::Remove,
            Ok(false) => {}
            Err(()) => return DiskFate::Skip,
        }
    }
    if let Some(reachable) = map_field(value, "reachable_on") {
        match reachable.as_str() {
            Some("") => return DiskFate::Skip,
            Some(text) if is_ip_address(text) || is_hostname(text) => {}
            Some(_) => return DiskFate::Remove,
            None => return DiskFate::Skip,
        }
    }
    let (status, code) = if age > DISCOVERY_STALE_SECS {
        ("stale", 0u64)
    } else if age > DISCOVERY_UNKNOWN_SECS {
        ("unknown", 100)
    } else {
        ("available", 1000)
    };
    map_set(value, "status", rmpv::Value::from(status));
    map_set(value, "status_code", rmpv::Value::from(code));
    DiskFate::Keep
}

/// Python persists these ids as hex. This stack persists the raw hash.
fn identity_blackholed(
    value: &rmpv::Value,
    key: &str,
    blackholed: &HashSet<AddressHash>,
) -> Result<bool, ()> {
    let field = map_field(value, key).ok_or(())?;
    let bytes = identity_bytes(field)?;
    Ok(AddressHash::new_from_raw_slice(&bytes).is_some_and(|hash| blackholed.contains(&hash)))
}

fn identity_bytes(value: &rmpv::Value) -> Result<Vec<u8>, ()> {
    if let Some(text) = value.as_str() {
        return crate::rpc::decode_hex_key(text).ok_or(());
    }
    if let Some(bytes) = value.as_slice() {
        return Ok(bytes.to_vec());
    }
    Err(())
}

/// Whether a stored `network_id` is in `interface_discovery_sources`.
/// `None` is Python's `bytes.fromhex` raising, which keeps the file.
/// This stack also persists the id as a raw 32-byte identity hash whose
/// first 16 bytes are the truncated id Python stores as hex.
fn in_discovery_sources(field: &rmpv::Value, sources: &HashSet<AddressHash>) -> Option<bool> {
    let member = |bytes: &[u8]| sources.iter().any(|hash| hash.as_slice() == bytes);
    match field {
        rmpv::Value::String(text) => {
            let bytes = crate::rpc::decode_hex_key(text.as_str()?)?;
            Some(member(&bytes))
        }
        rmpv::Value::Binary(bytes) if bytes.len() == 16 => Some(member(bytes)),
        rmpv::Value::Binary(bytes) if bytes.len() == 32 => Some(member(&bytes[..16])),
        _ => None,
    }
}

fn is_ip_address(text: &str) -> bool {
    text.parse::<std::net::IpAddr>().is_ok()
}

fn is_hostname(hostname: &str) -> bool {
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = hostname.split('.').collect();
    let Some(last) = labels.last() else {
        return false;
    };
    if !last.is_empty() && last.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    labels.iter().all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0] != b'-'
            && bytes[bytes.len() - 1] != b'-'
            && bytes
                .iter()
                .all(|ch| ch.is_ascii_alphanumeric() || *ch == b'-')
    })
}

fn map_set(value: &mut rmpv::Value, key: &str, field: rmpv::Value) {
    let rmpv::Value::Map(map) = value else {
        return;
    };
    if let Some(slot) = map.iter_mut().find(|(item, _)| item.as_str() == Some(key)) {
        slot.1 = field;
    } else {
        map.push((rmpv::Value::from(key), field));
    }
}

fn map_remove(value: &mut rmpv::Value, key: &str) {
    let rmpv::Value::Map(map) = value else {
        return;
    };
    map.retain(|(item, _)| item.as_str() != Some(key));
}

fn discovery_row(entry: &rmpv::Value, view: &StatusView, now: f64) -> Option<String> {
    let name = field_str(entry, "name").unwrap_or_default();
    if let Some(filter) = &view.name_filter {
        if !name.to_lowercase().contains(&filter.to_lowercase()) {
            return None;
        }
    }
    let status = discovery_status(entry, now);
    if status == "removed" || (status == "stale" && !view.show_stale) {
        return None;
    }
    let impl_name = field_str(entry, "impl_name").unwrap_or_default();
    let version = field_str(entry, "version").unwrap_or_default();
    let has_impl = !impl_name.is_empty() && !version.is_empty();
    if !has_impl && !view.show_unknown {
        return None;
    }
    let impl_str = if has_impl {
        clip_impl(&format!("{impl_name} {version}"))
    } else {
        "Unknown".to_string()
    };
    let kind = field_str(entry, "type")
        .unwrap_or_default()
        .replace("Interface", "");
    let shown = match status.as_str() {
        "available" => "✓ Available".to_string(),
        "unknown" => "? Unknown".to_string(),
        "stale" => "× Stale".to_string(),
        other => other.to_string(),
    };
    let heard = map_field(entry, "last_heard")
        .and_then(as_f64)
        .unwrap_or(now);
    let name = clip_name(&name);
    Some(format!(
        "{:<25} {:<10} {:<12} {:<12} {:<7} {:<16} {:<15}",
        name,
        kind,
        shown,
        heard_text(now - heard),
        display_num(map_field(entry, "value").unwrap_or(&rmpv::Value::Nil)),
        impl_str,
        location_text(entry),
    ))
}

fn discovery_status(entry: &rmpv::Value, now: f64) -> String {
    if let Some(text) = map_field(entry, "status").and_then(|value| value.as_str()) {
        return text.to_string();
    }
    let heard = map_field(entry, "last_heard")
        .and_then(as_f64)
        .unwrap_or(0.0);
    let age = now - heard;
    if age > 7.0 * 86_400.0 {
        "removed".to_string()
    } else if age > 3.0 * 86_400.0 {
        "stale".to_string()
    } else if age > 86_400.0 {
        "unknown".to_string()
    } else {
        "available".to_string()
    }
}

/// `-D` detail view (Python `config_entries` branch): one config-entry
/// block per discovered interface instead of the `-d` summary table.
fn render_discovery_details(entries: &[rmpv::Value], view: &StatusView, now: f64) -> String {
    let mut out = String::from("\n");
    for (index, entry) in entries
        .iter()
        .filter(
            |entry| match (&view.name_filter, field_str(entry, "name")) {
                (Some(filter), Some(name)) => name.to_lowercase().contains(&filter.to_lowercase()),
                (Some(_), None) => false,
                (None, _) => true,
            },
        )
        .enumerate()
    {
        let Some(block) = discovery_detail(entry, view, now) else {
            continue;
        };
        if index > 0 {
            out.push_str(&format!("\n{}\n\n", "=".repeat(47)));
        }
        out.push_str(&block);
    }
    out
}

/// One `-D` block. Python wraps the whole entry in `try`/`except`, so a
/// missing field before the first printed line drops the block silently
/// and a missing field after it truncates the block.
fn discovery_detail(entry: &rmpv::Value, view: &StatusView, now: f64) -> Option<String> {
    let name = field_str(entry, "name")?;
    let kind = field_str(entry, "type")?;
    let status = discovery_status(entry, now);
    let impl_name = field_str(entry, "impl_name").unwrap_or_default();
    let version = field_str(entry, "version").unwrap_or_default();
    let has_impl = !impl_name.is_empty() && !version.is_empty();
    if status == "stale" && !view.show_stale {
        return None;
    }
    if !has_impl && !view.show_unknown {
        return None;
    }
    let impl_str = if has_impl {
        format!("{impl_name} {version}")
    } else {
        "Unknown".to_string()
    };
    let status_display = match status.as_str() {
        "available" => "Available",
        "unknown" => "Unknown",
        "stale" => "Stale",
        other => other,
    };
    let discovered = map_field(entry, "discovered").and_then(as_f64)?;
    let heard = map_field(entry, "last_heard").and_then(as_f64)?;
    let transport = truthy(map_field(entry, "transport")?);
    let _ = map_field(entry, "latitude")?;

    let transport_id = map_field(entry, "transport_id").and_then(id_text);
    let lxmf_addr = map_field(entry, "operator_lxmf_address")
        .or_else(|| map_field(entry, "operator"))
        .and_then(id_text);
    let network = match (
        transport_id.as_ref(),
        map_field(entry, "network_id").and_then(id_text),
    ) {
        (Some(tid), Some(nid)) if &nid != tid => Some(nid),
        _ => None,
    };

    let mut out = String::new();
    if let Some(network) = network {
        out.push_str(&format!("Network   ID : {network}\n"));
    }
    if let Some(transport_id) = &transport_id {
        out.push_str(&format!("Transport ID : {transport_id}\n"));
    }
    if let Some(lxmf_addr) = lxmf_addr {
        out.push_str(&format!("LXMF address : {lxmf_addr}\n"));
    }
    out.push_str(&format!("Name         : {name}\n"));
    out.push_str(&format!("Type         : {kind}\n"));
    out.push_str(&format!("Stack        : {impl_str}\n"));
    out.push_str(&format!("Status       : {status_display}\n"));
    out.push_str(&format!(
        "Transport    : {}\n",
        if transport { "Enabled" } else { "Disabled" }
    ));
    let Some(hops) = map_field(entry, "hops") else {
        return Some(out);
    };
    out.push_str(&format!(
        "Distance     : {} hop{}\n",
        display_value(hops),
        if as_f64(hops) == Some(1.0) { "" } else { "s" }
    ));
    out.push_str(&format!(
        "Discovered   : {} ago\n",
        pretty_time_compact(now - discovered)
    ));
    out.push_str(&format!(
        "Last Heard   : {} ago\n",
        pretty_time_compact(now - heard)
    ));
    let location = match (
        map_field(entry, "latitude").and_then(as_f64),
        map_field(entry, "longitude").and_then(as_f64),
    ) {
        (Some(lat), Some(lon)) => {
            let height = map_field(entry, "height")
                .and_then(as_f64)
                .map(|value| format!(", {}m h", py_float_str(value)))
                .unwrap_or_default();
            format!("{}, {}{height}", py_round4(lat), py_round4(lon))
        }
        _ => "Unknown".to_string(),
    };
    out.push_str(&format!("Location     : {location}\n"));
    if let Some(value) = map_field(entry, "frequency") {
        out.push_str(&format!("Frequency    : {} Hz\n", comma_grouped(value)));
    }
    if let Some(value) = map_field(entry, "bandwidth") {
        out.push_str(&format!("Bandwidth    : {} Hz\n", comma_grouped(value)));
    }
    if let Some(value) = map_field(entry, "sf").or_else(|| map_field(entry, "spreadingfactor")) {
        out.push_str(&format!("Sprd. Factor : {}\n", display_value(value)));
    }
    if let Some(value) = map_field(entry, "cr").or_else(|| map_field(entry, "codingrate")) {
        out.push_str(&format!("Coding Rate  : {}\n", display_value(value)));
    }
    if let Some(value) = map_field(entry, "modulation") {
        out.push_str(&format!("Modulation   : {}\n", display_value(value)));
    }
    if let Some(value) = map_field(entry, "reachable_on") {
        out.push_str(&format!("Address      : {}\n", display_value(value)));
    }
    if let Some(value) = map_field(entry, "port") {
        out.push_str(&format!("Port         : {}\n", display_value(value)));
    }
    let Some(value) = map_field(entry, "value") else {
        return Some(out);
    };
    out.push_str(&format!("Stamp Value  : {}\n", display_value(value)));
    out.push_str("\nConfiguration Entry:\n");
    let config = field_str(entry, "config_entry").or_else(|| synthesize_config_entry(entry));
    let config = config?;
    for line in config.split('\n') {
        out.push_str(&format!("  {line}\n"));
    }
    Some(out)
}

/// `str(value)` for the fields the detail view prints verbatim.
fn display_value(value: &rmpv::Value) -> String {
    match value {
        rmpv::Value::String(text) => text.as_str().unwrap_or_default().to_string(),
        rmpv::Value::Binary(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        rmpv::Value::Boolean(flag) => {
            if *flag {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        rmpv::Value::F32(number) => py_float_str(*number as f64),
        other => display_num(other),
    }
}

/// Python `str(round(value, 4))`.
fn py_round4(value: f64) -> String {
    py_float_str((value * 10_000.0).round() / 10_000.0)
}

/// Python `str(float)`: integral floats keep a `.0` suffix.
fn py_float_str(value: f64) -> String {
    let text = format!("{value}");
    if text.contains('.') || text.contains('e') || !value.is_finite() {
        text
    } else {
        format!("{text}.0")
    }
}

/// Python `f"{value:,}"`: thousands separators in the integer part.
fn comma_grouped(value: &rmpv::Value) -> String {
    let text = display_value(value);
    let (int_part, rest) = match text.find(['.', 'e', 'E']) {
        Some(pos) => text.split_at(pos),
        None => (text.as_str(), ""),
    };
    let digits = int_part.strip_prefix('-').unwrap_or(int_part);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return text;
    }
    let mut grouped = String::new();
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    let sign = if int_part.starts_with('-') { "-" } else { "" };
    format!("{sign}{grouped}{rest}")
}

/// Python `RNS.prettytime(compact=True)`: whole seconds, at most two
/// components, the last joined with " and ".
fn pretty_time_compact(seconds: f64) -> String {
    let neg = seconds < 0.0;
    let mut time = seconds.abs();
    let days = (time / 86_400.0) as u64;
    time %= 86_400.0;
    let hours = (time / 3_600.0) as u64;
    time %= 3_600.0;
    let minutes = (time / 60.0) as u64;
    let secs = (time % 60.0) as u64;
    let mut parts = Vec::new();
    for (amount, unit) in [(days, "d"), (hours, "h"), (minutes, "m"), (secs, "s")] {
        if amount > 0 && parts.len() < 2 {
            parts.push(format!("{amount}{unit}"));
        }
    }
    let text = match parts.len() {
        0 => "0s".to_string(),
        1 => parts.remove(0),
        _ => format!("{} and {}", parts[0], parts[1]),
    };
    if neg {
        format!("-{text}")
    } else {
        text
    }
}

/// Stored id rendered the way Python prints its hex strings. This
/// stack persists raw hashes; the truncated first 16 bytes are the
/// identity hash Python stores as hex.
fn id_text(value: &rmpv::Value) -> Option<String> {
    match value {
        rmpv::Value::String(text) => text.as_str().map(str::to_string),
        rmpv::Value::Binary(bytes) => Some(
            bytes[..16.min(bytes.len())]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
        _ => None,
    }
}

/// Rebuild the `config_entry` Python synthesizes at announce time
/// (`InterfaceAnnounceHandler.received_announce`) for files that do not
/// carry it, like the ones this stack persists.
fn synthesize_config_entry(entry: &rmpv::Value) -> Option<String> {
    let kind = field_str(entry, "type")?;
    let name = field_str(entry, "name")?;
    let identity = map_field(entry, "transport_id").and_then(id_text)?;
    let netname = field_str(entry, "ifac_netname").filter(|text| !text.is_empty());
    let netkey = field_str(entry, "ifac_netkey").filter(|text| !text.is_empty());
    let ifac = format!(
        "{}{}",
        netname
            .map(|text| format!("\n  network_name = {text}"))
            .unwrap_or_default(),
        netkey
            .map(|text| format!("\n  passphrase = {text}"))
            .unwrap_or_default(),
    );
    match kind.as_str() {
        "BackboneInterface" | "TCPServerInterface" => {
            let host = field_str(entry, "reachable_on")?;
            let port = map_field(entry, "port").and_then(as_f64)? as u64;
            let (conn, remote) = if cfg!(any(target_os = "windows", target_os = "macos")) {
                ("TCPClientInterface", "target_host")
            } else {
                ("BackboneInterface", "remote")
            };
            Some(format!(
                "[[{name}]]\n  type = {conn}\n  enabled = yes\n  {remote} = {host}\n  target_port = {port}\n  transport_identity = {identity}{ifac}"
            ))
        }
        "I2PInterface" => {
            let host = field_str(entry, "reachable_on")?;
            Some(format!(
                "[[{name}]]\n  type = I2PInterface\n  enabled = yes\n  peers = {host}.b32.i2p\n  transport_identity = {identity}{ifac}"
            ))
        }
        "RNodeInterface" => {
            let frequency = map_field(entry, "frequency")?;
            let bandwidth = map_field(entry, "bandwidth")?;
            let sf = map_field(entry, "sf").or_else(|| map_field(entry, "spreadingfactor"))?;
            let cr = map_field(entry, "cr").or_else(|| map_field(entry, "codingrate"))?;
            Some(format!(
                "[[{name}]]\n  type = RNodeInterface\n  enabled = yes\n  port = \n  frequency = {}\n  bandwidth = {}\n  spreadingfactor = {}\n  codingrate = {}\n  txpower = {ifac}",
                display_value(frequency),
                display_value(bandwidth),
                display_value(sf),
                display_value(cr),
            ))
        }
        "WeaveInterface" => Some(format!(
            "[[{name}]]\n  type = WeaveInterface\n  enabled = yes\n  port = {ifac}"
        )),
        "KISSInterface" => {
            let frequency = map_field(entry, "frequency")?;
            let bandwidth = map_field(entry, "bandwidth")?;
            let modulation = map_field(entry, "modulation")?;
            Some(format!(
                "[[{name}]]\n  type = KISSInterface\n  enabled = yes\n  port = \n  # Frequency: {}\n  # Bandwidth: {}\n  # Modulation: {}\n  transport_identity = {identity}{ifac}",
                display_value(frequency),
                display_value(bandwidth),
                display_value(modulation),
            ))
        }
        _ => None,
    }
}

fn heard_text(diff: f64) -> String {
    if diff < 60.0 {
        "Just now".to_string()
    } else if diff < 3_600.0 {
        format!("{}m ago", (diff / 60.0) as u64)
    } else if diff < 86_400.0 {
        format!("{}h ago", (diff / 3_600.0) as u64)
    } else {
        format!("{}d ago", (diff / 86_400.0) as u64)
    }
}

fn location_text(entry: &rmpv::Value) -> String {
    match (
        map_field(entry, "latitude").and_then(as_f64),
        map_field(entry, "longitude").and_then(as_f64),
    ) {
        (Some(lat), Some(lon)) => format!("{}, {}", trim_coord(lat), trim_coord(lon)),
        _ => "N/A".to_string(),
    }
}

fn trim_coord(value: f64) -> String {
    let rounded = (value * 10_000.0).round() / 10_000.0;
    let mut text = format!("{rounded:.4}");
    while text.contains('.') && text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    text
}

fn clip_name(name: &str) -> String {
    if name.chars().count() > 24 {
        let mut out: String = name.chars().take(24).collect();
        out.push('…');
        out
    } else {
        name.to_string()
    }
}

fn clip_impl(text: &str) -> String {
    if text.chars().count() > 16 {
        let mut out: String = text.chars().take(15).collect();
        out.push('…');
        out
    } else {
        text.to_string()
    }
}

fn format_profiling(results: &rmpv::Value) -> String {
    let Some(rows) = results.as_map() else {
        return String::new();
    };
    let mut out = String::new();
    for (_, tag) in rows {
        if profile_super(tag).is_none() {
            out.push_str(&profile_tree(tag, results, 0));
        }
    }
    out
}

fn profile_tree(tag: &rmpv::Value, results: &rmpv::Value, level: usize) -> String {
    let mut out = profile_tag(tag, level + 1);
    out.push('\n');
    let name = field_str(tag, "name").unwrap_or_default();
    if let Some(rows) = results.as_map() {
        for (_, child) in rows {
            if profile_super(child).as_deref() == Some(name.as_str()) {
                out.push_str(&profile_tree(child, results, level + 1));
            }
        }
    }
    out
}

fn profile_tag(tag: &rmpv::Value, level: usize) -> String {
    let ind = "  ".repeat(level);
    let name = field_str(tag, "name").unwrap_or_default();
    let Some(stats_all) = map_field(tag, "stats_all").filter(|value| value.is_map()) else {
        return format!(" {ind}{name}");
    };
    let threads = field_u64(stats_all, "threads");
    let plural = if threads == 1 { "" } else { "s" };
    let mut out = format!(" {ind}{name}\n");
    out.push_str(&format!(
        " {ind}  Samples  : {} from {threads} thread{plural}\n",
        field_u64(stats_all, "count")
    ));
    out.push_str(&format!(
        " {ind}              {:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15}\n",
        "Mean", "Median", "Min", "Max", "St. dev", "Total"
    ));
    out.push_str(&profile_window(&ind, "  Stats    ", stats_all));
    for (key, label) in [
        ("stats_1m", "   0-1m    "),
        ("stats_5m", "   1-5m    "),
        ("stats_30m", "  5-30m    "),
        ("stats_60m", " 30-60m    "),
    ] {
        if let Some(window) = map_field(tag, key).filter(|value| value.is_map()) {
            out.push_str(&profile_window(&ind, label, window));
        }
    }
    out
}

fn profile_window(ind: &str, label: &str, window: &rmpv::Value) -> String {
    format!(
        " {ind}{label}: ({:^15} | {:^15} | {:^15} | {:^15} | {:^15} | {:^15})\n",
        short_time(map_field(window, "mean")),
        short_time(map_field(window, "median")),
        short_time(map_field(window, "min")),
        short_time(map_field(window, "max")),
        short_time(map_field(window, "stdev")),
        short_time(map_field(window, "sum")),
    )
}

fn profile_super(tag: &rmpv::Value) -> Option<String> {
    map_field(tag, "super").and_then(|value| value.as_str().map(str::to_string))
}

fn short_time(value: Option<&rmpv::Value>) -> String {
    let Some(value) = value else {
        return "-----".to_string();
    };
    if value.is_nil() {
        return "-----".to_string();
    }
    pretty_short_time(as_f64(value).unwrap_or(0.0))
}

fn pretty_short_time(seconds: f64) -> String {
    let mut micros = seconds * 1_000_000.0;
    if !micros.is_finite() {
        return "0us".to_string();
    }
    let neg = micros < 0.0;
    micros = micros.abs();
    let whole_seconds = (micros / 1_000_000.0) as u64;
    micros %= 1_000_000.0;
    let millis = (micros / 1_000.0) as u64;
    micros %= 1_000.0;
    let mut parts = Vec::new();
    if whole_seconds > 0 {
        parts.push(format!("{whole_seconds}s"));
    }
    if millis > 0 {
        parts.push(format!("{millis}ms"));
    }
    if micros > 0.0 {
        let rounded = micros.round();
        if (rounded - rounded.trunc()).abs() < 1e-6 {
            parts.push(format!("{}µs", rounded as u64));
        } else {
            parts.push(format!("{rounded}µs"));
        }
    }
    if parts.is_empty() {
        return "0us".to_string();
    }
    let text = parts.join(" ");
    if neg {
        format!("-{text}")
    } else {
        text
    }
}

fn speed_str(num: f64) -> String {
    let units = ["", "k", "M", "G", "T", "P", "E", "Z"];
    let mut num = num;
    for unit in units {
        if num.abs() < 1_000.0 {
            return format!("{num:3.2} {unit}bps");
        }
        num /= 1_000.0;
    }
    format!("{num:.2} Ybps")
}

fn pretty_speed(num: f64) -> String {
    format!("{}ps", pretty_unit(num, "b"))
}

fn pretty_unit(mut num: f64, suffix: &str) -> String {
    let units = ["", "K", "M", "G", "T", "P", "E", "Z"];
    for unit in units {
        if num.abs() < 1_000.0 {
            if unit.is_empty() {
                return format!("{num:.0} {unit}{suffix}");
            }
            return format!("{num:.2} {unit}{suffix}");
        }
        num /= 1_000.0;
    }
    format!("{num:.2} Y{suffix}")
}

fn pad_to(text: &mut String, width: usize) {
    while text.chars().count() < width {
        text.push(' ');
    }
}

fn display_num(value: &rmpv::Value) -> String {
    if let Some(number) = value.as_i64() {
        return number.to_string();
    }
    if let Some(number) = value.as_u64() {
        return number.to_string();
    }
    if let Some(number) = as_f64(value) {
        return format!("{number}");
    }
    "None".to_string()
}

fn truthy(value: &rmpv::Value) -> bool {
    match value {
        rmpv::Value::Nil => false,
        rmpv::Value::Boolean(item) => *item,
        rmpv::Value::Integer(item) => item.as_i64() != Some(0),
        rmpv::Value::F32(item) => *item != 0.0,
        rmpv::Value::F64(item) => *item != 0.0,
        rmpv::Value::String(item) => item.as_str().is_some_and(|text| !text.is_empty()),
        rmpv::Value::Binary(item) => !item.is_empty(),
        rmpv::Value::Array(item) => !item.is_empty(),
        rmpv::Value::Map(item) => !item.is_empty(),
        rmpv::Value::Ext(_, item) => !item.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn pretty_sizes() {
        assert_eq!(pretty_size(0), "0 B");
        assert_eq!(pretty_size(999), "999 B");
        assert_eq!(pretty_size(1500), "1.50 KB");
        assert_eq!(pretty_size(5_000_000), "5.00 MB");
    }

    #[test]
    fn pretty_speed_keeps_the_original_number() {
        assert_eq!(pretty_speed(500.0), "500 bps");
        assert_eq!(pretty_speed(8_000.0), "8.00 Kbps");
        assert_eq!(pretty_unit(4.0, "pps"), "4 pps");
    }

    #[test]
    fn profile_window_labels_match_python_widths() {
        let window = rmpv::Value::Map(vec![(
            rmpv::Value::from("mean"),
            rmpv::Value::from(0.001f64),
        )]);
        assert!(profile_window("", "   0-1m    ", &window).starts_with("    0-1m    :"));
        assert!(profile_window("", "   1-5m    ", &window).starts_with("    1-5m    :"));
        assert!(profile_window("", "  5-30m    ", &window).starts_with("   5-30m    :"));
        assert!(profile_window("", " 30-60m    ", &window).starts_with("  30-60m    :"));
        assert!(profile_window("", "  Stats    ", &window).starts_with("   Stats    :"));
    }

    #[test]
    fn disk_discovery_recomputes_status_and_unlinks() {
        let now = 1_700_000_000.0;
        let dir = std::env::temp_dir().join(format!(
            "rn-disc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let files = dir.join("storage").join("discovery").join("interfaces");
        std::fs::create_dir_all(&files).unwrap();
        let write = |name: &str, value: rmpv::Value| {
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &value).unwrap();
            std::fs::write(files.join(name), buf).unwrap();
        };
        let id = |byte: u8| {
            let mut text = String::new();
            for _ in 0..16 {
                text.push_str(&format!("{byte:02x}"));
            }
            text
        };
        write(
            "fresh",
            entry(
                "radio",
                "RNodeInterface",
                &id(1),
                &id(2),
                now - 10.0,
                "stale",
            ),
        );
        write(
            "old",
            entry(
                "gone",
                "RNodeInterface",
                &id(3),
                &id(4),
                now - 8.0 * 86_400.0,
                "available",
            ),
        );
        write(
            "notype",
            entry(
                "udp",
                "UdpInterface",
                &id(5),
                &id(6),
                now - 10.0,
                "available",
            ),
        );
        write(
            "noid",
            rmpv::Value::Map(vec![
                (rmpv::Value::from("name"), rmpv::Value::from("missing")),
                (
                    rmpv::Value::from("type"),
                    rmpv::Value::from("RNodeInterface"),
                ),
                (rmpv::Value::from("last_heard"), rmpv::Value::from(now)),
            ]),
        );
        write("badhost", {
            let mut value = entry(
                "host",
                "TCPServerInterface",
                &id(7),
                &id(8),
                now,
                "available",
            );
            map_set(&mut value, "reachable_on", rmpv::Value::from("not a host"));
            value
        });
        write(
            "binary",
            rmpv::Value::Map(vec![
                (rmpv::Value::from("name"), rmpv::Value::from("bin")),
                (
                    rmpv::Value::from("type"),
                    rmpv::Value::from("KISSInterface"),
                ),
                (
                    rmpv::Value::from("last_heard"),
                    rmpv::Value::from(now - 30.0),
                ),
                (rmpv::Value::from("value"), rmpv::Value::from(4u64)),
                (
                    rmpv::Value::from("transport_id"),
                    rmpv::Value::Binary(vec![9u8; 16]),
                ),
                (
                    rmpv::Value::from("network_id"),
                    rmpv::Value::Binary(vec![10u8; 16]),
                ),
            ]),
        );
        std::fs::write(files.join("corrupt"), b"not msgpack").unwrap();
        let mut blackholed = HashSet::new();
        blackholed.insert(AddressHash::new_from_raw_slice(&[0xbb; 16]).unwrap());
        write(
            "blocked",
            entry(
                "blocked",
                "WeaveInterface",
                &id(0xbb),
                &id(0xcc),
                now,
                "available",
            ),
        );

        let rows = read_discovery_files(&dir, now, &blackholed, &HashSet::new());
        let names: Vec<String> = rows
            .iter()
            .filter_map(|row| field_str(row, "name"))
            .collect();
        assert_eq!(names, vec!["bin".to_string(), "radio".to_string()]);
        assert_eq!(
            rows.iter()
                .find(|row| field_str(row, "name").as_deref() == Some("radio"))
                .and_then(|row| field_str(row, "status"))
                .as_deref(),
            Some("available")
        );
        assert!(!files.join("old").exists());
        assert!(!files.join("notype").exists());
        assert!(!files.join("noid").exists());
        assert!(!files.join("badhost").exists());
        assert!(!files.join("blocked").exists());
        assert!(files.join("corrupt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discovery_sources_allowlist_unlinks_foreign_entries() {
        let now = 1_700_000_000.0;
        let dir = std::env::temp_dir().join(format!(
            "rn-src-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let files = dir.join("storage").join("discovery").join("interfaces");
        std::fs::create_dir_all(&files).unwrap();
        let write = |name: &str, value: rmpv::Value| {
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &value).unwrap();
            std::fs::write(files.join(name), buf).unwrap();
        };
        let id = |byte: u8| {
            let mut text = String::new();
            for _ in 0..16 {
                text.push_str(&format!("{byte:02x}"));
            }
            text
        };
        let source_hex = id(0xaa);
        let mut sources = HashSet::new();
        sources.insert(AddressHash::new_from_hex_string(&source_hex).unwrap());
        write(
            "allowed",
            entry(
                "allowed",
                "RNodeInterface",
                &id(1),
                &source_hex,
                now - 10.0,
                "available",
            ),
        );
        write(
            "foreign",
            entry(
                "foreign",
                "RNodeInterface",
                &id(2),
                &id(3),
                now - 10.0,
                "available",
            ),
        );
        // This stack persists the raw 32-byte identity hash; its first
        // 16 bytes are the truncated id the allowlist holds.
        write("binary", {
            let mut value = entry(
                "bin",
                "WeaveInterface",
                &id(4),
                &id(5),
                now - 10.0,
                "available",
            );
            let mut full = [0u8; 32];
            full[..16].copy_from_slice(&[0xaau8; 16]);
            map_set(&mut value, "network_id", rmpv::Value::Binary(full.to_vec()));
            value
        });
        // A non-hex network id keeps the file, like Python's
        // `bytes.fromhex` raising, but is not listed.
        write("badhex", {
            let mut value = entry(
                "badhex",
                "KISSInterface",
                &id(6),
                &id(7),
                now - 10.0,
                "available",
            );
            map_set(&mut value, "network_id", rmpv::Value::from("zz-not-hex"));
            value
        });

        let rows = read_discovery_files(&dir, now, &HashSet::new(), &sources);
        let mut names: Vec<String> = rows
            .iter()
            .filter_map(|row| field_str(row, "name"))
            .collect();
        names.sort();
        assert_eq!(names, vec!["allowed".to_string(), "bin".to_string()]);
        assert!(!files.join("foreign").exists());
        assert!(files.join("badhex").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn entry(
        name: &str,
        kind: &str,
        transport_id: &str,
        network_id: &str,
        heard: f64,
        status: &str,
    ) -> rmpv::Value {
        rmpv::Value::Map(vec![
            (rmpv::Value::from("name"), rmpv::Value::from(name)),
            (rmpv::Value::from("type"), rmpv::Value::from(kind)),
            (
                rmpv::Value::from("transport_id"),
                rmpv::Value::from(transport_id),
            ),
            (
                rmpv::Value::from("network_id"),
                rmpv::Value::from(network_id),
            ),
            (rmpv::Value::from("last_heard"), rmpv::Value::from(heard)),
            (rmpv::Value::from("value"), rmpv::Value::from(2u64)),
            (rmpv::Value::from("status"), rmpv::Value::from(status)),
        ])
    }

    #[test]
    fn render_contains_transport_instance() {
        let report = StatusReport {
            instance_name: "test".to_string(),
            identity_hash: "<aabb>".to_string(),
            interfaces: vec![IfaceRow {
                name: "Interface[aa]".to_string(),
                kind: "UdpInterface".to_string(),
                status: "Up",
                mode: "Full",
                bitrate: "Unknown".to_string(),
                tx: "0 B".to_string(),
                rx: "0 B".to_string(),
                announces: "0/0 (0 B/0 B)".to_string(),
                path_requests: "0/0".to_string(),
                violations: "0/0 (filter 0)".to_string(),
            }],
            paths: vec![],
            link_counts: Default::default(),
            transport_enabled: true,
            active_links: None,
            queue_pressure: (0, [0; 4], [0; 4]),
        };
        let text = report.render();
        assert!(text.contains("Transport Instance <aabb> running"));
        assert!(text.contains("Name"));
        assert!(text.contains("Interface[aa]"));
        assert!(text.contains("No information available"));
    }
}
