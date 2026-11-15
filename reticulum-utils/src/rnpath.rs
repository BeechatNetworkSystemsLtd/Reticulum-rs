//! `rnpath` — path lookup utility (subset of `RNS/Utilities/rnpath.py`):
//! request a path to a destination and report hops/next hop, or dump the
//! local path table.
//!
//! Python reference behaviour (default mode):
//! ```text
//! Path to <hash> requested
//! Path found, destination <hash> is 2 hops away via <via> on <iface>
//! ```
//! or `Path not found` after the timeout, exiting with code 1.

use std::path::Path;
use std::time::Duration;

use reticulum::destination::link::{LinkEvent, LinkEventData};
use reticulum::destination::{DestinationDesc, DestinationName};
use reticulum::hash::AddressHash;
use reticulum::identity::PrivateIdentity;
use reticulum::transport::Transport;

use crate::common::{as_f64, prettyhexrep};

/// Default timeout for path requests (Python `Transport.PATH_REQUEST_TIMEOUT`
/// is 15 s; rnpath uses it as the default `-w` value).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Result of a successful path lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResult {
    pub destination: AddressHash,
    pub hops: u8,
    pub via: AddressHash,
    pub iface: AddressHash,
    /// Interface label from a shared-instance path table. Local snapshots
    /// leave this empty and render `Interface[<hash>]`.
    pub iface_name: Option<String>,
}

impl PathResult {
    /// Render like Python `rnpath`:
    /// `Path found, destination <hash> is N hops away via <via> on <iface>`.
    pub fn render(&self) -> String {
        let plural = if self.hops == 1 { "" } else { "s" };
        format!(
            "Path found, destination {} is {} hop{} away via {} on {}",
            prettyhexrep(self.destination.as_slice()),
            self.hops,
            plural,
            prettyhexrep(self.via.as_slice()),
            self.on_interface()
        )
    }

    pub fn on_interface(&self) -> String {
        match &self.iface_name {
            Some(name) => name.clone(),
            None => format!("Interface[{}]", self.iface.to_hex_string()),
        }
    }
}

/// Wait until a path to `destination` is known, requesting it first when it
/// is not. Returns `None` on timeout (Python prints "Path not found").
pub async fn wait_for_path(
    transport: &Transport,
    destination: &AddressHash,
    timeout: Duration,
) -> Option<PathResult> {
    if transport.has_path(destination).await {
        return path_result(transport, destination).await;
    }

    transport.request_path(destination, None, None).await;

    // Slow links need longer than the default timeout for a full round
    // trip: never wait less than the medium path timeout
    // (Python `rnpath`: `timeout = max(timeout,
    // reticulum.get_medium_path_timeout())`).
    let timeout = timeout.max(transport.medium_path_timeout().await);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if transport.has_path(destination).await {
            return path_result(transport, destination).await;
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn path_result(transport: &Transport, destination: &AddressHash) -> Option<PathResult> {
    let hops = transport.hops_to(destination).await?;
    let (via, iface) = transport.next_hop(destination).await?;
    Some(PathResult {
        destination: *destination,
        hops,
        via,
        iface,
        iface_name: None,
    })
}

/// Snapshot the path table, optionally filtered by destination and a max
/// hop count, sorted by (interface, hops) like Python `rnpath -t`.
pub async fn path_table(
    transport: &Transport,
    filter: Option<&AddressHash>,
    max_hops: Option<u8>,
) -> Vec<PathResult> {
    let mut entries: Vec<PathResult> = transport
        .path_table_snapshot()
        .await
        .into_iter()
        .filter(|entry| filter.map(|f| entry.destination == *f).unwrap_or(true))
        .filter(|entry| max_hops.map(|max| entry.hops <= max).unwrap_or(true))
        .map(|entry| PathResult {
            destination: entry.destination,
            hops: entry.hops,
            via: entry.via,
            iface: entry.iface,
            iface_name: None,
        })
        .collect();
    entries.sort_by(|left, right| {
        left.on_interface()
            .cmp(&right.on_interface())
            .then(left.hops.cmp(&right.hops))
    });
    entries
}

/// Path rows from a shared-instance `path_table` response.
pub fn paths_from_rpc(value: &rmpv::Value) -> Result<Vec<PathResult>, String> {
    let rows = value
        .as_array()
        .ok_or_else(|| "path table is not an array".to_string())?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let destination = rpc_hash(row, "hash")?;
        let via = rpc_hash(row, "via")?;
        let hops =
            rpc_u64(row, "hops").ok_or_else(|| "path table entry is missing hops".to_string())?;
        let interface = rpc_str(row, "interface").unwrap_or_else(|| "None".to_string());
        entries.push(PathResult {
            destination,
            hops: hops as u8,
            via,
            iface: AddressHash::new([0; 16]),
            iface_name: Some(interface),
        });
    }
    entries.sort_by(|left, right| {
        left.on_interface()
            .cmp(&right.on_interface())
            .then(left.hops.cmp(&right.hops))
    });
    Ok(entries)
}

fn rpc_field<'a>(row: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    row.as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn rpc_hash(row: &rmpv::Value, key: &str) -> Result<AddressHash, String> {
    let value = rpc_field(row, key).ok_or_else(|| format!("path table entry is missing {key}"))?;
    let bytes = value
        .as_slice()
        .ok_or_else(|| format!("path table {key} is not bytes"))?;
    AddressHash::new_from_raw_slice(bytes)
        .ok_or_else(|| format!("path table {key} has the wrong length"))
}

fn rpc_u64(row: &rmpv::Value, key: &str) -> Option<u64> {
    let value = rpc_field(row, key)?;
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|item| u64::try_from(item).ok()))
}

fn rpc_str(row: &rmpv::Value, key: &str) -> Option<String> {
    rpc_field(row, key).and_then(|value| value.as_str().map(str::to_string))
}

/// Render a path table like Python `rnpath -t`:
/// `<hash> is N hops away via <via> on <iface>`.
pub fn render_table(entries: &[PathResult]) -> String {
    let mut out = String::new();
    for entry in entries {
        let plural = if entry.hops == 1 { "" } else { "s" };
        out.push_str(&format!(
            "{} is {} hop{} away via {} on {}\n",
            prettyhexrep(entry.destination.as_slice()),
            entry.hops,
            plural,
            prettyhexrep(entry.via.as_slice()),
            entry.on_interface()
        ));
    }
    out
}

/// `YYYY-MM-DD HH:MM:SS` in UTC. Python uses local time; this process
/// has no safe local-time API, so the printed stamp is UTC.
pub fn timestamp_str(unix: f64) -> String {
    let secs = unix.floor() as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3_600;
    let minute = (tod % 3_600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}

/// Python `rnpath.pretty_date`. `then` and `now` are unix seconds.
/// A non-positive `then` yields an empty string.
pub fn pretty_date(then: i64, now: i64) -> String {
    if then <= 0 {
        return String::new();
    }
    let diff = now - then;
    if diff < 0 {
        return String::new();
    }
    let day_diff = diff / 86_400;
    let second_diff = diff % 86_400;
    if day_diff == 0 {
        if second_diff < 60 {
            return format!("{second_diff} seconds");
        }
        if second_diff < 70 {
            return "1 minute".to_string();
        }
        if second_diff < 7_200 {
            return format!("{} minutes", second_diff / 60);
        }
        return format!("{} hours", second_diff / 3_600);
    }
    if day_diff == 1 {
        return "1 day".to_string();
    }
    if day_diff < 7 {
        return format!("{day_diff} days");
    }
    if day_diff < 31 {
        return format!("{} weeks", day_diff / 7);
    }
    if day_diff < 365 {
        return format!("{} months", day_diff / 30);
    }
    format!("{} years", day_diff / 365)
}

struct NamedIdentity<'a>(&'a AddressHash);

impl reticulum::identity::HashIdentity for NamedIdentity<'_> {
    fn as_address_hash_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Destination address for `app.aspects` announced by `identity`
/// (Python `Destination.hash_from_name_and_identity`).
pub fn named_destination(app: &str, aspects: &str, identity: &AddressHash) -> AddressHash {
    DestinationName::new(app, aspects).address_hash_for(&NamedIdentity(identity))
}

/// Path table text from a shared-instance `path_table` response.
pub fn format_path_table(
    value: &rmpv::Value,
    filter: Option<&AddressHash>,
) -> Result<String, String> {
    format_path_rows(value, filter, true)
}

fn format_path_rows(
    value: &rmpv::Value,
    filter: Option<&AddressHash>,
    sort: bool,
) -> Result<String, String> {
    let rows = value
        .as_array()
        .ok_or_else(|| "path table is not an array".to_string())?;
    let mut entries = Vec::new();
    for row in rows {
        let destination = rpc_hash(row, "hash")?;
        if filter.is_some_and(|hash| destination != *hash) {
            continue;
        }
        let via = rpc_hash(row, "via")?;
        let hops =
            rpc_u64(row, "hops").ok_or_else(|| "path table entry is missing hops".to_string())?;
        let interface = rpc_field(row, "interface")
            .map(interface_label)
            .unwrap_or_else(|| "None".to_string());
        let expires = rpc_field(row, "expires").and_then(as_f64);
        entries.push((interface, hops, destination, via, expires));
    }
    if filter.is_some() && entries.is_empty() {
        return Err("No path known".to_string());
    }
    if sort {
        entries.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    }
    let mut out = String::new();
    for (interface, hops, destination, via, expires) in entries {
        let hop = if hops == 1 { " hop " } else { " hops" };
        let expires = match expires {
            Some(expires) => format!(" expires {}", timestamp_str(expires)),
            None => String::new(),
        };
        out.push_str(&format!(
            "{} is {hops}{hop} away via {} on {interface}{expires}\n",
            prettyhexrep(destination.as_slice()),
            prettyhexrep(via.as_slice()),
        ));
    }
    Ok(out)
}

/// Announce-rate text from a shared-instance `rate_table` response.
/// `now` is the unix time the rates are described against.
pub fn format_rate_table(
    value: &rmpv::Value,
    filter: Option<&AddressHash>,
    now: f64,
) -> Result<String, String> {
    let rows = value
        .as_array()
        .ok_or_else(|| "rate table is not an array".to_string())?;
    if rows.is_empty() {
        return Ok("No information available\n".to_string());
    }
    let mut indexed: Vec<(f64, &rmpv::Value)> = rows
        .iter()
        .map(|row| (rpc_field(row, "last").and_then(as_f64).unwrap_or(0.0), row))
        .collect();
    indexed.sort_by(|left, right| left.0.total_cmp(&right.0));
    let mut out = String::new();
    let mut displayed = 0usize;
    for (_, row) in indexed {
        let destination = rpc_hash(row, "hash")?;
        if filter.is_some_and(|hash| destination != *hash) {
            continue;
        }
        displayed += 1;
        out.push_str(&rate_line(&destination, row, now));
    }
    if filter.is_some() && displayed == 0 {
        return Err("No information available".to_string());
    }
    Ok(out)
}

fn rate_line(destination: &AddressHash, row: &rmpv::Value, now: f64) -> String {
    let pretty = prettyhexrep(destination.as_slice());
    let Some(timestamps) = rpc_field(row, "timestamps").and_then(|value| value.as_array()) else {
        return format!("Error while processing entry for {pretty}\n");
    };
    let stamps: Vec<f64> = timestamps.iter().filter_map(as_f64).collect();
    if stamps.is_empty() {
        return format!("Error while processing entry for {pretty}\n");
    }
    let last = rpc_field(row, "last").and_then(as_f64).unwrap_or(now);
    let last_str = pretty_date(last as i64, now as i64);
    let start = stamps[0];
    let span = (now - start).max(3_600.0);
    let hour_rate = stamps.len() as f64 / (span / 3_600.0);
    let span_str = pretty_date(start as i64, now as i64);
    let violations = rpc_u64(row, "rate_violations").unwrap_or(0);
    let violations = if violations > 0 {
        let plural = if violations == 1 { "" } else { "s" };
        format!(", {violations} active rate violation{plural}")
    } else {
        String::new()
    };
    let blocked = rpc_field(row, "blocked_until")
        .and_then(as_f64)
        .unwrap_or(0.0);
    let blocked = if blocked > now {
        let when = (2.0 * now - (blocked as i64) as f64) as i64;
        format!(
            ", new announces allowed in {}",
            pretty_date(when, now as i64)
        )
    } else {
        String::new()
    };
    format!(
        "{pretty} last heard {last_str} ago, {} announces/hour in the last {span_str}{violations}{blocked}\n",
        format_hour_rate(hour_rate)
    )
}

fn format_hour_rate(rate: f64) -> String {
    let rounded = (rate * 1_000.0).round() / 1_000.0;
    if (rounded - rounded.trunc()).abs() < 1e-9 {
        format!("{}", rounded as i64)
    } else {
        let mut text = format!("{rounded:.3}");
        while text.ends_with('0') {
            text.pop();
        }
        text
    }
}

fn interface_label(value: &rmpv::Value) -> String {
    if let Some(text) = value.as_str() {
        return text.to_string();
    }
    if let Some(bytes) = value.as_slice() {
        if let Some(hash) = AddressHash::new_from_raw_slice(bytes) {
            return format!("Interface[{}]", hash.to_hex_string());
        }
    }
    "None".to_string()
}

/// Shared-instance path table, rendered.
pub async fn path_table_text(
    config_dir: &Path,
    filter: Option<&AddressHash>,
    max_hops: Option<u8>,
) -> Result<String, String> {
    let value = path_table_value(config_dir, max_hops).await?;
    format_path_table(&value, filter)
}

/// Shared-instance path table value (one `get: path_table` RPC).
pub async fn path_table_value(
    config_dir: &Path,
    max_hops: Option<u8>,
) -> Result<rmpv::Value, String> {
    let max_hops = match max_hops {
        Some(max) => rmpv::Value::from(u64::from(max)),
        None => rmpv::Value::Nil,
    };
    crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![
            (rmpv::Value::from("get"), rmpv::Value::from("path_table")),
            (rmpv::Value::from("max_hops"), max_hops),
        ]),
    )
    .await
}

/// Shared-instance announce rates, rendered against `now`.
pub async fn rates_text(
    config_dir: &Path,
    filter: Option<&AddressHash>,
    now: f64,
) -> Result<String, String> {
    let value = rates_value(config_dir).await?;
    format_rate_table(&value, filter, now)
}

/// Shared-instance rate table value.
pub async fn rates_value(config_dir: &Path) -> Result<rmpv::Value, String> {
    crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("get"),
            rmpv::Value::from("rate_table"),
        )]),
    )
    .await
}

/// Ask the shared instance to expire a path.
pub async fn drop_path_text(
    config_dir: &Path,
    destination: &AddressHash,
) -> Result<String, String> {
    let value = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![
            (rmpv::Value::from("drop"), rmpv::Value::from("path")),
            (
                rmpv::Value::from("destination_hash"),
                rmpv::Value::Binary(destination.as_slice().to_vec()),
            ),
        ]),
    )
    .await?;
    drop_path_message(destination, value.as_bool() == Some(true))
}

pub fn drop_path_message(destination: &AddressHash, dropped: bool) -> Result<String, String> {
    let pretty = prettyhexrep(destination.as_slice());
    if dropped {
        Ok(format!("Dropped path to {pretty}"))
    } else {
        Err(format!("Unable to drop path to {pretty}. Does it exist?"))
    }
}

/// Ask the shared instance to drop queued announces.
pub async fn drop_announces_text(config_dir: &Path) -> Result<String, String> {
    crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("drop"),
            rmpv::Value::from("announce_queues"),
        )]),
    )
    .await?;
    Ok("Dropping announce queues on all interfaces...".to_string())
}

/// Ask the shared instance to expire every path whose next hop is `via`.
pub async fn drop_via_text(config_dir: &Path, via: &AddressHash) -> Result<String, String> {
    let value = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![
            (rmpv::Value::from("drop"), rmpv::Value::from("all_via")),
            (
                rmpv::Value::from("destination_hash"),
                rmpv::Value::Binary(via.as_slice().to_vec()),
            ),
        ]),
    )
    .await?;
    let count = value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|item| u64::try_from(item).ok()))
        .or_else(|| value.as_f64().map(|item| item as u64))
        .unwrap_or(0);
    drop_via_message(via, count)
}

pub fn drop_via_message(via: &AddressHash, count: u64) -> Result<String, String> {
    let pretty = prettyhexrep(via.as_slice());
    if count > 0 {
        Ok(format!("Dropped all paths via {pretty}"))
    } else {
        Err(format!(
            "Unable to drop paths via {pretty}. Does the transport instance exist?"
        ))
    }
}

/// Blackhole an identity through the shared instance. `shown` is the
/// hash text the operator typed.
pub async fn blackhole_text(
    config_dir: &Path,
    identity: &AddressHash,
    shown: &str,
    until: Option<f64>,
    reason: Option<&str>,
) -> Result<String, String> {
    let value = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("blackhole_identity"),
                rmpv::Value::Binary(identity.as_slice().to_vec()),
            ),
            (
                rmpv::Value::from("until"),
                until.map(rmpv::Value::from).unwrap_or(rmpv::Value::Nil),
            ),
            (
                rmpv::Value::from("reason"),
                reason
                    .map(|text| rmpv::Value::from(text.to_string()))
                    .unwrap_or(rmpv::Value::Nil),
            ),
        ]),
    )
    .await?;
    Ok(blackhole_message(shown, &value))
}

fn blackhole_message(shown: &str, value: &rmpv::Value) -> String {
    if value.as_bool() == Some(true) {
        format!("Blackholed identity {shown}")
    } else if value.is_nil() {
        format!("Identity {shown} already blackholed")
    } else {
        format!("Could not blackhole identity {shown}")
    }
}

/// Remove an identity from the shared instance blacklist.
pub async fn unblackhole_text(
    config_dir: &Path,
    identity: &AddressHash,
    shown: &str,
) -> Result<String, String> {
    let value = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("unblackhole_identity"),
            rmpv::Value::Binary(identity.as_slice().to_vec()),
        )]),
    )
    .await?;
    Ok(unblackhole_message(shown, &value))
}

fn unblackhole_message(shown: &str, value: &rmpv::Value) -> String {
    if value.as_bool() == Some(true) {
        format!("Lifted blackhole for identity {shown}")
    } else if value.is_nil() {
        format!("Identity {shown} not blackholed")
    } else {
        format!("Could not unblackhole identity {shown}")
    }
}

/// Render `get: blackholed_identities`. `own` suppresses the `by` clause
/// when the entry was published by this transport.
pub async fn blackholed_text(
    config_dir: &Path,
    filter: Option<&str>,
    now: f64,
    own: Option<&AddressHash>,
) -> Result<String, String> {
    let value = crate::common::shared_rpc(
        config_dir,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("get"),
            rmpv::Value::from("blackholed_identities"),
        )]),
    )
    .await?;
    format_blackholes(&value, filter, now, own)
}

pub fn format_blackholes(
    value: &rmpv::Value,
    filter: Option<&str>,
    now: f64,
    own: Option<&AddressHash>,
) -> Result<String, String> {
    let rows = value
        .as_map()
        .ok_or_else(|| "blackhole list is not a map".to_string())?;
    if rows.is_empty() {
        return Err("No blackholed identity data available".to_string());
    }
    let mut out = String::new();
    for (key, entry) in rows {
        let Some(hash) = key.as_slice().and_then(AddressHash::new_from_raw_slice) else {
            continue;
        };
        let line = blackhole_line(&hash, entry, now, own);
        let probe = blackhole_filter_text(&hash, entry, now, own);
        if filter.is_some_and(|filter| !probe.contains(filter)) {
            continue;
        }
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

fn blackhole_line(
    hash: &AddressHash,
    entry: &rmpv::Value,
    now: f64,
    own: Option<&AddressHash>,
) -> String {
    let (until_str, reason_str, by_str) = blackhole_parts(entry, now, own);
    format!(
        "{} blackholed {until_str}{reason_str}{by_str}",
        prettyhexrep(hash.as_slice())
    )
}

fn blackhole_filter_text(
    hash: &AddressHash,
    entry: &rmpv::Value,
    now: f64,
    own: Option<&AddressHash>,
) -> String {
    let (until_str, reason_str, by_str) = blackhole_parts(entry, now, own);
    format!(
        "{} {until_str} {reason_str} {by_str}",
        prettyhexrep(hash.as_slice())
    )
}

fn blackhole_parts(
    entry: &rmpv::Value,
    now: f64,
    own: Option<&AddressHash>,
) -> (String, String, String) {
    let until = rpc_field(entry, "until")
        .and_then(as_f64)
        .filter(|until| *until != 0.0);
    let until_str = match until {
        Some(until) => format!("for {}", crate::common::pretty_time((until - now).max(0.0))),
        None => "indefinitely".to_string(),
    };
    let reason = rpc_field(entry, "reason").and_then(|value| value.as_str());
    let reason_str = match reason {
        Some(reason) if !reason.is_empty() => format!(" ({})", clip_chars(reason, 64)),
        _ => String::new(),
    };
    let source = rpc_field(entry, "source")
        .and_then(|value| value.as_slice())
        .and_then(AddressHash::new_from_raw_slice);
    let by_str = match source {
        Some(source) if own.is_none_or(|own| source != *own) => {
            format!(" by {}", prettyhexrep(source.as_slice()))
        }
        _ => String::new(),
    };
    (until_str, reason_str, by_str)
}

fn clip_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Path table of a local transport, in the same shape as the RPC response.
pub async fn local_path_table_text(
    transport: &Transport,
    filter: Option<&AddressHash>,
    max_hops: Option<u8>,
) -> Result<String, String> {
    format_path_table(&local_path_rows(transport, max_hops).await, filter)
}

/// Local path table as one JSON document. Sorted like the text table.
/// The destination filter is not applied; Python dumps the whole table.
pub async fn local_path_table_value(
    transport: &Transport,
    max_hops: Option<u8>,
) -> Result<rmpv::Value, String> {
    let mut rows = match local_path_rows(transport, max_hops).await {
        rmpv::Value::Array(rows) => rows,
        other => return Ok(other),
    };
    rows.sort_by(|left, right| {
        let iface = |row: &rmpv::Value| rpc_str(row, "interface").unwrap_or_default();
        let hops = |row: &rmpv::Value| rpc_u64(row, "hops").unwrap_or(0);
        iface(left)
            .cmp(&iface(right))
            .then(hops(left).cmp(&hops(right)))
    });
    Ok(rmpv::Value::Array(rows))
}

async fn local_path_rows(transport: &Transport, max_hops: Option<u8>) -> rmpv::Value {
    let labels = iface_labels(transport).await;
    let mut rows = Vec::new();
    for entry in transport.path_table_snapshot().await {
        if max_hops.is_some_and(|max| entry.hops > max) {
            continue;
        }
        let interface = labels
            .iter()
            .find(|(address, _)| *address == entry.iface)
            .map(|(_, name)| name.clone())
            .unwrap_or_else(|| format!("Interface[{}]", entry.iface.to_hex_string()));
        rows.push(rmpv::Value::Map(vec![
            (
                rmpv::Value::from("hash"),
                rmpv::Value::Binary(entry.destination.as_slice().to_vec()),
            ),
            (
                rmpv::Value::from("via"),
                rmpv::Value::Binary(entry.via.as_slice().to_vec()),
            ),
            (
                rmpv::Value::from("hops"),
                rmpv::Value::from(u64::from(entry.hops)),
            ),
            (
                rmpv::Value::from("expires"),
                rmpv::Value::from(entry.expires_unix),
            ),
            (rmpv::Value::from("interface"), rmpv::Value::from(interface)),
        ]));
    }
    rmpv::Value::Array(rows)
}

/// Announce rates of a local transport.
pub async fn local_rates_text(
    transport: &Transport,
    filter: Option<&AddressHash>,
    now: f64,
) -> Result<String, String> {
    format_rate_table(&local_rate_rows(transport, now).await, filter, now)
}

/// Local rate table as one JSON document, sorted by `last`.
pub async fn local_rates_value(transport: &Transport, now: f64) -> rmpv::Value {
    sort_rate_rows(&local_rate_rows(transport, now).await)
}

async fn local_rate_rows(transport: &Transport, now: f64) -> rmpv::Value {
    let rows = transport
        .rate_table_snapshot()
        .await
        .into_iter()
        .map(|entry| {
            let last = now - entry.since_last.as_secs_f64();
            let blocked_until = entry
                .blocked_for
                .map(|blocked| now + blocked.as_secs_f64())
                .unwrap_or(0.0);
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::from("hash"),
                    rmpv::Value::Binary(entry.destination.as_slice().to_vec()),
                ),
                (rmpv::Value::from("last"), rmpv::Value::from(last)),
                (
                    rmpv::Value::from("rate_violations"),
                    rmpv::Value::from(u64::from(entry.violations)),
                ),
                (
                    rmpv::Value::from("blocked_until"),
                    rmpv::Value::from(blocked_until),
                ),
                (
                    rmpv::Value::from("timestamps"),
                    rmpv::Value::Array(
                        entry
                            .timestamps
                            .into_iter()
                            .map(rmpv::Value::from)
                            .collect(),
                    ),
                ),
            ])
        })
        .collect();
    rmpv::Value::Array(rows)
}

/// Expire one local path (Python `Reticulum.drop_path` calls `expire_path`).
pub async fn local_drop_path_text(
    transport: &Transport,
    destination: &AddressHash,
) -> Result<String, String> {
    let dropped = transport.expire_path(destination).await;
    drop_path_message(destination, dropped)
}

pub async fn local_drop_announces_text(transport: &Transport) -> String {
    transport.drop_announce_queues().await;
    "Dropping announce queues on all interfaces...".to_string()
}

/// Expire every local path whose next hop is `via`.
/// `Transport::drop_all_via` matches the interface address, which is not
/// the transport hash Python iterates.
pub async fn local_drop_via_text(
    transport: &Transport,
    via: &AddressHash,
) -> Result<String, String> {
    let destinations: Vec<AddressHash> = transport
        .path_table_snapshot()
        .await
        .into_iter()
        .filter(|entry| entry.via == *via)
        .map(|entry| entry.destination)
        .collect();
    let mut count = 0u64;
    for destination in destinations {
        if transport.expire_path(&destination).await {
            count += 1;
        }
    }
    drop_via_message(via, count)
}

pub async fn local_blackhole_text(
    transport: &Transport,
    identity: &AddressHash,
    shown: &str,
    until: Option<f64>,
    reason: Option<String>,
) -> Result<String, String> {
    if transport.is_blackholed(identity).await {
        return Ok(format!("Identity {shown} already blackholed"));
    }
    transport.blackhole_identity(*identity, until, reason).await;
    Ok(format!("Blackholed identity {shown}"))
}

pub async fn local_unblackhole_text(
    transport: &Transport,
    identity: &AddressHash,
    shown: &str,
) -> Result<String, String> {
    if transport.unblackhole_identity(identity).await {
        Ok(format!("Lifted blackhole for identity {shown}"))
    } else {
        Ok(format!("Identity {shown} not blackholed"))
    }
}

pub async fn local_blackholed_text(
    transport: &Transport,
    filter: Option<&str>,
    now: f64,
) -> Result<String, String> {
    let own = transport.identity_hash().await;
    let packed = transport.blackholes().read().await.pack_table();
    let value = rmpv::decode::read_value(&mut packed.as_slice())
        .map_err(|err| format!("blackhole list: {err}"))?;
    format_blackholes(&value, filter, now, Some(&own))
}

async fn iface_labels(transport: &Transport) -> Vec<(AddressHash, String)> {
    transport
        .iface_manager()
        .lock()
        .await
        .stats()
        .into_iter()
        .map(|stat| {
            let name = if stat.name.is_empty() {
                format!("Interface[{}]", stat.address.to_hex_string())
            } else {
                stat.name
            };
            (stat.address, name)
        })
        .collect()
}

/// Open a link and perform one request. `identity` is `None` for
/// destinations that do not authenticate (blackhole `/list`).
/// `data` is one msgpack element spliced as the request payload, or
/// empty for Python `None`.
pub async fn remote_request(
    transport: &Transport,
    destination: &AddressHash,
    identity: Option<&PrivateIdentity>,
    path: &str,
    data: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    remote_exchange(transport, destination, identity, path, data, timeout, true).await
}

/// Establish the management link and identify, then close it.
/// Used for remote commands Python refuses after the link is up.
pub async fn connect_remote(
    transport: &Transport,
    destination: &AddressHash,
    identity: Option<&PrivateIdentity>,
    timeout: Duration,
    progress: bool,
) -> Result<(), String> {
    let (link_id, _link) =
        open_remote_link(transport, destination, identity, timeout, progress).await?;
    let _ = transport.link_close(link_id).await;
    Ok(())
}

pub(crate) async fn remote_exchange(
    transport: &Transport,
    destination: &AddressHash,
    identity: Option<&PrivateIdentity>,
    path: &str,
    data: &[u8],
    timeout: Duration,
    progress: bool,
) -> Result<Vec<u8>, String> {
    let (link_id, link) =
        open_remote_link(transport, destination, identity, timeout, progress).await?;
    if progress {
        println!("Sending request...");
    }
    let element = if data.is_empty() { None } else { Some(data) };
    let request_id = transport
        .request_element(&link, path, element)
        .await
        .map_err(|_| "The remote request failed. Likely authentication failure.".to_string());
    let request_id = match request_id {
        Ok(request_id) => request_id,
        Err(err) => {
            let _ = transport.link_close(link_id).await;
            return Err(err);
        }
    };
    let response = transport.await_request_response(request_id, timeout).await;
    let _ = transport.link_close(link_id).await;
    response.ok_or_else(|| "The remote request failed. Likely authentication failure.".to_string())
}

async fn open_remote_link(
    transport: &Transport,
    destination: &AddressHash,
    identity: Option<&PrivateIdentity>,
    timeout: Duration,
    progress: bool,
) -> Result<
    (
        AddressHash,
        std::sync::Arc<tokio::sync::Mutex<reticulum::destination::link::Link>>,
    ),
    String,
> {
    let timeout = timeout.max(transport.medium_path_timeout().await);
    if !transport.has_path(destination).await && progress {
        println!("Path to {} requested", prettyhexrep(destination.as_slice()));
    }
    let desc = wait_for_destination(transport, destination, timeout)
        .await
        .ok_or_else(|| "Path request timed out".to_string())?;
    if progress {
        println!("Establishing link with remote transport instance...");
    }
    let mut events = transport.out_link_events();
    let link = transport.link(desc).await;
    let link_id = *link.lock().await.id();
    if let Err(err) = wait_link_active(&mut events, &link_id, timeout).await {
        let _ = transport.link_close(link_id).await;
        return Err(err);
    }
    if let Some(identity) = identity {
        let packet = link
            .lock()
            .await
            .identify(identity)
            .map_err(|err| format!("could not identify: {err:?}"))?;
        transport.send_packet(packet).await;
    }
    Ok((link_id, link))
}

async fn wait_link_active(
    events: &mut tokio::sync::broadcast::Receiver<LinkEventData>,
    link_id: &AddressHash,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err("The link timed out, exiting now".to_string());
        }
        let event = match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(event)) if event.id == *link_id => event.event,
            Ok(Ok(_)) => continue,
            _ => return Err("The link timed out, exiting now".to_string()),
        };
        match event {
            LinkEvent::Activated => return Ok(()),
            LinkEvent::Closed => {
                return Err("Link closed unexpectedly, exiting now".to_string());
            }
            _ => {}
        }
    }
}

pub async fn remote_path_table(
    transport: &Transport,
    transport_identity: &AddressHash,
    identity: &PrivateIdentity,
    filter: Option<&AddressHash>,
    max_hops: Option<u8>,
    timeout: Duration,
) -> Result<String, String> {
    let value = fetch_remote_path(
        transport,
        transport_identity,
        identity,
        filter,
        max_hops,
        timeout,
        true,
    )
    .await?;
    format_path_rows(&value, filter, false)
}

/// Remote path table as one JSON document. Byte fields are bare hex.
/// The table is left in the order the remote sent it.
pub async fn remote_path_json(
    transport: &Transport,
    transport_identity: &AddressHash,
    identity: &PrivateIdentity,
    filter: Option<&AddressHash>,
    max_hops: Option<u8>,
    timeout: Duration,
) -> Result<String, String> {
    let value = fetch_remote_path(
        transport,
        transport_identity,
        identity,
        filter,
        max_hops,
        timeout,
        false,
    )
    .await?;
    Ok(crate::common::msgpack_json(&value))
}

async fn fetch_remote_path(
    transport: &Transport,
    transport_identity: &AddressHash,
    identity: &PrivateIdentity,
    filter: Option<&AddressHash>,
    max_hops: Option<u8>,
    timeout: Duration,
    progress: bool,
) -> Result<rmpv::Value, String> {
    let destination = named_destination("rnstransport", "remote.management", transport_identity);
    let payload = encode_value(&path_query("table", filter, max_hops))?;
    remote_path_response(
        transport,
        &destination,
        identity,
        &payload,
        timeout,
        progress,
    )
    .await
}

fn path_query(command: &str, filter: Option<&AddressHash>, max_hops: Option<u8>) -> rmpv::Value {
    let mut items = vec![
        rmpv::Value::from(command),
        match filter {
            Some(hash) => rmpv::Value::Binary(hash.as_slice().to_vec()),
            None => rmpv::Value::Nil,
        },
    ];
    if command == "table" {
        items.push(match max_hops {
            Some(max) => rmpv::Value::from(u64::from(max)),
            None => rmpv::Value::Nil,
        });
    }
    rmpv::Value::Array(items)
}

pub async fn remote_rates(
    transport: &Transport,
    transport_identity: &AddressHash,
    identity: &PrivateIdentity,
    filter: Option<&AddressHash>,
    now: f64,
    timeout: Duration,
) -> Result<String, String> {
    let value = fetch_remote_rates(
        transport,
        transport_identity,
        identity,
        filter,
        timeout,
        true,
    )
    .await?;
    format_rate_table(&value, filter, now)
}

/// Remote rate table as one JSON document, sorted by `last` like Python.
pub async fn remote_rates_json(
    transport: &Transport,
    transport_identity: &AddressHash,
    identity: &PrivateIdentity,
    filter: Option<&AddressHash>,
    timeout: Duration,
) -> Result<String, String> {
    let value = fetch_remote_rates(
        transport,
        transport_identity,
        identity,
        filter,
        timeout,
        false,
    )
    .await?;
    Ok(crate::common::msgpack_json(&sort_rate_rows(&value)))
}

async fn fetch_remote_rates(
    transport: &Transport,
    transport_identity: &AddressHash,
    identity: &PrivateIdentity,
    filter: Option<&AddressHash>,
    timeout: Duration,
    progress: bool,
) -> Result<rmpv::Value, String> {
    let destination = named_destination("rnstransport", "remote.management", transport_identity);
    let payload = encode_value(&path_query("rates", filter, None))?;
    remote_path_response(
        transport,
        &destination,
        identity,
        &payload,
        timeout,
        progress,
    )
    .await
}

/// Published blacklist of a transport identity (`rnstransport.info.blackhole`).
pub async fn remote_blackhole_list(
    transport: &Transport,
    transport_identity: &AddressHash,
    timeout: Duration,
    filter: Option<&str>,
    now: f64,
) -> Result<String, String> {
    let destination = named_destination("rnstransport", "info.blackhole", transport_identity);
    let bytes = remote_request(transport, &destination, None, "/list", &[], timeout).await?;
    let value = decode_msgpack(&bytes)?;
    if !value.is_map() {
        return Err("The remote request failed.".to_string());
    }
    format_blackholes(&value, filter, now, None)
}

fn encode_value(value: &rmpv::Value) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, value).map_err(|err| err.to_string())?;
    Ok(buf)
}

fn decode_msgpack(bytes: &[u8]) -> Result<rmpv::Value, String> {
    let mut cursor = bytes;
    rmpv::decode::read_value(&mut cursor).map_err(|err| err.to_string())
}

fn sort_rate_rows(value: &rmpv::Value) -> rmpv::Value {
    let Some(rows) = value.as_array() else {
        return value.clone();
    };
    let mut rows = rows.clone();
    rows.sort_by(|left, right| {
        let left = rpc_field(left, "last").and_then(as_f64).unwrap_or(0.0);
        let right = rpc_field(right, "last").and_then(as_f64).unwrap_or(0.0);
        left.total_cmp(&right)
    });
    rmpv::Value::Array(rows)
}

async fn remote_path_response(
    transport: &Transport,
    destination: &AddressHash,
    identity: &PrivateIdentity,
    payload: &[u8],
    timeout: Duration,
    progress: bool,
) -> Result<rmpv::Value, String> {
    let bytes = remote_exchange(
        transport,
        destination,
        Some(identity),
        "/path",
        payload,
        timeout,
        progress,
    )
    .await?;
    let value = decode_msgpack(&bytes)?;
    if value.is_nil() || value.as_array().is_some_and(|rows| rows.is_empty()) {
        return Err("The remote request failed. Likely authentication failure.".to_string());
    }
    Ok(value)
}

/// Wait for an announce for `destination` and return the destination
/// description (needed to establish links, e.g. in `rncp`).
pub async fn wait_for_destination(
    transport: &Transport,
    destination: &AddressHash,
    timeout: Duration,
) -> Option<DestinationDesc> {
    if let Some(dest) = transport.get_out_destination(destination).await {
        return Some(dest.lock().await.desc);
    }

    // Subscribe BEFORE issuing the path request: on a fast local or
    // shared-instance path, the response announce can be processed
    // before a receiver created after the request would exist.
    let mut announces = transport.recv_announces().await;

    transport.request_path(destination, None, None).await;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }

        // Re-check in case the announce was processed between the
        // request and the first poll (and thus never emitted to us).
        if let Some(dest) = transport.get_out_destination(destination).await {
            return Some(dest.lock().await.desc);
        }

        let Ok(Ok(event)) = tokio::time::timeout(remaining, announces.recv()).await else {
            return None;
        };
        let desc = event.destination.lock().await.desc;
        if &desc.address_hash == destination {
            return Some(desc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_result_render() {
        let result = PathResult {
            destination: AddressHash::new([1; 16]),
            hops: 1,
            via: AddressHash::new([2; 16]),
            iface: AddressHash::new([3; 16]),
            iface_name: None,
        };
        assert!(result.render().contains("is 1 hop away"));
        let result = PathResult {
            destination: AddressHash::new([1; 16]),
            hops: 3,
            via: AddressHash::new([2; 16]),
            iface: AddressHash::new([3; 16]),
            iface_name: None,
        };
        assert!(result.render().contains("is 3 hops away"));
    }

    #[test]
    fn render_table_does_not_wrap_a_named_interface() {
        let result = PathResult {
            destination: AddressHash::new([1; 16]),
            hops: 2,
            via: AddressHash::new([2; 16]),
            iface: AddressHash::new([3; 16]),
            iface_name: Some("TCPInterface[Peer]".to_string()),
        };
        let text = render_table(&[result]);
        assert!(text.contains("on TCPInterface[Peer]"));
        assert!(!text.contains("Interface[TCP"));
    }

    #[test]
    fn timestamp_str_is_utc() {
        assert_eq!(timestamp_str(0.0), "1970-01-01 00:00:00");
        assert_eq!(timestamp_str(1_800_000_000.0), "2027-01-15 08:00:00");
    }

    #[test]
    fn pretty_date_matches_elapsed_buckets() {
        let now = 1_800_000_000;
        assert_eq!(pretty_date(now - 120, now), "2 minutes");
        assert_eq!(pretty_date(now - 7_200, now), "2 hours");
        assert_eq!(pretty_date(0, now), "");
    }
}
