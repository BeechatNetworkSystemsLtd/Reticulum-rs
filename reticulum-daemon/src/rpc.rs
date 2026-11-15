//! Shared-instance RPC on the control listener bound by the daemon.
//!
//! One connection is the Python `multiprocessing` handshake, one msgpack
//! call, then the matching `rpc_loop` sections. A missing field logs and
//! sends no further response.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reticulum::hash::{AddressHash, Hash};
use reticulum::iface::{IfaceControlState, InterfaceStats, RadioTelemetry};
use reticulum::packet::PROTOCOL_MTU;
use reticulum::transport::{RateTableEntry, Transport};
use rmpv::Value;
use tokio::sync::{mpsc, oneshot};

const DEFAULT_PER_HOP_TIMEOUT: f64 = 6.0;
/// Unset control bitrate (`IfaceControlState` default). Timeout getters
/// substitute Python's per-type guess while this value is still stored.
const DEFAULT_BITRATE: u64 = 62_500;
const SHARED_BITRATE_GUESS: u64 = 1_000_000_000;
const TCP_UDP_BITRATE_GUESS: u64 = 10_000_000;

pub enum BoundControl {
    Tcp(tokio::net::TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}

pub enum ManageOp {
    Attach(String),
    Detach(String),
    Reload(String),
}

pub struct ManageRequest {
    pub op: ManageOp,
    pub reply: oneshot::Sender<Option<bool>>,
}

pub struct RpcState {
    pub transport: Arc<Transport>,
    pub authkey: Vec<u8>,
    pub manage: Option<mpsc::Sender<ManageRequest>>,
    pub transport_enabled: bool,
    pub network_identity: Option<AddressHash>,
    pub probe_hash: Option<AddressHash>,
    pub started: Instant,
}

pub async fn serve(listener: BoundControl, state: Arc<RpcState>) {
    match listener {
        BoundControl::Tcp(listener) => serve_tcp(listener, state).await,
        #[cfg(unix)]
        BoundControl::Unix(listener) => serve_unix(listener, state).await,
    }
}

pub async fn serve_tcp(listener: tokio::net::TcpListener, state: Arc<RpcState>) {
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(err) = handle(&mut tokio::io::BufStream::new(sock), &state).await {
                        log::error!(
                            "An error occurred while handling RPC call from local client: {err}"
                        );
                    }
                });
            }
            Err(err) => {
                log::error!("shared instance control accept failed: {err}");
                break;
            }
        }
    }
}

#[cfg(unix)]
pub async fn serve_unix(listener: tokio::net::UnixListener, state: Arc<RpcState>) {
    loop {
        match listener.accept().await {
            Ok((sock, _)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(err) = handle(&mut tokio::io::BufStream::new(sock), &state).await {
                        log::error!(
                            "An error occurred while handling RPC call from local client: {err}"
                        );
                    }
                });
            }
            Err(err) => {
                log::error!("shared instance control accept failed: {err}");
                break;
            }
        }
    }
}

async fn handle<S>(sock: &mut S, state: &RpcState) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    reticulum_utils::rpc::server_handshake(sock, &state.authkey).await?;
    let frame = reticulum_utils::rpc::recv_bytes(sock, None)
        .await?
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "rpc message too large")
        })?;
    let call = rmpv::decode::read_value(&mut frame.as_slice())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
    for response in dispatch(state, &call).await {
        let mut packed = Vec::new();
        rmpv::encode::write_value(&mut packed, &response)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
        reticulum_utils::rpc::send_bytes(sock, &packed).await?;
    }
    Ok(())
}

async fn dispatch(state: &RpcState, call: &Value) -> Vec<Value> {
    if !call.is_map() {
        log::error!(
            "An error occurred while handling RPC call from local client: call is not a map"
        );
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Err(err) = dispatch_sections(state, call, &mut out).await {
        log::error!("An error occurred while handling RPC call from local client: {err}");
    }
    out
}

async fn dispatch_sections(
    state: &RpcState,
    call: &Value,
    out: &mut Vec<Value>,
) -> Result<(), String> {
    if map_get(call, "get").is_some()
        && let Some(value) = get_op(state, call).await?
    {
        out.push(value);
    }
    if map_get(call, "manage").is_some()
        && let Some(value) = manage_op(state, call).await?
    {
        out.push(value);
    }
    if map_get(call, "drop").is_some()
        && let Some(value) = drop_op(state, call).await?
    {
        out.push(value);
    }
    if map_get(call, "blackhole_identity").is_some() {
        out.push(blackhole_op(state, call).await?);
    }
    if map_get(call, "unblackhole_identity").is_some() {
        out.push(unblackhole_op(state, call).await?);
    }
    if map_get(call, "destination_data").is_some()
        && let Some(value) = destination_op(state, call).await?
    {
        out.push(value);
    }
    if map_get(call, "identity_data").is_some()
        && let Some(value) = identity_op(state, call).await?
    {
        out.push(value);
    }
    if map_get(call, "request").is_some()
        && let Some(value) = request_op(state, call).await?
    {
        out.push(value);
    }
    Ok(())
}

async fn get_op(state: &RpcState, call: &Value) -> Result<Option<Value>, String> {
    let path = map_get(call, "get")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing get".to_string())?;
    let value = match path {
        "path_table" => path_table(state, call).await?,
        "interface_stats" => interface_stats(state).await,
        "rate_table" => rate_table(state).await,
        "next_hop_if_name" => {
            Value::from(next_hop_if_name(state, &required_hash(call, "destination_hash")?).await)
        }
        "next_hop" => match next_hop_hash(state, &required_hash(call, "destination_hash")?).await {
            Some(hash) => Value::Binary(hash.as_slice().to_vec()),
            None => Value::Nil,
        },
        "first_hop_timeout" => {
            Value::from(first_hop_timeout(state, &required_hash(call, "destination_hash")?).await)
        }
        "lowest_interface_bitrate" => match state.transport.lowest_interface_bitrate().await {
            Some(bitrate) => Value::from(bitrate),
            None => Value::Nil,
        },
        "medium_path_timeout" => Value::from(medium_path_timeout(state).await),
        "link_count" => Value::from(state.transport.link_counts().await.link_table as u64),
        "active_link_count" => Value::from(state.transport.active_link_count().await as u64),
        "packet_rssi" => phy_value(
            state
                .transport
                .packet_rssi(&required_packet_hash(call, "packet_hash")?)
                .await,
        ),
        "packet_snr" => phy_value(
            state
                .transport
                .packet_snr(&required_packet_hash(call, "packet_hash")?)
                .await,
        ),
        "packet_q" => phy_value(
            state
                .transport
                .packet_q(&required_packet_hash(call, "packet_hash")?)
                .await,
        ),
        // No profiler is attached, so there is no report to return.
        "profiling_results" => Value::Nil,
        "blackholed_identities" => blackholed_identities(state).await,
        "is_blackholed" => Value::Boolean(
            state
                .transport
                .is_blackholed(&required_hash(call, "identity_hash")?)
                .await,
        ),
        _ => return Ok(None),
    };
    Ok(Some(value))
}

async fn manage_op(state: &RpcState, call: &Value) -> Result<Option<Value>, String> {
    let path = map_get(call, "manage")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing manage".to_string())?;
    let name = map_get(call, "name")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing name".to_string())?
        .to_string();
    let op = match path {
        "attach_interface" => ManageOp::Attach(name),
        "detach_interface" => ManageOp::Detach(name),
        "reload_interface" => ManageOp::Reload(name),
        _ => return Ok(None),
    };
    Ok(Some(match ask_manage(state, op).await {
        Some(value) => Value::Boolean(value),
        None => Value::Nil,
    }))
}

async fn drop_op(state: &RpcState, call: &Value) -> Result<Option<Value>, String> {
    let path = map_get(call, "drop")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing drop".to_string())?;
    let value = match path {
        "path" => Value::Boolean(
            state
                .transport
                .expire_path(&required_hash(call, "destination_hash")?)
                .await,
        ),
        "all_via" => {
            Value::from(drop_all_via(state, &required_hash(call, "destination_hash")?).await)
        }
        "announce_queues" => {
            state.transport.drop_announce_queues().await;
            Value::Nil
        }
        _ => return Ok(None),
    };
    Ok(Some(value))
}

async fn blackhole_op(state: &RpcState, call: &Value) -> Result<Value, String> {
    let hash_value = map_get(call, "blackhole_identity")
        .ok_or_else(|| "missing blackhole_identity".to_string())?;
    let Some(hash) = hash_of(hash_value) else {
        return Ok(Value::Boolean(false));
    };
    let until_v = map_get(call, "until").ok_or_else(|| "missing until".to_string())?;
    let until = if until_v.is_nil() {
        None
    } else {
        Some(as_f64(until_v).ok_or_else(|| "invalid until".to_string())?)
    };
    let reason_v = map_get(call, "reason").ok_or_else(|| "missing reason".to_string())?;
    let reason = if reason_v.is_nil() {
        None
    } else {
        Some(
            reason_v
                .as_str()
                .ok_or_else(|| "invalid reason".to_string())?
                .to_string(),
        )
    };
    if state.transport.is_blackholed(&hash).await {
        return Ok(Value::Nil);
    }
    state
        .transport
        .blackhole_identity(hash, until, reason)
        .await;
    Ok(Value::Boolean(true))
}

async fn unblackhole_op(state: &RpcState, call: &Value) -> Result<Value, String> {
    let hash = match hash_of(
        map_get(call, "unblackhole_identity")
            .ok_or_else(|| "missing unblackhole_identity".to_string())?,
    ) {
        Some(hash) => hash,
        None => return Ok(Value::Boolean(false)),
    };
    if state.transport.unblackhole_identity(&hash).await {
        Ok(Value::Boolean(true))
    } else {
        Ok(Value::Nil)
    }
}

async fn destination_op(state: &RpcState, call: &Value) -> Result<Option<Value>, String> {
    let operation = map_get(call, "destination_data")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing destination_data".to_string())?;
    let hash = required_hash(call, "destination_hash")?;
    let value = match operation {
        "used" => state.transport.used_destination_data(&hash).await,
        "retain" => state.transport.retain_destination_data(&hash).await,
        "unretain" => state.transport.unretain_destination_data(&hash).await,
        _ => return Ok(None),
    };
    Ok(Some(Value::Boolean(value)))
}

async fn identity_op(state: &RpcState, call: &Value) -> Result<Option<Value>, String> {
    let operation = map_get(call, "identity_data")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing identity_data".to_string())?;
    if operation != "retain" {
        return Ok(None);
    }
    let hash = required_hash(call, "identity_hash")?;
    Ok(Some(Value::Boolean(
        state.transport.retain_identity(&hash).await,
    )))
}

/// `{"request":"path","destination_hash":...}` emits `Transport.request_path`.
/// Any other `request` value is ignored so unknown ops produce no reply.
async fn request_op(state: &RpcState, call: &Value) -> Result<Option<Value>, String> {
    let operation = map_get(call, "request")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing request".to_string())?;
    if operation != "path" {
        return Ok(None);
    }
    let hash = required_hash(call, "destination_hash")?;
    state.transport.request_path(&hash, None, None).await;
    Ok(Some(Value::Boolean(true)))
}

async fn path_table(state: &RpcState, call: &Value) -> Result<Value, String> {
    let max_hops_v = map_get(call, "max_hops").ok_or_else(|| "missing max_hops".to_string())?;
    let max_hops = if max_hops_v.is_nil() {
        None
    } else {
        Some(as_u64(max_hops_v).ok_or_else(|| "invalid max_hops".to_string())?)
    };
    let now = unix_now();
    let labels = {
        let manager = state.transport.iface_manager();
        let manager = manager.lock().await;
        manager
            .stats()
            .into_iter()
            .map(|stat| {
                let name = interface_display_name(&manager, &stat.kind, &stat.name, &stat.address);
                (stat.address, name)
            })
            .collect::<Vec<_>>()
    };
    let mut rows = Vec::new();
    for entry in state.transport.path_table_snapshot().await {
        if max_hops.is_some_and(|max| u64::from(entry.hops) > max) {
            continue;
        }
        let interface = labels
            .iter()
            .find(|(address, _)| *address == entry.iface)
            .map(|(_, name)| name.clone())
            .unwrap_or_else(|| "None".to_string());
        let timestamp = now - entry.age_secs as f64;
        rows.push(Value::Map(vec![
            (
                Value::from("hash"),
                Value::Binary(entry.destination.as_slice().to_vec()),
            ),
            (Value::from("timestamp"), Value::from(timestamp)),
            (
                Value::from("via"),
                Value::Binary(entry.via.as_slice().to_vec()),
            ),
            (Value::from("hops"), Value::from(u64::from(entry.hops))),
            (Value::from("expires"), Value::from(entry.expires_unix)),
            (Value::from("interface"), Value::from(interface)),
        ]));
    }
    Ok(Value::Array(rows))
}

async fn rate_table(state: &RpcState) -> Value {
    let now = unix_now();
    let rows = state
        .transport
        .rate_table_snapshot()
        .await
        .into_iter()
        .map(|entry| rate_row(&entry, now))
        .collect();
    Value::Array(rows)
}

fn rate_row(entry: &RateTableEntry, now: f64) -> Value {
    let last = now - entry.since_last.as_secs_f64();
    let blocked_until = entry
        .blocked_for
        .map(|blocked| now + blocked.as_secs_f64())
        .unwrap_or(0.0);
    Value::Map(vec![
        (
            Value::from("hash"),
            Value::Binary(entry.destination.as_slice().to_vec()),
        ),
        (Value::from("last"), Value::from(last)),
        (
            Value::from("rate_violations"),
            Value::from(u64::from(entry.violations)),
        ),
        (Value::from("blocked_until"), Value::from(blocked_until)),
        (
            Value::from("timestamps"),
            Value::Array(entry.timestamps.iter().copied().map(Value::from).collect()),
        ),
    ])
}

async fn interface_stats(state: &RpcState) -> Value {
    let manager = state.transport.iface_manager();
    let manager = manager.lock().await;
    let stats = manager.stats();
    let mut interfaces = Vec::new();
    for stat in &stats {
        let mtu = manager.iface_hw_mtu(&stat.address);
        let display = interface_display_name(&manager, &stat.kind, &stat.name, &stat.address);
        let clients = manager.local_server_clients(&stat.address);
        let radio = manager.radio_telemetry(&stat.address);
        let entry = manager
            .with_control(&stat.address, |control| {
                interface_entry(stat, control, mtu, &display, clients, &radio)
            })
            .unwrap_or_else(|| {
                let mut control = IfaceControlState::new(tokio::time::Instant::now());
                interface_entry(stat, &mut control, mtu, &display, clients, &radio)
            });
        interfaces.push(entry);
    }
    drop(manager);

    let (total, heights, drops) = state.transport.inbound_queue_snapshot().await;
    let lengths = state.transport.inbound_queue_lengths().await;
    let tql = lengths.iter().sum::<usize>();
    // Transport-wide byte rates and PPS are not counted. Omit them
    // instead of reporting zero.
    let mut map = vec![
        (Value::from("interfaces"), Value::Array(interfaces)),
        (Value::from("rxqt"), Value::from(total as u64)),
        (Value::from("rxqd"), Value::from(heights[0] as u64)),
        (Value::from("rxqa"), Value::from(heights[1] as u64)),
        (Value::from("rxqp"), Value::from(heights[2] as u64)),
        (Value::from("rxqil"), Value::from(heights[3] as u64)),
        (Value::from("rxqtd"), Value::from(drops.iter().sum::<u64>())),
        (Value::from("rxqdd"), Value::from(drops[0])),
        (Value::from("rxqad"), Value::from(drops[1])),
        (Value::from("rxqpd"), Value::from(drops[2])),
        (Value::from("rxqild"), Value::from(drops[3])),
        (Value::from("tqpressure"), Value::from(pressure(total, tql))),
        (
            Value::from("dqpressure"),
            Value::from(pressure(heights[0], lengths[0])),
        ),
        (
            Value::from("aqpressure"),
            Value::from(pressure(heights[1], lengths[1])),
        ),
        (
            Value::from("pqpressure"),
            Value::from(pressure(heights[2], lengths[2])),
        ),
        (
            Value::from("ilqpressure"),
            Value::from(pressure(heights[3], lengths[3])),
        ),
        (Value::from("txq"), Value::Nil),
        (Value::from("rss"), Value::Nil),
    ];
    if state.transport_enabled {
        map.push((
            Value::from("transport_id"),
            Value::Binary(state.transport.identity_hash().await.as_slice().to_vec()),
        ));
        map.push((
            Value::from("network_id"),
            match &state.network_identity {
                Some(hash) => Value::Binary(hash.as_slice().to_vec()),
                None => Value::Nil,
            },
        ));
        map.push((
            Value::from("probe_responder"),
            match &state.probe_hash {
                Some(hash) => Value::Binary(hash.as_slice().to_vec()),
                None => Value::Nil,
            },
        ));
        map.push((
            Value::from("transport_uptime"),
            Value::from(state.started.elapsed().as_secs_f64()),
        ));
    }
    Value::Map(map)
}

fn interface_entry(
    stat: &InterfaceStats,
    control: &mut IfaceControlState,
    mtu: Option<usize>,
    display_name: &str,
    clients: Option<u64>,
    radio: &RadioTelemetry,
) -> Value {
    let now = tokio::time::Instant::now();
    // Instantaneous speeds, TX drops, stall, and the transmit buffer are
    // not counted. Omit those keys rather than reporting zero.
    let mut map = vec![
        (Value::from("name"), Value::from(display_name.to_string())),
        (Value::from("short_name"), Value::from(stat.name.clone())),
        (
            Value::from("hash"),
            Value::Binary(stat.address.as_slice().to_vec()),
        ),
        (Value::from("type"), Value::from(stat.kind.clone())),
        (Value::from("status"), Value::Boolean(stat.online)),
        (
            Value::from("mode"),
            Value::from(u64::from(control.mode as u8)),
        ),
        (
            Value::from("clients"),
            clients.map(Value::from).unwrap_or(Value::Nil),
        ),
        (Value::from("rxb"), Value::from(stat.rx_bytes)),
        (Value::from("txb"), Value::from(stat.tx_bytes)),
        (Value::from("bitrate"), Value::from(control.bitrate)),
        (
            Value::from("arxb"),
            Value::from(stat.announce_bytes_received),
        ),
        (Value::from("atxb"), Value::from(stat.announce_bytes_sent)),
        (Value::from("arxc"), Value::from(stat.announces_received)),
        (Value::from("atxc"), Value::from(stat.announces_sent)),
        (
            Value::from("prxc"),
            Value::from(stat.path_requests_received),
        ),
        (Value::from("ptxc"), Value::from(stat.path_requests_sent)),
        (
            Value::from("incoming_announce_frequency"),
            Value::from(control.incoming_announce_frequency(now)),
        ),
        (
            Value::from("outgoing_announce_frequency"),
            Value::from(control.outgoing_announce_frequency(now)),
        ),
        (
            Value::from("incoming_pr_frequency"),
            Value::from(control.incoming_pr_frequency(now)),
        ),
        (
            Value::from("outgoing_pr_frequency"),
            Value::from(control.outgoing_pr_frequency(now)),
        ),
        (
            Value::from("held_announces"),
            Value::from(control.held_announces_len() as u64),
        ),
        (
            Value::from("announce_queue"),
            Value::from(control.queued_announces_len() as u64),
        ),
        (Value::from("gravity"), Value::from(control.gravity)),
        (
            Value::from("protocol_violations"),
            Value::from(stat.protocol_violations),
        ),
        (
            Value::from("ifac_violations"),
            Value::from(stat.ifac_violations),
        ),
        (
            Value::from("packet_filter_hits"),
            Value::from(stat.packet_filter_hits),
        ),
        (Value::from("ifac_signature"), Value::Nil),
        (Value::from("ifac_size"), Value::Nil),
        (Value::from("ifac_netname"), Value::Nil),
        (
            Value::from("announces_to_internal"),
            match control.announces_to_internal {
                Some(value) => Value::Boolean(value),
                None => Value::Nil,
            },
        ),
    ];
    push_opt_secs(
        &mut map,
        "announce_rate_target",
        control.announce_rate_target,
    );
    push_opt_secs(
        &mut map,
        "announce_rate_penalty",
        control.announce_rate_penalty,
    );
    if let Some(grace) = control.announce_rate_grace {
        map.push((
            Value::from("announce_rate_grace"),
            Value::from(u64::from(grace)),
        ));
    }
    if let Some(mtu) = mtu {
        map.push((Value::from("mtu"), Value::from(mtu as u64)));
    }
    push_opt_f32(&mut map, "airtime_short", radio.airtime_short);
    push_opt_f32(&mut map, "airtime_long", radio.airtime_long);
    push_opt_f32(&mut map, "channel_load_short", radio.channel_load_short);
    push_opt_f32(&mut map, "channel_load_long", radio.channel_load_long);
    Value::Map(map)
}

fn push_opt_f32(map: &mut Vec<(Value, Value)>, key: &str, value: Option<f32>) {
    if let Some(value) = value {
        map.push((Value::from(key), Value::from(f64::from(value))));
    }
}

fn push_opt_secs(map: &mut Vec<(Value, Value)>, key: &str, value: Option<Duration>) {
    if let Some(value) = value {
        map.push((Value::from(key), Value::from(value.as_secs_f64())));
    }
}

async fn next_hop_hash(state: &RpcState, destination: &AddressHash) -> Option<AddressHash> {
    if let Some((via, _)) = state.transport.next_hop(destination).await {
        return Some(via);
    }
    if state.transport.has_destination(destination).await {
        return Some(state.transport.identity_hash().await);
    }
    None
}

async fn next_hop_if_name(state: &RpcState, destination: &AddressHash) -> String {
    if let Some((_, iface)) = state.transport.next_hop(destination).await {
        let manager = state.transport.iface_manager();
        let manager = manager.lock().await;
        if let Some(stat) = manager
            .stats()
            .into_iter()
            .find(|stat| stat.address == iface)
        {
            return interface_display_name(&manager, &stat.kind, &stat.name, &stat.address);
        }
        return "None".to_string();
    }
    if state.transport.has_destination(destination).await {
        let manager = state.transport.iface_manager();
        let manager = manager.lock().await;
        if let Some(stat) = manager
            .stats()
            .into_iter()
            .find(|stat| stat.kind == "LocalServer")
        {
            return interface_display_name(&manager, &stat.kind, &stat.name, &stat.address);
        }
    }
    "None".to_string()
}

fn guessed_bitrate(kind: &str, bitrate: u64) -> u64 {
    if bitrate != DEFAULT_BITRATE {
        return bitrate;
    }
    match kind {
        "LocalServer" | "LocalClient" => SHARED_BITRATE_GUESS,
        "TcpServer" | "TcpClient" | "UdpInterface" => TCP_UDP_BITRATE_GUESS,
        _ => bitrate,
    }
}

async fn iface_timeout_bitrate(state: &RpcState, address: &AddressHash) -> Option<u64> {
    let manager = state.transport.iface_manager();
    let manager = manager.lock().await;
    let kind = manager
        .stats()
        .into_iter()
        .find(|stat| stat.address == *address)
        .map(|stat| stat.kind)?;
    let bitrate = manager.with_control(address, |control| control.bitrate)?;
    Some(guessed_bitrate(&kind, bitrate))
}

async fn first_hop_timeout(state: &RpcState, destination: &AddressHash) -> f64 {
    let bitrate = if let Some((_, iface)) = state.transport.next_hop(destination).await {
        iface_timeout_bitrate(state, &iface).await
    } else if state.transport.has_destination(destination).await {
        let manager = state.transport.iface_manager();
        let manager = manager.lock().await;
        let local = manager
            .stats()
            .into_iter()
            .find(|stat| stat.kind == "LocalServer")
            .and_then(|stat| {
                manager.with_control(&stat.address, |control| {
                    guessed_bitrate(&stat.kind, control.bitrate)
                })
            });
        Some(local.unwrap_or(DEFAULT_BITRATE))
    } else {
        None
    };
    match bitrate {
        Some(bitrate) if bitrate > 0 => {
            PROTOCOL_MTU as f64 * 8.0 / bitrate as f64 + DEFAULT_PER_HOP_TIMEOUT
        }
        _ => DEFAULT_PER_HOP_TIMEOUT,
    }
}

async fn medium_path_timeout(state: &RpcState) -> f64 {
    const MINIMUM_BITRATE: f64 = 5.0;
    let manager = state.transport.iface_manager();
    let manager = manager.lock().await;
    let mut lowest: Option<u64> = None;
    for stat in manager.stats() {
        if !stat.online {
            continue;
        }
        let Some(bitrate) = manager.with_control(&stat.address, |control| control.bitrate) else {
            continue;
        };
        let bitrate = guessed_bitrate(&stat.kind, bitrate);
        lowest = Some(lowest.map_or(bitrate, |current| current.min(bitrate)));
    }
    let Some(bitrate) = lowest else {
        return 0.0;
    };
    2.0 * (PROTOCOL_MTU as f64 * 8.0 / (bitrate as f64).max(MINIMUM_BITRATE))
        + DEFAULT_PER_HOP_TIMEOUT
}

async fn drop_all_via(state: &RpcState, via: &AddressHash) -> u64 {
    let destinations: Vec<AddressHash> = state
        .transport
        .path_table_snapshot()
        .await
        .into_iter()
        .filter(|entry| entry.via == *via)
        .map(|entry| entry.destination)
        .collect();
    let mut dropped = 0u64;
    for destination in destinations {
        if state.transport.expire_path(&destination).await {
            dropped += 1;
        }
    }
    dropped
}

async fn blackholed_identities(state: &RpcState) -> Value {
    let packed = state.transport.blackholes().read().await.pack_table();
    rmpv::decode::read_value(&mut packed.as_slice()).unwrap_or(Value::Map(Vec::new()))
}

async fn ask_manage(state: &RpcState, op: ManageOp) -> Option<bool> {
    let Some(sender) = &state.manage else {
        return Some(false);
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    if sender
        .send(ManageRequest {
            op,
            reply: reply_tx,
        })
        .await
        .is_err()
    {
        return Some(false);
    }
    match tokio::time::timeout(Duration::from_secs(30), reply_rx).await {
        Ok(Ok(value)) => value,
        _ => Some(false),
    }
}

fn phy_value(value: Option<f64>) -> Value {
    match value {
        Some(value) => Value::from(value),
        None => Value::Nil,
    }
}

/// Python `str(interface)`. Spawned TCP and backbone peers are named
/// `Client on {parent}` in that string. `short_name` on the stat stays
/// the manager name so detach-by-config-name still finds the parent.
fn interface_display_name(
    manager: &reticulum::iface::InterfaceManager,
    kind: &str,
    short_name: &str,
    address: &AddressHash,
) -> String {
    let endpoint = manager.iface_endpoint(address);
    let label = match (kind, manager.spawned_parent_name(address)) {
        ("TcpClient" | "BackboneClient", Some(parent)) => format!("Client on {parent}"),
        _ => short_name.to_string(),
    };
    python_interface_name(kind, &label, &endpoint)
}

/// Python `str(interface)` from the Rust kind, config name, and endpoint.
fn python_interface_name(kind: &str, short_name: &str, endpoint: &str) -> String {
    let short = if short_name.is_empty() {
        kind
    } else {
        short_name
    };
    match kind {
        "TcpServer" => format!("TCPServerInterface[{short}/{}]", host_port(endpoint)),
        "TcpClient" => format!("TCPInterface[{short}/{}]", host_port(endpoint)),
        "UdpInterface" => format!("UDPInterface[{short}/{}]", host_port(endpoint)),
        "AutoInterface" => format!("AutoInterface[{short}]"),
        "AutoPeer" => {
            let body = short
                .strip_prefix("AutoPeer[")
                .and_then(|rest| rest.strip_suffix(']'))
                .unwrap_or(short);
            format!("AutoInterfacePeer[{body}]")
        }
        "BackboneServer" | "BackboneClient" => {
            format!("BackboneInterface[{short}/{}]", host_port(endpoint))
        }
        "LocalServer" => format!("Shared Instance[{}]", local_bracket(endpoint)),
        "LocalClient" => {
            let label = local_bracket(endpoint);
            let label = if label.is_empty() {
                short.to_string()
            } else {
                label
            };
            format!("LocalInterface[{label}]")
        }
        "I2pInterface" | "I2PInterface" => format!("I2PInterface[{short}]"),
        other => format!("{other}[{short}]"),
    }
}

fn host_port(endpoint: &str) -> String {
    if let Some((host, port)) = endpoint.rsplit_once(':')
        && host.contains(':')
        && !host.starts_with('[')
    {
        return format!("[{host}]:{port}");
    }
    endpoint.to_string()
}

fn local_bracket(endpoint: &str) -> String {
    let trimmed = endpoint.trim_start_matches('\0');
    if let Some(port) = trimmed.strip_prefix("127.0.0.1:") {
        port.to_string()
    } else {
        trimmed.to_string()
    }
}

fn pressure(height: usize, length: usize) -> f64 {
    if height == 0 || length == 0 {
        0.0
    } else {
        height as f64 / length as f64
    }
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, item)| item)
}

fn required_hash(call: &Value, key: &str) -> Result<AddressHash, String> {
    hash_of(map_get(call, key).ok_or_else(|| format!("missing {key}"))?)
        .ok_or_else(|| format!("invalid {key}"))
}

fn required_packet_hash(call: &Value, key: &str) -> Result<Hash, String> {
    packet_hash_of(map_get(call, key).ok_or_else(|| format!("missing {key}"))?)
        .ok_or_else(|| format!("invalid {key}"))
}

fn packet_hash_of(value: &Value) -> Option<Hash> {
    if let Some(bytes) = value.as_slice() {
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        return Some(Hash::new(bytes));
    }
    let text = value.as_str()?;
    let cleaned = text.trim().trim_matches(|ch| ch == '<' || ch == '>');
    if cleaned.len() != 64 || !cleaned.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (slot, chunk) in bytes.iter_mut().zip(cleaned.as_bytes().as_chunks::<2>().0) {
        let hex = std::str::from_utf8(chunk).ok()?;
        *slot = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(Hash::new(bytes))
}

fn hash_of(value: &Value) -> Option<AddressHash> {
    if let Some(bytes) = value.as_slice() {
        return AddressHash::new_from_raw_slice(bytes);
    }
    let text = value.as_str()?;
    let cleaned = text.trim().trim_matches(|ch| ch == '<' || ch == '>');
    if cleaned.len() != 32 || !cleaned.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    AddressHash::new_from_hex_string(cleaned).ok()
}

fn as_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|item| item as f64))
        .or_else(|| value.as_u64().map(|item| item as f64))
}

fn as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|item| u64::try_from(item).ok()))
        .or_else(|| {
            value.as_f64().and_then(|item| {
                if item >= 0.0 && item <= u64::MAX as f64 {
                    Some(item as u64)
                } else {
                    None
                }
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use reticulum::identity::PrivateIdentity;
    use reticulum::transport::TransportConfig;

    #[tokio::test]
    async fn authenticated_client_receives_path_table() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let transport = Arc::new(TransportConfig::new("rpc-test", &identity).build());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let authkey = b"rpc-test-key".to_vec();
        let state = Arc::new(RpcState {
            transport,
            authkey: authkey.clone(),
            manage: None,
            transport_enabled: false,
            network_identity: None,
            probe_hash: None,
            started: Instant::now(),
        });
        tokio::spawn(async move {
            serve_tcp(listener, state).await;
        });

        let request = Value::Map(vec![
            (Value::from("get"), Value::from("path_table")),
            (Value::from("max_hops"), Value::Nil),
        ]);
        let response = reticulum_utils::rpc::call(
            &reticulum_utils::rpc::ControlAddr::Tcp(port),
            &authkey,
            &request,
        )
        .await
        .expect("path table");
        assert!(response.is_array());

        let denied = reticulum_utils::rpc::call(
            &reticulum_utils::rpc::ControlAddr::Tcp(port),
            b"wrong-key",
            &request,
        )
        .await;
        assert!(denied.is_err());
    }

    #[tokio::test]
    async fn spawned_peer_rpc_name_uses_client_on_parent() {
        use reticulum::iface::InterfaceManager;
        use reticulum::iface::tcp_client::TcpClient;
        use reticulum::iface::tcp_server::TcpServer;
        use std::sync::Arc;

        let shared = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(4)));
        let parent = {
            let mut manager = shared.lock().await;
            let server = TcpServer::new("0.0.0.0:4242", Arc::clone(&shared));
            let context = manager.open_named("Server Interface", server);
            context.channel.address
        };
        let first_endpoint = "127.0.0.1:50000";
        let second_endpoint = "127.0.0.1:50001";
        let (first, second) = {
            let mut manager = shared.lock().await;
            let open = |manager: &mut InterfaceManager, endpoint: &str| {
                let context = manager.open_named(endpoint, TcpClient::new(endpoint));
                let address = context.channel.address;
                manager.note_spawned(&parent, &address);
                address
            };
            (
                open(&mut manager, first_endpoint),
                open(&mut manager, second_endpoint),
            )
        };
        let manager = shared.lock().await;
        let tcp = super::interface_display_name(&manager, "TcpClient", first_endpoint, &first);
        assert_eq!(
            tcp,
            "TCPInterface[Client on Server Interface/127.0.0.1:50000]"
        );
        assert!(tcp.starts_with("TCPInterface[Client"));
        let backbone =
            super::interface_display_name(&manager, "BackboneClient", second_endpoint, &second);
        assert_eq!(
            backbone,
            "BackboneInterface[Client on Server Interface/127.0.0.1:50001]"
        );
        assert!(backbone.starts_with("BackboneInterface[Client on"));
        let stats = manager.stats();
        assert_eq!(
            stats
                .iter()
                .find(|stat| stat.address == parent)
                .unwrap()
                .name,
            "Server Interface"
        );
        assert_eq!(
            stats
                .iter()
                .find(|stat| stat.address == first)
                .unwrap()
                .name,
            first_endpoint
        );
        let auto =
            super::interface_display_name(&manager, "AutoPeer", "AutoPeer[eth0/fe80::1]", &first);
        assert!(auto.starts_with("AutoInterfacePeer["));
        let (map, ambiguous) = manager.classify_stable_ids();
        assert!(ambiguous.is_empty());
        assert!(map.values().any(|address| *address == first));
        assert!(map.values().any(|address| *address == second));
    }

    #[tokio::test]
    async fn path_request_rpc_returns_true() {
        let identity = PrivateIdentity::new_from_rand(OsRng);
        let transport = Arc::new(TransportConfig::new("rpc-path", &identity).build());
        let state = RpcState {
            transport,
            authkey: b"k".to_vec(),
            manage: None,
            transport_enabled: false,
            network_identity: None,
            probe_hash: None,
            started: Instant::now(),
        };
        let request = Value::Map(vec![
            (Value::from("request"), Value::from("path")),
            (
                Value::from("destination_hash"),
                Value::Binary(vec![0x11; 16]),
            ),
        ]);
        let out = dispatch(&state, &request).await;
        assert_eq!(out, vec![Value::Boolean(true)]);

        let unknown = Value::Map(vec![(Value::from("request"), Value::from("other"))]);
        assert!(dispatch(&state, &unknown).await.is_empty());
    }
}
