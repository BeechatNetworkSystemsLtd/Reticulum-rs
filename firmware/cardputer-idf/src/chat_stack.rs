//! On-device Reticulum + LXMF chat stack.
//!
//! One dedicated thread (`chat`, 96 KiB stack) runs a current_thread
//! tokio runtime hosting: an in-process RNode link bridged onto the
//! modem session bus, the full `RnodeInterface` bring-up (firmware
//! detect + radio config frames), a `Transport`, and an `LxmRouter`.
//! The UI side gets two std::mpsc endpoints and never touches async.
//!
//! Link bridge (spec): `bus.register()` gives a `SessionGuard` whose
//! `rx` yields modem->host KISS frames; `bus.send_in(id, ..)` queues
//! host->modem bytes. A `tokio::io::duplex(2048)` pair is the tokio end:
//! the link side is split and handed to `RnodeLink::from_reader_writer`,
//! independent async pumps connect it to blocking bus helper threads.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use esp_idf_sys as sys;
use lxmf::router::{AnnounceInfo, DeliveryConfig, LxmEvent, LxmRouter, RouterConfig};
use lxmf::LXMessage;
use reticulum::hash::{AddressHash, Hash};
use reticulum::iface::rnode::{RnodeInterface, RnodeLink, RnodeRadioConfig};
use reticulum::identity::{OsRng, PrivateIdentity};
use reticulum::transport::{Transport, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bus::Bus;

/// Events surfaced to the UI thread.
#[derive(Debug)]
pub enum ChatEvent {
    /// A peer's lxmf.delivery announce arrived.
    Peer { dest_hash: [u8; 16], name: String },
    /// A message arrived; `name` is the peer's last announced display
    /// name, or its hex hash when none was seen.
    Received { from: [u8; 16], name: String, body: String },
    /// A message we sent was acknowledged by the recipient.
    Receipt { dest_hash: [u8; 16] },
    /// Stack lifecycle/failure line.
    Status(String),
}

/// Commands from the UI thread.
#[derive(Debug, Clone)]
pub enum ChatAction {
    Send { dest_hash: [u8; 16], body: String },
    Announce,
}

/// Mount the `storage` littlefs partition at `/reticulum`.
/// Returns false on failure; identity still persists in NVS.
pub fn mount_storage() -> bool {
    let mut conf = sys::esp_vfs_littlefs_conf_t::default();
    conf.base_path = b"/reticulum\0".as_ptr().cast::<core::ffi::c_char>();
    conf.partition_label = b"storage\0".as_ptr().cast::<core::ffi::c_char>();
    conf.set_format_if_mount_failed(1);
    unsafe {
        if sys::esp_littlefs_mounted(conf.partition_label) {
            return true;
        }
        match sys::esp_vfs_littlefs_register(&conf) {
            e if e == sys::ESP_OK => {
                crate::clog!("chat: littlefs mounted at /reticulum");
                true
            }
            e => {
                crate::clog!("chat: littlefs mount failed: {}", e);
                false
            }
        }
    }
}

// ---- NVS identity fallback ----
// Stores the same 128-character hex private key as the keyfile.
// Key "identity", namespace "rns".

fn nvs_open_rw() -> Option<sys::nvs_handle_t> {
    unsafe {
        let _ = sys::nvs_flash_init(); // idempotent; wifi may have done it
        let mut h: sys::nvs_handle_t = 0;
        if sys::nvs_open(
            b"rns\0".as_ptr().cast::<core::ffi::c_char>(),
            sys::nvs_open_mode_t_NVS_READWRITE,
            &mut h,
        ) == sys::ESP_OK
        {
            Some(h)
        } else {
            None
        }
    }
}

fn nvs_identity_load() -> Option<PrivateIdentity> {
    let h = nvs_open_rw()?;
    let mut buf = [0u8; 128];
    let mut len = buf.len();
    let ok = unsafe {
        sys::nvs_get_blob(
            h,
            b"identity\0".as_ptr().cast::<core::ffi::c_char>(),
            buf.as_mut_ptr().cast::<core::ffi::c_void>(),
            &mut len,
        ) == sys::ESP_OK
    };
    unsafe { sys::nvs_close(h) };
    if ok && len == buf.len() {
        std::str::from_utf8(&buf).ok().and_then(identity_from_hex)
    } else {
        None
    }
}

fn nvs_identity_store(id: &PrivateIdentity) {
    if let Some(h) = nvs_open_rw() {
        let bytes = id.to_hex_string();
        unsafe {
            if sys::nvs_set_blob(
                h,
                b"identity\0".as_ptr().cast::<core::ffi::c_char>(),
                bytes.as_ptr().cast::<core::ffi::c_void>(),
                bytes.len(),
            ) == sys::ESP_OK
            {
                if sys::nvs_commit(h) != sys::ESP_OK {
                    crate::clog!("chat: identity NVS commit failed");
                }
            }
            else {
                crate::clog!("chat: identity NVS write failed");
            }
            sys::nvs_close(h);
        }
    }
    else {
        crate::clog!("chat: identity NVS unavailable");
    }
}

fn identity_from_hex(hex: &str) -> Option<PrivateIdentity> {
    let hex = hex.trim();
    // The upstream hex constructor unwraps parsing and slices by byte.
    if hex.len() != 128 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    PrivateIdentity::new_from_hex_string(hex).ok()
}

/// Identity load order: hex keyfile `{data_dir}/identities/default`
/// (same single-hex-line format reticulum-actor writes), then NVS blob,
/// else a fresh OsRng identity persisted to both.
fn load_or_create_identity(data_dir: &str) -> anyhow::Result<PrivateIdentity> {
    let dir = format!("{data_dir}/identities");
    let path = format!("{dir}/default");
    let keyfile = std::fs::read_to_string(&path);
    if let Ok(hex) = &keyfile {
        if let Some(id) = identity_from_hex(hex) {
            crate::clog!("chat: identity loaded from {path}");
            return Ok(id);
        }
        crate::clog!("chat: unreadable identity file at {path}, trying NVS");
    }
    if let Some(id) = nvs_identity_load() {
        crate::clog!("chat: identity loaded from NVS");
        return Ok(id);
    }
    if keyfile.is_ok() || keyfile.as_ref().err().is_some_and(|e| e.kind() == std::io::ErrorKind::InvalidData) {
        anyhow::bail!("invalid identity file at {path}; refusing to replace the private key");
    }
    let id = PrivateIdentity::new_from_rand(OsRng);
    if std::fs::create_dir_all(&dir).is_ok()
        && std::fs::write(&path, id.to_hex_string().as_bytes()).is_ok()
    {
        crate::clog!("chat: new identity written to {path}");
    } else {
        crate::clog!("chat: keyfile unavailable, persisting identity to NVS");
    }
    // Preserve identity even if the filesystem could not be mounted.
    nvs_identity_store(&id);
    Ok(id)
}

/// Spawn the chat stack thread. `bus` is the session bus from
/// `Bus::new()`; `data_dir` is the persistence root (use `/reticulum`
/// after `mount_storage()`, though the NVS fallback works either way).
pub fn start(
    bus: &Arc<Bus>,
    data_dir: &str,
) -> anyhow::Result<(
    Sender<ChatAction>,
    Receiver<ChatEvent>,
    std::sync::mpsc::Sender<()>,
)> {
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let (action_tx, action_rx) = std::sync::mpsc::channel::<ChatAction>();
    let (event_tx, event_rx) = std::sync::mpsc::channel::<ChatEvent>();
    // Action feeder: bridge the std mpsc channel into the runtime's
    // unbounded channel. Spawned HERE (pre-gate) so its stack is
    // allocated before the transport/router allocations fragment the
    // heap — the post-announce spawn ran into ENOMEM on the S3.
    let (act_tx, act_rx_rt) = tokio::sync::mpsc::unbounded_channel::<ChatAction>();
    let feeder_tx = act_tx.clone();
    std::thread::Builder::new()
        .name("chat-act".into())
        .stack_size(4 * 1024)
        .spawn(move || {
            while let Ok(a) = action_rx.recv() {
                if feeder_tx.send(a).is_err() {
                    break;
                }
            }
        })?;
    let bus = Arc::clone(bus);
    let data_dir = data_dir.to_string();
    std::thread::Builder::new()
        .name("chat".into())
        // Measured peak is ~47 KiB with real LXMF delivery; reserve twice that.
        .stack_size(96 * 1024)
        .spawn(move || {
            // tokio's mio backend needs eventfd, which ESP-IDF VFS does
            // not provide until registered (eventfd() returns EPERM
            // otherwise — seen as "tokio runtime failed: Permission
            // denied" on the first flash).
            unsafe {
                let cfg = esp_idf_sys::esp_vfs_eventfd_config_t { max_fds: 4 };
                esp_idf_sys::esp_vfs_eventfd_register(&cfg);
            }
            // (bisect probes removed: tokio 1.5x crashes at runtime on
            // xtensa-espidf; 1.44.2 pinned in Cargo.toml)
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                // RAM: the blocking pool defaults to 2 MB stacks — instant
                // ENOMEM on the S3's ~375 KB heap ("pthread: Failed to
                // create task"). One small blocking thread is all the
                // duplex pumps need.
                .max_blocking_threads(1)
                .thread_stack_size(8 * 1024)
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    crate::clog!("chat: tokio runtime failed: {e}");
                    let _ = event_tx
                        .send(ChatEvent::Status(format!("tokio runtime failed: {e}")));
                    return;
                }
            };
            if let Err(e) = rt.block_on(run(bus, data_dir, act_rx_rt, event_tx.clone(), gate_rx)) {
                crate::clog!("chat: stack exited: {e:?}");
                let _ = event_tx.send(ChatEvent::Status(format!("chat stopped: {e:?}")));
            }
        })?;
    Ok((action_tx, event_rx, gate_tx))
}

fn hash16(h: &AddressHash) -> [u8; 16] {
    let mut b = [0u8; 16];
    b.copy_from_slice(h.as_slice());
    b
}

async fn run(
    bus: Arc<Bus>,
    data_dir: String,
    action_rx: tokio::sync::mpsc::UnboundedReceiver<ChatAction>,
    events: Sender<ChatEvent>,
    gate: Receiver<()>,
) -> anyhow::Result<()> {
    // Hold all heap-heavy init until every thread stack in main() is
    // allocated: the transport/router allocations fragment the heap and
    // later 32 KB+ stack requests fail with ENOMEM.
    let _ = gate.recv();
    let status = |msg: String| {
        crate::clog!("chat: {}", msg);
        let _ = events.send(ChatEvent::Status(msg));
    };
    // Mount is retried/owned here too so callers can't forget it.
    let mounted = mount_storage();
    if !mounted {
        status("storage unmounted — NVS identity only, no LXMF persistence".into());
    }

    let identity = load_or_create_identity(&data_dir)?;
    status(format!("identity {}", identity.address_hash().to_hex_string()));

    // ---- In-process RNode link over the session bus ----
    let guard = bus.register();
    let session_id = guard.id;

    // Keep blocking modem I/O outside the runtime.
    let (bus_tx, mut bus_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::Builder::new()
        .name("chat-bus-rx".into())
        .stack_size(4 * 1024)
        .spawn(move || {
            while let Ok(frame) = guard.rx.recv() {
                if bus_tx.blocking_send(frame).is_err() {
                    break;
                }
            }
            // `guard` drops here -> session unregistered on link death.
        })?;

    let (mod_tx, mut mod_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let bus_out = Arc::clone(&bus);
    std::thread::Builder::new()
        .name("chat-bus-tx".into())
        .stack_size(4 * 1024)
        .spawn(move || {
            while let Some(bytes) = mod_rx.blocking_recv() {
                bus_out.send_in(session_id, bytes);
            }
        })?;

    let (bus_end, link_end) = tokio::io::duplex(2048);
    let (mut bus_r, mut bus_w) = tokio::io::split(bus_end);
    let (link_r, link_w) = tokio::io::split(link_end);
    // These pumps must run independently while router.send awaits a link.
    tokio::spawn(async move {
        while let Some(frame) = bus_rx.recv().await {
            if bus_w.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        loop {
            match bus_r.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if mod_tx.send(buffer[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    // link halves move into the RnodeInterface task below, keeping the
    // duplex alive for the program lifetime.
    let link = RnodeLink::from_reader_writer(Box::new(link_r), Box::new(link_w))
        .map_err(|e| anyhow::anyhow!("rnode link: {e:?}"))?;

    let iface = RnodeInterface::from_link(
        link,
        // Cap LoRa868: 125 kHz fits within the 869.4–869.65 MHz sub-band.
        // Use its 10% airtime limit; national rules and antenna ERP still apply.
        RnodeRadioConfig {
            frequency: 869_525_000,
            bandwidth: 125_000,
            txpower: 22,
            spreadingfactor: 9,
            codingrate: 5,
            st_alock: None,
            lt_alock: Some(10.0),
        },
    );
    // Bound retained packet buffers for the S3's internal heap.
    let mut tcfg = TransportConfig::new("cardputer", &identity);
    tcfg.channel_capacity = 2;
    tcfg.announce_cache_capacity = 2;
    tcfg.phy_cache_capacity = 0;
    // Chat never runs resource transfers (compose is capped at 240
    // chars); the watchdog task's ~2.5 KB future OOMs the spawn here.
    tcfg.enable_resource_watchdog = false;
    tcfg = tcfg
        .set_inbound_queue_length(reticulum::transport::TrafficClass::Data, 64)
        .set_inbound_queue_length(reticulum::transport::TrafficClass::Announce, 32)
        .set_inbound_queue_length(reticulum::transport::TrafficClass::PathRequest, 32);
    let transport = Transport::new(tcfg);
    transport
        .iface_manager()
        .lock()
        .await
        .spawn(iface, RnodeInterface::spawn);
    status("rnode interface spawned".into());

    // Router storage root is data_dir: LxmRouter joins "lxmf" itself.
    let router = LxmRouter::new(
        transport,
        identity.clone(),
        &data_dir,
        Some("cardputer"),
        Some(DeliveryConfig {
            identity: Some(identity.clone()),
            display_name: Some("Cardputer".into()),
            stamp_cost: None,
        }),
        // Keep event fan-out small on the no-PSRAM target.
        RouterConfig {
            event_channel_capacity: 4,
            ..Default::default()
        },
    )
    .await;
    let my_hash = router.delivery_destination_hash().await;
    let mut lxmf_rx = router.subscribe();
    router.announce_delivery().await;
    match my_hash {
        Some(h) => status(format!("lxmf delivery announced: {}", h.to_hex_string())),
        None => status("lxmf delivery destination missing".into()),
    }
    let mut reannounce = tokio::time::interval(std::time::Duration::from_secs(600));
    reannounce.tick().await; // consume the immediate first tick

    // (The action feeder thread lives in start(), spawned pre-gate; its
    // unbounded receiver arrives here as `action_rx`.)
    let mut act_rx = action_rx;

    // dest_hash -> display name (from announces); message_hash ->
    // dest_hash (receipt routing for outbound sends).
    let mut names: HashMap<[u8; 16], String> = HashMap::new();
    let mut outbound: HashMap<Hash, [u8; 16]> = HashMap::new();

    loop {
        tokio::select! {
            Some(act) = act_rx.recv() => match act {
                ChatAction::Announce => router.announce_delivery().await,
                ChatAction::Send { dest_hash, body } => {
                    let Some(src) = my_hash else {
                        status("send failed: no delivery destination".into());
                        continue;
                    };
                    let mut msg = LXMessage::new(
                        AddressHash::new(dest_hash),
                        src,
                        b"",
                        body.as_bytes(),
                    );
                    match router.send(&mut msg, &identity).await {
                        Ok(()) => {
                            if let Some(h) = msg.hash {
                                outbound.insert(h, dest_hash);
                            }
                        }
                        Err(e) => status(format!("send failed: {e:?}")),
                    }
                }
            },
            _ = reannounce.tick() => router.announce_delivery().await,
            ev = lxmf_rx.recv() => match ev {
                Ok(LxmEvent::Announce(AnnounceInfo::Delivery {
                    destination_hash, display_name, ..
                })) => {
                    let dh = hash16(&destination_hash);
                    if Some(destination_hash) != my_hash {
                        let name = display_name
                            .unwrap_or_else(|| destination_hash.to_hex_string());
                        names.insert(dh, name.clone());
                        let _ = events.send(ChatEvent::Peer { dest_hash: dh, name });
                    }
                }
                Ok(LxmEvent::Received(msg)) => {
                    let from = hash16(&msg.source_hash);
                    let name = names
                        .get(&from)
                        .cloned()
                        .unwrap_or_else(|| msg.source_hash.to_hex_string());
                    let body = String::from_utf8_lossy(&msg.content).into_owned();
                    let _ = events.send(ChatEvent::Received { from, name, body });
                }
                Ok(LxmEvent::DeliveryReceipt { message_hash }) => {
                    if let Some(dh) = outbound.remove(&message_hash) {
                        let _ = events.send(ChatEvent::Receipt { dest_hash: dh });
                    }
                }
                Ok(LxmEvent::SendFailed { message_hash, reason }) => {
                    if !matches!(reason, lxmf::router::SendFailure::PathUnknown) {
                        outbound.remove(&message_hash);
                    }
                    status(format!("send failed: {reason:?}"));
                }
                Ok(_) => {} // Duplicate/PropagationStored/PropagationTransfer
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    status(format!("lxmf events lagged by {n}"));
                }
                Err(_) => break,
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_hex_is_validated_before_upstream_parser() {
        assert!(identity_from_hex(&"ab".repeat(64)).is_some());
        assert!(identity_from_hex(&"zz".repeat(64)).is_none());
        assert!(identity_from_hex(&"é".repeat(64)).is_none());
        assert!(identity_from_hex("ab").is_none());
    }
}
