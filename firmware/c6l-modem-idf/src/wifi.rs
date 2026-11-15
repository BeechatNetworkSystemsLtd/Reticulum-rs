//! WiFi STA bring-up for the TCP bridge (BRIDGE_PLAN Phase 1 + Phase 4).
//!
//! Contract (pinned — do not change signatures):
//!   - `start()` spawns the 16 KB thread then BLOCKS until the DHCP
//!     address is printed or a 15 s timeout elapses (a waiting USB
//!     host's first FEND would otherwise silence `wifi: got ip`).
//!   - `ip_addr()` returns the DHCPv4 address once GOT_IP arrives.
//!   - Credentials come from `C6L_WIFI_SSID` / `C6L_WIFI_PASSWORD` env
//!     vars at BUILD time (`option_env!`); unset => WiFi stays off.
//!     (cargo won't rebuild on env change — `touch src/main.rs`.)
//!   - ALL logging goes through `crate::clog!` (KISS-safe) — never
//!     `println!` directly.
//!   - Reconnect on disconnect with bounded backoff (Phase 4).
//!
//! Implementation target: raw `esp_idf_sys` calls only (no esp-idf-svc —
//! version conflict with esp-idf-hal 0.47). CAUTION: the generated
//! `Default` for `wifi_init_config_t` is a bindgen ZERO-INIT, NOT the C
//! WIFI_INIT_CONFIG_DEFAULT() macro — `wifi_run` builds the config
//! field-by-field instead. `g_wifi_osi_funcs` is exported. Init
//! sequence per BRIDGE_PLAN:
//!   nvs_flash_init -> esp_netif_init -> esp_event_loop_create_default
//!   -> esp_netif_create_default_wifi_sta -> esp_wifi_init
//!   -> register WIFI_EVENT + IP_EVENT handlers -> set_mode(STA)
//!   -> set_config -> start -> esp_wifi_connect on STA_START.
//!
//! Threading: the extern "C" event handlers run on the esp_event task
//! and only touch atomics (state, disconnect counter, reason, IP) —
//! NO esp_wifi_* calls and NO blocking there. This thread polls those
//! atomics every 50 ms and drives connect/reconnect.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use esp_idf_sys::{
    esp_event_base_t, wifi_auth_mode_t_WIFI_AUTH_OPEN, wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK,
    wifi_event_sta_disconnected_t, wifi_init_config_t, wifi_interface_t_WIFI_IF_STA,
    wifi_mode_t_WIFI_MODE_STA, wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH,
    ESP_ERR_NVS_NEW_VERSION_FOUND, ESP_ERR_NVS_NO_FREE_PAGES, ESP_EVENT_ANY_ID, IP_EVENT,
    WIFI_EVENT,
};

// Event ids are c_uint (u32) in the bindings; handlers receive i32.
const EV_STA_START: i32 = esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_START as i32;
const EV_STA_DISCONNECTED: i32 = esp_idf_sys::wifi_event_t_WIFI_EVENT_STA_DISCONNECTED as i32;
const EV_STA_GOT_IP: i32 = esp_idf_sys::ip_event_t_IP_EVENT_STA_GOT_IP as i32;

// Link states, written ONLY by the event handler (0 = pre-STA_START).
// CONNECTING is loop-local (the `connect_issued` flag below): the
// handler can't know when we issued esp_wifi_connect.
const ST_STARTED: u8 = 1;
const ST_DISCONNECTED: u8 = 2;
const ST_GOT_IP: u8 = 3;

static LINK_STATE: AtomicU8 = AtomicU8::new(0);
static DISCONNECTS: AtomicU32 = AtomicU32::new(0);
static DISC_REASON: AtomicU32 = AtomicU32::new(0);
static GOT_IP: AtomicU32 = AtomicU32::new(0);
/// Set right after the `wifi: got ip` line hits the console — start()
/// blocks on it so the address can't be silenced by an early FEND.
static IP_PRINTED: AtomicBool = AtomicBool::new(false);

/// Spawn the WiFi bring-up/reconnect thread, then BLOCK until the
/// `wifi: got ip` line is printed or 15 s elapse (main() starts the
/// modem thread right after us; a waiting USB host's first FEND would
/// otherwise silence the clog! before it prints).
/// No-op (with a `clog!` note) when credentials are not compiled in.
pub fn start() {
    let ssid = option_env!("C6L_WIFI_SSID");
    let password = option_env!("C6L_WIFI_PASSWORD");
    let Some(ssid) = ssid else {
        crate::clog!("wifi: no credentials (build with C6L_WIFI_SSID/C6L_WIFI_PASSWORD) — off");
        return;
    };
    std::thread::Builder::new()
        .stack_size(16384)
        .spawn(move || {
            if let Err(e) = wifi_run(ssid, password) {
                // WiFi down is survivable: the LoRa/USB modem keeps
                // running; only the TCP bridge is unreachable.
                crate::clog!("wifi: bring-up failed: {:?} — link down until reboot", e);
            }
        })
        .expect("wifi thread spawn"); // pre-KISS panic is safe (tcp_bridge pattern)
    // Wait for the got-ip line: 150 × 100 ms polls ≈ 15 s.
    for _ in 0..150 {
        if IP_PRINTED.load(Ordering::Relaxed) {
            return;
        }
        unsafe { esp_idf_sys::vTaskDelay(10) }; // 100 ms (100 Hz ticks)
    }
    // No address yet (AP down / bring-up failed) — the modem MUST
    // still come up; the WiFi thread keeps retrying in the background.
    crate::clog!("wifi: no ip within 15s — continuing anyway");
}

/// The DHCPv4 address once associated, `None` before GOT_IP / after loss.
pub fn ip_addr() -> Option<Ipv4Addr> {
    let raw = GOT_IP.load(std::sync::atomic::Ordering::Relaxed);
    (raw != 0).then(|| Ipv4Addr::from(raw.to_be_bytes()))
}

fn esp(r: i32, what: &str) -> anyhow::Result<()> {
    if r == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{}: {}", what, r))
    }
}

// ---- event handlers (esp_event task context: keep them TINY) ----

unsafe extern "C" fn on_wifi_event(
    _arg: *mut core::ffi::c_void,
    _base: esp_event_base_t,
    id: i32,
    data: *mut core::ffi::c_void,
) {
    if id == EV_STA_START {
        LINK_STATE.store(ST_STARTED, Ordering::Relaxed);
    } else if id == EV_STA_DISCONNECTED {
        // Stash the 802.11 reason code for the loop to print; no I/O here.
        let reason = unsafe { (*(data as *const wifi_event_sta_disconnected_t)).reason as u32 };
        DISC_REASON.store(reason, Ordering::Relaxed);
        DISCONNECTS.fetch_add(1, Ordering::Relaxed);
        LINK_STATE.store(ST_DISCONNECTED, Ordering::Relaxed);
        GOT_IP.store(0, Ordering::Relaxed);
    }
}

unsafe extern "C" fn on_ip_event(
    _arg: *mut core::ffi::c_void,
    _base: esp_event_base_t,
    id: i32,
    data: *mut core::ffi::c_void,
) {
    if id == EV_STA_GOT_IP {
        let ev = unsafe { &*(data as *const esp_idf_sys::ip_event_got_ip_t) };
        // esp_ip4_addr stores octet1 in bits [7:0] (lwIP-style
        // ESP_IP4TOADDR convention: first octet is the LSB). ip_addr()
        // renders via to_be_bytes(), so byte-swap on the way in.
        GOT_IP.store(ev.ip_info.ip.addr.swap_bytes(), Ordering::Relaxed);
        LINK_STATE.store(ST_GOT_IP, Ordering::Relaxed);
    }
}

// ---- bring-up + reconnect loop (this 16 KB thread) ----

fn wifi_run(ssid: &str, password: Option<&str>) -> anyhow::Result<()> {
    // Heap before/after: WiFi+lwIP eat ~70-120 KB of the 512 KB C6 —
    // the plan's #1 risk, so measure it (plan's mitigation).
    let heap0 = unsafe { esp_idf_sys::esp_get_free_heap_size() };

    // 1. NVS — WiFi calibration data lives here. A partition left dirty
    //    by a previous image needs one erase + retry.
    let mut r = unsafe { esp_idf_sys::nvs_flash_init() };
    if r == ESP_ERR_NVS_NO_FREE_PAGES || r == ESP_ERR_NVS_NEW_VERSION_FOUND {
        unsafe { esp_idf_sys::nvs_flash_erase() };
        r = unsafe { esp_idf_sys::nvs_flash_init() };
    }
    esp(r, "nvs_flash_init")?;

    // 2-3. TCP/IP stack + default event loop.
    esp(unsafe { esp_idf_sys::esp_netif_init() }, "esp_netif_init")?;
    esp(
        unsafe { esp_idf_sys::esp_event_loop_create_default() },
        "esp_event_loop_create_default",
    )?;

    // 4. Default STA netif; keep the pointer for the thread's lifetime
    //    (it must never be freed — the driver owns it from here on).
    let _sta_netif = unsafe { esp_idf_sys::esp_netif_create_default_wifi_sta() };

    // 5. WiFi driver init config, mirroring WIFI_INIT_CONFIG_DEFAULT()
    //    (esp_wifi.h:251-276) with THIS build's sdkconfig values. The
    //    bindings' `Default` is bindgen ZERO-INIT — osi_funcs=NULL,
    //    zeroed wpa_crypto_funcs, buffer counts 0, magic=0 — which
    //    esp_wifi_init rejects (or crashes on), so the full literal is
    //    field-by-field instead. All values mirror this build's sdkconfig;
    //    NO deliberate deviations (the plan's ampdu_rx_enable=0 heap
    //    mitigation was tried and REJECTED — see the field below).
    let init_cfg = wifi_init_config_t {
        osi_funcs: core::ptr::addr_of_mut!(esp_idf_sys::g_wifi_osi_funcs), // pointer, not access
        wpa_crypto_funcs: unsafe { esp_idf_sys::g_wifi_default_wpa_crypto_funcs },
        static_rx_buf_num: 10,     // CONFIG_ESP_WIFI_STATIC_RX_BUFFER_NUM
        dynamic_rx_buf_num: 32,    // CONFIG_ESP_WIFI_DYNAMIC_RX_BUFFER_NUM
        tx_buf_type: 1,            // CONFIG_ESP_WIFI_TX_BUFFER_TYPE (dynamic)
        static_tx_buf_num: 0,      // CONFIG_ESP_WIFI_STATIC_TX_BUFFER unset
        dynamic_tx_buf_num: 32,    // CONFIG_ESP_WIFI_DYNAMIC_TX_BUFFER_NUM
        rx_mgmt_buf_type: 0,       // CONFIG_ESP_WIFI_DYNAMIC_RX_MGMT_BUF
        rx_mgmt_buf_num: 5,        // CONFIG_ESP_WIFI_RX_MGMT_BUF_NUM_DEF
        cache_tx_buf_num: 0,       // no SPIRAM on this build
        csi_enable: 0,             // CONFIG_ESP_WIFI_CSI_ENABLED unset
        ampdu_rx_enable: 1,        // CONFIG_ESP_WIFI_AMPDU_RX_ENABLED. The
                                   // plan's heap mitigation (0) also worked
                                   // on the bench, but sdkconfig parity is
                                   // what's verified on HEAD (cost ~5 KB).
        ampdu_tx_enable: 1,        // CONFIG_ESP_WIFI_AMPDU_TX_ENABLED
        amsdu_tx_enable: 0,        // CONFIG_ESP_WIFI_AMSDU_TX_ENABLED unset
        nvs_enable: 1,             // CONFIG_ESP_WIFI_NVS_ENABLED
        nano_enable: 0,            // CONFIG_NEWLIB_NANO_FORMAT unset
        rx_ba_win: 6,              // CONFIG_ESP_WIFI_RX_BA_WIN. MUST be > 0
                                   // when ampdu_rx is on — the driver rejects
                                   // the init outright ("rx ba window 0
                                   // error" and WiFi stays down).
        wifi_task_core_id: 0,      // CONFIG_ESP_WIFI_TASK_PINNED_TO_CORE_1 unset
        beacon_max_len: 752,       // CONFIG_ESP_WIFI_SOFTAP_BEACON_MAX_LEN
        mgmt_sbuf_num: 32,         // CONFIG_ESP_WIFI_MGMT_SBUF_NUM
        feature_caps: esp_idf_sys::WIFI_ENABLE_WPA3_SAE as u64, // no SPIRAM/FTM
        sta_disconnected_pm: true, // CONFIG_ESP_WIFI_STA_DISCONNECTED_PM_ENABLE
        espnow_max_encrypt_num: 7, // CONFIG_ESP_WIFI_ESPNOW_MAX_ENCRYPT_NUM
        magic: esp_idf_sys::WIFI_INIT_CONFIG_MAGIC as i32, // 0x1F2F3F4F
    };
    esp(unsafe { esp_idf_sys::esp_wifi_init(&init_cfg) }, "esp_wifi_init")?;

    // 6. Handlers BEFORE start, so STA_START is never missed.
    esp(
        unsafe {
            esp_idf_sys::esp_event_handler_register(
                WIFI_EVENT,
                ESP_EVENT_ANY_ID,
                Some(on_wifi_event),
                core::ptr::null_mut(),
            )
        },
        "register WIFI_EVENT",
    )?;
    esp(
        unsafe {
            esp_idf_sys::esp_event_handler_register(
                IP_EVENT,
                EV_STA_GOT_IP,
                Some(on_ip_event),
                core::ptr::null_mut(),
            )
        },
        "register IP_EVENT",
    )?;

    // 7. STA config. SSID/password are fixed-size byte arrays (no NUL
    //    terminator); truncate anything longer than the fields hold.
    let mut cfg = esp_idf_sys::wifi_config_t {
        sta: esp_idf_sys::wifi_sta_config_t::default(),
    };
    let authmode = unsafe {
        let slen = ssid.len().min(32);
        cfg.sta.ssid[..slen].copy_from_slice(&ssid.as_bytes()[..slen]);
        match password {
            // Empty password == open network: threshold must stay OPEN,
            // a WPA2 threshold never matches an open AP.
            Some(p) if !p.is_empty() => {
                let plen = p.len().min(64);
                cfg.sta.password[..plen].copy_from_slice(&p.as_bytes()[..plen]);
                wifi_auth_mode_t_WIFI_AUTH_WPA2_PSK
            }
            _ => wifi_auth_mode_t_WIFI_AUTH_OPEN,
        }
    };
    unsafe {
        cfg.sta.threshold.authmode = authmode;
        // v5.1.3 C station example sets PWE BOTH (hunt-and-peck + hash-
        // to-element): WPA3-only H2E APs refuse to associate without
        // it; WPA2/open APs ignore the PWE method entirely.
        cfg.sta.sae_pwe_h2e = wifi_sae_pwe_method_t_WPA3_SAE_PWE_BOTH;
        esp(
            esp_idf_sys::esp_wifi_set_mode(wifi_mode_t_WIFI_MODE_STA),
            "esp_wifi_set_mode",
        )?;
        esp(
            esp_idf_sys::esp_wifi_set_config(wifi_interface_t_WIFI_IF_STA, &mut cfg),
            "esp_wifi_set_config",
        )?;
        esp(esp_idf_sys::esp_wifi_start(), "esp_wifi_start")?;
    }
    crate::clog!(
        "wifi: sta up ({}), heap {} -> {} bytes",
        ssid,
        heap0,
        unsafe { esp_idf_sys::esp_get_free_heap_size() }
    );

    // Phase 4 reconnect loop: poll the handler's atomics every 50 ms
    // (1 tick = 10 ms at the 100 Hz tick rate).
    let mut backoff_ms: u32 = 1000; // 1 s doubling to a 30 s cap
    let mut connect_issued = false;
    let mut logged_ip: u32 = 0;
    let mut handled_disc: u32 = 0;
    loop {
        unsafe { esp_idf_sys::vTaskDelay(5) };
        match LINK_STATE.load(Ordering::Relaxed) {
            ST_STARTED => {
                // esp_wifi_connect() is only legal after STA_START.
                // Retry on synchronous failure — a failed call emits
                // no DISCONNECTED event, so a one-shot attempt would
                // wedge the link until reboot.
                if !connect_issued {
                    let r = unsafe { esp_idf_sys::esp_wifi_connect() };
                    if r != 0 {
                        crate::clog!("wifi: connect failed: {} — retrying", r);
                        unsafe { esp_idf_sys::vTaskDelay(100) }; // ~1s
                    } else {
                        connect_issued = true;
                    }
                }
            }
            ST_GOT_IP => {
                connect_issued = false;
                let ip = GOT_IP.load(Ordering::Relaxed);
                if ip != logged_ip {
                    logged_ip = ip;
                    backoff_ms = 1000;
                    if let Some(a) = ip_addr() {
                        crate::clog!("wifi: got ip {}", a);
                        // Latch for start()'s boot wait — any print
                        // (including a reconnect's re-log) satisfies it.
                        IP_PRINTED.store(true, Ordering::Relaxed);
                    }
                }
            }
            ST_DISCONNECTED => {
                logged_ip = 0; // re-log the address after a reconnect
                let d = DISCONNECTS.load(Ordering::Relaxed);
                if d != handled_disc {
                    handled_disc = d;
                    let reason = DISC_REASON.load(Ordering::Relaxed);
                    // esp-println eats clog! lines during the wifi log
                    // flood (TIMED_OUT latch) — this diagnostic must
                    // survive, so write it through the direct FIFO path
                    // (still gated: never after KISS started).
                    if crate::console::may_log() {
                        let msg = format!(
                            "wifi: disconnected (reason {}), retry in {}ms\r\n",
                            reason, backoff_ms
                        );
                        crate::usb_write_direct(msg.as_bytes());
                    }
                }
                if !connect_issued {
                    // bounded-backoff wait, then reconnect (double to
                    // 30s cap). Retried every pass, not just on event
                    // edges: a synchronously failing esp_wifi_connect()
                    // produces no follow-up DISCONNECTED and would
                    // otherwise wedge the link forever.
                    unsafe { esp_idf_sys::vTaskDelay((backoff_ms / 10).max(1)) };
                    let r = unsafe { esp_idf_sys::esp_wifi_connect() };
                    if r == 0 {
                        connect_issued = true;
                    } else {
                        crate::clog!("wifi: reconnect failed: {}", r);
                    }
                    backoff_ms = (backoff_ms * 2).min(30_000);
                }
            }
            _ => {} // 0 = waiting for STA_START
        }
    }
}
