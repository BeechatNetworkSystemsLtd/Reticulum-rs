//! Console output gating: the USB-Serial-JTAG console shares its wire
//! with KISS data. Once the host sends its first FEND byte, any println!
//! corrupts the KISS stream — all diagnostics must go through `clog!`,
//! which silences output after that point.

use std::sync::atomic::{AtomicBool, Ordering};

static SAW_KISS: AtomicBool = AtomicBool::new(false);

/// Mark that KISS traffic has started (first FEND seen on any session).
/// Acts only on the false -> true transition; idempotent afterwards.
pub fn mark_kiss() {
    // swap() returns the previous value: act exactly once, on the first
    // FEND, so concurrent callers can't repeat the C-side shutdown.
    if !SAW_KISS.swap(true, Ordering::Relaxed) {
        // `clog!` only gates Rust-side prints; the ESP-IDF C stack
        // (wifi/netif/lwIP event logging via ESP_LOGx) writes to the
        // SAME USB-Serial-JTAG wire as the KISS stream. A connect/
        // disconnect ESP_LOGI would corrupt the stream just like a bare
        // println!, so silence ALL C-side tags once KISS starts.
        unsafe {
            esp_idf_sys::esp_log_level_set(
                b"*\0".as_ptr().cast::<core::ffi::c_char>(),
                esp_idf_sys::esp_log_level_t_ESP_LOG_NONE,
            );
        }
    }
}

/// True while printing to the console is still safe.
pub fn may_log() -> bool {
    !SAW_KISS.load(Ordering::Relaxed)
}

/// `println!` that silences itself once KISS traffic starts.
#[macro_export]
macro_rules! clog {
    ($($arg:tt)*) => {
        if $crate::console::may_log() {
            ::esp_println::println!($($arg)*);
        }
    };
}
