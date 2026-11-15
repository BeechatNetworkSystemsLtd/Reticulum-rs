//! Radio configuration model, quantization, airtime accounting and
//! telemetry state — the radio-facing half of the modem.
//!
//! Frequency quantization mirrors the SX1262 PLL grid (32 Hz steps) the
//! same way `rnode_sim.rs` does, and airtime maths follow the upstream
//! RNode firmware's `add_airtime` (symbol-time based).

/// Radio configuration commanded by the host, as tracked by the modem.
/// Mirrors `reticulum::iface::rnode::RnodeRadioConfig` semantics on the
/// device side.
#[derive(Clone, Debug, PartialEq)]
pub struct RadioParams {
    pub frequency: u32,
    pub bandwidth: u32,
    pub txpower: u8,
    pub sf: u8,
    pub cr: u8,
    /// RNode `CMD_IMPLICIT` extension: implicit (fixed-length) header
    /// mode. Hosts that do not send it get explicit headers.
    pub implicit: bool,
    pub radio_on: bool,
}

impl Default for RadioParams {
    fn default() -> Self {
        // The repo hardware-test channel: 867.5 MHz, BW 125 kHz, SF9,
        // CR 4/5, 2 dBm (examples/rnode_listen.rs defaults).
        Self {
            frequency: 867_500_000,
            bandwidth: 125_000,
            txpower: 2,
            sf: 9,
            cr: 5,
            implicit: false,
            radio_on: false,
        }
    }
}

/// Quantize a frequency in Hz to the SX1262 PLL grid (32 Hz steps),
/// matching how real hardware echoes `CMD_FREQUENCY` (see `rnode_sim.rs`).
pub fn quantize_frequency(hz: u32) -> u32 {
    hz & !0x1F
}

/// Payload-carrying frame length in bytes for airtime purposes.
/// PHY constants from the RNode firmware:
///   `PHY_CRC_LORA_BITS = 16`, `PHY_HEADER_LORA_SYMBOLS = 20`.
const PHY_CRC_LORA_BITS: f32 = 16.0;
const PHY_HEADER_LORA_SYMBOLS: f32 = 20.0;

/// Airtime of one LoRa transmission in milliseconds, following the RNode
/// firmware's `lora_symbol_time` / `add_airtime` maths for explicit-header
/// LoRa packets at SF7..12.
pub fn airtime_ms(len: usize, params: &RadioParams) -> f32 {
    let sf = params.sf.clamp(7, 12) as f32;
    let bw_hz = params.bandwidth.max(7_800) as f32;
    let symbol_ms = (1u32 << (sf as u32)) as f32 * 1000.0 / bw_hz;

    let mut symbols: f32 = (8.0 * len as f32 + PHY_CRC_LORA_BITS - 4.0 * sf + 8.0
        + PHY_HEADER_LORA_SYMBOLS)
        / (4.0 * params.cr.clamp(5, 8) as f32);
    symbols += 8.0; // sync word etc. in symbol time, RNode convention
    symbols += 8.0; // preamble symbols (RNode default preamble length)

    symbols * symbol_ms
}

/// Airtime ledger with the RNode firmware's short/long-term windows:
/// short term ≈ 2 × 15 s bins, long term ≈ 1 h.
#[derive(Clone, Debug)]
pub struct AirtimeTracker {
    /// Total transmitted milliseconds, binned per 15 s.
    bins: [u32; 240],
    bin_cursor: usize,
    /// Milliseconds elapsed counter (advanced by `tick_ms`).
    elapsed_ms: u64,
}

impl Default for AirtimeTracker {
    fn default() -> Self {
        Self {
            bins: [0; 240],
            bin_cursor: 0,
            elapsed_ms: 0,
        }
    }
}

impl AirtimeTracker {
    /// Record a completed transmission of `len` bytes.
    pub fn add(&mut self, len: usize, params: &RadioParams) {
        let cost = airtime_ms(len, params);
        self.bins[self.bin_cursor] += cost as u32;
    }

    /// Advance wall-clock tracking; call from a periodic timer.
    pub fn tick_ms(&mut self, ms: u64) {
        let before = self.elapsed_ms;
        self.elapsed_ms += ms;
        // roll bins crossed by the clock
        let bin_ms = 15_000u64;
        let mut target = ((self.elapsed_ms / bin_ms) as usize) % self.bins.len();
        if self.elapsed_ms / bin_ms == before / bin_ms {
            return;
        }
        // wrap-around aware advance, clearing bins on the way
        while self.bin_cursor != target {
            self.bin_cursor = (self.bin_cursor + 1) % self.bins.len();
            self.bins[self.bin_cursor] = 0;
            if self.bin_cursor == target {
                break;
            }
        }
        let _ = &mut target;
    }

    /// Short-term utilisation fraction (last ~30 s of airtime).
    pub fn short_term(&self) -> f32 {
        let prev = if self.bin_cursor == 0 {
            self.bins.len() - 1
        } else {
            self.bin_cursor - 1
        };
        (self.bins[self.bin_cursor] + self.bins[prev]) as f32 / 30_000.0
    }

    /// Long-term utilisation fraction (last hour).
    pub fn long_term(&self) -> f32 {
        self.bins.iter().map(|&b| b as u64).sum::<u64>() as f32 / 3_600_000.0
    }
}

/// Live status snapshot for telemetry frames.
#[derive(Clone, Debug, Default)]
pub struct ModemStats {
    pub rssi: i16,
    pub snr: f32,
    /// Battery percentage; `None` when no battery sense is wired.
    pub battery: Option<u8>,
    /// Chip temperature in °C; `None` when unsupported.
    pub temperature: Option<i8>,
}

/// Short/long-term airtime locks in percent (RNode `CMD_ST_ALOCK` /
/// `CMD_LT_ALOCK`). `None` = unrestricted.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AirtimeLocks {
    pub short_term: Option<f32>,
    pub long_term: Option<f32>,
}

impl AirtimeLocks {
    /// Whether a transmission is currently permitted under the locks,
    /// given the ledger. Mirrors the RNode firmware gating order.
    pub fn permits(&self, airtime: &AirtimeTracker) -> bool {
        if let Some(st) = self.short_term
            && airtime.short_term() >= st / 100.0 {
                return false;
            }
        if let Some(lt) = self.long_term
            && airtime.long_term() >= lt / 100.0 {
                return false;
            }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frequency_quantizes_to_32_hz_grid() {
        assert_eq!(quantize_frequency(867_500_017), 867_500_000);
        assert_eq!(quantize_frequency(869_525_024), 869_525_024 & !0x1F);
    }

    #[test]
    fn airtime_is_sane_at_sf9_bw125() {
        // ~50 bytes at SF9/BW125 is well under a second on air.
        let ms = airtime_ms(50, &RadioParams::default());
        assert!(ms > 50.0 && ms < 700.0, "airtime {ms}ms out of expected band");
    }

    #[test]
    fn locks_gate_on_ledger() {
        let mut tracker = AirtimeTracker::default();
        let locks = AirtimeLocks {
            short_term: Some(10.0),
            long_term: None,
        };
        assert!(locks.permits(&tracker));
        // ~150 ms packets at SF9/BW125: 4 packets ≈ 0.6 s ≈ 2% of the
        // 30 s window — allowed under a 10% lock.
        for _ in 0..4 {
            tracker.add(50, &RadioParams::default());
        }
        assert!(locks.permits(&tracker));
        // Past 10% (~3 s of airtime in 30 s) the lock must engage.
        for _ in 0..24 {
            tracker.add(50, &RadioParams::default());
        }
        assert!(!locks.permits(&tracker));
    }
}
