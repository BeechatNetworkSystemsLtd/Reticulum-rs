//! Device-side KISS command handling: the pure protocol state machine.
//!
//! `Protocol::handle` turns one parsed `(command, payload)` into zero or
//! more reply frames plus (optionally) a radio operation; the firmware
//! shims wire those to the physical link writer and the SX1262 driver.
//! Semantics mirror `rnode_sim.rs::DeviceParser` (validated against the
//! host client in CI) extended with the airtime-lock gating of the RNode
//! firmware.

use alloc::vec::Vec;

use crate::frame::kiss_frame;
use crate::radio::{AirtimeLocks, AirtimeTracker, ModemStats, RadioParams, quantize_frequency};
use crate::{FW_VERSION_MAJ, FW_VERSION_MIN, PLATFORM_CUSTOM};

// Command bytes — asserted equal to the host-side constants in
// `tests/host_parity.rs` so the two sides can never drift.
pub const CMD_UNKNOWN: u8 = 0xFE;
pub const CMD_DATA: u8 = 0x00;
pub const CMD_FREQUENCY: u8 = 0x01;
pub const CMD_BANDWIDTH: u8 = 0x02;
pub const CMD_TXPOWER: u8 = 0x03;
pub const CMD_SF: u8 = 0x04;
pub const CMD_CR: u8 = 0x05;
pub const CMD_RADIO_STATE: u8 = 0x06;
pub const CMD_RADIO_LOCK: u8 = 0x07;
pub const CMD_DETECT: u8 = 0x08;
pub const CMD_LEAVE: u8 = 0x0A;
pub const CMD_ST_ALOCK: u8 = 0x0B;
pub const CMD_LT_ALOCK: u8 = 0x0C;
pub const CMD_READY: u8 = 0x0F;
pub const CMD_STAT_RX: u8 = 0x21;
pub const CMD_STAT_TX: u8 = 0x22;
pub const CMD_STAT_RSSI: u8 = 0x23;
pub const CMD_STAT_SNR: u8 = 0x24;
pub const CMD_STAT_CHTM: u8 = 0x25;
pub const CMD_STAT_BAT: u8 = 0x27;
pub const CMD_STAT_CSMA: u8 = 0x28;
pub const CMD_STAT_TEMP: u8 = 0x29;
// Grouped query (RNode firmware behaviour): respond with the full status set.
pub const CMD_STAT_ALL: u8 = 0x2A;
pub const CMD_STAT_PHYPRM: u8 = 0x2C;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;

pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;
pub const RADIO_STATE_ON: u8 = 0x01;
pub const RADIO_STATE_OFF: u8 = 0x00;

/// What the firmware should do with the radio as a result of a command.
#[derive(Clone, Debug, PartialEq)]
pub enum RadioOp {
    /// (Re)configure and (re)start the radio with the given parameters.
    Configure(RadioParams),
    RadioOn,
    RadioOff,
    /// Queue a transmission of `data` bytes.
    Transmit(Vec<u8>),
}

/// Outcome of handling one command: frames to write back to the link
/// that sent the command, plus radio operations to perform.
pub struct Handled {
    pub replies: Vec<Vec<u8>>,
    pub ops: Vec<RadioOp>,
}

impl Handled {
    fn empty() -> Self {
        Self {
            replies: Vec::new(),
            ops: Vec::new(),
        }
    }
}

/// Pure device-side protocol state.
pub struct Protocol {
    pub params: RadioParams,
    pub locks: AirtimeLocks,
    pub airtime: AirtimeTracker,
    pub stats: ModemStats,
    /// Counters reported via `CMD_STAT_RX` / `CMD_STAT_TX`.
    pub stat_rx: u32,
    pub stat_tx: u32,
    /// MCU identification byte reported over `CMD_MCU`.
    pub mcu: u8,
    /// Emit `CMD_READY` after accepted data frames (flow control).
    pub flow_control: bool,
    /// Firmware/platform identification.
    pub platform: u8,
}

impl Protocol {
    pub fn new(mcu: u8) -> Self {
        Self {
            params: RadioParams::default(),
            locks: AirtimeLocks::default(),
            airtime: AirtimeTracker::default(),
            stats: ModemStats::default(),
            stat_rx: 0,
            stat_tx: 0,
            mcu,
            flow_control: true,
            platform: PLATFORM_CUSTOM,
        }
    }

    /// Handle one complete frame from a host.
    pub fn handle(&mut self, command: u8, payload: &[u8]) -> Handled {
        let mut out = Handled::empty();
        match command {
            CMD_DETECT if payload.first() == Some(&DETECT_REQ) => {
                out.replies.push(kiss_frame(CMD_DETECT, &[DETECT_RESP]));
                out.replies.push(kiss_frame(
                    CMD_FW_VERSION,
                    &[FW_VERSION_MAJ, FW_VERSION_MIN],
                ));
                out.replies.push(kiss_frame(CMD_PLATFORM, &[self.platform]));
                out.replies.push(kiss_frame(CMD_MCU, &[self.mcu]));
            }
            CMD_DATA if !payload.is_empty() => {
                if !self.locks.permits(&self.airtime) {
                    // Airtime-locked: drop, but keep the link responsive.
                    if self.flow_control {
                        out.replies.push(kiss_frame(CMD_READY, &[0x01]));
                    }
                    return out;
                }
                out.ops.push(RadioOp::Transmit(payload.to_vec()));
                self.stat_tx += 1;
                if self.flow_control {
                    // v1: queue accepted, radio task completes it. Ready
                    // again immediately; a fuller implementation gates
                    // this on actual TX completion.
                    out.replies.push(kiss_frame(CMD_READY, &[0x01]));
                }
            }
            CMD_RADIO_STATE if !payload.is_empty() => {
                if payload[0] == 0xFF {
                    // Query: report current state (RNode `kiss_indicate_radiostate`)
                    let state = if self.params.radio_on { RADIO_STATE_ON } else { RADIO_STATE_OFF };
                    out.replies.push(kiss_frame(CMD_RADIO_STATE, &[state]));
                } else {
                    self.params.radio_on = payload[0] == RADIO_STATE_ON;
                    out.replies.push(kiss_frame(CMD_RADIO_STATE, &payload[..1]));
                    out.ops.push(if self.params.radio_on {
                        RadioOp::RadioOn
                    } else {
                        RadioOp::RadioOff
                    });
                }
            }
            CMD_FREQUENCY if payload.len() == 4 => {
                // 0xFFFFFFFF is a QUERY (RNode firmware `kiss_indicate_frequency`):
                // report the current value without changing anything.
                if payload.iter().all(|&b| b == 0xFF) {
                    out.replies.push(kiss_frame(
                        CMD_FREQUENCY,
                        &self.params.frequency.to_be_bytes(),
                    ));
                } else {
                    let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let quantized = quantize_frequency(raw);
                    self.params.frequency = quantized;
                    out.replies
                        .push(kiss_frame(CMD_FREQUENCY, &quantized.to_be_bytes()));
                    out.ops.push(RadioOp::Configure(self.params.clone()));
                }
            }
            CMD_BANDWIDTH if payload.len() == 4 => {
                if payload.iter().all(|&b| b == 0xFF) {
                    out.replies.push(kiss_frame(
                        CMD_BANDWIDTH,
                        &self.params.bandwidth.to_be_bytes(),
                    ));
                } else {
                    let bw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    self.params.bandwidth = bw;
                    out.replies.push(kiss_frame(CMD_BANDWIDTH, &bw.to_be_bytes()));
                    out.ops.push(RadioOp::Configure(self.params.clone()));
                }
            }
            CMD_TXPOWER if !payload.is_empty() => {
                if payload[0] == 0xFF {
                    out.replies.push(kiss_frame(CMD_TXPOWER, &[self.params.txpower]));
                } else {
                    self.params.txpower = payload[0];
                    out.replies.push(kiss_frame(CMD_TXPOWER, &[payload[0]]));
                    out.ops.push(RadioOp::Configure(self.params.clone()));
                }
            }
            CMD_SF if !payload.is_empty() => {
                if payload[0] == 0xFF {
                    out.replies.push(kiss_frame(CMD_SF, &[self.params.sf]));
                } else {
                    self.params.sf = payload[0];
                    out.replies.push(kiss_frame(CMD_SF, &[payload[0]]));
                    out.ops.push(RadioOp::Configure(self.params.clone()));
                }
            }
            CMD_CR if !payload.is_empty() => {
                if payload[0] == 0xFF {
                    out.replies.push(kiss_frame(CMD_CR, &[self.params.cr]));
                } else {
                    self.params.cr = payload[0];
                    out.replies.push(kiss_frame(CMD_CR, &[payload[0]]));
                    out.ops.push(RadioOp::Configure(self.params.clone()));
                }
            }
            CMD_ST_ALOCK if payload.len() == 2 => {
                let cch = u16::from_be_bytes([payload[0], payload[1]]);
                self.locks.short_term = decode_lock(cch);
                out.replies.push(kiss_frame(CMD_ST_ALOCK, &payload[..2]));
            }
            CMD_LT_ALOCK if payload.len() == 2 => {
                let cch = u16::from_be_bytes([payload[0], payload[1]]);
                self.locks.long_term = decode_lock(cch);
                out.replies.push(kiss_frame(CMD_LT_ALOCK, &payload[..2]));
            }
            CMD_STAT_RSSI => {
                out.replies.push(kiss_frame(CMD_STAT_RSSI, &self.stats.rssi.to_be_bytes()));
            }
            CMD_STAT_SNR => {
                let raw = (self.stats.snr * 4.0) as i8;
                out.replies.push(kiss_frame(CMD_STAT_SNR, &[raw as u8]));
            }
            CMD_STAT_RX => {
                out.replies
                    .push(kiss_frame(CMD_STAT_RX, &self.stat_rx.to_be_bytes()));
            }
            CMD_STAT_TX => {
                out.replies
                    .push(kiss_frame(CMD_STAT_TX, &self.stat_tx.to_be_bytes()));
            }
            CMD_STAT_CHTM => {
                let st = (self.airtime.short_term() * 10_000.0) as u16;
                let lt = (self.airtime.long_term() * 10_000.0) as u16;
                let utilisation = ((st as u32) << 16) | lt as u32;
                out.replies
                    .push(kiss_frame(CMD_STAT_CHTM, &utilisation.to_be_bytes()));
            }
            CMD_STAT_BAT => {
                let level = self.stats.battery.unwrap_or(0);
                out.replies.push(kiss_frame(CMD_STAT_BAT, &[level]));
            }
            CMD_STAT_TEMP => {
                let temp = self.stats.temperature.unwrap_or(0);
                out.replies.push(kiss_frame(CMD_STAT_TEMP, &[temp as u8]));
            }
            CMD_FW_VERSION => {
                out.replies
                    .push(kiss_frame(CMD_FW_VERSION, &[FW_VERSION_MAJ, FW_VERSION_MIN]));
            }
            CMD_PLATFORM => {
                out.replies.push(kiss_frame(CMD_PLATFORM, &[self.platform]));
            }
            CMD_MCU => {
                out.replies.push(kiss_frame(CMD_MCU, &[self.mcu]));
            }
            CMD_LEAVE => {
                out.replies.push(kiss_frame(CMD_LEAVE, &[0xFF]));
                out.ops.push(RadioOp::RadioOff);
            }
            _ => {}
        }
        out
    }

    /// Build the frame a host receives for over-the-air data.
    pub fn data_frame(data: &[u8]) -> Vec<u8> {
        kiss_frame(CMD_DATA, data)
    }

    /// Record a completed radio transmission (call from the radio task).
    pub fn tx_complete(&mut self, len: usize) {
        self.airtime.add(len, &self.params);
    }

    /// Record a received radio packet (call from the radio task).
    pub fn rx_packet(&mut self) {
        self.stat_rx += 1;
    }
}

// Individual query frames also get direct answers, like the RNode
// firmware does.
impl Protocol {
    /// Identifier for tests: the board this protocol instance claims.
    pub fn describes(&self) -> (u8, u8) {
        (self.platform, self.mcu)
    }
}

/// Decode the RNode airtime-lock encoding: hundredths of a percent in
/// a big-endian u16; `>= 100%` (cch 10000) means "no lock".
fn decode_lock(cch: u16) -> Option<f32> {
    let pct = cch as f32 / 100.0;
    if pct >= 100.0 || cch == 0 {
        None
    } else {
        Some(pct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FEND;

    fn protocol() -> Protocol {
        Protocol::new(crate::MCU_ESP32_C6)
    }

    #[test]
    fn detect_burst_answers_all_four() {
        let mut p = protocol();
        let out = p.handle(CMD_DETECT, &[DETECT_REQ]);
        assert_eq!(out.replies.len(), 4);
        assert_eq!(out.replies[0], kiss_frame(CMD_DETECT, &[DETECT_RESP]));
        assert_eq!(
            out.replies[1],
            kiss_frame(CMD_FW_VERSION, &[FW_VERSION_MAJ, FW_VERSION_MIN])
        );
    }

    #[test]
    fn frequency_echoes_quantized() {
        let mut p = protocol();
        let out = p.handle(CMD_FREQUENCY, &867_500_017u32.to_be_bytes());
        assert_eq!(out.replies.len(), 1);
        let echoed = quantize_frequency(867_500_017);
        assert_eq!(out.replies[0], kiss_frame(CMD_FREQUENCY, &echoed.to_be_bytes()));
    }

    #[test]
    fn data_frames_become_transmits() {
        let mut p = protocol();
        let out = p.handle(CMD_DATA, &[0xAA, FEND, 0xBB]);
        assert_eq!(out.ops.len(), 1);
        match &out.ops[0] {
            RadioOp::Transmit(data) => assert_eq!(data, &vec![0xAA, FEND, 0xBB]),
            other => panic!("expected transmit, got {other:?}"),
        }
        // flow-control ready frame follows
        assert!(out
            .replies
            .iter()
            .any(|f| f == &kiss_frame(CMD_READY, &[0x01])));
    }

    #[test]
    fn airtime_lock_blocks_transmit() {
        let mut p = protocol();
        p.locks.short_term = Some(1.0);
        for _ in 0..8 {
            p.tx_complete(50);
        }
        let out = p.handle(CMD_DATA, &[0x01]);
        assert!(out.ops.is_empty(), "transmit must be blocked under lock");
    }

    #[test]
    fn ff_payload_queries_report_current_values() {
        // Python RNS validateRadioState queries each parameter with 0xFF
        // payloads and expects the CURRENT value echoed, unchanged.
        let mut p = protocol();
        p.handle(CMD_FREQUENCY, &867_500_000u32.to_be_bytes());
        p.handle(CMD_BANDWIDTH, &125_000u32.to_be_bytes());
        p.handle(CMD_SF, &[9]);
        p.handle(CMD_CR, &[5]);
        p.handle(CMD_TXPOWER, &[14]);
        p.handle(CMD_RADIO_STATE, &[RADIO_STATE_ON]);

        let q = p.handle(CMD_FREQUENCY, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(q.ops.len(), 0, "query must not reconfigure");
        assert_eq!(q.replies[0], kiss_frame(CMD_FREQUENCY, &867_500_000u32.to_be_bytes()));

        let q = p.handle(CMD_BANDWIDTH, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(q.ops.len(), 0);
        assert_eq!(q.replies[0], kiss_frame(CMD_BANDWIDTH, &125_000u32.to_be_bytes()));

        for (cmd, val) in [(CMD_SF, 9u8), (CMD_CR, 5), (CMD_TXPOWER, 14)] {
            let q = p.handle(cmd, &[0xFF]);
            assert_eq!(q.ops.len(), 0);
            assert_eq!(q.replies[0], kiss_frame(cmd, &[val]));
        }

        let q = p.handle(CMD_RADIO_STATE, &[0xFF]);
        assert_eq!(q.ops.len(), 0);
        assert_eq!(q.replies[0], kiss_frame(CMD_RADIO_STATE, &[RADIO_STATE_ON]));

        // and the radio is still on / params unchanged
        assert!(p.params.radio_on);
        assert_eq!(p.params.frequency, 867_500_000);
    }

    #[test]
    fn leave_turns_radio_off() {
        let mut p = protocol();
        p.params.radio_on = true;
        let out = p.handle(CMD_LEAVE, &[0xFF]);
        assert!(out.ops.contains(&RadioOp::RadioOff));
        assert_eq!(out.replies[0], kiss_frame(CMD_LEAVE, &[0xFF]));
    }
}
