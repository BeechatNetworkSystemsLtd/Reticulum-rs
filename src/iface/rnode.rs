//! RNode interfaces — Python `RNS.Interfaces.RNodeInterface` and
//! `RNodeMultiInterface` parity (Phase 5.5).
//!
//! * [`RnodeInterface`]: one LoRa radio reachable over serial, TCP, or
//!   `ble://` (the btleplug backend is feature `iface-rnode-ble`),
//!   speaking the RNode KISS command protocol: hardware detection
//!   (firmware/platform/MCU), radio configuration (frequency, bandwidth,
//!   TX power, spreading factor, coding rate, airtime locks), radio
//!   state control, flow control (`CMD_READY`) and radio status
//!   telemetry (RSSI, SNR, link quality, airtime).
//! * [`RnodeMultiInterface`]: one multi-band radio exposing up to twelve
//!   virtual ports; each port is spawned as its own interface and
//!   addressed with `CMD_SEL_INT` prefixes and the per-port data
//!   commands.
//!
//! Firmware >= 1.52 is required, validated on connect
//! (Python `REQUIRED_FW_VER_*`).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::{Interface, InterfaceContext, InterfaceManager, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

// ---------------------------------------------------------------------------
// KISS framing constants (Python RNodeInterface.KISS).
// ---------------------------------------------------------------------------

pub const FEND: u8 = 0xC0;
pub const FESC: u8 = 0xDB;
pub const TFEND: u8 = 0xDC;
pub const TFESC: u8 = 0xDD;

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
pub const CMD_STAT_PHYPRM: u8 = 0x26;
pub const CMD_STAT_BAT: u8 = 0x27;
pub const CMD_STAT_CSMA: u8 = 0x28;
pub const CMD_STAT_TEMP: u8 = 0x29;
/// RNodeMulti port inventory query (Python `CMD_INTERFACES`).
pub const CMD_INTERFACES: u8 = 0x71;
pub const CMD_BLINK: u8 = 0x30;
pub const CMD_RANDOM: u8 = 0x40;
pub const CMD_FB_EXT: u8 = 0x41;
pub const CMD_FB_READ: u8 = 0x42;
pub const CMD_FB_WRITE: u8 = 0x43;
/// Bluetooth controller command (Python `CMD_BT_CTRL`).
pub const CMD_BT_CTRL: u8 = 0x46;
/// `CMD_BT_CTRL` payload: disable (Python `disable_bluetooth`).
pub const BT_CTRL_DISABLE: u8 = 0x00;
/// `CMD_BT_CTRL` payload: enable (Python `enable_bluetooth`).
pub const BT_CTRL_ENABLE: u8 = 0x01;
/// `CMD_BT_CTRL` payload: start pairing (Python `bluetooth_pair`).
pub const BT_CTRL_PAIR: u8 = 0x02;
pub const CMD_PLATFORM: u8 = 0x48;
pub const CMD_MCU: u8 = 0x49;
pub const CMD_FW_VERSION: u8 = 0x50;
pub const CMD_ROM_READ: u8 = 0x51;
pub const CMD_RESET: u8 = 0x55;
pub const CMD_ERROR: u8 = 0x90;

pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;

pub const RADIO_STATE_ON: u8 = 0x01;
pub const RADIO_STATE_OFF: u8 = 0x00;

/// RSSI is reported as `byte - RSSI_OFFSET` dBm
/// (Python `RSSI_OFFSET`).
pub const RSSI_OFFSET: i16 = 157;

/// Minimum firmware version (Python `REQUIRED_FW_VER_*`).
pub const REQUIRED_FW_VER_MAJ: u8 = 1;
pub const REQUIRED_FW_VER_MIN: u8 = 52;

/// Link-quality scaling (Python `Q_SNR_*`).
pub const Q_SNR_MIN_BASE: f32 = -9.0;
pub const Q_SNR_MAX: f32 = 6.0;
pub const Q_SNR_STEP: f32 = 2.0;

/// Encoded identification-beacon limit (Python `CALLSIGN_MAX_LEN`).
pub const CALLSIGN_MAX_LEN: usize = 32;

/// 2.4 GHz chip kinds from `CMD_INTERFACES` (Python `SX128X` / `SX1280`).
const KIND_SX128X: u8 = 0x20;
const KIND_SX1280: u8 = 0x21;

/// RNodeMulti virtual-port selection (Python `CMD_SEL_INT`).
pub const CMD_SEL_INT: u8 = 0x1F;

/// Per-virtual-port data commands, index == vport
/// (Python `CMD_INT{0..11}_DATA`).
pub const CMD_INT_DATA: [u8; 12] = [
    0x00, 0x10, 0x20, 0x70, 0x75, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
];

// ---------------------------------------------------------------------------
// Framing.
// ---------------------------------------------------------------------------

/// KISS escaping (Python `KISS.escape`).
pub fn kiss_escape(data: &[u8], out: &mut Vec<u8>) {
    for &byte in data {
        match byte {
            FEND => out.extend_from_slice(&[FESC, TFEND]),
            FESC => out.extend_from_slice(&[FESC, TFESC]),
            _ => out.push(byte),
        }
    }
}

/// Build a command frame: `FEND cmd escaped-payload FEND`.
pub fn kiss_frame(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![FEND, command];
    kiss_escape(payload, &mut frame);
    frame.push(FEND);
    frame
}

/// The hardware detection request burst
/// (Python `RNodeInterface.detect`).
pub fn detect_request() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kiss_frame(CMD_DETECT, &[DETECT_REQ]));
    out.extend_from_slice(&kiss_frame(CMD_FW_VERSION, &[0x00]));
    out.extend_from_slice(&kiss_frame(CMD_PLATFORM, &[0x00]));
    out.extend_from_slice(&kiss_frame(CMD_MCU, &[0x00]));
    out
}

/// RNodeMulti detection burst (Python `RNodeMultiInterface.detect`):
/// the single-radio probe plus `CMD_INTERFACES`.
pub fn multi_detect_request() -> Vec<u8> {
    let mut out = detect_request();
    out.extend_from_slice(&kiss_frame(CMD_INTERFACES, &[0x00]));
    out
}

/// On-air bitrate in bits per second (Python `updateBitrate`).
///
/// `None` when spreading factor, coding rate, or bandwidth is zero or the
/// result is not a positive finite rate.
pub fn on_air_bitrate(sf: u8, cr: u8, bandwidth_hz: u32) -> Option<f64> {
    if sf == 0 || cr == 0 || bandwidth_hz == 0 {
        return None;
    }
    let sf = sf as f64;
    let cr = cr as f64;
    let bandwidth = bandwidth_hz as f64;
    let bitrate = sf * ((4.0 / cr) / (2.0_f64.powf(sf) / (bandwidth / 1000.0))) * 1000.0;
    (bitrate.is_finite() && bitrate > 0.0).then_some(bitrate)
}

/// Whether `frequency` is in the band for a `CMD_INTERFACES` kind byte.
///
/// Python `interface_type_to_str` only picks the chip name. Unknown kinds
/// become `"SX127X"`. `RNodeSubInterface` accepts 137000000–1000000000 for
/// SX126X/SX127X and 2200000000–2600000000 for SX128X.
pub fn reported_kind_accepts_frequency(kind: u8, frequency: u64) -> bool {
    match kind {
        KIND_SX128X | KIND_SX1280 => (2_200_000_000..=2_600_000_000).contains(&frequency),
        _ => (137_000_000..=1_000_000_000).contains(&frequency),
    }
}

fn beacon_config(interval_secs: u64, callsign: &[u8]) -> Option<(u64, Vec<u8>)> {
    if callsign.len() <= CALLSIGN_MAX_LEN {
        Some((interval_secs, callsign.to_vec()))
    } else {
        log::error!(
            "rnode: encoded id callsign is {} bytes; max is {CALLSIGN_MAX_LEN}",
            callsign.len()
        );
        None
    }
}

/// Tell the device the host is leaving (Python `RNodeInterface.leave`).
pub fn leave_request() -> Vec<u8> {
    kiss_frame(CMD_LEAVE, &[0xFF])
}

/// Hard-reset the device (Python `RNodeInterface.hard_reset`).
pub fn reset_request() -> Vec<u8> {
    kiss_frame(CMD_RESET, &[0xF8])
}

/// Radio configuration of one (virtual) interface
/// (Python `RNodeInterface` configuration options).
#[derive(Debug, Clone)]
pub struct RnodeRadioConfig {
    pub frequency: u64,
    pub bandwidth: u32,
    pub txpower: u8,
    pub spreadingfactor: u8,
    pub codingrate: u8,
    /// Short-term airtime lock in percent.
    pub st_alock: Option<f32>,
    /// Long-term airtime lock in percent.
    pub lt_alock: Option<f32>,
}

impl RnodeRadioConfig {
    /// Build the radio configuration command frames in the Python order
    /// (`setFrequency`, `setBandwidth`, `setTXPower`,
    /// `setSpreadingFactor`, `setCodingRate`, airtime locks, radio
    /// state).
    pub fn configuration_frames(&self, radio_state: u8) -> Vec<Vec<u8>> {
        // Python `setFrequency`: four big-endian bytes.
        let mut frames = vec![
            kiss_frame(CMD_FREQUENCY, &(self.frequency as u32).to_be_bytes()),
            kiss_frame(CMD_BANDWIDTH, &self.bandwidth.to_be_bytes()),
            kiss_frame(CMD_TXPOWER, &[self.txpower]),
            kiss_frame(CMD_SF, &[self.spreadingfactor]),
            kiss_frame(CMD_CR, &[self.codingrate]),
        ];

        if let Some(st_alock) = self.st_alock {
            let at = (st_alock * 100.0) as u16;
            frames.push(kiss_frame(CMD_ST_ALOCK, &at.to_be_bytes()));
        }

        if let Some(lt_alock) = self.lt_alock {
            let at = (lt_alock * 100.0) as u16;
            frames.push(kiss_frame(CMD_LT_ALOCK, &at.to_be_bytes()));
        }

        frames.push(kiss_frame(CMD_RADIO_STATE, &[radio_state]));
        frames
    }

    /// Whether the radio state echoed by the device matches this
    /// configuration (Python `validateRadioState`).
    pub fn validate(&self, echoed: &RnodeEchoState) -> Result<(), &'static str> {
        let Some(r_frequency) = echoed.frequency else {
            return Err("device did not report frequency");
        };
        if self.frequency.abs_diff(r_frequency) > 100 {
            return Err("frequency mismatch");
        }
        if Some(self.bandwidth) != echoed.bandwidth {
            return Err("bandwidth mismatch");
        }
        if Some(self.txpower) != echoed.txpower {
            return Err("TX power mismatch");
        }
        if Some(self.spreadingfactor) != echoed.spreadingfactor {
            return Err("spreading factor mismatch");
        }
        if Some(self.codingrate) != echoed.codingrate {
            return Err("coding rate mismatch");
        }
        if Some(RADIO_STATE_ON) != echoed.radio_state {
            return Err("radio state mismatch");
        }
        Ok(())
    }
}

/// Radio state reported back by the device
/// (Python `r_frequency` and friends).
#[derive(Debug, Default, Clone)]
pub struct RnodeEchoState {
    pub frequency: Option<u64>,
    pub bandwidth: Option<u32>,
    pub txpower: Option<u8>,
    pub spreadingfactor: Option<u8>,
    pub codingrate: Option<u8>,
    pub radio_state: Option<u8>,
    pub st_alock: Option<f32>,
    pub lt_alock: Option<f32>,
    /// RNodeMulti port this report belongs to, when the device has
    /// selected one.
    pub vport: Option<u8>,
}

impl RnodeEchoState {
    fn merge(&mut self, other: RnodeEchoState) {
        if other.frequency.is_some() {
            self.frequency = other.frequency;
        }
        if other.bandwidth.is_some() {
            self.bandwidth = other.bandwidth;
        }
        if other.txpower.is_some() {
            self.txpower = other.txpower;
        }
        if other.spreadingfactor.is_some() {
            self.spreadingfactor = other.spreadingfactor;
        }
        if other.codingrate.is_some() {
            self.codingrate = other.codingrate;
        }
        if other.radio_state.is_some() {
            self.radio_state = other.radio_state;
        }
        if other.st_alock.is_some() {
            self.st_alock = other.st_alock;
        }
        if other.lt_alock.is_some() {
            self.lt_alock = other.lt_alock;
        }
        if other.vport.is_some() {
            self.vport = other.vport;
        }
    }

    pub fn on_air_bitrate(&self) -> Option<f64> {
        match (self.spreadingfactor, self.codingrate, self.bandwidth) {
            (Some(sf), Some(cr), Some(bandwidth)) => on_air_bitrate(sf, cr, bandwidth),
            _ => None,
        }
    }
}

/// Live status telemetry of a radio (Python `r_stat_*` fields).
#[derive(Debug, Default, Clone)]
pub struct RnodeStatus {
    pub stat_rx: Option<u32>,
    pub stat_tx: Option<u32>,
    pub rssi: Option<i16>,
    pub snr: Option<f32>,
    /// Derived link quality percentage (Python `r_stat_q`).
    pub quality: Option<f32>,
    /// Battery charge percent 0–100 (Python `r_battery_percent`).
    pub battery: Option<u16>,
    /// Battery state byte (Python `r_battery_state`).
    pub battery_state: Option<u8>,
    /// MCU temperature in °C when the report is in range (Python
    /// `r_temperature`).
    pub temperature: Option<i16>,
    /// `Some` when this event is a temperature frame. The inner value is
    /// `None` for an out-of-range reading, which clears a stored temperature.
    pub temperature_report: Option<Option<i16>>,
    /// CSMA contention window (Python `r_csma_cw_band` / `min` / `max`).
    pub csma_cw_band: Option<u8>,
    pub csma_cw_min: Option<u8>,
    pub csma_cw_max: Option<u8>,
    /// CSMA slot time in milliseconds (Python `r_csma_slot_time_ms`).
    pub csma_slot_time_ms: Option<u16>,
    /// DIFS time in milliseconds (Python `r_csma_difs_ms`).
    pub csma_difs_ms: Option<u16>,
    /// Symbol time in milliseconds (Python `r_symbol_time_ms`).
    pub symbol_time_ms: Option<f32>,
    /// Symbol rate in baud (Python `r_symbol_rate`).
    pub symbol_rate: Option<u16>,
    /// Preamble length in symbols (Python `r_preamble_symbols`).
    pub preamble_symbols: Option<u16>,
    /// Preamble time in milliseconds (Python `r_premable_time_ms`).
    pub preamble_time_ms: Option<u16>,
    /// Short-term airtime percent (Python `r_airtime_short`).
    pub airtime_short: Option<f32>,
    /// Long-term airtime percent (Python `r_airtime_long`).
    pub airtime_long: Option<f32>,
    /// Short-term channel load percent (Python `r_channel_load_short`).
    pub channel_load_short: Option<f32>,
    /// Long-term channel load percent (Python `r_channel_load_long`).
    pub channel_load_long: Option<f32>,
    /// Instantaneous RSSI from a channel-time report (Python `r_current_rssi`).
    pub current_rssi: Option<i16>,
    /// Noise floor from a channel-time report (Python `r_noise_floor`).
    pub noise_floor: Option<i16>,
    /// Interference RSSI (Python `r_interference`).
    pub interference: Option<i16>,
    /// `Some` when this event is an 11-byte channel-time frame. The inner
    /// value is `None` when the radio reports no interference (`0xFF`).
    pub interference_report: Option<Option<i16>>,
    /// RNodeMulti port this report belongs to.
    pub vport: Option<u8>,
}

impl RnodeStatus {
    /// Link quality from an SNR report
    /// (Python `r_stat_snr` quality computation).
    pub fn quality_for(snr: f32, spreadingfactor: Option<u8>) -> Option<f32> {
        let sf = spreadingfactor?;
        let sfs = sf.saturating_sub(7) as f32;
        let q_min = Q_SNR_MIN_BASE - sfs * Q_SNR_STEP;
        let span = Q_SNR_MAX - q_min;
        Some((((snr - q_min) / span) * 100.0).clamp(0.0, 100.0))
    }

    fn merge_from(&mut self, src: &RnodeStatus) {
        if let Some(value) = src.stat_rx {
            self.stat_rx = Some(value);
        }
        if let Some(value) = src.stat_tx {
            self.stat_tx = Some(value);
        }
        if let Some(value) = src.rssi {
            self.rssi = Some(value);
        }
        if let Some(value) = src.snr {
            self.snr = Some(value);
        }
        if let Some(value) = src.quality {
            self.quality = Some(value);
        }
        if let Some(value) = src.battery {
            self.battery = Some(value);
        }
        if let Some(value) = src.battery_state {
            self.battery_state = Some(value);
        }
        if let Some(reading) = src.temperature_report {
            self.temperature = reading;
        }
        if let Some(value) = src.csma_cw_band {
            self.csma_cw_band = Some(value);
        }
        if let Some(value) = src.csma_cw_min {
            self.csma_cw_min = Some(value);
        }
        if let Some(value) = src.csma_cw_max {
            self.csma_cw_max = Some(value);
        }
        if let Some(value) = src.csma_slot_time_ms {
            self.csma_slot_time_ms = Some(value);
        }
        if let Some(value) = src.csma_difs_ms {
            self.csma_difs_ms = Some(value);
        }
        if let Some(value) = src.symbol_time_ms {
            self.symbol_time_ms = Some(value);
        }
        if let Some(value) = src.symbol_rate {
            self.symbol_rate = Some(value);
        }
        if let Some(value) = src.preamble_symbols {
            self.preamble_symbols = Some(value);
        }
        if let Some(value) = src.preamble_time_ms {
            self.preamble_time_ms = Some(value);
        }
        if let Some(value) = src.airtime_short {
            self.airtime_short = Some(value);
        }
        if let Some(value) = src.airtime_long {
            self.airtime_long = Some(value);
        }
        if let Some(value) = src.channel_load_short {
            self.channel_load_short = Some(value);
        }
        if let Some(value) = src.channel_load_long {
            self.channel_load_long = Some(value);
        }
        if let Some(value) = src.current_rssi {
            self.current_rssi = Some(value);
        }
        if let Some(value) = src.noise_floor {
            self.noise_floor = Some(value);
        }
        if let Some(reading) = src.interference_report {
            self.interference = reading;
        }
    }
}

/// Events produced by parsing the device byte stream.
#[derive(Debug, Clone)]
pub enum RnodeEvent {
    /// Payload data (CMD_DATA or a per-vport data command).
    Data {
        vport: Option<u8>,
        data: Vec<u8>,
    },
    /// A virtual port was selected (RNodeMulti).
    SelectedVport(u8),
    Detect,
    FirmwareVersion {
        major: u8,
        minor: u8,
    },
    Platform(u8),
    Mcu(u8),
    Ready(bool),
    Echo(RnodeEchoState),
    Status(RnodeStatus),
    Error(u8),
    /// One virtual port from `CMD_INTERFACES`, in report order.
    /// The kind byte is Python `command_buffer[1]`.
    InterfaceKind(u8),
    /// Raw random bytes from CMD_RANDOM.
    Random(Vec<u8>),
}

/// Streaming parser for the device byte stream
/// (Python `RNodeInterface.read_loop` / `RNodeMultiInterface.readLoop`
/// state machines).
#[derive(Debug, Default)]
pub struct RnodeParser {
    in_frame: bool,
    escaped: bool,
    command: u8,
    data_buffer: Vec<u8>,
    /// RNodeMulti mode: per-vport data commands are recognised.
    multi: bool,
    /// Last vport reported selected by the device.
    selected_vport: Option<u8>,
}

impl RnodeParser {
    pub fn new(multi: bool) -> Self {
        Self {
            multi,
            ..Default::default()
        }
    }

    fn unescape(&mut self, byte: u8) -> Option<u8> {
        if self.escaped {
            self.escaped = false;
            Some(match byte {
                TFEND => FEND,
                TFESC => FESC,
                _ => byte,
            })
        } else if byte == FESC {
            self.escaped = true;
            None
        } else {
            Some(byte)
        }
    }

    fn vport_of(&self, command: u8) -> Option<u8> {
        if self.multi {
            CMD_INT_DATA
                .iter()
                .position(|&cmd| cmd == command)
                .map(|v| v as u8)
        } else if command == CMD_DATA {
            Some(0)
        } else {
            None
        }
    }

    /// Feed received bytes, invoking `on_event` for every parsed event.
    pub fn feed(&mut self, bytes: &[u8], mut on_event: impl FnMut(RnodeEvent)) {
        for &byte in bytes {
            if byte == FEND {
                if self.in_frame {
                    self.emit(&mut on_event);
                    self.in_frame = false;
                    self.command = CMD_UNKNOWN;
                } else {
                    self.in_frame = true;
                    self.command = CMD_UNKNOWN;
                    self.data_buffer.clear();
                }
                continue;
            }

            if !self.in_frame {
                continue;
            }

            if self.command == CMD_UNKNOWN && self.data_buffer.is_empty() {
                self.command = byte;
                continue;
            }

            let Some(byte) = self.unescape(byte) else {
                continue;
            };

            // Bound the accumulating frame: a malicious TCP endpoint can
            // stream unterminated bytes indefinitely (Python caps
            // data_buffer at HW_MTU).
            if self.data_buffer.len() < 2048 {
                self.data_buffer.push(byte);
            }
        }
    }

    fn emit(&mut self, on_event: &mut impl FnMut(RnodeEvent)) {
        let command = self.command;
        let data = std::mem::take(&mut self.data_buffer);

        // vport data commands
        if let Some(vport) = self.vport_of(command) {
            if !data.is_empty() {
                on_event(RnodeEvent::Data {
                    vport: if self.multi { Some(vport) } else { None },
                    data,
                });
            }
            return;
        }

        // RNodeMulti: vport selection acknowledgement
        if self.multi && command == CMD_SEL_INT && data.len() == 1 {
            self.selected_vport = Some(data[0]);
            on_event(RnodeEvent::SelectedVport(data[0]));
            return;
        }

        match command {
            CMD_DETECT if data.first() == Some(&DETECT_RESP) => on_event(RnodeEvent::Detect),
            CMD_FW_VERSION if data.len() >= 2 => on_event(RnodeEvent::FirmwareVersion {
                major: data[0],
                minor: data[1],
            }),
            CMD_PLATFORM if !data.is_empty() => on_event(RnodeEvent::Platform(data[0])),
            CMD_MCU if !data.is_empty() => on_event(RnodeEvent::Mcu(data[0])),
            CMD_READY if !data.is_empty() => on_event(RnodeEvent::Ready(data[0] == 0x01)),
            CMD_FREQUENCY if data.len() >= 4 => {
                self.emit_echo(
                    RnodeEchoState {
                        frequency: Some(
                            u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u64
                        ),
                        ..Default::default()
                    },
                    on_event,
                )
            }
            CMD_BANDWIDTH if data.len() >= 4 => self.emit_echo(
                RnodeEchoState {
                    bandwidth: Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_TXPOWER if !data.is_empty() => self.emit_echo(
                RnodeEchoState {
                    txpower: Some(data[0]),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_SF if !data.is_empty() => self.emit_echo(
                RnodeEchoState {
                    spreadingfactor: Some(data[0]),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_CR if !data.is_empty() => self.emit_echo(
                RnodeEchoState {
                    codingrate: Some(data[0]),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_RADIO_STATE if !data.is_empty() => self.emit_echo(
                RnodeEchoState {
                    radio_state: Some(data[0]),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_ST_ALOCK if data.len() >= 2 => self.emit_echo(
                RnodeEchoState {
                    st_alock: Some(u16::from_be_bytes([data[0], data[1]]) as f32 / 100.0),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_LT_ALOCK if data.len() >= 2 => self.emit_echo(
                RnodeEchoState {
                    lt_alock: Some(u16::from_be_bytes([data[0], data[1]]) as f32 / 100.0),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_STAT_RSSI if !data.is_empty() => self.emit_status(
                RnodeStatus {
                    rssi: Some(data[0] as i16 - RSSI_OFFSET),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_STAT_SNR if !data.is_empty() => {
                let snr = data[0] as i8 as f32 * 0.25;
                self.emit_status(
                    RnodeStatus {
                        snr: Some(snr),
                        ..Default::default()
                    },
                    on_event,
                )
            }
            CMD_STAT_RX if data.len() >= 4 => self.emit_status(
                RnodeStatus {
                    stat_rx: Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_STAT_TX if data.len() >= 4 => self.emit_status(
                RnodeStatus {
                    stat_tx: Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_STAT_BAT if data.len() >= 2 => {
                let percent = data[1].min(100);
                self.emit_status(
                    RnodeStatus {
                        battery_state: Some(data[0]),
                        battery: Some(u16::from(percent)),
                        ..Default::default()
                    },
                    on_event,
                )
            }
            CMD_STAT_TEMP if !data.is_empty() => {
                let temp = data[0] as i16 - 120;
                let reading = (-30..=90).contains(&temp).then_some(temp);
                self.emit_status(
                    RnodeStatus {
                        temperature: reading,
                        temperature_report: Some(reading),
                        ..Default::default()
                    },
                    on_event,
                )
            }
            CMD_STAT_CSMA if data.len() >= 3 => self.emit_status(
                RnodeStatus {
                    csma_cw_band: Some(data[0]),
                    csma_cw_min: Some(data[1]),
                    csma_cw_max: Some(data[2]),
                    ..Default::default()
                },
                on_event,
            ),
            CMD_STAT_CHTM if data.len() >= 8 => {
                let mut status = RnodeStatus {
                    airtime_short: Some(u16::from_be_bytes([data[0], data[1]]) as f32 / 100.0),
                    airtime_long: Some(u16::from_be_bytes([data[2], data[3]]) as f32 / 100.0),
                    channel_load_short: Some(u16::from_be_bytes([data[4], data[5]]) as f32 / 100.0),
                    channel_load_long: Some(u16::from_be_bytes([data[6], data[7]]) as f32 / 100.0),
                    ..Default::default()
                };
                // Single-radio reports are 11 bytes and add RSSI. An 8-byte
                // multi report leaves a previous interference reading alone.
                if data.len() >= 11 {
                    let interference = (data[10] != 0xFF).then_some(data[10] as i16 - RSSI_OFFSET);
                    status.current_rssi = Some(data[8] as i16 - RSSI_OFFSET);
                    status.noise_floor = Some(data[9] as i16 - RSSI_OFFSET);
                    status.interference = interference;
                    status.interference_report = Some(interference);
                }
                self.emit_status(status, on_event)
            }
            CMD_STAT_PHYPRM if data.len() >= 10 => {
                let mut status = RnodeStatus {
                    symbol_time_ms: Some(u16::from_be_bytes([data[0], data[1]]) as f32 / 1000.0),
                    symbol_rate: Some(u16::from_be_bytes([data[2], data[3]])),
                    preamble_symbols: Some(u16::from_be_bytes([data[4], data[5]])),
                    preamble_time_ms: Some(u16::from_be_bytes([data[6], data[7]])),
                    csma_slot_time_ms: Some(u16::from_be_bytes([data[8], data[9]])),
                    ..Default::default()
                };
                if data.len() >= 12 {
                    status.csma_difs_ms = Some(u16::from_be_bytes([data[10], data[11]]));
                }
                self.emit_status(status, on_event)
            }
            CMD_INTERFACES if data.len() >= 2 => {
                let mut index = 0;
                while index + 1 < data.len() {
                    on_event(RnodeEvent::InterfaceKind(data[index + 1]));
                    index += 2;
                }
            }
            CMD_ERROR if !data.is_empty() => on_event(RnodeEvent::Error(data[0])),
            CMD_RANDOM => on_event(RnodeEvent::Random(data)),
            _ => {}
        }
    }

    fn emit_echo(&mut self, mut echo: RnodeEchoState, on_event: &mut impl FnMut(RnodeEvent)) {
        if self.multi {
            echo.vport = self.selected_vport;
        }
        on_event(RnodeEvent::Echo(echo));
    }

    fn emit_status(&mut self, mut status: RnodeStatus, on_event: &mut impl FnMut(RnodeEvent)) {
        if self.multi {
            status.vport = self.selected_vport;
        }
        on_event(RnodeEvent::Status(status));
    }
}

/// Shared radio state: validated echo state, telemetry and flow-control
/// readiness.
pub type SharedRnodeState = Arc<std::sync::RwLock<RnodeShared>>;

#[derive(Default)]
pub struct RnodeShared {
    pub echo: RnodeEchoState,
    pub status: RnodeStatus,
    pub firmware: Option<(u8, u8)>,
    pub platform: Option<u8>,
    pub mcu: Option<u8>,
    pub detected: bool,
    /// Flow control: tx paused until CMD_READY.
    pub interface_ready: bool,
    /// On-air bitrate in bits per second (Python `bitrate`), rounded.
    pub bitrate: u64,
    /// Kinds reported by `CMD_INTERFACES`, vport 0 first.
    pub subinterface_kinds: Vec<u8>,
    /// Per-virtual-port modem echoes (RNodeMulti).
    pub vport_echo: HashMap<u8, RnodeEchoState>,
    /// Per-virtual-port on-air bitrate in bits per second.
    pub vport_bitrate: HashMap<u8, u64>,
}

impl RnodeShared {
    /// Fold a modem echo into the shared state. Returns `(vport, bps)` when
    /// the on-air rate can be computed.
    pub fn note_echo(&mut self, echo: RnodeEchoState) -> Option<(Option<u8>, u64)> {
        let vport = echo.vport;
        let rate = if let Some(vport) = vport {
            let slot = self.vport_echo.entry(vport).or_default();
            slot.merge(echo);
            slot.on_air_bitrate()
        } else {
            self.echo.merge(echo);
            self.echo.on_air_bitrate()
        }?;
        let bps = rate.round() as u64;
        if bps == 0 {
            return None;
        }
        if let Some(vport) = vport {
            self.vport_bitrate.insert(vport, bps);
        } else {
            self.bitrate = bps;
        }
        Some((vport, bps))
    }

    /// Fold a telemetry report into the shared status. Recomputes link
    /// quality when the report carries an SNR.
    pub fn note_status(&mut self, status: RnodeStatus) -> (Option<i16>, Option<f32>, Option<f32>) {
        let snr = status.snr;
        let sf = if let Some(vport) = status.vport {
            self.vport_echo
                .get(&vport)
                .and_then(|echo| echo.spreadingfactor)
                .or(self.echo.spreadingfactor)
        } else {
            self.echo.spreadingfactor
        };
        self.status.merge_from(&status);
        if let Some(snr) = snr {
            if let Some(quality) = RnodeStatus::quality_for(snr, sf) {
                self.status.quality = Some(quality);
            }
        }
        (self.status.rssi, self.status.snr, self.status.quality)
    }
}

/// Identification beacon window.
/// Opens only after a non-beacon write succeeds and clears only after the
/// beacon write succeeds.
struct IdBeacon {
    interval: Duration,
    callsign: Vec<u8>,
    first_tx: Option<Instant>,
}

impl IdBeacon {
    fn new(interval_secs: u64, callsign: Vec<u8>) -> Self {
        Self {
            interval: Duration::from_secs(interval_secs),
            callsign,
            first_tx: None,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        self.first_tx
            .map(|start| start + self.interval + Duration::from_nanos(1))
    }

    fn on_written(&mut self, payload: &[u8], now: Instant) {
        if payload == self.callsign.as_slice() {
            self.first_tx = None;
        } else if self.first_tx.is_none() {
            self.first_tx = Some(now);
        }
    }
}

async fn wait_for_interface_ready(
    state: &SharedRnodeState,
    cancel: &tokio_util::sync::CancellationToken,
    link_cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    loop {
        if state
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .interface_ready
        {
            return true;
        }
        tokio::select! {
            _ = cancel.cancelled() => return false,
            _ = link_cancel.cancelled() => return false,
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }
    }
}

fn vport_transmit_frames(index: u8, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (
        kiss_frame(CMD_SEL_INT, &[index]),
        kiss_frame(CMD_DATA, data),
    )
}

/// Nordic UART UUIDs (Python `BLEConnection.UART_*_UUID`).
pub const BLE_UART_SERVICE_UUID: &str = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
pub const BLE_UART_RX_UUID: &str = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E";
pub const BLE_UART_TX_UUID: &str = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E";

/// Python `BLEConnection.SCAN_TIMEOUT`.
pub const BLE_SCAN_TIMEOUT: Duration = Duration::from_secs(2);
/// Python `BLEConnection.CONNECT_TIMEOUT`.
pub const BLE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Who `ble://` should attach to (Python `BLEConnection` target parse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BleTarget {
    /// `ble://` — first bonded device advertising the Nordic UART service.
    /// Python does not require the name to start with `RNode `.
    Any,
    /// `ble://<name>` when the remainder is not a 17-character MAC.
    Name(String),
    /// `ble://F4:12:73:29:4E:89` (six colon-separated fields, length 17).
    Address(String),
}

/// Parse a `ble://` port. `None` when `port` is not that scheme.
///
/// The scheme compare is case-insensitive. The remainder keeps its
/// original spelling, matching Python's slice after `ble://`.
pub fn parse_ble_target(port: &str) -> Option<BleTarget> {
    const SCHEME: &str = "ble://";
    if port.len() < SCHEME.len()
        || !port.as_bytes()[..SCHEME.len()].eq_ignore_ascii_case(SCHEME.as_bytes())
    {
        return None;
    }
    let rest = &port[SCHEME.len()..];
    if rest.is_empty() {
        return Some(BleTarget::Any);
    }
    if rest.len() == 17 && rest.split(':').count() == 6 {
        Some(BleTarget::Address(rest.to_string()))
    } else {
        Some(BleTarget::Name(rest.to_string()))
    }
}

/// Python `BLEConnection.device_filter` after bond status is known.
///
/// `address` is `None` when the controller has no public MAC. An unbonded
/// device never matches. `BleTarget::Any` does not look at the local name.
/// The btleplug caller is behind `iface-rnode-ble`; unit tests cover the
/// rule without that feature.
#[cfg_attr(not(feature = "iface-rnode-ble"), allow(dead_code))]
fn ble_candidate_matches(
    target: &BleTarget,
    local_name: Option<&str>,
    address: Option<&str>,
    bonded: bool,
) -> bool {
    if !bonded {
        return false;
    }
    match target {
        BleTarget::Any => true,
        BleTarget::Name(name) => local_name == Some(name.as_str()),
        BleTarget::Address(want) => address.is_some_and(|addr| addr.eq_ignore_ascii_case(want)),
    }
}

/// Android USB serial (`RNS.Interfaces.Android` via `usb4a`) is not
/// implemented. Those targets are an explicit [`RnsError::Unsupported`],
/// not a host serial open.
pub fn android_usb_error(target: &str) -> Result<(), RnsError> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("usb://")
        || lower.starts_with("android-usb://")
        || lower == "androidrnodeinterface"
        || lower == "androidserialinterface"
        || lower == "androidkissinterface"
    {
        log::error!("rnode: Android USB interface type '{target}' is not supported");
        Err(RnsError::Unsupported)
    } else {
        Ok(())
    }
}

/// Byte pipe to an RNode over BLE (Python `BLEConnection` read/write).
///
/// `connected` is true only after a live controller session exists.
/// [`FakeBleLink`] never reports one.
pub trait BleLink: Send {
    fn write(
        &mut self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), RnsError>> + Send;
    fn read(
        &mut self,
        buffer: &mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, RnsError>> + Send;
    fn connected(&self) -> bool;
}

/// In-memory [`BleLink`]. Records host writes and replays queued device
/// bytes. It does not open an adapter and is never connected.
#[derive(Debug, Default)]
pub struct FakeBleLink {
    written: Vec<u8>,
    inbound: VecDeque<u8>,
}

impl FakeBleLink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn written(&self) -> &[u8] {
        &self.written
    }

    /// Queue bytes the next [`BleLink::read`] calls will return.
    pub fn queue_rx(&mut self, bytes: &[u8]) {
        self.inbound.extend(bytes);
    }
}

impl BleLink for FakeBleLink {
    fn write(
        &mut self,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<(), RnsError>> + Send {
        self.written.extend_from_slice(data);
        async { Ok(()) }
    }

    fn read(
        &mut self,
        buffer: &mut [u8],
    ) -> impl std::future::Future<Output = Result<usize, RnsError>> + Send {
        let n = buffer.len().min(self.inbound.len());
        for slot in &mut buffer[..n] {
            *slot = self.inbound.pop_front().unwrap_or(0);
        }
        async move { Ok(n) }
    }

    fn connected(&self) -> bool {
        false
    }
}

/// One open link to an RNode device: serial, TCP, or BLE
/// (Python serial / `use_tcp` / `use_ble`).
pub struct RnodeLink {
    reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
}

impl RnodeLink {
    /// Open a serial link.
    ///
    /// USB-serial devices need a moment to release the tty after a
    /// previous close; an immediate reopen can fail with EIO, so the
    /// open is retried briefly.
    #[cfg(feature = "iface-serial")]
    pub async fn serial(port: &str, baudrate: u32) -> Result<Self, RnsError> {
        let builder = tokio_serial::new(port, baudrate);

        let mut last_err = None;
        for attempt in 0..5 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(200 * attempt as u64)).await;
            }
            match tokio_serial::SerialStream::open(&builder) {
                Ok(port) => {
                    // Python `RNodeInterface` connect resets the device via
                    // a DTR/RTS transition; the ESP32 native USB-Serial/
                    // JTAG peripheral hardware-resets the same way. Toggle
                    // the lines so every connection starts from a clean
                    // protocol state (also re-enumerates wedged CDC ports).
                    #[cfg(unix)]
                    {
                        use std::os::unix::io::AsRawFd;
                        // Sequence matched to what pyserial/`rnodeconf`
                        // produce: DTR clear + RTS asserted pulses the
                        // reset line, then both settle high.
                        let fd = port.as_raw_fd();
                        let reset: libc::c_int = libc::TIOCM_RTS;
                        let run: libc::c_int = libc::TIOCM_DTR | libc::TIOCM_RTS;
                        unsafe {
                            libc::ioctl(fd, libc::TIOCMSET, &reset);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        unsafe {
                            libc::ioctl(fd, libc::TIOCMSET, &run);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                    let (reader, writer) = tokio::io::split(port);
                    return Ok(Self {
                        reader: Box::new(reader),
                        writer: Box::new(writer),
                    });
                }
                Err(error) => {
                    log::debug!(
                        "rnode: serial open attempt {attempt} on {port} failed: {error}; retrying"
                    );
                    last_err = Some(error);
                }
            }
        }

        let _ = last_err;
        Err(RnsError::ConnectionError)
    }

    /// Open a TCP link (Python `use_tcp`).
    pub async fn tcp(addr: &str) -> Result<Self, RnsError> {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|_| RnsError::ConnectionError)?;
        stream.set_nodelay(true).ok();
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
        })
    }

    /// Wrap externally-provided byte streams (e.g. an in-process link to
    /// an RNode KISS modem on embedded targets).
    pub fn from_reader_writer(
        reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    ) -> Result<Self, RnsError> {
        Ok(Self { reader, writer })
    }

    /// Open `ble://`. Without `iface-rnode-ble` this is
    /// [`RnsError::Unsupported`] and does not touch an adapter.
    pub async fn connect_ble(port: &str) -> Result<Self, RnsError> {
        let Some(target) = parse_ble_target(port) else {
            return Err(RnsError::InvalidArgument);
        };
        #[cfg(feature = "iface-rnode-ble")]
        {
            let link = ble_backend::BtleplugBleLink::connect(&target).await?;
            Ok(link.into_rnode_link())
        }
        #[cfg(not(feature = "iface-rnode-ble"))]
        {
            let _ = target;
            log::error!(
                "rnode: BLE target '{port}' requires building with --features iface-rnode-ble"
            );
            Err(RnsError::Unsupported)
        }
    }

    pub async fn write(&mut self, data: &[u8]) -> Result<(), RnsError> {
        self.writer
            .write_all(data)
            .await
            .map_err(|_| RnsError::ConnectionError)?;
        self.writer
            .flush()
            .await
            .map_err(|_| RnsError::ConnectionError)
    }

    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, RnsError> {
        self.reader
            .read(buffer)
            .await
            .map_err(|_| RnsError::ConnectionError)
    }
}

async fn open_rnode_link(
    tcp: Option<&str>,
    port: Option<&str>,
    baudrate: u32,
    multi: bool,
) -> Result<RnodeLink, RnsError> {
    if let Some(addr) = tcp {
        return RnodeLink::tcp(addr).await;
    }
    let Some(port) = port else {
        #[cfg(feature = "iface-serial")]
        {
            return Err(RnsError::InvalidArgument);
        }
        #[cfg(not(feature = "iface-serial"))]
        {
            let _ = baudrate;
            return Err(RnsError::Unsupported);
        }
    };
    android_usb_error(port)?;
    if parse_ble_target(port).is_some() {
        if multi {
            log::error!("rnode_multi: ble:// is not supported");
            return Err(RnsError::Unsupported);
        }
        return RnodeLink::connect_ble(port).await;
    }
    #[cfg(feature = "iface-serial")]
    {
        RnodeLink::serial(port, baudrate).await
    }
    #[cfg(not(feature = "iface-serial"))]
    {
        let _ = baudrate;
        log::error!("rnode: serial port '{port}' requires building with --features iface-serial");
        Err(RnsError::Unsupported)
    }
}

/// Handle detection, firmware validation and radio validation on a link
/// (Python `detect` / `validate_firmware` / `validateRadioState`).
pub async fn detect_and_validate(
    link: &mut RnodeLink,
    config: &RnodeRadioConfig,
    shared: &SharedRnodeState,
) -> Result<(), RnsError> {
    detect_and_configure(link, config, shared, false).await
}

async fn detect_and_configure(
    link: &mut RnodeLink,
    config: &RnodeRadioConfig,
    shared: &SharedRnodeState,
    probe_interfaces: bool,
) -> Result<(), RnsError> {
    let request = if probe_interfaces {
        shared
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .subinterface_kinds
            .clear();
        multi_detect_request()
    } else {
        detect_request()
    };
    link.write(&request).await?;

    let mut parser = RnodeParser::new(false);
    let mut buffer = [0u8; 4096];

    // Detection phase: collect detect/fw/platform/mcu responses.
    // Answers may arrive split across reads (serial timing, TCP
    // segmentation), so the seen-flags accumulate across iterations.
    let mut firmware_seen = false;
    let mut platform_seen = false;
    let mut mcu_seen = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(RnsError::ConnectionError);
        }

        let read = tokio::time::timeout(std::time::Duration::from_secs(2), link.read(&mut buffer))
            .await
            .map_err(|_| RnsError::ConnectionError)?
            .map_err(|_| RnsError::ConnectionError)?;

        if read == 0 {
            return Err(RnsError::ConnectionError);
        }

        parser.feed(&buffer[..read], |event| {
            note_probe_event(
                shared,
                event,
                &mut firmware_seen,
                &mut platform_seen,
                &mut mcu_seen,
            );
        });

        // The detect burst queries detect, firmware, platform and MCU;
        // answers may arrive split across reads (serial timing, TCP
        // segmentation). Wait for the full set before proceeding, the
        // deadline above bounds the wait.
        if firmware_seen && platform_seen && mcu_seen {
            break;
        }
    }

    if probe_interfaces {
        if let Ok(Ok(read)) = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            link.read(&mut buffer),
        )
        .await
        {
            if read > 0 {
                parser.feed(&buffer[..read], |event| {
                    note_probe_event(
                        shared,
                        event,
                        &mut firmware_seen,
                        &mut platform_seen,
                        &mut mcu_seen,
                    );
                });
            }
        }
    }

    // Firmware validation (Python `validate_firmware`).
    let (major, minor) = shared
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .firmware
        .ok_or(RnsError::ConnectionError)?;

    let ok = major > REQUIRED_FW_VER_MAJ
        || (major >= REQUIRED_FW_VER_MAJ && minor >= REQUIRED_FW_VER_MIN);
    if !ok {
        log::error!(
            "rnode: firmware {major}.{minor} too old, at least              {REQUIRED_FW_VER_MAJ}.{REQUIRED_FW_VER_MIN} required"
        );
        return Err(RnsError::Unsupported);
    }

    // Configure the radio, then collect configuration echoes.
    for frame in config.configuration_frames(RADIO_STATE_ON) {
        link.write(&frame).await?;
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let mut collected = RnodeEchoState::default();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() > deadline {
            break;
        }

        let read =
            tokio::time::timeout(std::time::Duration::from_secs(1), link.read(&mut buffer)).await;

        let Ok(Ok(read)) = read else { break };
        if read == 0 {
            break;
        }

        parser.feed(&buffer[..read], |event| {
            if let RnodeEvent::Echo(echo) = event {
                collected.merge(echo);
            }
        });

        if config.validate(&collected).is_ok() {
            break;
        }
    }

    config.validate(&collected).map_err(|reason| {
        log::error!("rnode: radio state validation failed: {reason}");
        RnsError::ConnectionError
    })?;

    {
        let mut shared = shared.write().unwrap_or_else(|e| e.into_inner());
        let _ = shared.note_echo(collected);
        shared.interface_ready = true;
    }

    Ok(())
}

fn note_probe_event(
    shared: &SharedRnodeState,
    event: RnodeEvent,
    firmware_seen: &mut bool,
    platform_seen: &mut bool,
    mcu_seen: &mut bool,
) {
    let mut shared = shared.write().unwrap_or_else(|e| e.into_inner());
    match event {
        RnodeEvent::Detect => shared.detected = true,
        RnodeEvent::FirmwareVersion { major, minor } => {
            shared.firmware = Some((major, minor));
            *firmware_seen = true;
        }
        RnodeEvent::Platform(platform) => {
            shared.platform = Some(platform);
            *platform_seen = true;
        }
        RnodeEvent::Mcu(mcu) => {
            shared.mcu = Some(mcu);
            *mcu_seen = true;
        }
        RnodeEvent::InterfaceKind(kind) => shared.subinterface_kinds.push(kind),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// RNodeInterface: one radio per interface.
// ---------------------------------------------------------------------------

/// The single-radio RNode interface
/// (Python `RNodeInterface`).
pub struct RnodeInterface {
    /// TCP address when `tcp` mode is used.
    pub tcp_addr: Option<String>,
    /// Serial port when serial mode is used (requires `iface-serial`).
    pub serial_port: Option<String>,
    pub baudrate: u32,
    pub config: RnodeRadioConfig,
    /// Require a CMD_READY notification before each transmission.
    pub flow_control: bool,
    /// Interface manager of the owning transport (tunnel synthesis).
    pub iface_manager: Option<Arc<tokio::sync::Mutex<InterfaceManager>>>,
    /// Shared radio state, exposed to embedders for diagnostics.
    pub state: SharedRnodeState,
    id_interval: Option<u64>,
    id_callsign: Option<Vec<u8>>,
    /// Link injected via [`Self::from_link`]; consumed by the first
    /// `spawn` reconnect pass.
    injected_link: Option<RnodeLink>,
}

impl RnodeInterface {
    pub fn tcp(addr: impl Into<String>, config: RnodeRadioConfig) -> Self {
        Self {
            tcp_addr: Some(addr.into()),
            serial_port: None,
            baudrate: 115200,
            config,
            flow_control: false,
            iface_manager: None,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
            id_interval: None,
            id_callsign: None,
            injected_link: None,
        }
    }

    /// BLE port (Python `port = ble://...`).
    ///
    /// A value without the scheme is prefixed with `ble://`. Opening the
    /// radio still requires feature `iface-rnode-ble`.
    pub fn ble(port: impl Into<String>, config: RnodeRadioConfig) -> Self {
        let port = port.into();
        let port = if parse_ble_target(&port).is_some() {
            port
        } else {
            format!("ble://{port}")
        };
        Self {
            tcp_addr: None,
            serial_port: Some(port),
            baudrate: 115200,
            config,
            flow_control: false,
            iface_manager: None,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
            id_interval: None,
            id_callsign: None,
            injected_link: None,
        }
    }

    #[cfg(feature = "iface-serial")]
    pub fn serial(port: impl Into<String>, baudrate: u32, config: RnodeRadioConfig) -> Self {
        Self {
            tcp_addr: None,
            serial_port: Some(port.into()),
            baudrate,
            config,
            flow_control: false,
            iface_manager: None,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
            id_interval: None,
            id_callsign: None,
            injected_link: None,
        }
    }

    /// Interface over an already-open link (e.g. an in-process transport
    /// built via [`RnodeLink::from_reader_writer`] on embedded targets).
    /// `spawn` consumes the link once; it is not reopened after a drop.
    pub fn from_link(link: RnodeLink, config: RnodeRadioConfig) -> Self {
        Self {
            tcp_addr: None,
            serial_port: None,
            baudrate: 115200,
            config,
            flow_control: false,
            iface_manager: None,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
            id_interval: None,
            id_callsign: None,
            injected_link: Some(link),
        }
    }

    pub fn with_manager(mut self, manager: Arc<tokio::sync::Mutex<InterfaceManager>>) -> Self {
        self.iface_manager = Some(manager);
        self
    }

    pub fn with_flow_control(mut self, flow_control: bool) -> Self {
        self.flow_control = flow_control;
        self
    }

    /// Identification beacon (Python `id_interval` / `id_callsign`).
    /// Callsigns longer than [`CALLSIGN_MAX_LEN`] are rejected and the
    /// beacon stays disabled.
    pub fn with_beacon(mut self, interval_secs: u64, callsign: impl AsRef<[u8]>) -> Self {
        if let Some((interval, callsign)) = beacon_config(interval_secs, callsign.as_ref()) {
            self.id_interval = Some(interval);
            self.id_callsign = Some(callsign);
        }
        self
    }

    pub fn id_callsign(&self) -> Option<&[u8]> {
        self.id_callsign.as_deref()
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let inner = context.inner.clone();
        let state = { context.inner.lock().unwrap().state.clone() };
        let (rx_channel, tx_channel) = context.channel.split();
        let rx_channel = Arc::new(tokio::sync::Mutex::new(rx_channel));
        let mut tx_channel_slot = Some(tx_channel);

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let link = {
                let (tcp_addr, serial_port, baudrate, injected) = {
                    let mut inner = inner.lock().unwrap();
                    (
                        inner.tcp_addr.clone(),
                        inner.serial_port.clone(),
                        inner.baudrate,
                        inner.injected_link.take(),
                    )
                };

                let result = match injected {
                    Some(link) => Ok(link),
                    None => {
                        open_rnode_link(tcp_addr.as_deref(), serial_port.as_deref(), baudrate, false)
                            .await
                    }
                };

                match result {
                    Ok(link) => link,
                    Err(_) => {
                        log::warn!("rnode: could not open device link, retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                }
            };
            let mut link = link;

            let (config, flow_control, id_beacon) = {
                let inner = context.inner.lock().unwrap();
                let id_beacon = match (inner.id_interval, inner.id_callsign.clone()) {
                    (Some(interval), Some(callsign)) => Some(IdBeacon::new(interval, callsign)),
                    _ => None,
                };
                (inner.config.clone(), inner.flow_control, id_beacon)
            };

            // Detection + firmware + radio validation
            // (Python connect sequence).
            if let Err(error) = detect_and_validate(&mut link, &config, &state).await {
                log::error!("rnode: device validation failed: {error:?}");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            log::info!("rnode: device online and radio configuration validated");
            stats.set_online(true);

            // Tunnel synthesis hook (RNodes participate in tunnel
            // endpoints via wants_tunnel, like Python).
            let manager_of = { inner.lock().unwrap().iface_manager.clone() };
            let on_air = state.read().unwrap_or_else(|e| e.into_inner()).bitrate;
            if let Some(manager) = &manager_of {
                let manager = manager.lock().await;
                manager.set_iface_wants_tunnel(&iface_address, true);
                if on_air > 0 {
                    manager.set_iface_bitrate(&iface_address, on_air);
                }
            }

            let mut writer = link.writer;
            let mut reader = link.reader;
            let link_cancel = tokio_util::sync::CancellationToken::new();

            let rx_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let rx_channel = rx_channel.clone();
                let state = state.clone();
                let manager_of = manager_of.clone();

                tokio::spawn(async move {
                    let mut parser = RnodeParser::new(false);
                    let mut buffer = [0u8; 4096];

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = link_cancel.cancelled() => true,
                            result = reader.read(&mut buffer) => match result {
                                Ok(0) | Err(_) => true,
                                Ok(n) => {
                                    let mut packets: Vec<Vec<u8>> = Vec::new();
                                    let mut bitrate_bps = None;
                                    parser.feed(&buffer[..n], |event| {
                                        match event {
                                            RnodeEvent::Data { data, .. } => packets.push(data),
                                            RnodeEvent::Ready(ready) => {
                                                state.write().unwrap_or_else(|e| e.into_inner()).interface_ready = ready;
                                            }
                                            RnodeEvent::Status(status) => {
                                                let mut shared = state.write().unwrap_or_else(|e| e.into_inner());
                                                let (rssi, snr, quality) = shared.note_status(status);
                                                let airtime_short = shared.status.airtime_short;
                                                let airtime_long = shared.status.airtime_long;
                                                let channel_load_short = shared.status.channel_load_short;
                                                let channel_load_long = shared.status.channel_load_long;
                                                drop(shared);
                                                stats.set_radio_quality(rssi, snr, quality);
                                                stats.set_radio_channel(
                                                    airtime_short,
                                                    airtime_long,
                                                    channel_load_short,
                                                    channel_load_long,
                                                );
                                            }
                                            RnodeEvent::Echo(echo) => {
                                                if let Some((_, bps)) = state.write().unwrap_or_else(|e| e.into_inner()).note_echo(echo) {
                                                    bitrate_bps = Some(bps);
                                                }
                                            }
                                            RnodeEvent::Error(code) => {
                                                log::debug!("rnode: device error code {code:#x}");
                                            }
                                            _ => {}
                                        }
                                    });

                                    if let Some(bps) = bitrate_bps {
                                        if let Some(manager) = &manager_of {
                                            manager.lock().await.set_iface_bitrate(&iface_address, bps);
                                        }
                                    }

                                    let rx_channel = rx_channel.lock().await;
                                    for data in packets {
                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&data)) {
                                            stats.count_rx(data.len());
                                            let _ = rx_channel.send(RxMessage { address: iface_address, packet: Box::new(packet) }).await;
                                        }
                                    }

                                    false
                                }
                            },
                        };

                        if closed {
                            link_cancel.cancel();
                            break;
                        }
                    }
                })
            };

            let tx_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let state = state.clone();
                let tx_channel = tx_channel_slot.take();

                tokio::spawn(async move {
                    let mut tx_channel = tx_channel?;
                    let mut id_beacon = id_beacon;
                    loop {
                        let mut buffer = [0u8; 2048];
                        let beacon_at = id_beacon.as_ref().and_then(IdBeacon::deadline);

                        let message = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = link_cancel.cancelled() => break,
                            _ = async {
                                match beacon_at {
                                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                                    None => std::future::pending().await,
                                }
                            } => {
                                if let Some(beacon) = id_beacon.as_mut() {
                                    if flow_control && !wait_for_interface_ready(&state, &cancel, &link_cancel).await {
                                        return Some(tx_channel);
                                    }
                                    let callsign = beacon.callsign.clone();
                                    let frame = kiss_frame(CMD_DATA, &callsign);
                                    if writer.write_all(&frame).await.is_ok()
                                        && writer.flush().await.is_ok()
                                    {
                                        stats.count_tx(callsign.len());
                                        beacon.on_written(&callsign, Instant::now());
                                        if flow_control {
                                            state.write().unwrap_or_else(|e| e.into_inner()).interface_ready = false;
                                        }
                                        log::debug!("rnode: transmitted beacon data");
                                    } else {
                                        link_cancel.cancel();
                                        return Some(tx_channel);
                                    }
                                }
                                continue;
                            }
                            message = tx_channel.recv() => match message {
                                Some(message) => message,
                                None => break,
                            },
                        };

                        if flow_control {
                            // Flow control: wait for interface readiness
                            // (Python CMD_READY handling).
                            if !wait_for_interface_ready(&state, &cancel, &link_cancel).await {
                                return Some(tx_channel);
                            }
                        }

                        let packet = message.packet;
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let frame = kiss_frame(CMD_DATA, output.as_slice());
                            if writer.write_all(&frame).await.is_ok()
                                && writer.flush().await.is_ok()
                            {
                                stats.count_tx(output.offset());
                                if let Some(beacon) = id_beacon.as_mut() {
                                    beacon.on_written(output.as_slice(), Instant::now());
                                }
                                if flow_control {
                                    state
                                        .write()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .interface_ready = false;
                                }
                            } else {
                                link_cancel.cancel();
                                break;
                            }
                        }
                    }

                    Some(tx_channel)
                })
            };

            let mut rx_task = rx_task;
            let mut tx_task = tx_task;
            let tx_result = tokio::select! {
                _ = &mut rx_task => {
                    link_cancel.cancel();
                    tx_task.await
                }
                result = &mut tx_task => {
                    link_cancel.cancel();
                    let _ = rx_task.await;
                    result
                }
                _ = context.cancel.cancelled() => {
                    link_cancel.cancel();
                    let _ = rx_task.await;
                    tx_task.await
                }
            };
            if let Ok(Some(tx_channel)) = tx_result {
                tx_channel_slot = Some(tx_channel);
            }
            stats.set_online(false);
            if context.cancel.is_cancelled() {
                break;
            }
            log::warn!("rnode: device link lost, reconnecting");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

impl Interface for RnodeInterface {
    fn mtu() -> usize {
        500
    }

    fn should_ingress_limit() -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// RNodeMultiInterface: virtual ports over one device.
// ---------------------------------------------------------------------------

/// One virtual port of a multi-interface
/// (Python `RNodeMultiInterfacePeer`).
#[derive(Debug, Clone)]
pub struct RnodeVport {
    /// Virtual port index (0..11).
    pub index: u8,
    pub config: RnodeRadioConfig,
}

impl RnodeVport {
    /// The prefixed configuration frames for this port
    /// (Python `FEND SEL_INT idx FEND FEND CMD ... FEND`).
    pub fn configuration_frames(&self, radio_state: u8) -> Vec<Vec<u8>> {
        let prefix = kiss_frame(CMD_SEL_INT, &[self.index]);

        self.config
            .configuration_frames(radio_state)
            .into_iter()
            .map(|frame| {
                let mut out = prefix.clone();
                out.extend_from_slice(&frame);
                out
            })
            .collect()
    }
}

/// The multi-band RNode interface: owns the device and one spawned peer
/// interface per configured virtual port
/// (Python `RNodeMultiInterface`).
pub struct RnodeMultiInterface {
    pub tcp_addr: Option<String>,
    pub serial_port: Option<String>,
    pub baudrate: u32,
    /// Virtual ports to spawn (Python `[[subinterfaces]]`).
    pub vports: Vec<RnodeVport>,
    /// Interface manager: peers are spawned into it.
    pub iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    pub state: SharedRnodeState,
    receive_only: Vec<u8>,
    id_interval: Option<u64>,
    id_callsign: Option<Vec<u8>>,
}

impl RnodeMultiInterface {
    pub fn tcp(
        addr: impl Into<String>,
        vports: Vec<RnodeVport>,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            tcp_addr: Some(addr.into()),
            serial_port: None,
            baudrate: 115200,
            vports,
            iface_manager,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
            receive_only: Vec::new(),
            id_interval: None,
            id_callsign: None,
        }
    }

    #[cfg(feature = "iface-serial")]
    pub fn serial(
        port: impl Into<String>,
        baudrate: u32,
        vports: Vec<RnodeVport>,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            tcp_addr: None,
            serial_port: Some(port.into()),
            baudrate,
            vports,
            iface_manager,
            state: Arc::new(std::sync::RwLock::new(RnodeShared::default())),
            receive_only: Vec::new(),
            id_interval: None,
            id_callsign: None,
        }
    }

    /// Virtual port that receives but does not transmit
    /// (Python subinterface `outgoing = False`).
    pub fn with_receive_only(mut self, index: u8) -> Self {
        if !self.receive_only.contains(&index) {
            self.receive_only.push(index);
        }
        self
    }

    /// Identification beacon sent on every virtual port
    /// (Python `id_interval` / `id_callsign`).
    pub fn with_beacon(mut self, interval_secs: u64, callsign: impl AsRef<[u8]>) -> Self {
        if let Some((interval, callsign)) = beacon_config(interval_secs, callsign.as_ref()) {
            self.id_interval = Some(interval);
            self.id_callsign = Some(callsign);
        }
        self
    }

    pub fn id_callsign(&self) -> Option<&[u8]> {
        self.id_callsign.as_deref()
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let parent_address = context.channel.address;
        let inner = context.inner.clone();
        let state = { context.inner.lock().unwrap().state.clone() };
        let (_parent_rx, _parent_tx) = context.channel.split();
        let _ = (_parent_rx, _parent_tx);

        loop {
            if context.cancel.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let mut link = {
                let (tcp_addr, serial_port, baudrate) = {
                    let inner = inner.lock().unwrap();
                    (
                        inner.tcp_addr.clone(),
                        inner.serial_port.clone(),
                        inner.baudrate,
                    )
                };

                let result =
                    open_rnode_link(tcp_addr.as_deref(), serial_port.as_deref(), baudrate, true)
                        .await;

                match result {
                    Ok(link) => link,
                    Err(_) => {
                        log::warn!("rnode_multi: could not open device link, retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        continue;
                    }
                }
            };

            // Detection + firmware validation using the first vport's
            // configuration; radio state per vport is configured below.
            let first_config = {
                let inner = inner.lock().unwrap();
                inner
                    .vports
                    .first()
                    .map(|vport| vport.config.clone())
                    .unwrap_or(RnodeRadioConfig {
                        frequency: 867_500_000,
                        bandwidth: 125_000,
                        txpower: 0,
                        spreadingfactor: 9,
                        codingrate: 5,
                        st_alock: None,
                        lt_alock: None,
                    })
            };

            if let Err(error) = detect_and_configure(&mut link, &first_config, &state, true).await {
                log::error!("rnode_multi: device validation failed: {error:?}");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            // Configure and spawn each virtual port.
            let (vports, iface_manager, receive_only, id_beacon) = {
                let inner = inner.lock().unwrap();
                let id_beacon = match (inner.id_interval, inner.id_callsign.clone()) {
                    (Some(interval), Some(callsign)) => Some(IdBeacon::new(interval, callsign)),
                    _ => None,
                };
                (
                    inner.vports.clone(),
                    inner.iface_manager.clone(),
                    inner.receive_only.clone(),
                    id_beacon,
                )
            };

            let kinds = state
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .subinterface_kinds
                .clone();
            let ports_ok = vports.iter().all(|vport| {
                match kinds.get(vport.index as usize).copied() {
                    Some(kind) if reported_kind_accepts_frequency(kind, vport.config.frequency) => {
                        true
                    }
                    Some(_) => {
                        log::error!(
                            "rnode_multi: frequency for virtual port {} is outside the reported band",
                            vport.index
                        );
                        false
                    }
                    None => {
                        log::error!(
                            "rnode_multi: virtual port {} was not reported by CMD_INTERFACES",
                            vport.index
                        );
                        false
                    }
                }
            });
            if !ports_ok {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                continue;
            }

            let (vport_tx, vport_rx) = tokio::sync::mpsc::unbounded_channel::<(u8, Vec<u8>)>();
            let inbound: VportInbound =
                Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
            let mut vport_addresses = HashMap::new();

            {
                let mut manager = iface_manager.lock().await;
                let parent_name = manager
                    .stats()
                    .into_iter()
                    .find(|stat| stat.address == parent_address)
                    .map(|stat| stat.name)
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| "RnodeMultiInterface".to_string());
                for vport in &vports {
                    // Per-vport configuration with the SEL_INT prefix.
                    for frame in vport.configuration_frames(RADIO_STATE_ON) {
                        let _ = link.write(&frame).await;
                    }

                    let (peer_in_tx, peer_in_rx) =
                        tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    inbound
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(vport.index, peer_in_tx);

                    // Parent name plus vport index, recorded before the
                    // worker starts and before this lock is released.
                    let label = format!("{parent_name}/{}", vport.index);
                    let address = manager.spawn_named(
                        &label,
                        RnodeVportPeer {
                            index: vport.index,
                            endpoint: label.clone(),
                            outbound: vport_tx.clone(),
                            inbound: Some(peer_in_rx),
                            outgoing: !receive_only.contains(&vport.index),
                        },
                        RnodeVportPeer::spawn,
                    );
                    vport_addresses.insert(vport.index, address);

                    // RNodeMulti peers use tunnel endpoints
                    // (Python wants_tunnel on the spawned peers).
                    manager.set_iface_wants_tunnel(&address, true);
                }
            }

            stats.set_online(true);
            log::info!(
                "rnode_multi: device online with {} virtual ports",
                vports.len()
            );
            let link_cancel = tokio_util::sync::CancellationToken::new();

            // Writer pump: vport peers submit packets through the
            // channel; each is framed with its port's data command.
            let writer_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let stats = stats.clone();
                let mut writer = link.writer;
                let mut vport_rx = vport_rx;
                let beacon_ports: Vec<u8> = vports.iter().map(|vport| vport.index).collect();

                tokio::spawn(async move {
                    let mut id_beacon = id_beacon;
                    loop {
                        let beacon_at = if beacon_ports.is_empty() {
                            None
                        } else {
                            id_beacon.as_ref().and_then(IdBeacon::deadline)
                        };
                        let outgoing = tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = link_cancel.cancelled() => break,
                            _ = async {
                                match beacon_at {
                                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                                    None => std::future::pending().await,
                                }
                            } => {
                                let Some(beacon) = id_beacon.as_mut() else {
                                    continue;
                                };
                                let callsign = beacon.callsign.clone();
                                let mut wrote = false;
                                for index in &beacon_ports {
                                    let (select, frame) = vport_transmit_frames(*index, &callsign);
                                    if writer.write_all(&select).await.is_err()
                                        || writer.write_all(&frame).await.is_err()
                                        || writer.flush().await.is_err()
                                    {
                                        link_cancel.cancel();
                                        return;
                                    }
                                    stats.count_tx(callsign.len());
                                    wrote = true;
                                }
                                if wrote {
                                    beacon.on_written(&callsign, Instant::now());
                                    log::debug!("rnode_multi: transmitted beacon data");
                                }
                                continue;
                            }
                            outgoing = vport_rx.recv() => match outgoing {
                                Some(outgoing) => outgoing,
                                None => break,
                            },
                        };

                        let (index, data) = outgoing;
                        // RNodeMulti selects a virtual interface first; data
                        // itself is always transmitted with the normal data
                        // command. Per-port data commands are receive-only.
                        let (select, frame) = vport_transmit_frames(index, &data);
                        if writer.write_all(&select).await.is_ok()
                            && writer.write_all(&frame).await.is_ok()
                            && writer.flush().await.is_ok()
                        {
                            stats.count_tx(data.len());
                            if let Some(id_beacon) = id_beacon.as_mut() {
                                id_beacon.on_written(&data, Instant::now());
                            }
                        } else {
                            link_cancel.cancel();
                            break;
                        }
                    }
                })
            };

            // Reader pump: parse device frames, dispatch data to the
            // spawned vport peers by their data command.
            let reader_task = {
                let cancel = context.cancel.clone();
                let link_cancel = link_cancel.clone();
                let mut reader = link.reader;
                let state = state.clone();
                let inbound = inbound.clone();
                let rx_stats = stats.clone();
                let iface_manager = iface_manager.clone();
                let vport_addresses = vport_addresses.clone();

                tokio::spawn(async move {
                    let mut parser = RnodeParser::new(true);
                    let mut buffer = [0u8; 4096];

                    loop {
                        let closed = tokio::select! {
                            _ = cancel.cancelled() => true,
                            _ = link_cancel.cancelled() => true,
                            result = reader.read(&mut buffer) => match result {
                                Ok(0) | Err(_) => true,
                                Ok(n) => {
                                    let mut routed: Vec<(Option<u8>, Vec<u8>)> = Vec::new();
                                    let mut bitrate_updates = Vec::new();
                                    parser.feed(&buffer[..n], |event| {
                                        match event {
                                            RnodeEvent::Data { vport, data } => routed.push((vport, data)),
                                            RnodeEvent::SelectedVport(_) => {}
                                            RnodeEvent::Status(status) => {
                                                let mut shared = state.write().unwrap_or_else(|e| e.into_inner());
                                                let (rssi, snr, quality) = shared.note_status(status);
                                                let airtime_short = shared.status.airtime_short;
                                                let airtime_long = shared.status.airtime_long;
                                                let channel_load_short = shared.status.channel_load_short;
                                                let channel_load_long = shared.status.channel_load_long;
                                                drop(shared);
                                                rx_stats.set_radio_quality(rssi, snr, quality);
                                                rx_stats.set_radio_channel(
                                                    airtime_short,
                                                    airtime_long,
                                                    channel_load_short,
                                                    channel_load_long,
                                                );
                                            }
                                            RnodeEvent::Echo(echo) => {
                                                if let Some(update) = state.write().unwrap_or_else(|e| e.into_inner()).note_echo(echo) {
                                                    bitrate_updates.push(update);
                                                }
                                            }
                                            RnodeEvent::InterfaceKind(kind) => {
                                                state.write().unwrap_or_else(|e| e.into_inner()).subinterface_kinds.push(kind);
                                            }
                                            _ => {}
                                        }
                                    });

                                    if !bitrate_updates.is_empty() {
                                        let manager = iface_manager.lock().await;
                                        for (vport, bps) in bitrate_updates {
                                            if let Some(vport) = vport {
                                                if let Some(address) = vport_addresses.get(&vport) {
                                                    manager.set_iface_bitrate(address, bps);
                                                }
                                            }
                                        }
                                    }

                                    for (vport, data) in routed {
                                        if let Some(vport) = vport {
                                            if let Some(sender) = inbound
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner())
                                                .get(&vport)
                                            {
                                                let _ = sender.send(data);
                                            }
                                        }
                                    }

                                    false
                                }
                            },
                        };

                        if closed {
                            link_cancel.cancel();
                            break;
                        }
                    }
                })
            };

            let mut writer_task = writer_task;
            let mut reader_task = reader_task;
            tokio::select! {
                _ = &mut writer_task => {
                    link_cancel.cancel();
                    let _ = reader_task.await;
                }
                _ = &mut reader_task => {
                    link_cancel.cancel();
                    let _ = writer_task.await;
                }
                _ = context.cancel.cancelled() => {
                    link_cancel.cancel();
                    let _ = writer_task.await;
                    let _ = reader_task.await;
                }
            }
            stats.set_online(false);
            if context.cancel.is_cancelled() {
                break;
            }
            log::warn!("rnode_multi: device link lost, reconnecting");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}

impl Interface for RnodeMultiInterface {
    fn mtu() -> usize {
        500
    }

    fn should_ingress_limit() -> bool {
        false
    }
}

/// Inbound data senders by virtual port (parent -> peer).
pub type VportInbound =
    Arc<std::sync::Mutex<std::collections::HashMap<u8, mpsc::UnboundedSender<Vec<u8>>>>>;

/// A spawned virtual-port peer: packets from the parent's device reader
/// arrive on `inbound`, outgoing packets are forwarded to the parent's
/// writer pump (Python `RNodeMultiInterfacePeer`).
pub struct RnodeVportPeer {
    pub index: u8,
    /// Parent interface name plus the vport index. Stable across restart.
    endpoint: String,
    /// Outbound pump to the parent device writer.
    pub outbound: mpsc::UnboundedSender<(u8, Vec<u8>)>,
    /// Inbound data from the parent device reader (taken by the worker).
    pub inbound: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Python subinterface `OUT`. Receive-only ports drop transmissions.
    pub outgoing: bool,
}

impl RnodeVportPeer {
    pub async fn spawn(context: InterfaceContext<Self>) {
        let stats = context.channel.stats.clone();
        let iface_address = context.channel.address;
        let (rx_channel, mut tx_channel) = context.channel.split();

        let mut inbound = context
            .inner
            .lock()
            .unwrap()
            .inbound
            .take()
            .expect("vport inbound taken once");

        loop {
            // Route both directions without select! to keep the arm
            // types independent.
            tokio::select! {
                biased;

                message = tx_channel.recv() => match message {
                    Some(message) => {
                        let (index, outbound, outgoing) = {
                            let inner = context.inner.lock().unwrap();
                            (inner.index, inner.outbound.clone(), inner.outgoing)
                        };
                        if !outgoing {
                            continue;
                        }
                        let packet = message.packet;
                        let mut buffer = [0u8; 2048];
                        let mut output = OutputBuffer::new(&mut buffer[..]);
                        if packet.serialize(&mut output).is_ok() {
                            let _ = outbound.send((index, output.as_slice().to_vec()));
                            stats.count_tx(output.offset());
                        }
                        continue;
                    }
                    None => break,
                },

                data = inbound.recv() => match data {
                    Some(data) => {
                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(&data)) {
                            stats.count_rx(data.len());
                            let _ = rx_channel
                                .try_send(RxMessage { address: iface_address, packet: Box::new(packet) });
                        }
                        continue;
                    }
                    None => continue,
                },

                _ = context.cancel.cancelled() => break,
            }
        }
    }
}

impl Interface for RnodeVportPeer {
    fn mtu() -> usize {
        500
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn should_ingress_limit() -> bool {
        false
    }
}

#[cfg(feature = "iface-rnode-ble")]
mod ble_backend {
    use std::pin::Pin;
    use std::time::Duration;

    use btleplug::api::{
        Central, CentralEvent, Manager as _, Peripheral as _, ScanFilter, ValueNotification,
        WriteType,
    };
    use btleplug::platform::{Adapter, Manager, Peripheral};
    use futures_util::future::FutureExt;
    use futures_util::stream::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    use super::{
        ble_candidate_matches, BleTarget, RnodeLink, BLE_CONNECT_TIMEOUT, BLE_SCAN_TIMEOUT,
    };
    use crate::error::RnsError;

    const UART_SERVICE_U128: u128 = 0x6E40_0001_B5A3_F393_E0A9_E50E_24DC_CA9E;
    const UART_RX_U128: u128 = 0x6E40_0002_B5A3_F393_E0A9_E50E_24DC_CA9E;
    const UART_TX_U128: u128 = 0x6E40_0003_B5A3_F393_E0A9_E50E_24DC_CA9E;

    /// ATT payload before an MTU exchange. btleplug does not report the
    /// negotiated write-without-response length (Python Android `BASE_MTU`
    /// is 20). Desktop Python uses the characteristic's negotiated size.
    const BLE_WRITE_CHUNK: usize = 20;

    pub(super) struct BtleplugBleLink {
        adapter: Adapter,
        peripheral: Peripheral,
        rx: btleplug::api::Characteristic,
        tx_uuid: Uuid,
        notes: Pin<Box<dyn futures_util::Stream<Item = ValueNotification> + Send>>,
    }

    impl BtleplugBleLink {
        pub(super) async fn connect(target: &BleTarget) -> Result<Self, RnsError> {
            let manager = Manager::new().await.map_err(|err| {
                log::error!("rnode: BLE manager unavailable: {err}");
                RnsError::ConnectionError
            })?;
            let adapters = manager.adapters().await.map_err(|err| {
                log::error!("rnode: BLE adapters unavailable: {err}");
                RnsError::ConnectionError
            })?;
            let Some(adapter) = adapters.into_iter().next() else {
                log::error!("rnode: no BLE adapter");
                return Err(RnsError::ConnectionError);
            };
            let bonded_macs = bonded_addresses().await;
            let service = Uuid::from_u128(UART_SERVICE_U128);
            // Subscribe before scanning so a report is not lost, then discard
            // the cached DeviceDiscovered replay. `peripherals()` is every
            // remembered device, and its service list can be GATT state from
            // an earlier connection rather than this advertisement.
            let mut events = adapter.events().await.map_err(|err| {
                log::error!("rnode: BLE scan events unavailable: {err}");
                RnsError::ConnectionError
            })?;
            while let Some(Some(_)) = events.next().now_or_never() {}
            adapter
                .start_scan(ScanFilter {
                    services: vec![service],
                })
                .await
                .map_err(|err| {
                    log::error!("rnode: BLE scan failed: {err}");
                    RnsError::ConnectionError
                })?;

            let deadline = tokio::time::Instant::now() + BLE_SCAN_TIMEOUT;
            let mut chosen = None;
            let mut logged_unpaired: Vec<String> = Vec::new();
            while tokio::time::Instant::now() < deadline && chosen.is_none() {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                let event = match tokio::time::timeout(remaining, events.next()).await {
                    Ok(Some(event)) => event,
                    _ => break,
                };
                // An already-paired radio often only updates RSSI or
                // manufacturer/service data. Those events mean it is
                // advertising now; BlueZ does not emit InterfacesAdded again.
                // ServicesAdvertisement carries the live UUID list. The other
                // events do not, so the UART check uses the device properties.
                let (id, advertised_uart) = match event {
                    CentralEvent::ServicesAdvertisement { id, services } => {
                        (id, Some(services.contains(&service)))
                    }
                    CentralEvent::DeviceDiscovered(id) | CentralEvent::DeviceUpdated(id) => {
                        (id, None)
                    }
                    CentralEvent::ManufacturerDataAdvertisement { id, .. }
                    | CentralEvent::ServiceDataAdvertisement { id, .. } => (id, None),
                    _ => continue,
                };
                let Ok(peripheral) = adapter.peripheral(&id).await else {
                    continue;
                };
                let Ok(Some(props)) = peripheral.properties().await else {
                    continue;
                };
                let uart_present =
                    advertised_uart.unwrap_or_else(|| props.services.contains(&service));
                if !uart_present {
                    continue;
                }
                // CoreBluetooth has no public MAC. btleplug reports
                // 00:00:00:00:00:00 there; that is not a matchable address.
                // Use properties().address when it is populated, not
                // Peripheral::address().
                let mac = if props.address.as_ref().iter().all(|byte| *byte == 0) {
                    None
                } else {
                    Some(props.address.to_string())
                };
                let bonded = mac.as_deref().is_some_and(|addr| {
                    bonded_macs
                        .iter()
                        .any(|known| known.eq_ignore_ascii_case(addr))
                });
                if ble_candidate_matches(
                    target,
                    props.local_name.as_deref(),
                    mac.as_deref(),
                    bonded,
                ) {
                    chosen = Some(peripheral);
                    break;
                }
                if !bonded {
                    let label = match target {
                        BleTarget::Name(name)
                            if props.local_name.as_deref() == Some(name.as_str()) =>
                        {
                            Some(name.clone())
                        }
                        BleTarget::Address(addr)
                            if mac
                                .as_deref()
                                .is_some_and(|mac| mac.eq_ignore_ascii_case(addr)) =>
                        {
                            Some(addr.clone())
                        }
                        _ => None,
                    };
                    if let Some(label) = label {
                        if !logged_unpaired.iter().any(|seen| seen == &label) {
                            log::error!(
                                "rnode: can't connect to target device {label} over BLE, device is not bonded"
                            );
                            logged_unpaired.push(label);
                        }
                    }
                }
            }
            let _ = adapter.stop_scan().await;
            let Some(peripheral) = chosen else {
                log::error!("rnode: no bonded BLE RNode matched the target");
                return Err(RnsError::ConnectionError);
            };

            let connect_result =
                tokio::time::timeout(BLE_CONNECT_TIMEOUT, peripheral.connect()).await;
            if !matches!(connect_result, Ok(Ok(()))) {
                log::error!("rnode: BLE connect failed");
                // Dropping the connect future does not send Disconnect.
                let _ = peripheral.disconnect().await;
                return Err(RnsError::ConnectionError);
            }
            if peripheral.discover_services().await.is_err() {
                let _ = peripheral.disconnect().await;
                return Err(RnsError::ConnectionError);
            }
            let rx_uuid = Uuid::from_u128(UART_RX_U128);
            let tx_uuid = Uuid::from_u128(UART_TX_U128);
            let chars = peripheral.characteristics();
            let Some(rx) = chars.into_iter().find(|item| item.uuid == rx_uuid) else {
                let _ = peripheral.disconnect().await;
                log::error!("rnode: BLE UART RX characteristic missing");
                return Err(RnsError::ConnectionError);
            };
            let tx = peripheral
                .characteristics()
                .into_iter()
                .find(|item| item.uuid == tx_uuid);
            let Some(tx) = tx else {
                let _ = peripheral.disconnect().await;
                log::error!("rnode: BLE UART TX characteristic missing");
                return Err(RnsError::ConnectionError);
            };
            if peripheral.subscribe(&tx).await.is_err() {
                let _ = peripheral.disconnect().await;
                return Err(RnsError::ConnectionError);
            }
            let notes = match peripheral.notifications().await {
                Ok(notes) => notes,
                Err(err) => {
                    log::error!("rnode: BLE notify failed: {err}");
                    let _ = peripheral.disconnect().await;
                    return Err(RnsError::ConnectionError);
                }
            };

            Ok(Self {
                adapter,
                peripheral,
                rx,
                tx_uuid,
                notes,
            })
        }

        pub(super) fn into_rnode_link(self) -> RnodeLink {
            let Self {
                adapter,
                peripheral,
                rx,
                tx_uuid,
                notes,
            } = self;
            let (reader, device_to_host) = tokio::io::simplex(64 * 1024);
            let (host_to_device, writer) = tokio::io::simplex(64 * 1024);
            // Unbounded on purpose: macOS/Windows btleplug delivers notifications
            // through broadcast::channel(16) and drops the lagging receiver.
            let (inbound_tx, mut inbound_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let stop = tokio_util::sync::CancellationToken::new();

            tokio::spawn({
                let stop = stop.clone();
                async move {
                    let mut device_to_host = device_to_host;
                    loop {
                        let bytes = tokio::select! {
                            _ = stop.cancelled() => break,
                            bytes = inbound_rx.recv() => bytes,
                        };
                        let Some(bytes) = bytes else { break };
                        if device_to_host.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    // Dropping the writer is the read-side EOF the reconnect loop uses.
                }
            });

            let watch_peripheral = peripheral.clone();
            let peripheral_id = peripheral.id();
            let watch_stop = stop.clone();
            tokio::spawn(async move {
                let mut notes = notes;
                let mut events = adapter.events().await.ok();
                // `is_connected` is a separate task so a BlueZ round-trip does
                // not stop the notification drain. Linux notifications() does
                // not end when Connected becomes false.
                let (down_tx, mut down_rx) = tokio::sync::mpsc::channel::<()>(1);
                let poll_peripheral = watch_peripheral.clone();
                let poll_stop = watch_stop.clone();
                tokio::spawn(async move {
                    let mut link_check = tokio::time::interval(Duration::from_secs(1));
                    link_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    link_check.tick().await;
                    loop {
                        tokio::select! {
                            _ = poll_stop.cancelled() => break,
                            _ = link_check.tick() => {
                                match poll_peripheral.is_connected().await {
                                    Ok(true) => {}
                                    _ => {
                                        let _ = down_tx.send(()).await;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
                loop {
                    tokio::select! {
                        _ = watch_stop.cancelled() => break,
                        _ = down_rx.recv() => break,
                        note = notes.next() => {
                            match note {
                                Some(note) if note.uuid == tx_uuid => {
                                    if inbound_tx.send(note.value).is_err() {
                                        break;
                                    }
                                }
                                Some(_) => {}
                                None => break,
                            }
                        }
                        event = async {
                            match events.as_mut() {
                                Some(stream) => stream.next().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            match event {
                                Some(CentralEvent::DeviceDisconnected(id)) if id == peripheral_id => {
                                    break;
                                }
                                Some(_) => {}
                                None => break,
                            }
                        }
                    }
                }
                drop(inbound_tx);
                watch_stop.cancel();
                let _ = watch_peripheral.disconnect().await;
            });

            tokio::spawn(async move {
                let mut host_to_device = host_to_device;
                let mut outbound = [0u8; 512];
                loop {
                    match host_to_device.read(&mut outbound).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if write_chunks(&peripheral, &rx, &outbound[..n])
                                .await
                                .is_err()
                            {
                                stop.cancel();
                                break;
                            }
                        }
                    }
                }
                let _ = peripheral.disconnect().await;
            });

            RnodeLink {
                reader: Box::new(reader),
                writer: Box::new(writer),
            }
        }
    }

    /// Addresses Python treats as bonded. btleplug does not keep the flag.
    async fn bonded_addresses() -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            linux_bonded_addresses().await
        }
        #[cfg(target_os = "windows")]
        {
            windows_paired_addresses().await
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            // CoreBluetooth exposes no MAC and no bond flag. Python's Bonded
            // property is absent there, so the device stays unbonded.
            Vec::new()
        }
    }

    /// BlueZ `Device1.Bonded`. The system bus is opened on a blocking thread.
    /// `BluetoothSession::new` both blocks on the caller and detaches a dbus
    /// task the returned future cannot abort, so this drives `IOResource`
    /// itself and aborts that task before returning.
    #[cfg(target_os = "linux")]
    async fn linux_bonded_addresses() -> Vec<String> {
        use dbus::nonblock::stdintf::org_freedesktop_dbus::ObjectManager;

        let opened = tokio::task::spawn_blocking(dbus_tokio::connection::new_system_sync).await;
        let (resource, connection) = match opened {
            Ok(Ok(pair)) => pair,
            Ok(Err(err)) => {
                log::error!("rnode: BlueZ bond lookup unavailable: {err}");
                return Vec::new();
            }
            Err(err) => {
                log::error!("rnode: BlueZ bond lookup unavailable: {err}");
                return Vec::new();
            }
        };
        let driver = tokio::spawn(async move {
            let _ = resource.await;
        });
        let proxy = dbus::nonblock::Proxy::new(
            "org.bluez",
            "/",
            std::time::Duration::from_secs(5),
            connection,
        );
        let objects = match proxy.get_managed_objects().await {
            Ok(objects) => objects,
            Err(err) => {
                log::error!("rnode: BlueZ bond lookup failed: {err}");
                driver.abort();
                return Vec::new();
            }
        };
        driver.abort();
        let mut macs = Vec::new();
        for (_path, interfaces) in objects {
            let Some(props) = interfaces.get("org.bluez.Device1") else {
                continue;
            };
            if dbus::arg::prop_cast::<bool>(props, "Bonded") != Some(&true) {
                continue;
            }
            if let Some(address) = dbus::arg::prop_cast::<String>(props, "Address") {
                macs.push(address.clone());
            }
        }
        macs
    }

    /// Python `_get_windows_paired_ble_addresses`: WinRT devices paired with
    /// the system, last `-` segment of the device id.
    #[cfg(target_os = "windows")]
    async fn windows_paired_addresses() -> Vec<String> {
        let joined = tokio::task::spawn_blocking(|| {
            let selector = match windows::Devices::Bluetooth::BluetoothLEDevice::GetDeviceSelectorFromPairingState(true)
            {
                Ok(selector) => selector,
                Err(err) => {
                    log::error!("rnode: Windows paired-device selector failed: {err}");
                    return Vec::new();
                }
            };
            let operation = match windows::Devices::Enumeration::DeviceInformation::FindAllAsyncAqsFilter(&selector)
            {
                Ok(operation) => operation,
                Err(err) => {
                    log::error!("rnode: Windows paired-device query failed: {err}");
                    return Vec::new();
                }
            };
            let infos = match operation.get() {
                Ok(infos) => infos,
                Err(err) => {
                    log::error!("rnode: Windows paired-device query failed: {err}");
                    return Vec::new();
                }
            };
            let mut macs = Vec::new();
            for info in infos {
                let Ok(id) = info.Id() else {
                    continue;
                };
                let id = id.to_string();
                if let Some(suffix) = id.rsplit('-').next() {
                    if !suffix.is_empty() {
                        macs.push(suffix.to_lowercase());
                    }
                }
            }
            macs
        })
        .await;
        match joined {
            Ok(macs) => macs,
            Err(err) => {
                log::error!("rnode: Windows paired-device lookup failed: {err}");
                Vec::new()
            }
        }
    }

    async fn write_chunks(
        peripheral: &Peripheral,
        rx: &btleplug::api::Characteristic,
        data: &[u8],
    ) -> Result<(), RnsError> {
        for chunk in data.chunks(BLE_WRITE_CHUNK) {
            peripheral
                .write(rx, chunk, WriteType::WithoutResponse)
                .await
                .map_err(|err| {
                    log::debug!("rnode: BLE write failed: {err}");
                    RnsError::ConnectionError
                })?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_target_parse_matches_python_port_forms() {
        assert_eq!(parse_ble_target("ble://"), Some(BleTarget::Any));
        assert_eq!(parse_ble_target("BLE://"), Some(BleTarget::Any));
        assert_eq!(
            parse_ble_target("ble://F4:12:73:29:4E:89"),
            Some(BleTarget::Address("F4:12:73:29:4E:89".into()))
        );
        assert_eq!(
            parse_ble_target("ble://RNode 3B87"),
            Some(BleTarget::Name("RNode 3B87".into()))
        );
        // Six colon-separated fields but not 17 characters is a name.
        assert_eq!(
            parse_ble_target("ble://A:B:C:D:E:F"),
            Some(BleTarget::Name("A:B:C:D:E:F".into()))
        );
        assert!(parse_ble_target("/dev/ttyUSB0").is_none());
        assert!(parse_ble_target("tcp://127.0.0.1:7633").is_none());
    }

    #[test]
    fn ble_candidate_requires_bond_and_any_ignores_name_prefix() {
        assert!(ble_candidate_matches(
            &BleTarget::Any,
            Some("Other Radio"),
            Some("F4:12:73:29:4E:89"),
            true
        ));
        assert!(ble_candidate_matches(
            &BleTarget::Any,
            None,
            Some("F4:12:73:29:4E:89"),
            true
        ));
        assert!(!ble_candidate_matches(
            &BleTarget::Any,
            Some("RNode 3B87"),
            Some("F4:12:73:29:4E:89"),
            false
        ));
        assert!(ble_candidate_matches(
            &BleTarget::Name("RNode 3B87".into()),
            Some("RNode 3B87"),
            Some("F4:12:73:29:4E:89"),
            true
        ));
        assert!(!ble_candidate_matches(
            &BleTarget::Name("RNode 3B87".into()),
            Some("RNode 3B87"),
            Some("F4:12:73:29:4E:89"),
            false
        ));
        assert!(!ble_candidate_matches(
            &BleTarget::Name("RNode 3B87".into()),
            Some("Other"),
            Some("F4:12:73:29:4E:89"),
            true
        ));
        assert!(ble_candidate_matches(
            &BleTarget::Address("f4:12:73:29:4e:89".into()),
            None,
            Some("F4:12:73:29:4E:89"),
            true
        ));
        // No public MAC (CoreBluetooth reports zeros) cannot match ble://<mac>.
        assert!(!ble_candidate_matches(
            &BleTarget::Address("F4:12:73:29:4E:89".into()),
            Some("RNode 3B87"),
            None,
            true
        ));
    }

    #[test]
    fn android_usb_interface_types_are_unsupported() {
        assert_eq!(
            android_usb_error("AndroidRNodeInterface"),
            Err(RnsError::Unsupported)
        );
        assert_eq!(
            android_usb_error("AndroidSerialInterface"),
            Err(RnsError::Unsupported)
        );
        assert_eq!(
            android_usb_error("AndroidKISSInterface"),
            Err(RnsError::Unsupported)
        );
        assert_eq!(android_usb_error("usb://1-1"), Err(RnsError::Unsupported));
        assert_eq!(android_usb_error("/dev/ttyUSB0"), Ok(()));
        assert_eq!(android_usb_error("ble://RNode 3B87"), Ok(()));
    }

    #[test]
    fn cmd_bt_ctrl_frames_match_python_bytes() {
        assert_eq!(CMD_BT_CTRL, 0x46);
        assert_eq!(
            kiss_frame(CMD_BT_CTRL, &[BT_CTRL_ENABLE]),
            vec![FEND, CMD_BT_CTRL, 0x01, FEND]
        );
        assert_eq!(
            kiss_frame(CMD_BT_CTRL, &[BT_CTRL_DISABLE]),
            vec![FEND, CMD_BT_CTRL, 0x00, FEND]
        );
        assert_eq!(
            kiss_frame(CMD_BT_CTRL, &[BT_CTRL_PAIR]),
            vec![FEND, CMD_BT_CTRL, 0x02, FEND]
        );
        assert_eq!(
            BLE_UART_SERVICE_UUID,
            "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
        );
        assert_eq!(BLE_UART_RX_UUID, "6E400002-B5A3-F393-E0A9-E50E24DCCA9E");
        assert_eq!(BLE_UART_TX_UUID, "6E400003-B5A3-F393-E0A9-E50E24DCCA9E");
        assert_eq!(BLE_SCAN_TIMEOUT, Duration::from_secs(2));
        assert_eq!(BLE_CONNECT_TIMEOUT, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn ble_framing_uses_the_fake_and_does_not_claim_connected() {
        let mut link = FakeBleLink::new();
        assert!(!link.connected());

        // Android `bluetooth_control(..., pairing_mode=True)` writes enable
        // then the pair command. rnodeconf's `bluetooth_pair` is only 0x02.
        let enable = kiss_frame(CMD_BT_CTRL, &[BT_CTRL_ENABLE]);
        let pair = kiss_frame(CMD_BT_CTRL, &[BT_CTRL_PAIR]);
        link.write(&enable).await.unwrap();
        link.write(&pair).await.unwrap();
        assert_eq!(
            link.written(),
            [enable.as_slice(), pair.as_slice()].concat()
        );
        assert!(!link.connected());

        link.queue_rx(&kiss_frame(CMD_DETECT, &[DETECT_RESP]));
        let mut buffer = [0u8; 8];
        let n = link.read(&mut buffer).await.unwrap();
        assert_eq!(
            &buffer[..n],
            kiss_frame(CMD_DETECT, &[DETECT_RESP]).as_slice()
        );
        assert_eq!(link.read(&mut buffer).await.unwrap(), 0);
        assert!(!link.connected());

        let iface = RnodeInterface::ble(
            "RNode 3B87",
            RnodeRadioConfig {
                frequency: 867_500_000,
                bandwidth: 125_000,
                txpower: 7,
                spreadingfactor: 8,
                codingrate: 5,
                st_alock: None,
                lt_alock: None,
            },
        );
        assert_eq!(iface.serial_port.as_deref(), Some("ble://RNode 3B87"));
        assert!(iface.tcp_addr.is_none());
    }

    #[cfg(not(feature = "iface-rnode-ble"))]
    #[tokio::test]
    async fn ble_without_the_feature_is_unsupported_and_does_not_open_an_adapter() {
        match RnodeLink::connect_ble("ble://RNode 3B87").await {
            Err(RnsError::Unsupported) => {}
            Err(other) => panic!("expected Unsupported, got {other:?}"),
            Ok(_) => panic!("ble open must not succeed without iface-rnode-ble"),
        }
        match RnodeLink::connect_ble("not-ble").await {
            Err(RnsError::InvalidArgument) => {}
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(_) => panic!("a non-ble port must not open"),
        }
    }

    #[test]
    fn radio_state_and_multi_transmit_frames_match_protocol() {
        assert_eq!(RADIO_STATE_ON, 0x01);
        assert_eq!(RADIO_STATE_OFF, 0x00);

        let (select, data) = vport_transmit_frames(3, b"payload");
        assert_eq!(select, kiss_frame(CMD_SEL_INT, &[3]));
        assert_eq!(data, kiss_frame(CMD_DATA, b"payload"));
        assert_ne!(data, kiss_frame(CMD_INT_DATA[3], b"payload"));
    }

    #[tokio::test]
    async fn flow_control_waits_for_each_ready_event_and_observes_cancellation() {
        let state = Arc::new(std::sync::RwLock::new(RnodeShared::default()));
        let cancel = tokio_util::sync::CancellationToken::new();
        let link_cancel = tokio_util::sync::CancellationToken::new();

        let waiter = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            let link_cancel = link_cancel.clone();
            async move { wait_for_interface_ready(&state, &cancel, &link_cancel).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!waiter.is_finished());
        state.write().unwrap().interface_ready = true;
        assert!(waiter.await.unwrap());

        // A successful transmission consumes readiness, so the next one
        // blocks until another CMD_READY. Cancellation must still wake it.
        state.write().unwrap().interface_ready = false;
        let waiter = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            let link_cancel = link_cancel.clone();
            async move { wait_for_interface_ready(&state, &cancel, &link_cancel).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!waiter.is_finished());
        link_cancel.cancel();
        assert!(!waiter.await.unwrap());
    }

    #[test]
    fn on_air_bitrate_matches_the_modem_formula() {
        let sf9 = on_air_bitrate(9, 5, 125_000).unwrap();
        assert!((sf9 - 1757.8125).abs() < 1e-6);
        assert_eq!(sf9.round() as u64, 1758);
        assert_eq!(on_air_bitrate(7, 5, 125_000).unwrap().round() as u64, 5469);
        assert_eq!(on_air_bitrate(12, 8, 62_500).unwrap().round() as u64, 92);
        assert_eq!(on_air_bitrate(8, 6, 250_000).unwrap().round() as u64, 5208);
        assert!(on_air_bitrate(0, 5, 125_000).is_none());
        assert!(on_air_bitrate(9, 0, 125_000).is_none());
        assert!(on_air_bitrate(9, 5, 0).is_none());
    }

    #[test]
    fn id_beacon_window_tracks_successful_writes() {
        let mut beacon = IdBeacon::new(60, b"N0CALL".to_vec());
        let now = Instant::now();
        assert!(beacon.deadline().is_none());

        beacon.on_written(b"N0CALL", now);
        assert!(beacon.deadline().is_none());

        beacon.on_written(b"packet", now);
        let due = beacon.deadline().unwrap();
        assert!(due > now + Duration::from_secs(60));

        beacon.on_written(b"N0CALL", now + Duration::from_secs(61));
        assert!(beacon.deadline().is_none());
    }

    #[test]
    fn echo_and_status_update_bitrate_and_telemetry() {
        let mut shared = RnodeShared::default();
        assert_eq!(
            shared.note_echo(RnodeEchoState {
                spreadingfactor: Some(9),
                codingrate: Some(5),
                bandwidth: Some(125_000),
                ..RnodeEchoState::default()
            }),
            Some((None, 1758))
        );
        assert_eq!(shared.bitrate, 1758);

        assert_eq!(
            shared.note_echo(RnodeEchoState {
                spreadingfactor: Some(7),
                codingrate: Some(5),
                bandwidth: Some(125_000),
                vport: Some(1),
                ..RnodeEchoState::default()
            }),
            Some((Some(1), 5469))
        );
        assert_eq!(shared.bitrate, 1758);
        assert_eq!(shared.vport_bitrate.get(&1).copied(), Some(5469));

        let mut events = Vec::new();
        let mut parser = RnodeParser::new(false);
        parser.feed(&kiss_frame(CMD_STAT_SNR, &[0xFC]), |event| {
            events.push(event)
        });
        let RnodeEvent::Status(status) = events.pop().unwrap() else {
            panic!("expected snr status");
        };
        let (_rssi, snr, quality) = shared.note_status(status);
        assert_eq!(snr, Some(-1.0));
        let expected = RnodeStatus::quality_for(-1.0, Some(9)).unwrap();
        assert_eq!(quality, Some(expected));
        assert!((shared.status.quality.unwrap() - expected).abs() < 1e-4);
    }

    #[test]
    fn multi_probe_and_band_limits() {
        let detect = detect_request();
        let multi = multi_detect_request();
        assert!(multi.starts_with(&detect));
        assert!(multi.ends_with(&kiss_frame(CMD_INTERFACES, &[0x00])));

        assert!(reported_kind_accepts_frequency(0x11, 867_500_000));
        assert!(!reported_kind_accepts_frequency(0x21, 867_500_000));
        assert!(reported_kind_accepts_frequency(0x21, 2_400_000_000));
        assert!(!reported_kind_accepts_frequency(0x11, 2_400_000_000));
        assert!(reported_kind_accepts_frequency(0xFE, 867_500_000));
    }

    #[tokio::test]
    async fn receive_only_vport_drops_transmissions() {
        use crate::iface::{InterfaceManager, TxMessage, TxMessageType};
        use crate::packet::Packet;

        let (silent_tx, mut silent_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_silent_in_tx, silent_in_rx) = tokio::sync::mpsc::unbounded_channel();
        let (live_tx, mut live_rx) = tokio::sync::mpsc::unbounded_channel();
        let (_live_in_tx, live_in_rx) = tokio::sync::mpsc::unbounded_channel();

        let mut manager = InterfaceManager::new(4);
        let silent = manager.spawn(
            RnodeVportPeer {
                index: 1,
                endpoint: "parent/1".into(),
                outbound: silent_tx,
                inbound: Some(silent_in_rx),
                outgoing: false,
            },
            RnodeVportPeer::spawn,
        );
        let live = manager.spawn(
            RnodeVportPeer {
                index: 0,
                endpoint: "parent/0".into(),
                outbound: live_tx,
                inbound: Some(live_in_rx),
                outgoing: true,
            },
            RnodeVportPeer::spawn,
        );

        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(silent),
                packet: Box::new(Packet::default()),
            })
            .await;
        manager
            .send(TxMessage {
                tx_type: TxMessageType::Direct(live),
                packet: Box::new(Packet::default()),
            })
            .await;

        let forwarded = tokio::time::timeout(Duration::from_secs(2), live_rx.recv())
            .await
            .expect("outgoing vport forwards")
            .expect("outgoing channel open");
        assert_eq!(forwarded.0, 0);
        assert!(!forwarded.1.is_empty());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(silent_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn vport_stable_ids_follow_parent_name_and_index() {
        let mut manager = InterfaceManager::new(4);
        let mut register = |parent: &str, index: u8| {
            let label = format!("{parent}/{index}");
            let (outbound, _dropped) = mpsc::unbounded_channel();
            let (_dropped, inbound) = mpsc::unbounded_channel();
            manager.spawn_named(
                &label,
                RnodeVportPeer {
                    index,
                    endpoint: label.clone(),
                    outbound,
                    inbound: Some(inbound),
                    outgoing: true,
                },
                RnodeVportPeer::spawn,
            )
        };
        let a0 = register("radio-a", 0);
        let a1 = register("radio-a", 1);
        let b0 = register("radio-b", 0);
        register("radio-b", 1);

        let (map, ambiguous) = manager.classify_stable_ids();
        assert!(ambiguous.is_empty());
        assert_eq!(map.len(), 4);
        let id_of = |address| {
            map.iter()
                .find(|(_, live)| **live == address)
                .map(|(id, _)| *id)
        };
        assert_ne!(id_of(a0), id_of(a1), "two ports on one radio must differ");
        assert_ne!(
            id_of(a0),
            id_of(b0),
            "port 0 on two radios with different parent names must differ"
        );
    }
}
