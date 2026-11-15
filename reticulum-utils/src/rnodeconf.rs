//! Host-side RNode frames from Python `RNS/Utilities/rnodeconf.py`.
//!
//! Probe and radio validation are unchanged. EEPROM read/write, the
//! firmware-info query, TNC mode, display, WiFi, and BLE control are the
//! same command bytes the Python tool writes. `--flash` runs an external
//! `rnodeconf` or `esptool` only when that program is on `PATH`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use reticulum::error::RnsError;
use reticulum::iface::rnode::{
    detect_request, kiss_frame, leave_request, reset_request, RnodeLink, RnodeParser,
    RnodeRadioConfig, RnodeShared, CMD_DETECT, CMD_FW_VERSION, CMD_MCU, CMD_PLATFORM, CMD_ROM_READ,
    CMD_STAT_RSSI, CMD_STAT_SNR, DETECT_REQ, FEND, FESC, RADIO_STATE_ON, TFEND, TFESC,
};

/// Python `KISS` command bytes that the interface crate does not export.
pub const CMD_DISP_INT: u8 = 0x45;
pub const CMD_BT_CTRL: u8 = 0x46;
pub const CMD_BOARD: u8 = 0x47;
pub const CMD_ROM_WRITE: u8 = 0x52;
pub const CMD_CONF_SAVE: u8 = 0x53;
pub const CMD_CONF_DELETE: u8 = 0x54;
pub const CMD_DEV_HASH: u8 = 0x56;
pub const CMD_ROM_WIPE: u8 = 0x59;
pub const CMD_HASHES: u8 = 0x60;
pub const CMD_DISP_ADR: u8 = 0x63;
pub const CMD_DISP_BLNK: u8 = 0x64;
pub const CMD_DISP_ROT: u8 = 0x67;
pub const CMD_DISP_RCND: u8 = 0x68;
pub const CMD_WIFI_MODE: u8 = 0x6A;
pub const CMD_WIFI_SSID: u8 = 0x6B;
pub const CMD_WIFI_PSK: u8 = 0x6C;
pub const CMD_CFG_READ: u8 = 0x6D;
pub const CMD_WIFI_CHN: u8 = 0x6E;
pub const CMD_WIFI_IP: u8 = 0x84;
pub const CMD_WIFI_NM: u8 = 0x85;

pub const BT_CTRL_OFF: u8 = 0x00;
pub const BT_CTRL_ON: u8 = 0x01;
pub const BT_CTRL_PAIR: u8 = 0x02;

pub const WIFI_OFF: u8 = 0x00;
pub const WIFI_STATION: u8 = 0x01;
pub const WIFI_AP: u8 = 0x02;

/// Python `ROM.PLATFORM_ESP32`. `setTNCMode` hard-resets this platform.
pub const PLATFORM_ESP32: u8 = 0x80;
/// Python `ROM.PLATFORM_NRF52`. EEPROM wipe does not reset this platform.
const PLATFORM_NRF52: u8 = 0x70;

const INFO_LOCK_BYTE: u8 = 0x73;
const CONF_OK_BYTE: u8 = 0x73;
const CONF_SET_BYTE: u8 = 0x73;

const ADDR_PRODUCT: usize = 0x00;
const ADDR_MODEL: usize = 0x01;
const ADDR_HW_REV: usize = 0x02;
const ADDR_SERIAL: usize = 0x03;
const ADDR_MADE: usize = 0x07;
const ADDR_INFO_LOCK: usize = 0x9B;
const ADDR_CONF_SF: usize = 0x9C;
const ADDR_CONF_CR: usize = 0x9D;
const ADDR_CONF_TXP: usize = 0x9E;
const ADDR_CONF_BW: usize = 0x9F;
const ADDR_CONF_FREQ: usize = 0xA3;
const ADDR_CONF_OK: usize = 0xA7;
const ADDR_CONF_BT: usize = 0xB0;
const ADDR_CONF_DINT: usize = 0xB2;
const ADDR_CONF_DADR: usize = 0xB3;
const ADDR_CONF_DBLK: usize = 0xB4;
const ADDR_CONF_BSET: usize = 0xB7;
const ADDR_CONF_DROT: usize = 0xB8;
const ADDR_CONF_WIFI: usize = 0xBA;
const ADDR_CONF_WCHN: usize = 0xBB;

/// Where to find the device.
pub enum DeviceTarget {
    Serial { port: String, baudrate: u32 },
    Tcp { addr: String },
}

/// Information gathered from a device probe.
#[derive(Debug, Default)]
pub struct DeviceInfo {
    pub detected: bool,
    pub firmware: Option<(u8, u8)>,
    pub platform: Option<u8>,
    pub mcu: Option<u8>,
    pub rssi: Option<i16>,
    pub snr: Option<f32>,
}

/// Radio parameters stored in EEPROM when the TNC marker is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TncStored {
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power: u8,
    pub bandwidth: u32,
    pub frequency: u32,
}

/// Identity and host-config bytes from an EEPROM image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EepromMap {
    pub product: u8,
    pub model: u8,
    pub hw_rev: u8,
    pub serial: u32,
    pub made: u32,
    pub info_locked: bool,
    pub tnc: Option<TncStored>,
    pub bluetooth_on: bool,
    pub display_intensity: u8,
    pub display_address: u8,
    pub display_blanking: Option<u8>,
    pub display_rotation: u8,
    pub wifi_mode: u8,
    pub wifi_channel: u8,
}

/// External flasher selected for `--flash`. The program is not spawned here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// Probe a device and report its firmware/platform/MCU identity and
/// live radio status (Python `rnodeconf --device-info`).
pub async fn device_info(target: &DeviceTarget) -> Result<DeviceInfo, RnsError> {
    let mut link = open_link(target).await?;
    drain_pending(&mut link).await;

    // Ask for identity and current stats.
    let mut request = detect_request();
    request.extend_from_slice(&kiss_frame(CMD_STAT_RSSI, &[0x00]));
    request.extend_from_slice(&kiss_frame(CMD_STAT_SNR, &[0x00]));
    link.write(&request).await?;

    let mut parser = RnodeParser::new(false);
    let mut info = DeviceInfo::default();
    let mut buffer = [0u8; 4096];

    let identity_complete = |info: &DeviceInfo| {
        info.detected && info.firmware.is_some() && info.platform.is_some() && info.mcu.is_some()
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() > deadline {
            break;
        }

        let read = tokio::time::timeout(Duration::from_secs(2), link.read(&mut buffer)).await;
        let Ok(Ok(read)) = read else { break };
        if read == 0 {
            break;
        }

        parser.feed(&buffer[..read], |event| note_device_info(&mut info, event));

        // Wait for the complete identity (detect/fw/platform/mcu arrive as
        // separate frames; breaking on firmware alone drops the rest).
        if identity_complete(&info) {
            break;
        }
    }

    // Retry the detect burst once if the first was lost.
    if !identity_complete(&info) {
        link.write(&detect_request()).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            let read = tokio::time::timeout(Duration::from_secs(1), link.read(&mut buffer)).await;
            let Ok(Ok(read)) = read else { break };
            if read == 0 {
                break;
            }
            parser.feed(&buffer[..read], |event| note_device_info(&mut info, event));
            if identity_complete(&info) {
                break;
            }
        }
    }

    Ok(info)
}

/// Validate the device's current radio configuration against a target
/// (Python `rnodeconf` configuration validation).
pub async fn validate_config(
    target: &DeviceTarget,
    config: &RnodeRadioConfig,
) -> Result<bool, RnsError> {
    let mut link = open_link(target).await?;

    let shared = std::sync::Arc::new(std::sync::RwLock::new(RnodeShared::default()));
    reticulum::iface::rnode::detect_and_validate(&mut link, config, &shared).await?;
    Ok(true)
}

/// Render device info like the upstream tool.
pub fn render_info(info: &DeviceInfo) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "Detected RNode : {}\n",
        if info.detected { "yes" } else { "no" }
    ));

    if let Some((major, minor)) = info.firmware {
        out.push_str(&format!("Firmware       : {major}.{minor}\n"));
    }
    if let Some(platform) = info.platform {
        out.push_str(&format!("Platform       : {platform:#04x}\n"));
    }
    if let Some(mcu) = info.mcu {
        out.push_str(&format!("MCU            : {mcu:#04x}\n"));
    }
    if let Some(rssi) = info.rssi {
        out.push_str(&format!("RSSI           : {rssi} dBm\n"));
    }
    if let Some(snr) = info.snr {
        out.push_str(&format!("SNR            : {snr} dB\n"));
    }

    out
}

/// Python `RNode.detect`: firmware, platform, MCU, board, and hash queries.
///
/// One `FEND` separates commands, matching the bytes that function writes.
pub fn firmware_info_request() -> Vec<u8> {
    vec![
        FEND,
        CMD_DETECT,
        DETECT_REQ,
        FEND,
        CMD_FW_VERSION,
        0x00,
        FEND,
        CMD_PLATFORM,
        0x00,
        FEND,
        CMD_MCU,
        0x00,
        FEND,
        CMD_BOARD,
        0x00,
        FEND,
        CMD_DEV_HASH,
        0x01,
        FEND,
        CMD_HASHES,
        0x01,
        FEND,
        CMD_HASHES,
        0x02,
        FEND,
    ]
}

/// Fold device replies into [`DeviceInfo`]. Unknown frames are ignored.
pub fn absorb_device_info(bytes: &[u8]) -> DeviceInfo {
    let mut info = DeviceInfo::default();
    let mut parser = RnodeParser::new(false);
    parser.feed(bytes, |event| note_device_info(&mut info, event));
    info
}

fn note_device_info(info: &mut DeviceInfo, event: reticulum::iface::rnode::RnodeEvent) {
    use reticulum::iface::rnode::RnodeEvent;
    match event {
        RnodeEvent::Detect => info.detected = true,
        RnodeEvent::FirmwareVersion { major, minor } => {
            info.firmware = Some((major, minor));
        }
        RnodeEvent::Platform(platform) => info.platform = Some(platform),
        RnodeEvent::Mcu(mcu) => info.mcu = Some(mcu),
        RnodeEvent::Status(status) => {
            if status.rssi.is_some() {
                info.rssi = status.rssi;
            }
            if status.snr.is_some() {
                info.snr = status.snr;
            }
        }
        _ => {}
    }
}

pub fn eeprom_read_frame() -> Vec<u8> {
    kiss_frame(CMD_ROM_READ, &[0x00])
}

pub fn eeprom_write_frame(addr: u8, byte: u8) -> Vec<u8> {
    kiss_frame(CMD_ROM_WRITE, &[addr, byte])
}

pub fn eeprom_wipe_frame() -> Vec<u8> {
    kiss_frame(CMD_ROM_WIPE, &[0xf8])
}

pub fn cfg_read_frame() -> Vec<u8> {
    kiss_frame(CMD_CFG_READ, &[0x00])
}

pub fn tnc_save_frame() -> Vec<u8> {
    kiss_frame(CMD_CONF_SAVE, &[0x00])
}

pub fn normal_mode_frame() -> Vec<u8> {
    kiss_frame(CMD_CONF_DELETE, &[0x00])
}

/// Radio configuration frames followed by `CMD_CONF_SAVE`.
///
/// The ESP32 hard reset Python sends after `setTNCMode` is applied in
/// [`enter_tnc_mode`].
pub fn tnc_mode_frames(config: &RnodeRadioConfig) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in config.configuration_frames(RADIO_STATE_ON) {
        out.extend_from_slice(&frame);
    }
    out.extend_from_slice(&tnc_save_frame());
    out
}

pub fn display_intensity_frame(intensity: u8) -> Vec<u8> {
    kiss_frame(CMD_DISP_INT, &[intensity])
}

pub fn display_blanking_frame(timeout: u8) -> Vec<u8> {
    kiss_frame(CMD_DISP_BLNK, &[timeout])
}

pub fn display_rotation_frame(rotation: u8) -> Vec<u8> {
    kiss_frame(CMD_DISP_ROT, &[rotation])
}

pub fn display_recondition_frame() -> Vec<u8> {
    kiss_frame(CMD_DISP_RCND, &[0x01])
}

pub fn display_address_frame(address: u8) -> Vec<u8> {
    kiss_frame(CMD_DISP_ADR, &[address])
}

/// Address command plus the hard reset Python sends after it.
pub fn display_address_sequence(address: u8) -> Vec<u8> {
    let mut out = display_address_frame(address);
    out.extend_from_slice(&reset_request());
    out
}

pub fn bluetooth_ctrl_frame(ctrl: u8) -> Vec<u8> {
    kiss_frame(CMD_BT_CTRL, &[ctrl])
}

/// On and off match Python: the control frame, then `leave`. Pair does not.
pub fn bluetooth_host_frames(ctrl: u8) -> Vec<u8> {
    let mut out = bluetooth_ctrl_frame(ctrl);
    if ctrl != BT_CTRL_PAIR {
        out.extend_from_slice(&leave_request());
    }
    out
}

pub fn wifi_mode_frame(mode: u8) -> Vec<u8> {
    kiss_frame(CMD_WIFI_MODE, &[mode])
}

/// Python `set_wifi_mode`: `sta*` is station, `ap*` is AP, anything else is off.
pub fn wifi_mode_code(mode: &str) -> u8 {
    let mode = mode.trim().to_ascii_lowercase();
    if mode.starts_with("sta") {
        WIFI_STATION
    } else if mode.starts_with("ap") {
        WIFI_AP
    } else {
        WIFI_OFF
    }
}

pub fn wifi_channel_frame(channel: u8) -> Result<Vec<u8>, RnsError> {
    if !(1..=14).contains(&channel) {
        return Err(RnsError::InvalidArgument);
    }
    Ok(kiss_frame(CMD_WIFI_CHN, &[channel]))
}

pub fn wifi_ssid_frame(ssid: Option<&str>) -> Result<Vec<u8>, RnsError> {
    terminated_frame(CMD_WIFI_SSID, ssid, 1, 33)
}

pub fn wifi_psk_frame(psk: Option<&str>) -> Result<Vec<u8>, RnsError> {
    // Python rejects an encoded length below 8, including the trailing NUL.
    terminated_frame(CMD_WIFI_PSK, psk, 8, 33)
}

pub fn wifi_ip_frame(ip: Option<&str>) -> Result<Vec<u8>, RnsError> {
    ipv4_frame(CMD_WIFI_IP, ip)
}

pub fn wifi_nm_frame(mask: Option<&str>) -> Result<Vec<u8>, RnsError> {
    ipv4_frame(CMD_WIFI_NM, mask)
}

/// Decode an EEPROM image. `None` if the buffer is shorter than the config tail.
pub fn parse_eeprom(image: &[u8]) -> Option<EepromMap> {
    if image.len() <= ADDR_CONF_WCHN {
        return None;
    }
    let info_locked = image[ADDR_INFO_LOCK] == INFO_LOCK_BYTE;
    let tnc = if info_locked && image[ADDR_CONF_OK] == CONF_OK_BYTE {
        Some(TncStored {
            spreading_factor: image[ADDR_CONF_SF],
            coding_rate: image[ADDR_CONF_CR],
            tx_power: image[ADDR_CONF_TXP],
            bandwidth: u32_at(image, ADDR_CONF_BW)?,
            frequency: u32_at(image, ADDR_CONF_FREQ)?,
        })
    } else {
        None
    };
    let blanking = image[ADDR_CONF_DBLK];
    Some(EepromMap {
        product: image[ADDR_PRODUCT],
        model: image[ADDR_MODEL],
        hw_rev: image[ADDR_HW_REV],
        serial: u32_at(image, ADDR_SERIAL)?,
        made: u32_at(image, ADDR_MADE)?,
        info_locked,
        tnc,
        bluetooth_on: image[ADDR_CONF_BT] == CONF_SET_BYTE,
        display_intensity: image[ADDR_CONF_DINT],
        display_address: image[ADDR_CONF_DADR],
        display_blanking: if image[ADDR_CONF_BSET] == CONF_SET_BYTE && blanking != 0 {
            Some(blanking)
        } else {
            None
        },
        display_rotation: image[ADDR_CONF_DROT],
        wifi_mode: image[ADDR_CONF_WIFI],
        wifi_channel: image[ADDR_CONF_WCHN],
    })
}

pub fn render_eeprom(map: &EepromMap) -> String {
    let mut out = String::new();
    out.push_str(&format!("Product        : {:#04x}\n", map.product));
    out.push_str(&format!("Model          : {:#04x}\n", map.model));
    out.push_str(&format!("Hardware rev   : {}\n", map.hw_rev));
    out.push_str(&format!("Serial         : {:08x}\n", map.serial));
    out.push_str(&format!("Manufactured   : {}\n", map.made));
    out.push_str(&format!(
        "Info lock      : {}\n",
        if map.info_locked { "yes" } else { "no" }
    ));
    if let Some(tnc) = &map.tnc {
        out.push_str("Device mode    : TNC\n");
        out.push_str(&format!("  Frequency    : {}\n", tnc.frequency));
        out.push_str(&format!("  Bandwidth    : {}\n", tnc.bandwidth));
        out.push_str(&format!("  TX power     : {}\n", tnc.tx_power));
        out.push_str(&format!("  SF           : {}\n", tnc.spreading_factor));
        out.push_str(&format!("  CR           : {}\n", tnc.coding_rate));
    } else {
        out.push_str("Device mode    : Normal (host-controlled)\n");
    }
    out.push_str(&format!(
        "Bluetooth      : {}\n",
        if map.bluetooth_on {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!("Display level  : {}\n", map.display_intensity));
    if map.display_address == 0xFF {
        out.push_str("Display addr   : default\n");
    } else {
        out.push_str(&format!("Display addr   : {:#04x}\n", map.display_address));
    }
    match map.display_blanking {
        Some(seconds) => out.push_str(&format!("Display blank  : {seconds}s\n")),
        None => out.push_str("Display blank  : disabled\n"),
    }
    if map.display_rotation == 0xFF {
        out.push_str("Display rotate : default\n");
    } else {
        out.push_str(&format!("Display rotate : {}\n", map.display_rotation));
    }
    let wifi = match map.wifi_mode {
        WIFI_STATION => "station",
        WIFI_AP => "ap",
        _ => "off",
    };
    out.push_str(&format!("WiFi           : {wifi}\n"));
    if map.wifi_mode == WIFI_STATION || map.wifi_mode == WIFI_AP {
        out.push_str(&format!("WiFi channel   : {}\n", map.wifi_channel));
    }
    out
}

/// Payload of the last `command` frame in `bytes`, or `None` if it is absent.
pub fn command_payload(bytes: &[u8], command: u8) -> Option<Vec<u8>> {
    let mut active = false;
    let mut escaped = false;
    let mut cmd = 0u8;
    let mut payload = Vec::new();
    let mut matched = None;
    for &byte in bytes {
        if byte == FEND {
            if active && cmd == command {
                matched = Some(std::mem::take(&mut payload));
            }
            active = false;
            escaped = false;
            payload.clear();
            continue;
        }
        if !active {
            active = true;
            cmd = byte;
            payload.clear();
            escaped = false;
            continue;
        }
        if escaped {
            escaped = false;
            payload.push(match byte {
                TFEND => FEND,
                TFESC => FESC,
                other => other,
            });
        } else if byte == FESC {
            escaped = true;
        } else {
            payload.push(byte);
        }
        if payload.len() > 4096 {
            active = false;
            payload.clear();
        }
    }
    matched
}

/// Write `request` and return the bytes the device sends before it goes quiet.
pub async fn transact(target: &DeviceTarget, request: &[u8]) -> Result<Vec<u8>, RnsError> {
    let mut link = open_link(target).await?;
    drain_pending(&mut link).await;
    link.write(request).await?;
    read_burst(&mut link).await
}

pub async fn read_eeprom(target: &DeviceTarget) -> Result<Option<Vec<u8>>, RnsError> {
    let raw = transact(target, &eeprom_read_frame()).await?;
    Ok(command_payload(&raw, CMD_ROM_READ))
}

/// Wipe EEPROM on one open link: write the frame, wait 13 seconds, then
/// hard-reset unless the platform is nRF52.
pub async fn wipe_eeprom(target: &DeviceTarget) -> Result<(), RnsError> {
    let mut link = open_link(target).await?;
    drain_pending(&mut link).await;

    let mut platform = None;
    if link.write(&firmware_info_request()).await.is_ok() {
        if let Ok(bytes) = read_burst(&mut link).await {
            platform = absorb_device_info(&bytes).platform;
        }
    }

    link.write(&eeprom_wipe_frame()).await?;
    // The wipe frame is already written. Silence or a later read error is
    // not a failed wipe, and the port stays open for the 13 second wait.
    let _ = read_burst(&mut link).await;
    tokio::time::sleep(Duration::from_secs(13)).await;

    if platform.is_none() && link.write(&firmware_info_request()).await.is_ok() {
        if let Ok(bytes) = read_burst(&mut link).await {
            platform = absorb_device_info(&bytes).platform;
        }
    }
    if platform != Some(PLATFORM_NRF52) {
        link.write(&reset_request()).await?;
    }
    Ok(())
}

/// `CMD_CONF_DELETE` when the EEPROM info-lock byte is `0x73`.
pub async fn enter_normal_mode(target: &DeviceTarget) -> Result<(), RnsError> {
    let mut link = open_link(target).await?;
    drain_pending(&mut link).await;
    require_info_lock(&mut link).await?;
    link.write(&normal_mode_frame()).await?;
    let _ = read_burst(&mut link).await;
    Ok(())
}

/// Radio configuration and `CMD_CONF_SAVE` when the info-lock byte is `0x73`.
///
/// ESP32 is hard-reset. A probe that reports no platform returns an error
/// and writes nothing.
pub async fn enter_tnc_mode(
    target: &DeviceTarget,
    config: &RnodeRadioConfig,
) -> Result<(), RnsError> {
    let mut link = open_link(target).await?;
    drain_pending(&mut link).await;
    link.write(&firmware_info_request()).await?;
    let info = absorb_device_info(&read_burst(&mut link).await?);
    let Some(platform) = info.platform else {
        return Err(RnsError::ResourceMsg("device did not report a platform"));
    };
    require_info_lock(&mut link).await?;
    let mut frames = tnc_mode_frames(config);
    if platform == PLATFORM_ESP32 {
        frames.extend_from_slice(&reset_request());
    }
    link.write(&frames).await?;
    let _ = read_burst(&mut link).await;
    Ok(())
}

async fn require_info_lock(link: &mut RnodeLink) -> Result<(), RnsError> {
    link.write(&eeprom_read_frame()).await?;
    let raw = read_burst(link).await?;
    let locked = command_payload(&raw, CMD_ROM_READ)
        .is_some_and(|image| image.get(ADDR_INFO_LOCK) == Some(&INFO_LOCK_BYTE));
    if locked {
        Ok(())
    } else {
        Err(RnsError::ResourceMsg("EEPROM is invalid"))
    }
}

/// Argv for an external flasher. Does not spawn a process.
///
/// A firmware path and offset select `esptool` `write_flash`. Otherwise an
/// external `rnodeconf --flash` is used when that program is on `PATH` and
/// is not this process.
pub fn flash_command(
    port: &str,
    baud_flash: u32,
    firmware: Option<&Path>,
    offset: Option<u32>,
) -> Result<FlashCommand, String> {
    if port.is_empty() {
        return Err("a serial port is required to flash".into());
    }
    let rnodeconf = program_on_path("rnodeconf").filter(|path| {
        let Ok(current) = std::env::current_exe() else {
            return true;
        };
        match (std::fs::canonicalize(path), std::fs::canonicalize(&current)) {
            (Ok(found), Ok(current)) => found != current,
            _ => true,
        }
    });
    let esptool = program_on_path("esptool").or_else(|| program_on_path("esptool.py"));

    if firmware.is_some() || offset.is_some() {
        let program = esptool.ok_or("esptool is not on PATH")?;
        let firmware = firmware.ok_or("--firmware is required with --flash-offset")?;
        let offset = offset.ok_or("--flash-offset is required with --firmware")?;
        return Ok(FlashCommand {
            program,
            args: vec![
                "--port".into(),
                port.into(),
                "--baud".into(),
                baud_flash.to_string(),
                "write_flash".into(),
                format!("0x{offset:x}"),
                firmware.display().to_string(),
            ],
        });
    }

    if let Some(program) = rnodeconf {
        return Ok(FlashCommand {
            program,
            args: vec![
                "--flash".into(),
                port.into(),
                "--baud-flash".into(),
                baud_flash.to_string(),
            ],
        });
    }

    if esptool.is_some() {
        return Err("esptool needs --firmware and --flash-offset".into());
    }
    Err("no external rnodeconf or esptool on PATH".into())
}

async fn open_link(target: &DeviceTarget) -> Result<RnodeLink, RnsError> {
    match target {
        DeviceTarget::Tcp { addr } => RnodeLink::tcp(addr).await,
        DeviceTarget::Serial { port, baudrate } => {
            #[cfg(feature = "iface-serial")]
            {
                RnodeLink::serial(port, *baudrate).await
            }
            #[cfg(not(feature = "iface-serial"))]
            {
                let _ = (port, baudrate);
                Err(RnsError::Unsupported)
            }
        }
    }
}

async fn drain_pending(link: &mut RnodeLink) {
    let drain = tokio::time::Instant::now() + Duration::from_millis(200);
    let mut scratch = [0u8; 4096];
    while tokio::time::Instant::now() < drain {
        match tokio::time::timeout(Duration::from_millis(50), link.read(&mut scratch)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
}

async fn read_burst(link: &mut RnodeLink) -> Result<Vec<u8>, RnsError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(600), link.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(err)) => return Err(err),
            Err(_) => break,
        }
    }
    Ok(out)
}

fn u32_at(image: &[u8], addr: usize) -> Option<u32> {
    let bytes = image.get(addr..addr + 4)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn terminated_frame(
    command: u8,
    text: Option<&str>,
    min_with_nul: usize,
    max_with_nul: usize,
) -> Result<Vec<u8>, RnsError> {
    let data = match text {
        None => vec![0x00],
        Some(text) => {
            let mut data = text.as_bytes().to_vec();
            data.push(0x00);
            if data.len() < min_with_nul || data.len() > max_with_nul {
                return Err(RnsError::InvalidArgument);
            }
            data
        }
    };
    Ok(kiss_frame(command, &data))
}

fn ipv4_frame(command: u8, addr: Option<&str>) -> Result<Vec<u8>, RnsError> {
    let octets = match addr {
        None => [0, 0, 0, 0],
        Some(addr) => {
            let mut octets = [0u8; 4];
            let parts: Vec<&str> = addr.split('.').collect();
            if parts.len() != 4 {
                return Err(RnsError::InvalidArgument);
            }
            for (slot, part) in octets.iter_mut().zip(parts) {
                let value: u16 = part.parse().map_err(|_| RnsError::InvalidArgument)?;
                if value > 255 {
                    return Err(RnsError::InvalidArgument);
                }
                *slot = value as u8;
            }
            octets
        }
    };
    Ok(kiss_frame(command, &octets))
}

fn program_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        let Ok(meta) = std::fs::metadata(&candidate) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return Some(candidate);
    }
    None
}
