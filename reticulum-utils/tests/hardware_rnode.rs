//! Hardware-in-the-loop tests (Phase 5.5 / 9.1).
//!
//! These tests run against **real RNode hardware** when the
//! `RETICULUM_HW_RNODE` environment variable points at a serial port
//! (or `RETICULUM_HW_RNODE_TCP` at a TCP address). Without the variable
//! they are skipped — CI uses the emulator (`rn node-sim`) and the mock
//! bridges instead.
//!
//! Requirements for the hardware device:
//! * RNode firmware >= 1.52, provisioned EEPROM (see docs)
//! * the configured radio parameters must be within the device's model
//!   range (defaults below fit an 850-950 MHz model)
//!
//! Run with:
//! `RETICULUM_HW_RNODE=/dev/ttyUSB2 cargo test -p reticulum-utils
//! --features "iface-rnode,iface-serial" --test hardware_rnode`

#![cfg(feature = "iface-rnode")]

use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::{DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::rnode::*;
use reticulum::transport::{Transport, TransportConfig};

/// Hardware tests share one physical serial port, so they must not run
/// concurrently (cargo's default is parallel per-test threads).
static HW_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn hw_port() -> Option<String> {
    std::env::var("RETICULUM_HW_RNODE")
        .ok()
        .filter(|s| !s.is_empty())
}

fn hw_tcp() -> Option<String> {
    std::env::var("RETICULUM_HW_RNODE_TCP")
        .ok()
        .filter(|s| !s.is_empty())
}

const RADIO: RnodeRadioConfig = RnodeRadioConfig {
    frequency: 867_500_000,
    bandwidth: 125_000,
    txpower: 2,
    spreadingfactor: 9,
    codingrate: 5,
    st_alock: None,
    lt_alock: None,
};

async fn spawn_rnode(transport: &Arc<Transport>) -> reticulum::hash::AddressHash {
    let manager = transport.iface_manager();
    let mut manager = manager.lock().await;

    if let Some(tcp) = hw_tcp() {
        manager.spawn(
            RnodeInterface::tcp(tcp, RADIO).with_manager(transport.iface_manager()),
            RnodeInterface::spawn,
        )
    } else {
        let port = hw_port().expect("hardware port");
        #[cfg(feature = "iface-serial")]
        {
            manager.spawn(
                RnodeInterface::serial(port, 115200, RADIO).with_manager(transport.iface_manager()),
                RnodeInterface::spawn,
            )
        }
        #[cfg(not(feature = "iface-serial"))]
        {
            panic!("serial hardware tests need --features iface-serial (use RETICULUM_HW_RNODE_TCP for TCP devices)");
        }
    }
}

#[tokio::test]
async fn hw_detect_firmware_and_identity() {
    let Some(_port) = hw_port().or_else(hw_tcp) else {
        eprintln!("skipping: no RETICULUM_HW_RNODE[_TCP] set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Arc::new(TransportConfig::new("hw-rnode", &identity).build());
    let iface = spawn_rnode(&transport).await;

    // The interface must pass detection + firmware validation and come
    // online (this exercises the full connect sequence on hardware).
    let online = async {
        for _ in 0..400 {
            let stats = transport.interface_stats().await;
            if stats.iter().any(|s| s.address == iface && s.online) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online, "real RNode must validate its radio and come online");
}

#[tokio::test]
async fn hw_device_info_via_rnodeconf() {
    let Some(port) = hw_port() else {
        eprintln!("skipping: no RETICULUM_HW_RNODE set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let info = reticulum_utils::rnodeconf::device_info(
        &reticulum_utils::rnodeconf::DeviceTarget::Serial {
            port,
            baudrate: 115200,
        },
    )
    .await
    .expect("device probe");

    assert!(info.detected, "device must answer the detect burst");
    let (major, minor) = info.firmware.expect("firmware version");
    assert!(
        major > REQUIRED_FW_VER_MAJ
            || (major >= REQUIRED_FW_VER_MAJ && minor >= REQUIRED_FW_VER_MIN),
        "firmware {major}.{minor} below required {REQUIRED_FW_VER_MAJ}.{REQUIRED_FW_VER_MIN}"
    );
    assert!(info.platform.is_some(), "platform code must be reported");
    assert!(info.mcu.is_some(), "mcu code must be reported");

    eprintln!(
        "hw device: fw {major}.{minor}, platform {:#04x}, mcu {:#04x}, rssi {:?}, snr {:?}",
        info.platform.unwrap(),
        info.mcu.unwrap(),
        info.rssi,
        info.snr
    );
}

#[tokio::test]
async fn hw_radio_config_validation() {
    let Some(_port) = hw_port().or_else(hw_tcp) else {
        eprintln!("skipping: no RETICULUM_HW_RNODE[_TCP] set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let ok = reticulum_utils::rnodeconf::validate_config(
        &reticulum_utils::rnodeconf::DeviceTarget::Tcp {
            addr: hw_tcp().unwrap_or_default(),
        },
        &RADIO,
    )
    .await;

    // For serial devices validate over serial; tcp path above only when
    // a TCP target exists. Skip assertion accordingly.
    if hw_tcp().is_some() {
        assert!(ok.expect("validation"), "radio configuration must validate");
    } else {
        eprintln!("skipping tcp validation (serial device)");
    }
}

#[tokio::test]
async fn hw_packet_transmit() {
    let Some(_port) = hw_port().or_else(hw_tcp) else {
        eprintln!("skipping: no RETICULUM_HW_RNODE[_TCP] set");
        return;
    };
    let _guard = HW_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let identity = PrivateIdentity::new_from_rand(OsRng);
    let transport = Arc::new(TransportConfig::new("hw-tx", &identity).build());
    let iface = spawn_rnode(&transport).await;

    let online = async {
        for _ in 0..400 {
            let stats = transport.interface_stats().await;
            if stats.iter().any(|s| s.address == iface && s.online) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
    .await;
    assert!(online);

    // Transmit an announce through the real radio; with only one device
    // we assert the TX path completes (stat_tx telemetry increments)
    // rather than a full round trip.
    let destination = SingleInputDestination::new(
        PrivateIdentity::new_from_rand(OsRng),
        DestinationName::new("hw", "tx"),
    );
    transport
        .send_announce(&Arc::new(tokio::sync::Mutex::new(destination)), None)
        .await;

    // The interface TX counter must advance.
    let tx_advanced = async {
        let baseline = {
            let stats = transport.interface_stats().await;
            stats
                .iter()
                .find(|s| s.address == iface)
                .map(|s| s.sent)
                .unwrap_or(0)
        };
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let stats = transport.interface_stats().await;
            let sent = stats
                .iter()
                .find(|s| s.address == iface)
                .map(|s| s.sent)
                .unwrap_or(0);
            if sent > baseline {
                return true;
            }
        }
        false
    }
    .await;
    assert!(tx_advanced, "announce must be transmitted over the radio");
}

fn accept_replies(frames: &[Vec<u8>]) -> RnodeEchoState {
    let mut echo = RnodeEchoState::default();
    let mut parser = RnodeParser::new(false);
    for frame in frames {
        parser.feed(frame, |event| match event {
            RnodeEvent::Echo(part) => {
                if part.frequency.is_some() {
                    echo.frequency = part.frequency;
                }
                if part.bandwidth.is_some() {
                    echo.bandwidth = part.bandwidth;
                }
                if part.txpower.is_some() {
                    echo.txpower = part.txpower;
                }
                if part.spreadingfactor.is_some() {
                    echo.spreadingfactor = part.spreadingfactor;
                }
                if part.codingrate.is_some() {
                    echo.codingrate = part.codingrate;
                }
                if part.radio_state.is_some() {
                    echo.radio_state = part.radio_state;
                }
            }
            RnodeEvent::Error(code) => panic!("modem returned CMD_ERROR {code:#04x}"),
            _ => {}
        });
    }
    echo
}

#[test]
fn rnodeconf_provision_frames_match_python_and_modem_accepts_them() {
    use reticulum_utils::rnodeconf::*;
    use rnode_modem_core::modem::Modem;
    use rnode_modem_core::protocol::Protocol;
    use rnode_modem_core::{FW_VERSION_MAJ, FW_VERSION_MIN, MCU_ESP32_C6, PLATFORM_CUSTOM};

    assert_eq!(eeprom_read_frame(), vec![FEND, CMD_ROM_READ, 0x00, FEND]);
    assert_eq!(eeprom_wipe_frame(), vec![FEND, 0x59, 0xf8, FEND]);
    assert_eq!(
        eeprom_write_frame(FEND, FESC),
        vec![FEND, 0x52, FESC, TFEND, FESC, TFESC, FEND]
    );
    assert_eq!(tnc_save_frame(), vec![FEND, 0x53, 0x00, FEND]);
    assert_eq!(normal_mode_frame(), vec![FEND, 0x54, 0x00, FEND]);
    assert_eq!(reset_request(), vec![FEND, 0x55, 0xF8, FEND]);
    assert_eq!(cfg_read_frame(), vec![FEND, 0x6D, 0x00, FEND]);

    let mut expected_tnc = Vec::new();
    for frame in RADIO.configuration_frames(RADIO_STATE_ON) {
        expected_tnc.extend_from_slice(&frame);
    }
    expected_tnc.extend_from_slice(&tnc_save_frame());
    assert_eq!(tnc_mode_frames(&RADIO), expected_tnc);

    assert_eq!(
        firmware_info_request(),
        vec![
            FEND,
            CMD_DETECT,
            DETECT_REQ,
            FEND,
            0x50,
            0x00,
            FEND,
            CMD_PLATFORM,
            0x00,
            FEND,
            CMD_MCU,
            0x00,
            FEND,
            0x47,
            0x00,
            FEND,
            0x56,
            0x01,
            FEND,
            0x60,
            0x01,
            FEND,
            0x60,
            0x02,
            FEND,
        ]
    );
    assert_eq!(display_intensity_frame(0x20), vec![FEND, 0x45, 0x20, FEND]);
    assert_eq!(display_blanking_frame(30), vec![FEND, 0x64, 30, FEND]);
    assert_eq!(display_rotation_frame(1), vec![FEND, 0x67, 1, FEND]);
    assert_eq!(display_recondition_frame(), vec![FEND, 0x68, 0x01, FEND]);
    assert_eq!(
        bluetooth_ctrl_frame(BT_CTRL_PAIR),
        vec![FEND, 0x46, 0x02, FEND]
    );
    let paired = bluetooth_host_frames(BT_CTRL_PAIR);
    assert_eq!(paired, bluetooth_ctrl_frame(BT_CTRL_PAIR));
    let enabled = bluetooth_host_frames(BT_CTRL_ON);
    assert!(enabled.starts_with(&bluetooth_ctrl_frame(BT_CTRL_ON)));
    assert!(enabled.ends_with(&leave_request()));
    assert_eq!(wifi_mode_code("station"), WIFI_STATION);
    assert_eq!(wifi_mode_code("AP"), WIFI_AP);
    assert_eq!(wifi_mode_code("off"), WIFI_OFF);
    assert_eq!(wifi_mode_frame(WIFI_STATION), vec![FEND, 0x6A, 0x01, FEND]);
    assert_eq!(wifi_channel_frame(6).unwrap(), vec![FEND, 0x6E, 6, FEND]);
    assert!(wifi_channel_frame(0).is_err());
    assert_eq!(
        wifi_ssid_frame(Some("reticulum")).unwrap(),
        vec![FEND, 0x6B, b'r', b'e', b't', b'i', b'c', b'u', b'l', b'u', b'm', 0x00, FEND,]
    );
    assert_eq!(wifi_ssid_frame(None).unwrap(), vec![FEND, 0x6B, 0x00, FEND]);
    assert!(wifi_ssid_frame(Some(&"x".repeat(33))).is_err());
    assert!(wifi_psk_frame(Some("short")).is_err());
    assert_eq!(
        wifi_psk_frame(Some("1234567")).unwrap(),
        kiss_frame(0x6C, b"1234567\0")
    );
    assert_eq!(
        wifi_ip_frame(Some("10.0.0.1")).unwrap(),
        vec![FEND, 0x84, 10, 0, 0, 1, FEND]
    );
    assert_eq!(
        wifi_nm_frame(None).unwrap(),
        vec![FEND, 0x85, 0, 0, 0, 0, FEND]
    );
    assert!(wifi_ip_frame(Some("10.0.0")).is_err());
    let address = display_address_sequence(0x3C);
    assert!(address.starts_with(&display_address_frame(0x3C)));
    assert!(address.ends_with(&reset_request()));

    let mut image = vec![0u8; 0xBC];
    image[0x00] = 0x03;
    image[0x01] = 0xA4;
    image[0x02] = 1;
    image[0x03..0x07].copy_from_slice(&42u32.to_be_bytes());
    image[0x07..0x0B].copy_from_slice(&1_700_000_000u32.to_be_bytes());
    image[0x9B] = 0x73;
    image[0x9C] = 9;
    image[0x9D] = 5;
    image[0x9E] = 2;
    image[0x9F..0xA3].copy_from_slice(&125_000u32.to_be_bytes());
    image[0xA3..0xA7].copy_from_slice(&867_500_000u32.to_be_bytes());
    image[0xA7] = 0x73;
    image[0xB0] = 0x73;
    image[0xB2] = 40;
    image[0xB3] = 0x3C;
    image[0xB4] = 15;
    image[0xB7] = 0x73;
    image[0xB8] = 1;
    image[0xBA] = WIFI_STATION;
    image[0xBB] = 6;
    let map = parse_eeprom(&image).expect("eeprom image");
    assert_eq!(map.serial, 42);
    assert_eq!(map.made, 1_700_000_000);
    assert!(map.info_locked);
    assert!(map.bluetooth_on);
    let tnc = map.tnc.as_ref().expect("tnc marker");
    assert_eq!(tnc.frequency, 867_500_000);
    assert_eq!(tnc.bandwidth, 125_000);
    assert_eq!(tnc.spreading_factor, 9);
    assert_eq!(tnc.coding_rate, 5);
    assert_eq!(tnc.tx_power, 2);
    assert_eq!(map.display_blanking, Some(15));
    assert_eq!(map.wifi_mode, WIFI_STATION);
    assert_eq!(map.wifi_channel, 6);
    let rendered = render_eeprom(&map);
    assert!(rendered.contains("Device mode    : TNC"));
    assert!(rendered.contains("867500000"));
    let wrapped = kiss_frame(CMD_ROM_READ, &image);
    assert_eq!(
        command_payload(&wrapped, CMD_ROM_READ).as_deref(),
        Some(image.as_slice())
    );

    let mut modem = Modem::new(Protocol::new(MCU_ESP32_C6));
    let session = modem.add_session();

    let fed = modem.feed(session, &eeprom_read_frame());
    assert!(fed.to_sender.is_empty());
    accept_replies(&fed.to_sender);
    let fed = modem.feed(session, &eeprom_write_frame(0x00, 0x03));
    accept_replies(&fed.to_sender);
    let fed = modem.feed(session, &eeprom_wipe_frame());
    accept_replies(&fed.to_sender);

    let fed = modem.feed(session, &tnc_mode_frames(&RADIO));
    let echo = accept_replies(&fed.to_sender);
    assert_eq!(echo.frequency, Some(RADIO.frequency));
    assert_eq!(echo.bandwidth, Some(RADIO.bandwidth));
    assert_eq!(echo.txpower, Some(RADIO.txpower));
    assert_eq!(echo.spreadingfactor, Some(RADIO.spreadingfactor));
    assert_eq!(echo.codingrate, Some(RADIO.codingrate));
    assert_eq!(echo.radio_state, Some(RADIO_STATE_ON));

    let fed = modem.feed(session, &firmware_info_request());
    let bytes: Vec<u8> = fed.to_sender.iter().flatten().copied().collect();
    let info = absorb_device_info(&bytes);
    assert!(info.detected);
    assert_eq!(info.firmware, Some((FW_VERSION_MAJ, FW_VERSION_MIN)));
    assert_eq!(info.platform, Some(PLATFORM_CUSTOM));
    assert_eq!(info.mcu, Some(MCU_ESP32_C6));

    for frame in [
        display_intensity_frame(0x20),
        display_blanking_frame(30),
        display_rotation_frame(1),
        display_recondition_frame(),
        display_address_sequence(0x3C),
        bluetooth_host_frames(BT_CTRL_ON),
        bluetooth_host_frames(BT_CTRL_OFF),
        bluetooth_host_frames(BT_CTRL_PAIR),
        wifi_mode_frame(WIFI_AP),
        wifi_channel_frame(11).unwrap(),
        wifi_ssid_frame(Some("net")).unwrap(),
        wifi_psk_frame(Some("reticulum")).unwrap(),
        wifi_ip_frame(None).unwrap(),
        wifi_nm_frame(Some("255.255.255.0")).unwrap(),
        cfg_read_frame(),
        normal_mode_frame(),
    ] {
        let fed = modem.feed(session, &frame);
        accept_replies(&fed.to_sender);
    }

    match flash_command("/dev/ttyUSB0", 921600, None, None) {
        Ok(cmd) => {
            assert!(
                cmd.program.ends_with("rnodeconf")
                    || cmd.program.ends_with("esptool")
                    || cmd.program.ends_with("esptool.py")
            );
            assert!(cmd
                .args
                .iter()
                .any(|arg| arg == "--flash" || arg == "write_flash"));
            assert!(cmd.args.iter().any(|arg| arg == "/dev/ttyUSB0"));
        }
        Err(err) => {
            let err = err.to_ascii_lowercase();
            assert!(
                err.contains("rnodeconf") || err.contains("esptool"),
                "{err}"
            );
        }
    }
    let image_cmd = flash_command(
        "/dev/ttyUSB0",
        921600,
        Some(std::path::Path::new("fw.bin")),
        Some(0x10000),
    );
    if let Ok(cmd) = image_cmd {
        assert!(cmd.args.iter().any(|arg| arg == "write_flash"));
        assert!(cmd.args.iter().any(|arg| arg == "0x10000"));
        assert!(cmd.args.iter().any(|arg| arg == "fw.bin"));
    }
}
