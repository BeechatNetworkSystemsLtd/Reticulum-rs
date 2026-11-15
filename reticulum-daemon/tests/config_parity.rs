//! Config parity tests (Phase 7.2): unknown keys warn but never fail, and
//! the additional interface types (serial / KISS / pipe / local) parse.

use std::path::PathBuf;

use reticulum_daemon::config::{
    Config, InterfaceConfig, KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS, KNOWN_RETICULUM_KEYS,
    SUPPORTED_INTERFACE_TYPES,
};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rs-rnsd-cfg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn unknown_keys_and_sections_do_not_fail_parsing() {
    let dir = temp_dir("unknown");
    std::fs::write(
        dir.join("config.toml"),
        r#"
[reticulum]
enable_transport = false
instance_name = "test-instance"
completely_unknown_option = "whatever"
storagepath = "/tmp/somewhere"

[logging]
loglevel = "Info"
logdest = "file"

[some_future_section]
key = 1

[[interfaces]]
name = "UDP"
type = "UDPInterface"
listen_ip = "127.0.0.1"
listen_port = 4242
forward_ip = "127.0.0.1"
forward_port = 4243
mode = "gateway"
configured_bitrate = 12000
"#,
    )
    .unwrap();

    let config = Config::from_file(&dir).expect("config must parse despite unknown keys");
    assert!(!config.reticulum.enable_transport);
    assert_eq!(
        config.reticulum.instance_name.as_deref(),
        Some("test-instance")
    );
    assert_eq!(config.interfaces.len(), 1);
}

#[test]
fn serial_kiss_pipe_local_interfaces_parse() {
    let dir = temp_dir("ifaces");
    std::fs::write(
        dir.join("config.toml"),
        r#"
[[interfaces]]
name = "Serial"
type = "SerialInterface"
port = "/dev/ttyUSB0"
speed = 57600

[[interfaces]]
name = "KISS"
type = "KISSInterface"
port = "/dev/ttyUSB1"
speed = 115200

[[interfaces]]
name = "Pipe"
type = "PipeInterface"
command = "socat - TCP:localhost:5000"
respawn_delay = 5.5

[[interfaces]]
name = "Local"
type = "LocalInterface"
listen_ip = "127.0.0.1"
listen_port = 37428

[[interfaces]]
name = "FutureThing"
type = "SomeNewInterfaceType"
"#,
    )
    .unwrap();

    let config = Config::from_file(&dir).expect("config must parse");
    let kinds: Vec<&str> = config
        .interfaces
        .iter()
        .map(|iface| match &iface.config {
            InterfaceConfig::SerialInterface { .. } => "serial",
            InterfaceConfig::KISSInterface { .. } => "kiss",
            InterfaceConfig::PipeInterface { .. } => "pipe",
            InterfaceConfig::LocalInterface { .. } => "local",
            InterfaceConfig::Unsupported => "unsupported",
            _ => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["serial", "kiss", "pipe", "local", "unsupported"]
    );
    assert_eq!(config.interfaces[4].configured_type, "SomeNewInterfaceType");
    assert!(config.interfaces[4].configured_enabled);

    match &config.interfaces[0].config {
        InterfaceConfig::SerialInterface { port, speed, .. } => {
            assert_eq!(port, "/dev/ttyUSB0");
            assert_eq!(*speed, 57600);
        }
        other => panic!("expected serial interface, got {other:?}"),
    }
    match &config.interfaces[2].config {
        InterfaceConfig::PipeInterface {
            command,
            respawn_delay,
            ..
        } => {
            assert!(command.starts_with("socat"));
            assert_eq!(*respawn_delay, 5.5);
        }
        other => panic!("expected pipe interface, got {other:?}"),
    }
    match &config.interfaces[3].config {
        InterfaceConfig::LocalInterface {
            listen_ip,
            listen_port,
            ..
        } => {
            assert_eq!(listen_ip, "127.0.0.1");
            assert_eq!(*listen_port, 37428);
        }
        other => panic!("expected local interface, got {other:?}"),
    }
    // Everything defaults to enabled.
    assert!(matches!(
        &config.interfaces[1].config,
        InterfaceConfig::KISSInterface { enabled: true, .. }
    ));
}

#[test]
fn weave_interface_parses_and_unknown_type_keeps_extra_keys() {
    let dir = temp_dir("weave");
    std::fs::write(
        dir.join("config.toml"),
        r#"
[[interfaces]]
name = "Weave"
type = "WeaveInterface"
port = "/dev/ttyACM0"

[[interfaces]]
name = "WeaveAlias"
type = "WeaveInterface"
port = "/dev/ttyACM1"
enabled = false
interface_enabled = true

[[interfaces]]
name = "WeaveOff"
type = "WeaveInterface"
port = "/dev/ttyACM2"
enabled = false
interface_enabled = false

[[interfaces]]
name = "Future"
type = "SomeNewInterfaceType"
widget = 1
enabled = false
interface_enabled = true
"#,
    )
    .unwrap();

    let config = Config::from_file(&dir).expect("config must parse");
    assert!(SUPPORTED_INTERFACE_TYPES.contains(&"WeaveInterface"));
    match &config.interfaces[0].config {
        InterfaceConfig::WeaveInterface { enabled, port } => {
            assert!(*enabled);
            assert_eq!(port, "/dev/ttyACM0");
        }
        other => panic!("expected weave interface, got {other:?}"),
    }
    assert!(config.interfaces[0].configured_enabled);
    assert_eq!(config.interfaces[0].configured_type, "WeaveInterface");
    assert!(config.interfaces[0].raw_config.is_none());

    match &config.interfaces[1].config {
        InterfaceConfig::WeaveInterface { enabled, port } => {
            assert!(
                *enabled,
                "interface_enabled = true must start the interface"
            );
            assert_eq!(port, "/dev/ttyACM1");
        }
        other => panic!("expected weave interface, got {other:?}"),
    }
    assert!(config.interfaces[1].configured_enabled);
    assert!(config.interfaces[1].raw_config.is_none());

    match &config.interfaces[2].config {
        InterfaceConfig::WeaveInterface { enabled, .. } => {
            assert!(!*enabled);
        }
        other => panic!("expected weave interface, got {other:?}"),
    }
    assert!(!config.interfaces[2].configured_enabled);

    assert!(matches!(
        config.interfaces[3].config,
        InterfaceConfig::Unsupported
    ));
    assert_eq!(config.interfaces[3].configured_type, "SomeNewInterfaceType");
    assert!(config.interfaces[3].configured_enabled);
    let widget = config.interfaces[3]
        .raw_config
        .as_ref()
        .and_then(|value| value.get("widget"))
        .and_then(toml::Value::as_integer);
    assert_eq!(widget, Some(1));
}

#[test]
fn share_instance_port_defaults_match_python() {
    let dir = temp_dir("defaults");
    std::fs::write(dir.join("config.toml"), "[reticulum]\n").unwrap();
    let config = Config::from_file(&dir).expect("parse");
    assert!(config.reticulum.share_instance);
    assert_eq!(config.reticulum.shared_instance_port, 37428);
    assert_eq!(config.reticulum.instance_control_port, 37429);
    assert!(config.reticulum.use_implicit_proof);
    assert!(!config.reticulum.static_transport_identity);
    assert_eq!(
        config.reticulum.blackhole_update_every(),
        std::time::Duration::from_secs(60 * 60)
    );
}

#[test]
fn empty_config_shares_the_instance() {
    let dir = temp_dir("empty");
    std::fs::write(dir.join("config.toml"), "").unwrap();
    let config = Config::from_file(&dir).expect("empty config");
    assert!(config.reticulum.share_instance);
    assert!(config.logging.logtimestamps);
}

#[test]
fn unapplied_warnings_skip_keys_python_does_not_apply() {
    for key in [
        "link_mtu_discovery",
        "network_identity",
        "static_transport_identity",
        "storagepath",
        "require_if_time_sync",
        "enable_stranded_announce_rebroadcast",
    ] {
        assert!(
            !KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS.contains(&key),
            "{key} must not warn as unapplied"
        );
        assert!(
            KNOWN_RETICULUM_KEYS.contains(&key),
            "{key} must stay a known key"
        );
    }
    assert!(SUPPORTED_INTERFACE_TYPES.contains(&"BackboneInterface"));
    assert!(SUPPORTED_INTERFACE_TYPES.contains(&"BackboneClientInterface"));
    assert!(KNOWN_RETICULUM_KEYS.contains(&"instance_control_port"));
    assert!(!KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS.contains(&"instance_control_port"));
    assert!(KNOWN_RETICULUM_KEYS.contains(&"rpc_key"));
    assert!(!KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS.contains(&"rpc_key"));
    assert!(KNOWN_RETICULUM_KEYS.contains(&"enable_interface_management"));
    assert!(!KNOWN_BUT_UNAPPLIED_RETICULUM_KEYS.contains(&"enable_interface_management"));
}

#[test]
fn python_interface_knobs_parse_and_announce_cap_is_a_fraction() {
    let dir = temp_dir("knobs");
    std::fs::write(
        dir.join("config.toml"),
        r#"
[reticulum]
enable_transport = true
use_implicit_proof = false
static_transport_identity = true
local_hops_delta = true
network_identity = "~/reticulum/network"
blackhole_update_interval = 1
default_gravity = 4
discover_interfaces = true
required_discovery_value = 8
autoconnect_discovered_interfaces = 3
autoconnect_unverified_implementations = true
autoconnect_interface_mode = "gw"
autoconnect_announces_to_internal = true
qlen_in_data = 0
qlen_in_announce = 32
default_ar_grace = 0
interface_discovery_sources = "00112233445566778899aabbccddeeff"

[logging]
logtimestamps = false

[[interfaces]]
name = "Backbone"
type = "BackboneInterface"
listen_on = "0.0.0.0"
port = 4242
interface_mode = "ap"
announce_cap = 25
announce_rate_target = 120
kiss_framing = true
bitrate = 4
discoverable = true
announce_interval = 10
discovery_stamp_value = 4
reachable_on = "gw.example"
publish_ifac = true
networkname = "mesh"
ifac_size = 64

[[interfaces]]
name = "UDP shorthand"
type = "UDPInterface"
listen_ip = "0.0.0.0"
forward_ip = "255.255.255.255"
port = 4243
mode = "ptp"

[[interfaces]]
name = "Radio"
type = "KISSInterface"
port = "/dev/ttyUSB0"
id_interval = 60
id_callsign = "N0CALL"
mode = "gw"
"#,
    )
    .unwrap();

    let config = Config::from_file(&dir).expect("python knobs");
    assert!(!config.reticulum.use_implicit_proof);
    assert!(config.reticulum.static_transport_identity);
    assert!(config.reticulum.local_hops_delta);
    assert_eq!(
        config.reticulum.network_identity.as_deref(),
        Some("~/reticulum/network")
    );
    assert_eq!(
        config.reticulum.blackhole_update_every(),
        std::time::Duration::from_secs(2 * 60)
    );
    assert_eq!(config.reticulum.default_gravity, Some(4));
    assert_eq!(config.reticulum.autoconnect_discovered_interfaces, 3);
    assert_eq!(
        config.reticulum.autoconnect_interface_mode.as_deref(),
        Some("gw")
    );
    assert_eq!(config.reticulum.qlen_in_data, Some(0));
    assert_eq!(config.reticulum.qlen_in_announce, Some(32));
    assert!(!config.logging.logtimestamps);
    assert_eq!(config.interfaces.len(), 3);

    let backbone = &config.interfaces[0];
    assert_eq!(backbone.mode.as_deref(), Some("ap"));
    assert_eq!(backbone.announce_cap_fraction(), 0.25);
    assert_eq!(backbone.announce_rate_target, Some(120));
    assert!(backbone.kiss_framing);
    assert_eq!(backbone.bitrate, Some(4));
    assert_eq!(backbone.discovery_announce_interval_minutes, Some(10));
    match &backbone.config {
        InterfaceConfig::BackboneInterface {
            listen_ip,
            bind_port,
            ..
        } => {
            assert_eq!(listen_ip, "0.0.0.0");
            assert_eq!(*bind_port, 4242);
        }
        other => panic!("expected backbone, got {other:?}"),
    }

    match &config.interfaces[1].config {
        InterfaceConfig::UDPInterface {
            listen_port,
            forward_port,
            port,
            ..
        } => {
            assert!(listen_port.is_none());
            assert!(forward_port.is_none());
            assert_eq!(*port, Some(4243));
        }
        other => panic!("expected udp, got {other:?}"),
    }
    assert_eq!(config.interfaces[1].mode.as_deref(), Some("ptp"));
    assert_eq!(config.interfaces[2].mode.as_deref(), Some("gw"));
    assert_eq!(config.interfaces[2].id_interval, Some(60));
    assert_eq!(config.interfaces[2].id_callsign.as_deref(), Some("N0CALL"));

    assert_eq!(
        reticulum::iface::InterfaceMode::from_name("ap"),
        Some(reticulum::iface::InterfaceMode::AccessPoint)
    );
    assert_eq!(
        reticulum::iface::InterfaceMode::from_name("ptp"),
        Some(reticulum::iface::InterfaceMode::PointToPoint)
    );
    assert_eq!(
        reticulum::iface::InterfaceMode::from_name("gw"),
        Some(reticulum::iface::InterfaceMode::Gateway)
    );
}
