//! Device-side RNode modem core.
//!
//! This crate implements the *device* half of the RNode KISS wire protocol
//! (the side normally implemented by the RNode firmware on an Arduino-class
//! board), factored so that:
//!
//! * the protocol logic is pure and `no_std`-with-`alloc` — it runs on any
//!   MCU behind thin link shims (USB-CDC, UART, WiFi-TCP, ...) and a radio
//!   driver (SX1262, ...),
//! * the same code is exercised on the host in `tests/` against the real
//!   host-side client in `reticulum::iface::rnode`, so protocol regressions
//!   are caught in CI without hardware.
//!
//! The semantics mirrored here come from three in-repo sources of truth:
//! the host-side implementation (`src/iface/rnode.rs`), the device emulator
//! (`reticulum-utils/src/rnode_sim.rs`), and the upstream RNode firmware
//! behaviour (detect burst, configuration echo with SX1262 frequency
//! quantization, CMD_READY flow control, status telemetry, leave/reset).
//!
//! `rn node-sim` remains the reference emulator; this crate is the
//! embeddable version of the same behaviour.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

extern crate alloc;

pub mod frame;
pub mod modem;
pub mod protocol;
pub mod radio;

/// Firmware version reported over `CMD_FW_VERSION`. Hosts gate on
/// `>= 1.52` (`reticulum::iface::rnode::REQUIRED_FW_VER_*`), mirroring
/// Python RNS. We report a clearly-custom minor so installs are
/// identifiable while passing the gate.
pub const FW_VERSION_MAJ: u8 = 1;
pub const FW_VERSION_MIN: u8 = 90;

/// Platform / MCU identification bytes. Hosts collect these for
/// diagnostics; only the firmware version is a hard gate. We use an
/// unregistered custom value so the device is identifiable and never
/// confused with an official platform in provisioning tools.
pub const PLATFORM_CUSTOM: u8 = 0xF0;

/// ESP32-C6 (RISC-V) — custom MCU id, see `PLATFORM_CUSTOM`.
pub const MCU_ESP32_C6: u8 = 0xC6;

/// ESP32-S3 (Xtensa LX7) — custom MCU id, see `PLATFORM_CUSTOM`.
pub const MCU_ESP32_S3: u8 = 0x53;
