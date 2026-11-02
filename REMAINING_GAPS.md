# Remaining gaps vs Python Reticulum 1.5.5

Comparison target: Python Reticulum checkout (`RNS/_version.py` =
1.5.5). The items below are the differences that remain after the parity
series landed. LXMF, LXST, `reticulum-actor`, `reticulum-ffi`, and
`firmware/` are Rust-side extras, not Python parity items, and are not
listed here.

## Interfaces and platform support

- **No Android USB host stack.** On Android, Python keeps the config
  types `RNodeInterface`, `SerialInterface`, and `KISSInterface` but
  swaps in the `RNS/Interfaces/Android/` modules, where USB serial is a
  device id resolved through `usb4a.usb.get_usb_device(port)`; the
  Android Weave module takes the same path. Rust has no `usb4a` /
  `usbserial4a` host stack, so none of those Android USB serial ports
  can be opened, and `reticulum-daemon/src/main.rs` (commit `01a9d73`)
  logs and does not start a Weave USB serial interface when
  `target_os = "android"`.
- **RNode over `ble://` needs a cargo feature.** The btleplug backend
  lives behind `iface-rnode-ble` (`Cargo.toml`, commit `58eb91f`);
  without it `RnodeLink::connect_ble` returns `RnsError::Unsupported`.
  Python also fails closed: a desktop `RNodeInterface` opens `ble://`
  only when `bleak` imports (`setup.py` `install_requires` is just
  `cryptography` and `pyserial`, so a normal install has no BLE stack,
  and the device must be bonded), and Android needs the `able` /
  `BluetoothDispatcher` library.
- **No `interfaces/` file plugins.** When the config `type` is not a
  built-in, Python `Reticulum._synthesize_interface` execs
  `{configdir}/interfaces/<Type>.py` (`RNS/Reticulum.py`); Rust never
  loads that file. The daemon can still start an enabled unknown type
  in-process through `register_interface_factory`
  (`reticulum-daemon/src/config.rs`, commit `01a9d73`) and errors with
  `type '{name}' is not supported` only when no factory is registered.
  `warn_about_unknown_keys` still logs `type '{iface_type}' which is
  not supported yet` for any type outside `SUPPORTED_INTERFACE_TYPES`,
  including one a factory will then start.
- **AutoInterface enumeration is per-OS.** `platform_addresses()` in
  `src/iface/auto.rs` covers Linux, Android, macOS, the BSDs, and
  Windows; any other target (for example Solaris, which Python's
  vendored `netinfo` handles via `getifaddrs`) gets an empty list, so
  AutoInterface finds no subinterfaces there.

## Utilities

- **`rnodeconf` is framing-only.** `reticulum-utils/src/rnodeconf.rs`
  covers probing, EEPROM read/write, firmware info, TNC mode, display,
  WiFi, and BLE control frames. Not ported from
  `RNS/Utilities/rnodeconf.py` (major items, not every missing
  command): the `models` firmware map and autoinstall/update/extract
  flow, MD5 image hashing and RSA signing/key files, the bundled
  `recovery_esptool.py`, the NeoPixel intensity (`--np` /
  `set_neopixel_intensity`) and interference-avoidance (`--ia-enable` /
  `--ia-disable` / `set_disable_interference_avoidance`) control
  frames, the extra RAK4631 `sleep(10)` after the EEPROM wipe (the 13s
  wipe wait itself is ported) and most other inter-command timing
  sleeps, and the `input()` "Press enter to exit" Bluetooth-pairing
  wait. `--flash` builds an argv for an external `rnodeconf` or
  `esptool` on `PATH` (`flash_command`) that `run_nodeconf` then spawns
  with `std::process::Command` (`55a3d5c`); the Rust binary does not
  flash in-process.
- **`rngit` has no web output.** `reticulum-utils/src/rngit.rs`
  implements the node, client, and `git-remote-rns` wire operations.
  The Python tool's HTML repository pages (`rngit/pages.py`), syntax
  highlighting (`rngit/highlight.py`), and media transcoding to WebP
  (`rngit/media.py`) are not ported.

## Stubs on both sides — not gaps

- `rnir` and `rnpkg` are attach-only stubs in both trees: Python's
  `RNS/Utilities/rnir.py` and `rnpkg.py` instantiate `RNS.Reticulum`
  and exit; `reticulum-utils/src/rnir.rs` and `rnpkg.rs` do the same.
- `Resolver.resolve_identity` is an empty stub in `RNS/Resolver.py`;
  there is no Rust resolver implementing it either.
