# Hardware testing

How the hardware-dependent parts of Reticulum-rs are tested. The guiding
principle: **every tier below runs the same code path**, so a bug caught
at a cheap tier is a hardware bug caught early, and a pass at the top
tier is meaningful.

## The test ladder

| Tier | What it exercises | Where | Runs |
|---|---|---|---|
| 1. Unit | codec + parsers (KISS framing, radio config encoding, status telemetry, validation rules) | `src/iface/rnode.rs` tests, `tests/rnode_iface.rs` | every CI run |
| 2. Emulator | full connect sequence + data path against a faithful device emulator | `rn node-sim`, `tests/hardware_rnode.rs` with `RETICULUM_HW_RNODE_TCP` | every CI run |
| 3. Mock bridges | protocol against scripted counterparts (SAM bridge for I2P, bridging TCP mock for RNode) | `tests/i2p_iface.rs`, `tests/rnode_iface.rs` | every CI run |
| 4. Hardware-in-the-loop | real RNode firmware on real silicon | same `tests/hardware_rnode.rs` with `RETICULUM_HW_RNODE=<port>` | on demand |
| 5. Real radio exchange | two nodes, over-the-air LoRa | manual checklist below | on demand |

### Tier 2 — the emulator

`rn node-sim` implements the RNode device side of the wire protocol:
detect burst responses, configuration echo **with SX1262-style frequency
quantization**, radio-state transitions, periodic RSSI/SNR telemetry and
optional `CMD_READY` flow control. Data frames are bridged between all
connected hosts, simulating a shared radio channel:

```
rn node-sim --tcp 127.0.0.1:4990
RETICULUM_HW_RNODE_TCP=127.0.0.1:4990 \
  cargo test -p reticulum-utils --features iface-rnode --test hardware_rnode -- --nocapture
```

### Tier 4 — hardware-in-the-loop

Point the same tests at a real device (RNode firmware >= 1.52,
provisioned EEPROM):

```
sudo chmod 666 /dev/ttyUSB2    # if not in dialout
RETICULUM_HW_RNODE=/dev/ttyUSB2 \
  cargo test -p reticulum-utils --features "iface-rnode,iface-serial" --test hardware_rnode -- --nocapture
```

The tests cover: detect + firmware gate + identity (platform/MCU), full
radio-configuration validation via `rnodeconf`, and transmission with TX
counter advancement. `rn nodeconf --port <port>` gives the same
diagnostics interactively.

### Tier 5 — over-the-air

With two nodes on one channel:

```
# node A (listener side)
rn probe --loopback        # or any transport with an RNode interface
# node B announces; A must learn the path:
rn status                  # path table shows the announce
```

For a full link/data test, run two `rs-rnsd` instances (one per port)
with an `RNodeInterface` each and exchange announces — the tier-4
`hw_packet_transmit` asserts the same TX path that carries them.

## Field report: Heltec V3 (2026-08-18)

A Heltec V3 (ESP32-S3, SX1262, 8 MB flash) was provisioned as a test
device. **Heltec V3 is officially supported RNode hardware** (product
`0xC1`, model `0xCA` 850-950 MHz, official release builds and
`rnodeconf` support) — an earlier revision of this report wrongly
generalised a 2023 issue (#73, from when V3 support was *added*) into
"BLE not fleshed out". Corrected findings:

**What was validated against real hardware (all green):**
* full flashing flow at the reference offsets — note the ESP32-S3
  bootloader goes at **0x0**, not 0x1000 (bootloader 0x0, partitions
  0x8000, boot_app0 0xe000, app 0x10000, console 0x210000)
* EEPROM identity bootstrap (product/model/hwrev/serial/MD5 checksum/
  signature/info-lock), the `ADDR_CONF_BT` enable byte, and the
  `CMD_FW_HASH` firmware-hash handshake
* the **entire serial command protocol of `iface/rnode.rs` against
  genuine firmware 1.86 and 1.80**: detect burst responses (fw 1.86,
  platform 0x80, MCU 0x81), configuration echo with real SX1262
  frequency quantization (867,500,000 → 867,499,996 — the ±100 Hz
  validation tolerance is correct), battery/temperature telemetry,
  radio-state reporting

**RESOLVED — the device is now a fully working RNode.** The complete
root cause, found by building the actual firmware from source
(arduino-esp32 2.0.17, the exact toolchain of the official build) with
gate-level instrumentation:

* **Bluetooth was never the problem.** `btStart()` / bluedroid init /
  enable all succeed on this hardware (a minimal probe sketch and the
  instrumented firmware both confirm `bt_ready = true`)
* the sole failing gate was `fw_signature_validated` in
  `device_init()`: the stored firmware-hash target in EEPROM read
  `0xFF…FF` (erased) — the manual provisioning had never stored it,
  and an intermediate NVS erase had wiped earlier attempts
* the fix is the step official `rnodeconf` performs after flashing:
  **`CMD_FW_HASH` (0x58) with the app-image hash**. Critical detail:
  `esp_partition_get_sha256` hashes only the *app image region*, so the
  correct value is the `.bin`'s embedded hash (`fw[-32:]`, exactly what
  rnodeconf sends) — **not** the SHA-256 of the full 2 MB partition
  (verified: full-partition hash mismatches, embedded hash matches)
* with the hash stored: `device_init()` passes, `hw_ready = true`,
  `startRadio()` brings the SX1262 up

**Result, verified with the real radio:**

* `tests/hardware_rnode.rs` — **4/4 pass against the hardware**,
  including `hw_detect_firmware_and_identity`, which requires the full
  validation chain (firmware gate, config echo with real SX1262
  quantization, and the radio-state echo `0x01` that only arrives once
  the radio is actually on)
* `hw_packet_transmit` drives real LoRa transmissions
* `rn nodeconf` reads live **RSSI (-36 dBm)** from the receiving radio

Note: the corrected `RADIO_STATE_ON = 0x01` / `RADIO_STATE_OFF = 0x00`
constants (Python lines 85–86) are what make hardware validation work —
the firmware echoes the boolean `radio_online`, and the earlier
`0x08/0x09` values would never have matched.

The device now runs genuine RNode firmware 1.86 (Heltec V3, product
`0xC1`, model `0xCA` 850–950 MHz) with a provisioned identity. The
original Meshtastic image is preserved for restore:

Restoring the original Meshtastic image at any time:

```
hw-backup/heltec_v3_meshtastic_2.7.5_backup.bin   # full 8 MB image
uv tool run esptool --port /dev/ttyUSB2 --baud 921600 write-flash 0x0 hw-backup/heltec_v3_meshtastic_2.7.5_backup.bin
```

Reprovisioning checklist (from a blank/Meshtastic device to a working
RNode):

1. flash firmware at the reference offsets — **bootloader at 0x0** for
   ESP32-S3 (not 0x1000); partitions 0x8000, boot_app0 0xe000, app
   0x10000, console 0x210000
2. bootstrap the EEPROM identity (`hw-backup/bootstrap_eeprom.py`
   covers product/model/hwrev/serial/checksum/signature/info-lock)
3. store the firmware hash: `CMD_FW_HASH` with `app_bin[-32:]`
   (`hw-backup/` has the scripts; the stored target must equal the
   running-image hash or `device_init()` keeps the radio off)
4. configure the radio from the host (our `RnodeInterface` does this
   automatically: frequency/bandwidth/TX power/SF/CR + radio on)

Diagnostic techniques that worked: `CMD_HASHES` (target vs calculated
firmware hashes) as a `device_init()` oracle; a minimal `btStart()` probe
sketch to rule the BT controller in or out; gate-level `Serial.printf`
instrumentation of the real firmware when inference ran dry.

## I2P and Backbone hardware

* **I2P**: the hardware dependency is the SAM bridge of an I2P router.
  Tier-3 covers the protocol completely against the mock bridge
  (`tests/i2p_iface.rs`). Against a real router, run one locally
  (`i2pd --sam.enabled=true`) and point `I2pServer::new("127.0.0.1:7656", ...)`
  at it — no code changes needed.
* **Backbone**: plain TCP; "hardware" is the network itself. The
  end-to-end test covers server/client, fast-flap suppression and tunnel
  synthesis.
* **Weave**: requires WeaveMesh radio hardware; the WDCL device protocol
  has no observable surface without the device.
