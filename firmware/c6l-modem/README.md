# c6l-modem — M5Stack Unit C6L RNode-class modem firmware

Turns the C6L (ESP32-C6 + SX1262) into an RNode-class LoRa modem for
Reticulum hosts, exposed over the board's native USB Serial/JTAG console
(`/dev/ttyACM*`). The KISS device protocol is implemented by
[`rnode-modem-core`](../../rnode-modem-core) — validated on the host
against the real `reticulum::iface::rnode` client in CI — this crate is
the board shim: SX1262 driver, USB-CDC link, polling superloop.

## Build

    rustup target add riscv32imac-unknown-none-elf
    cargo build --release

## Flash (after backing up the current firmware!)

    esptool --port /dev/ttyACM1 --chip esp32c6 \
        write_flash 0x0 --flash_mode dio --flash_freq 80m --flash_size 4MB \
        <converted bin>   # see Makefile target `c6-flash-prep`

## Host-side verification

    RETICULUM_HW_RNODE_TCP=<addr> ...   # via USB serial:
    cargo run --example rnode_listen --features "iface-rnode,iface-serial" -- \
        --port /dev/ttyACM1

## Air conventions (interop with Heltec-class RNodes)

- sync word 0x1424 (regs 0x0740/0x0741)
- 8-symbol preamble, explicit header, LoRa CRC on
- default channel 867.5 MHz / BW125 / SF9 / CR4/5 (host reconfigures)

## Status (hardware-verified 2026-09-13)

Verified on real hardware against the full host stack:

- 16/16 protocol acceptance checks (detect/fw/platform/mcu, quantized
  frequency echo, full radio-config echo set, airtime locks, RSSI/SNR
  telemetry, CMD_READY flow control after radio TX, leave + liveness)
- `rn`-side: repeated `rnode_listen` sessions + 115 s soak with zero
  validation failures, and the `reticulum-actor` engine ran a complete
  announce-over-the-air cycle (`sent=1 announces_sent=1`) through the
  real SX1262.

### Hardware findings (worth keeping in mind)

- **USB-Serial/JTAG resets the chip on DTR/RTS transitions** — the
  same mechanism esptool uses. Hosts must pulse the reset-on-open
  sequence (`RnodeLink::serial` now mirrors pyserial/rnodeconf) and
  must not assume a connection survives control-line games.
- **GPIO19 (vendor "BUSY") reads high at idle while the radio is fully
  responsive** — the driver does not gate on it (logged once at boot).
- **esp_println busy-waits for console space**: never println at
  runtime in the modem loop or a closed port deadlocks the firmware;
  boot-time messages only (they fit the CDC FIFO).
- USB writes go through a bounded non-blocking TX queue; blocking
  `write_all` against a closed port is what wedged early builds.


## WiFi-TCP link (v0.2 — codex-reviewed, narrowed to one bug)

Architecture complete and compiling (`src/wifi.rs`, `src/sessions.rs`):
WiFi STA (build-env credentials), embassy-net DHCP, TCP server on 4990,
one session per host feeding the shared modem core.

Progress after a codex-cli review flagged **esp-wifi's documented
opt-level >= 2 requirement** (we shipped "s"): with
`[profile.release.package.esp-wifi] opt-level = 2`, the full bring-up
runs on hardware — WIFI-STEP 1→7: task, `esp_wifi::init`,
`new_with_config` (previously an eternal blocker), `embassy_net::new`,
net task, `start_async`. Eliminated suspects: executor flavour,
`low_power_wait`, SYSTIMER-vs-TIMG1 time driver, global MIE, heap size,
init location (main vs task), upstream-parity structure.

**Remaining wall:** `connect_async` (RF-active) freezes the whole
scheduler — no ISR serviced afterwards. This is below our layer
(esp-wifi 0.12 blob/preempt-scheduler interaction). The wifi task is
gated at spawn; `esp_wifi::init` still runs in main (harmless, keeps
TIMG0 ticking). USB+LoRa modem fully verified in this state.

Also learned (the hard way): adding a `clog!` telemetry line to the
actor loop or esp-wifi package opt overrides regressed the modem — the
current committed semantics are the proven-working set; bisect those
before touching the actor loop again.

**Next step: migrate to esp-hal 1.x / esp-wifi 0.14** (upstream
reworked the preempt scheduler + executor integration this bug lives
in), then re-enable the wifi task spawn.


## Migration to esp-hal 1.1 / esp-radio 0.18 / esp-rtos 0.3 (v0.4)

Migrated off the dead esp-wifi 0.12 generation onto the current stack
(esp-hal 1.1.2, esp-rtos 0.3.0, esp-radio 0.18.0, embassy-executor
0.10, embassy-net 0.9). Verified on hardware, in order:

- Scheduler: `esp_rtos::start` + rtos thread-delay wake ✓
- SX1262 radio init (blocking, pre-scheduler) ✓
- `esp_radio::wifi::new` bring-up in main-thread context ✓ (returns,
  config accepted — this never happened on esp-wifi 0.12)
- InterruptExecutor (SWI-1): tasks poll, embassy timers tick ✓
- USB RX path: dedicated `usb_rx_task` (select-cancellation of an
  in-flight async USB read drops the bytes it consumed — never put
  `usb.read()` inside a `select` that can be cancelled by a ticker)
- `logq` backing store must be `static mut` — a plain `static` lands in
  flash-mapped .rodata and stores fault (found via backtrace
  symbolization: `mepc` → `logq::push`)
- Modem session ids: `Modem::add_session()` returns ids starting at 1;
  the USB reader task must feed the *actual* id (`USB_SID`), not a
  routing constant

### v0.4.1: USB TX fixed — full modem verified on the new stack

The "stale byte" symptom was **not** the TxQueue (its wraparound
handling is correct). Root cause: session-id routing —
`Modem::add_session()` returns ids starting at **1**, but four call
sites compared against the routing constant `sessions::USB_SESSION`
(0). USB replies therefore routed through the TCP-session registry,
found no entry, and were silently dropped. Fixed by comparing against
the runtime id (`usb_sid`) everywhere: the `try_receive` drain loop,
the `select3` inbound arm, the radio-IRQ fan-out, and `handle_ops`'
CMD_READY path.

Hardware verification (2026-09-15, esp-hal 1.1 stack):

- protocol acceptance: **16/16 PASS** (detect/fw/platform/mcu,
  quantized frequency echo, full radio-config echo set, airtime locks,
  RSSI/SNR telemetry, CMD_READY flow control, leave + liveness)
- 3× consecutive `rnode_listen` sessions (reset-on-open each time),
  115 s soak — zero validation failures
- `reticulum-actor` end-to-end: announce over the air
  (`sent=1 announces_sent=1`), clean stop

### Executor notes (hardware findings)

- The esp-rtos **thread-mode executor never wakes tasks** on this board
  (initial poll works, timer/flag wakeups never fire) — scheduler
  delay and the tick thread themselves work. Unresolved; possibly an
  esp-rtos 0.3 single-core bug.
- The **InterruptExecutor works fully** (timers, tasks, spawns).
- `esp_radio::wifi::new` blocks on driver threads: call it from the
  main task, never at interrupt priority and never inside an executor
  task before the executor is proven up.
- The esp-radio async connect path wedges under both executors on this
  stack — association is therefore still gated off; needs an esp-rtos
  issue upstream.
