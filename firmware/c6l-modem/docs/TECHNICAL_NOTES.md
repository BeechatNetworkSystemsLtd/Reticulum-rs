# c6l-modem: Technical Documentation

## Overview

The c6l-modem firmware turns the M5Stack Unit C6L (ESP32-C6 + SX1262)
into an RNode-class LoRa modem with USB and WiFi-TCP host links,
driven by the Reticulum-rs Rust SDK.

## Architecture (v0.5 — Single-Thread)

All tasks run on the main RTOS thread's executor. No cross-thread
communication needed.

```
┌─ Main RTOS Thread Executor ────────────────────┐
│                                                │
│  modem_task ─── KISS protocol, LoRa, USB TX   │
│    usb_rx_task ─── dedicated USB reader       │
│    yield_helper ─── forces round-robin        │
│                                                │
│  wifi_task ─── WiFi association + DHCP        │
│    connection_task ─── WiFi event monitor     │
│    net_task ─── smoltcp (10ms re-poll)        │
│    tcp_session ─── per-host KISS over TCP     │
│                                                │
│  Communication: embassy_sync Channel          │
│  (works perfectly within single executor)     │
└────────────────────────────────────────────────┘

Host runs: `nc -l 4990` (or equivalent listener)
Modem reverse-connects to C6L_TCP_HOST:4990
```

## What Works (All Hardware-Verified)

| Feature | Status |
|---------|--------|
| USB KISS modem | ✅ 16/16 protocol acceptance |
| Multi-session stability | ✅ 5/5 reset cycles |
| 115s soak | ✅ 0 failures |
| reticulum-actor end-to-end | ✅ announce over the air |
| WiFi association + DHCP | ✅ IP 192.168.1.233/24 |
| TCP KISS over WiFi | ✅ 7-frame detect burst |
| USB + TCP simultaneously | ✅ both active |

## The Actual Root Cause of the TCP Bug

After extensive debugging (hours of cross-thread investigation), the
TCP data path failure was caused by a **one-line omission** in
`rnode-modem-core/src/modem.rs`:

```rust
// BEFORE: TCP data silently dropped
pub fn feed(&mut self, id: u64, bytes: &[u8]) -> Fed {
    let Some((_, session)) = self.sessions.iter_mut().find(...) else {
        return Fed::empty();  // ← session 2 (TCP) never found!
    };
}

// AFTER: auto-create unknown sessions
pub fn feed(&mut self, id: u64, bytes: &[u8]) -> Fed {
    if !self.sessions.iter().any(|(sid, _)| *sid == id) {
        self.sessions.push((id, Session::new()));
    }
    ...
}
```

TCP sessions registered with the outbound routing registry (for reply
delivery) but were never added to the modem's internal frame parser.
`feed()` returned zero replies, making it appear as if cross-thread
communication was broken. It wasn't — the channel worked fine within
the single-thread executor. The select3 handler received TCP data and
called `feed()`, which returned `Fed{replies: 0}` because session 2
wasn't in the parser list.

## Build System

### Environment Variables (Compile-Time)
```bash
rm -f target/riscv32imac-unknown-none-elf/release/c6l-modem
find src ../patches ../../rnode-modem-core/src -name "*.rs" -exec touch {} \;
C6L_WIFI_SSID="YourNetwork" \
C6L_WIFI_PASS="YourPassword" \
C6L_TCP_HOST="192.168.1.161" \
    cargo build --release
# Verify (cargo doesn't rebuild on env-var changes!)
strings target/.../c6l-modem | grep "YourNetwork"
```

### Dependency Stack
- esp-hal 1.1.2 (unstable)
- esp-rtos 0.3.0 (patched)
- esp-radio 0.18.0
- embassy-executor 0.10 / embassy-net 0.9 (patched)
- opt-level 2 for esp-radio, "s" for app

### Patches Applied

**esp-rtos** (`firmware/patches/esp-rtos/`):
1. Executor poll loop: yields when tasks self-wake during poll
2. ThreadFlag::set(): forced yield on flag-set-without-waiter (race fix)
3. Diagnostic counters (RTOS_DIAG)

**embassy-net** (`firmware/patches/embassy-net/`):
1. `Runner::run()`: timer-based re-poll (10ms) — the esp-radio driver
   never calls the runner's waker on packet arrival
2. Accept instrumentation: logs socket state transitions
3. Driver receive tracking

**rnode-modem-core** (`rnode-modem-core/`):
1. `Modem::feed()`: auto-create sessions for unknown IDs (THE fix)

## Hardware Findings

| # | Finding | Resolution |
|---|---------|-----------|
| 1 | esp-radio driver never calls runner's waker | Timer re-poll (10ms) |
| 2 | esp-radio driver drops incoming TCP SYNs | Reverse-connect mode |
| 3 | esp_println deadlocks at interrupt priority | Avoid prints in ISR |
| 4 | logq static must be `static mut` | Fixed |
| 5 | Session IDs from add_session() start at 1 | Runtime USB_SID |
| 6 | Cargo doesn't rebuild on env-var changes | Documented workaround |
| 7 | StaticCell::init() panics on double-init | Direct static registry |
| 8 | select3 cancels in-flight async reads | Dedicated usb_rx_task |
| 9 | embassy-net Runner always self-wakes | Timer re-poll |
| 10 | Modem.feed() drops unregistered sessions | Auto-create (THE fix) |

## Test Suite

```bash
make c6-acceptance   # 16 protocol checks over USB
make c6-stability    # 5 open/close reset cycles
make c6-soak        # 115s continuous connection
make c6-test        # all three
```

## TCP Host Setup

The modem connects OUT to a configured host (reverse-connect). Run a
listener on your laptop:

```bash
nc -l 4990
# Or a proper KISS host using reticulum-rs:
RUST_LOG=info cargo run --example rnode_listen \
    --features "iface-rnode,iface-serial" -- --port /dev/ttyACM1
```

Build with `C6L_TCP_HOST=<laptop-ip>` to set the target.

## Files Modified

- `firmware/c6l-modem/src/` — firmware (5 source files)
- `firmware/c6l-modem/tests/` — acceptance, stability, soak tests
- `firmware/patches/esp-rtos/` — esp-rtos fork
- `firmware/patches/embassy-net/` — embassy-net fork
- `rnode-modem-core/` — protocol core (the critical fix)
- `src/iface/rnode.rs` — host-side (detect validation, reset-on-open)
- `src/iface.rs` — announces_sent counter fix

---

## SPI / Radio Findings (2026-09-15, deep debugging session)

### Bugs found and fixed

1. **TCXO command byte order** — `SetDio3AsTcxoClock` (opcode 0x97)
   parameter order is `voltage[15:8], voltage[7:0], timeout[15:8],
   timeout[7:0]` (voltage FIRST, datasheet Table 11-8). We had timeout
   first, which sent the timeout value (0x0500 = 12800 × 10mV = 128V!)
   as the TCXO voltage. The SX1262 rejected it and went into permanent
   BUSY.

2. **TCXO voltage encoding** — the voltage is in 10 mV steps: 3.0 V →
   `300` (0x012C), not `3000`. The formula `(v * 10.0) as u32 * 100`
   produced 3000 = 30 V. Correct: `(v * 100.0) as u32`.

3. **ESP32-C6 IO_MUX base address** — the IO_MUX peripheral is at
   `0x6009_0000` (from PAC `esp32c6::IO_MUX`), NOT `0x6000_9000`. The
   `gpio[]` register array starts at offset `+0x04` (after `pin_ctrl`),
   so GPIO N's IO_MUX register is at `0x6009_0004 + N*4`.

4. **ESP32-C6 GPIO register offsets** (from PAC RegisterBlock field
   order):
   - `bt_select` at +0x00 (NOT GPIO_OUT!)
   - `out` (GPIO_OUT) at +0x04
   - `out_w1ts` at +0x08, `out_w1tc` at +0x0C
   - `enable` at +0x20, `in_` (GPIO_IN) at +0x3C

5. **ESP32-C6 SPI2 (GPSPI2) register offsets** (from PAC field docs,
   base 0x6008_1000):
   - `USER` at +0x10, `USER1` at +0x14, `USER2` at +0x18
   - `MS_DLEN` at +0x1C, `MISC` at +0x20
   - `DIN_MODE` at +0x24, `DIN_NUM` at +0x28, `DOUT_MODE` at +0x2C
   - `W[0..16]` FIFO at +0x98..0xD8

6. **SPI USER register garbage phases** — the default USER register had
   `USR_DUMMY` (bit 29) and `USR_ADDR` (bit 30) set, and `DOUTDIN`
   (bit 0) clear. This means the SPI inserted dummy cycles and an
   address phase between the opcode and data, garbling all multi-byte
   commands. Fixed by writing:
   ```rust
   (user | (1<<0)) & !((1<<29) | (1<<30) | (1<<31))
   ```

### Current state

- `GetStatus` (single-byte transfer) works — returns valid SX1262
  status 0xD2 (mode 5 = RX, cmd_status 1 = data available).
- All init steps complete without SPI errors.
- BUSY pad (GPIO19) reads HIGH even after a fresh power-cycle. The
  radio still responds to GetStatus, so we bypass BUSY gating.
- The SX1262 does NOT process multi-byte write commands (SetStandby,
  SetRfFrequency, etc.) — the mode never changes from RX.
- Multi-byte reads (IRQ status, buffer) return the status byte 0xD2
  for every byte instead of actual data.
- Meshtastic (ESP-IDF SPI driver + RadioLib) works perfectly on the
  same hardware with the same pins, confirming the hardware is OK.

### Root cause hypothesis

The esp-hal 1.1.2 SPI driver on ESP32-C6 generates multi-byte SPI
transactions differently from ESP-IDF's `spi_master` driver in a way
that the SX1262 does not recognize. The SPI register configuration
looks correct (verified full-duplex, no dummy/addr/command phases,
2 MHz, Mode 0, MSB first), but the actual signal timing or FIFO
handling may differ subtly.

### Next steps

1. Compare SPI signal generation between esp-hal and ESP-IDF at the
   register level (clock gating, FIFO thresholds, `update()` sync).
2. Consider writing a minimal SPI driver using direct PAC register
   access that mirrors ESP-IDF's `spi_master` behavior exactly.
3. File upstream issues: esp-hal (SPI register defaults leave dummy/
   addr phases enabled) and/or the TCXO command byte order bug is ours.

---

## Deep Debugging Session Summary (2026-09-16)

### What was verified working

1. **SPI data path (loopback test)**: Routed MISO to read from GPIO21
   (MOSI pad). Sent [0x1D,0x07,0x40,0x00] and received identical data.
   GPSPI2 FIFO packing confirmed correct (right-aligned big-endian).

2. **IO_MUX direct mode**: SPI pins (20/21/22) use MCU_SEL=0 (IO_MUX
   direct). This bypasses the GPIO matrix entirely. Switching to
   MCU_SEL=1 (GPIO matrix) breaks MISO (reads 0xFF).

3. **SPI configuration**: Mode 0, 2 MHz, 50% duty cycle, MSB first,
   full-duplex (DOUTDIN=1), no dummy/address/command phases.

4. **GPIO matrix routing** (when active): SCK=signal 63 (FSPICLK),
   MOSI=signal 65 (FSPID). Verified via FUNC_OUT_SEL_CFG reads.

5. **SX1262 responds**: CS LOW → MISO carries 0xF6 (status byte).
   CS HIGH → MISO reads 0xFF (floating).

### What doesn't work

- SX1262 does not process multi-byte SPI commands
- Status byte stays at 0xF6 (bits [5:3]=110=TX mode from Meshtastic)
- All read commands return status byte echo (not actual data)
- Radio never enters RX mode (our SetRx command not processed)
- No LoRa packet reception

### Status byte format (corrected)

From SX1262 datasheet section 13.3:
- Bits [7:6]: reserved (11)
- Bits [5:3]: circuit mode (2=STBY_RC, 3=STBY_XOSC, 4=FS, 5=RX, 6=TX)
- Bits [2:1]: command status (1=data available, 2=in progress, 3=timeout)
- Bit [0]: reserved (0)

Common error: mode is at bits [5:3], NOT [6:4].

### Root cause (unknown)

Despite verified-correct SPI data reaching the SX1262's MOSI pin,
the chip does not recognize or process our commands. Meshtastic
(ESP-IDF spi_master + RadioLib) works on identical hardware.

Possible causes to investigate with an oscilloscope:
1. Clock edge timing (sample point vs. data valid window)
2. CS setup/hold timing relative to first/last clock edge
3. Signal rise/fall times and overshoot
4. Ground bounce or crosstalk between SPI lines

### Recommended next steps

1. **Oscilloscope comparison**: Capture SPI waveforms (SCK, MOSI, CS)
   from both our firmware and Meshtastic running on the same board.
   Compare timing, voltage levels, and edge characteristics.

2. **Try esp-idf-sys**: Use the `esp-idf-sys` crate to call ESP-IDF's
   `spi_master` driver directly from Rust, bypassing both esp-hal and
   our raw driver. This would use the exact same driver as Meshtastic.

3. **Port RadioLib**: Compile RadioLib's SX126x driver as a static
   library and link it into our firmware, using its proven SPI wrapper.

4. **Alternative: use Arduino framework**: Build the firmware with
   the Arduino framework (like Meshtastic) instead of esp-hal, trading
   some control for proven SPI compatibility.

---

## ROOT CAUSE FOUND: SSD1306 SPI Bus Contention (2026-09-16)

### The problem

The M5Stack Unit C6L has TWO devices on the same SPI bus:
- SX1262 LoRa radio (CS=GPIO23)
- SSD1306 OLED display (CS=GPIO6, DC=GPIO18, RESET=GPIO15)

If GPIO6 (OLED CS) is not driven HIGH, the SSD1306 is SELECTED and
drives the shared MISO line. This causes bus contention with the
SX1262's MISO output, corrupting all SPI reads AND writes.

### The fix

Before any SPI communication with the SX1262, configure the SSD1306
control pins to fully disable the OLED:
```rust
// GPIO 6 (CS) = OUTPUT HIGH (deselect)
// GPIO 18 (DC) = OUTPUT HIGH
// GPIO 15 (RESET) = OUTPUT LOW (hold in reset)
```

### Evidence

Before fix: MISO reads 0xF6 (SSD1306 data, NOT valid SX1262 status)
After fix: MISO reads 0xD2 (valid SX1262 status: mode=5 RX, RSSI=-105)

The 0xF6 was the SSD1306's output on MISO, not the SX1262. This
misled ALL previous debugging efforts.

### Remaining issue

SX1262 write commands still appear not to be processed (radio stays
in Meshtastic's RX mode). Reads work (valid status/RSSI). The radio
may be in a stuck BUSY state from the earlier 30V TCXO command.
