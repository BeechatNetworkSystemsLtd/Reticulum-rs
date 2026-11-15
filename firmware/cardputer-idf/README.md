# Cardputer Advanced Reticulum + LXMF chat firmware

Standalone Reticulum + LXMF chat firmware for the M5Stack Cardputer Advanced
(ESP32-S3, 8 MB flash, no PSRAM). Cloned from the `c6l-modem-idf` KISS modem
base; the chat stack reaches the radio through an in-process KISS session.

## Hardware

| Component | Wiring / configuration |
| --- | --- |
| SX1262 (Cap LoRa868 module) | SPI2: SCK GPIO40, MISO GPIO39, MOSI GPIO14, CS GPIO5; RST GPIO3, DIO1 GPIO4, BUSY GPIO6 |
| Radio control | DIO2 controls the RF switch; DIO3 supplies the 1.8 V TCXO (`0x02`) |
| Radio defaults (EU868) | 869.525 MHz, 125 kHz bandwidth, SF9, CR5, 22 dBm; 10% long-term airtime lock |
| PI4IOE5V6408 module gate | I2C `0x43`; writes `0x03=0x01`, `0x07=0x00`, `0x05=0x01` |
| TCA8418 keyboard | I2C `0x34`, 7×8 matrix; interrupt GPIO11 unused (polling) |
| ST7789 LCD | 240×135 landscape, SPI3 @ 40 MHz: SCK GPIO36, MOSI GPIO35, CS GPIO37, DC GPIO34, RST GPIO33; backlight GPIO38 (active high) |

The module gate is probed on Wire1 (SDA GPIO2 / SCL GPIO1), then Wire
(SDA GPIO8 / SCL GPIO9). The keyboard also uses dual-bus probing. Both
probes log which bus ACKed.

SX1262 notes: BUSY (GPIO6) is wired and polled before commands — the
earlier fixed-delay flow lost commands issued while the chip was busy
("TX TIMEOUT, no TxDone"). The esp-idf-hal
`SpiDeviceDriver::new_single` argument order is `(host, sclk,
sdo = MOSI, sdi = MISO, cs, …)`; passing this board's MISO(39) as
`sdo` and MOSI(14) as `sdi` swaps the data directions — register
reads returned `0x00` and there was no functioning RF until fixed.

The panel is a native 135×240 portrait IPS at offset (52, 40) inside
the ST7789's 240×320 GRAM, mounted landscape: drive it as 135×240
with a 90° rotation (the driver derives window offset (40, 53)) and
colour inversion ON — without INVON black renders white.

The EU868 radio config targets this unit's Cap LoRa868 variant:
869.525 MHz sits in the 869.4–869.65 MHz ERC/REC 70-03 sub-band, and
the 10% long-term airtime lock (`lt_alock`) is set so the modem
refuses TX beyond the sub-band's duty-cycle allowance. National
rules and antenna/ERP limits still apply — verify for your
regulator and hardware.

## Build

From the repository root, using the configured ESP toolchain on this host:

```sh
cd firmware/cardputer-idf
. /home/lio/export-esp.sh
export LD_LIBRARY_PATH="/home/lio/Android/Sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/lib:$LD_LIBRARY_PATH"
cargo +esp build --release
```

The crate's `.cargo/config.toml` also sets `LD_LIBRARY_PATH` and
`LIBCLANG_PATH` in `[env]`. The Android NDK library directory provides
`libxml2.so.2` for esp-clang; these paths are host-specific.

## Flash and run

From the firmware directory after building:

```sh
sudo ~/.cargo/bin/espflash flash --port /dev/ttyACM2 target/xtensa-esp32s3-espidf/release/cardputer-idf
sudo ~/.cargo/bin/espflash monitor --port /dev/ttyACM2
```

If espflash cannot attach, physically unplug and reconnect USB, then retry.
The firmware runs the chat stack on the device and announces every 600 seconds.

Equivalent targets from the repository root:

```sh
make card-build
make card-flash
make card-monitor
# Override the serial device when needed:
make card-monitor PORT=/dev/ttyACM2
```

`card-flash` builds before flashing and passes
`--partition-table firmware/cardputer-idf/partitions.csv` explicitly
(run from the repo root, espflash does not discover the nested
`espflash.toml`); `card-monitor` only opens the monitor.

## Chat UI

240×135, ASCII `FONT_8X13` (29 columns; 7 message/peer rows between
header and compose/status rows), full redraw per frame over the 40 MHz
SPI — no framebuffer.

- Peer list: `;`/`.` move the selection (the arrow-printed keys work
  without Fn here), `Enter` opens the conversation, `` ` `` (Esc)
  sends a re-announce.
- Chat screen: type to compose (240 chars max), `Enter` sends (empty
  messages are not sent), `Fn` + `` ` `` (Esc) returns to the peer
  list. `Fn` + `,`/`;`/`.`/`/` produce Left/Up/Down/Right anywhere.
- Chat history is held in RAM only — it is lost on reboot; identity
  persists (littlefs `/reticulum`, NVS fallback).

## Architecture

```text
UI thread (keyboard + LCD)
        ↕ chat actions / events
Chat thread: Tokio current_thread runtime
        Reticulum transport + LXMF router
        ↕ RnodeInterface::from_link
        ↕ RnodeLink::from_reader_writer
        In-process KISS session
        ↕ modem bus
Modem thread → SX1262 → LoRa
```

Identity and littlefs-backed storage live at `/reticulum`, on the `storage`
partition. The runtime lives in its own thread rather than the main task.

## RAM budget

There is no PSRAM; retain the small queues and stack-allocation order:

- `TransportConfig.channel_capacity = 2`,
  `TransportConfig.enable_resource_watchdog = false` (the watchdog task's
  ~2.5 KB future would OOM its spawn; without it, resource transfer
  retries/timeouts are unavailable — this is a short-text chat image,
  not a large-attachment node).
- Transport inbound queue lengths: Data 64, Announce 32, PathRequest 32
  (IngressLimited keeps the default 8).
- `TransportConfig.announce_cache_capacity = 2` — the default 8192
  retains a full packet buffer per distinct announce; unbounded for
  this heap (a 2048-byte allocation failed in announce validate during
  the smoke run).
- `TransportConfig.phy_cache_capacity = 0` — the default 512-sample
  RSSI/SNR/quality history costs ~60 KiB (3 × 512 samples); the UI
  never queries it. Aggregate interface stats still accumulate.
- `RouterConfig.event_channel_capacity = 4`.
- Thread stacks: chat 96 KiB (measured ~47 KiB peak with real LXMF
  delivery — calibrated to ~2×), modem 36 KiB, UI 20 KiB; the watchdog,
  helper pump and headless-event threads run 2–4 KiB. The tokio
  blocking pool is capped at 1 thread with an 8 KiB stack.
- Chat transport/router initialization is gated until all thread stacks have
  been allocated. Starting that heap-heavy initialization earlier fragments
  the heap and prevents later stack allocations.

## Known issues and constraints

- Tokio is pinned to `=1.44.2`: the 1.5x series crashes at runtime on
  `xtensa-espidf`. Keep the pin when changing dependencies.
- Tokio's eventfd backend needs ESP-IDF VFS registration before runtime
  creation. The chat thread registers eventfd with `max_fds = 4`; without
  registration, runtime creation fails with `Permission denied`.
- No BM8563 RTC was found on this unit: the clock is unsynchronized
  after every reboot, so LXMF message timestamps are unreliable (they
  land near the epoch). A watchdog thread reboots the device if the
  modem loop stalls.
- Built with `default-features = false`: the `bz2` codec is not
  compiled in, so resource transfers cannot carry compressed payloads
  and the delivery announce does not advertise compression support.
