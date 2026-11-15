
---

## 2026-09-16: BIDIRECTIONAL LoRa ACHIEVED (C6L <-> RNode)

### Summary
The ESP-IDF firmware now exchanges LoRa packets in **both directions** with a
Heltec RNode (fw 1.86): RNode→C6L `hello` ×5 (RSSI −40 dBm, SNR +40 dB) and
C6L→RNode `HELLO`.

### Why it took so long — the full root-cause chain

1. **Wrong KISS command IDs** — RNode's command set (Framing.h / RNS):
   `0x01` frequency, `0x02` bandwidth, `0x03` txpower, `0x04` SF, `0x05` CR,
   `0x06` radio state, `0x08` detect, `0x00` data. Earlier tests used
   0x05/0x06/0x07/0x08/0x09, which configure CR/radio-state/lock/detect/
   implicit instead — the RNode never actually changed frequency/BW/SF.
2. **Wrong device** — USB ports swapped: `/dev/ttyUSB0` is rfsight's
   rid_sniffer node (does not speak RNode KISS); the RNode is
   `/dev/ttyUSB1`. Verify with `CMD_FW_VERSION (0x50 0xFF)` before testing.
3. **Radio never turned on** — RNode keeps its radio off until the host
   sends `CMD_RADIO_STATE = 0x01` after the detect burst + config frames
   (mirror of `RnodeRadioConfig::configuration_frames(RADIO_STATE_ON)` in
   `src/iface/rnode.rs`).
4. **Blind register writes** — regs `0x0736` (IQ errata 15.4) and `0x0889`
   (modem sensitivity) must be **read-modify-write**. Blind `0x04` writes
   clobber other bits: constant −73 dBm RSSI floor, no preamble detection.
5. **Sync word** — RNode hardcodes `[0x14, 0x24]` in `sx126x::setSyncWord()`
   (writes regs 0x0740/0x0741 literally). NOT the RadioLib
   `setSyncWord(0x12)` encoding `[0x10, 0x20]`.
6. **Full RNode init order** (sx126x.cpp `begin()`): calibrate(0x7F) →
   image-cal(863-870 → `0xD7 0xDB`) → TCXO **3.0 V** for C6L (variant.h;
   Heltec V3 uses 3.3 V) → packet type → frequency → sync word →
   DIO2-as-RF-switch → mod params → `0x0889 |= 0x04` → 9-byte packet
   params (preamble **18**, explicit, len 0xFF, CRC **on**, std IQ) →
   `0x0736 |= 0x04` **after every SetPacketParams** (the command resets
   the register) → buffer base → SetRegulatorMode(DCDC) → IRQ mask →
   SetRx.
7. **RNode wire format** — every RNode LoRa packet is
   `[header(seq<<4 | flags), payload…]`; `receive_callback` reads the
   first byte as header/split-marker. Raw payloads get misparsed.
8. **TX length** — explicit-header TX takes the payload length from the
   *last* SetPacketParams; leaving 0xFF transmits a 255-byte packet that
   fails CRC at the receiver. Set the real length before SetTx.
9. **SetTx(0x000000)** — RNode's single-shot mode. With a 1 s timeout
   parameter the chip refused to enter TX at all (mode stuck 2/STBY_RC,
   no IRQ). Use `0x83 00 00 00 00`.
10. **FIFO mechanics** — `ReadBuffer` data at buf[3] (opcode, addr,
    dummy, data…); `GetRxBufferStatus` len@buf[3] offset@buf[4]; in
    continuous RX the write pointer advances per packet, so issue
    `SetBufferBaseAddress(0,0)` after each read to prevent accumulation.
11. **LNA boost disabled** — `0x08AC = 0x96` (RNode uses it) produced a
    constant −73 dBm floor on the C6L; board-level noise from the
    ESP32-C6. Leave at default.
12. **Watchdog** — the TX-poll loop must `vTaskDelay(1)` (not
    `yield_now()`); otherwise the thread is killed and USB drops.

### Environment gotchas
- The rfsight rid_sniffer (ttyUSB0) sits centimeters away with an SX1262
  scanning 868 MHz with rotating configs — its near-field RF blankets the
  whole 868 band at ≈ −73 dBm. At 915 MHz the C6L floor is a clean −95 dBm,
  confirming the source. Keep the boards apart or test out-of-band.
- C6L re-enumerates (ttyACM1 ↔ ttyACM2) after a crash; check `ls /dev/ttyACM*`.
- GetRssiInst reads: data byte at buf[2]; RSSI = −byte/2.

### Working SPI conventions (ESP-IDF spi_master on C6L)
- CS (GPIO23) is a plain GPIO; hold LOW across the whole command.
- Byte-by-byte `transfer_in_place` per byte works for BOTH reads and
  writes (RNode's `executeOpcode` does exactly this); multi-byte writes
  also work for most commands but SetTx was only verified single-shot
  with all-byte-by-byte framing.

### Round-trip test
`tests/lora_roundtrip.py [freq_hz]` — configures the RNode on ttyUSB1,
prints C6L RX on ttyACM2, expects `hello` ×5 and the RNode receiving
`HELLO`.

---

## 2026-09-17 (later): rnsd integration + RX loss analysis

### Working
- rnode-modem-core: RNode 0xFF-query semantics (RNS validateRadioState passes)
- `delay_ms` tick conversion + reply-before-op flush (RNS 250ms validation window)
- rnsd brings the C6L up on both nodes; announces B->A + path discovery over LoRa
- Full app round trip proven by replay: rnsd's exact 131-byte probe frame,
  replayed through the RNode, reached the responder over the air and the
  proof returned ("Valid reply", responder `*** RECEIVED`)
- KISS acceptance 10/10 incl. 212-byte payloads

### The remaining blocker: ~50% per-packet RX loss on the C6L
Measured with rnprobe x8: A's RNode transmits every probe (airtime
verified) but the C6L delivers only ~half to rnsd. Pattern is roughly
alternating — consistent with the modem being deaf for a window after
its own TX (proofs), though slower announces only marginally improved
it. With single-shot probes that means "timed out"; LXMF's transport
retries would eventually deliver, but multi-packet link handshakes
(rnx) don't complete.

Suspected causes to investigate next (in order):
1. RX processing latency: byte-by-byte SPI FIFO reads (~131 bytes =
   ~5ms of bit-banged CS-held transfers) + 10ms poll cadence may
   collide with the next packet's preamble in busier traffic.
   -> move to multi-byte FIFO reads (works for WriteBuffer) or
      DIO1-driven processing.
2. The post-TX recovery: currently standby + 2x start_rx with 20/50ms
   settles — improved 2/8 -> 3/8 but not fixed.
3. RF switch (DIO2) settling after PA ramp-down.

### Recovery procedure (hardware-verified)
The SX1262 occasionally wedges (no boot console, no KISS response).
ESP32 resets do NOT clear it (no NRESET pin on the C6L). Recovery:
1. Unplug/replug USB (full power cycle) — usually enough.
2. If not: flash Meshtastic, let it boot 5s, re-flash our firmware.
If espflash cannot attach after Meshtastic: esptool elf2image the ELF
and write bootloader/partition-table/app at 0x0/0x8000/0x10000.

---

## 2026-09-17 (evening): codex-assisted isolation — modem exonerated

Codex CLI review of the driver flagged two datasheet violations, both fixed:
1. **Post-RxDone reconfiguration removed**: RX-continuous mode AUTO-REARMS
   after each packet; our `start_rx()` after every reception raced the
   modem and dropped packets. Now: SetBufferBaseAddress(0,0) +
   ClearIrqStatus(RxDone only).
2. **Verified post-TX RX entry**: SetRx can be silently rejected while
   the chip is busy — now GetStatus-checked (mode==5) with retry.
   (Note: an attempted ReadBuffer-with-returned-offset change REGRESSED
   payload alignment — the byte-by-byte framing does not expose the
   offset where expected; reverted to proven read-from-0.)

### The complete isolation matrix (all same radios, same config)
| Who drives the RNode | Payload | C6L reception |
|---|---|---|
| test script, 4-5s spacing | 6-13B | 10/10 |
| test script, 0.6s spacing | 6B / 125B | 19/20 |
| test script, rnsd's captured frames | 132-135B | **5/5** |
| **rnsd (live)** | its own 131B | **~40-50%** |
| rnsd (live, RNode freshly KISS-reset) | same | ~40% |

The alternating timeout/valid pattern persists across every C6L
firmware change AND RNode resets — the loss is exclusively correlated
with rnsd-a's live process driving the Heltec (its readLoop + flow-
control timing vs RNode fw 1.86's TX queue/CSMA). The C6L modem
itself receives essentially 100% of what the RNode actually puts on
the air under any other driver.

### Next steps (need hardware/tools beyond this session)
- Logic analyzer on the Heltec's serial during live-rnsd probes vs
  scripted replays (compare CMD_READY timing + TX patterns)
- Or try a different RNode firmware version on the Heltec
- Or an SDR capture at 867.5 during both driving modes

## FINAL RESULT: 100% packet delivery (2026-09-17)

After the FIFO offset fixes, the full rnsd round-trip works flawlessly:
```
rnprobe → rnsd-a → Heltec RNode → LoRa → C6L modem → rnsd-b → responder
         ← proof ← C6L TX ← LoRa ← Heltec RNode ← rnsd-a ← rnprobe
Sent 8, received 8, packet loss 0.0%
```

The three bugs (SetBufferBaseAddress corruption, wrong length byte, 
missing offset in ReadBuffer) accounted for ALL the packet loss.

---

## 2026-09-18: WiFi-TCP + LoRa bridge (BRIDGE_PLAN)

Landed the BRIDGE_PLAN modules: `src/wifi.rs` (STA bring-up + reconnect),
`src/tcp_bridge.rs` (listener + sessions), `src/bus.rs` (session bus),
`src/console.rs` (`clog!`, KISS-safe logging). All module logging goes
through `clog!`, which silences after the first FEND — including the
`wifi: got ip` line, so read the IP at boot (or from the router lease
table) before starting KISS traffic.

### Thread layout (as built, stack sizes from code)
| Thread | Stack | Owns |
|---|---|---|
| modem | 64 KB | Radio/SX1262 SPI, USB-Serial-JTAG, `Modem` core, radio ops |
| watchdog | 16 KB | `LOOP_COUNT` stall detect → `esp_restart()` (pre-existing) |
| wifi bring-up | 16 KB | esp_wifi STA init, 50 ms poll loop, reconnect |
| tcp-accept | 16 KB | `TcpListener` 0.0.0.0:7633, spawns sessions |
| tcp-session × ≤2 | 12 KB each | one `TcpStream`, BOTH directions (see Deviations) |

### Session routing (bus.rs)
- Session id 1 = `USB_SESSION`, internal to the modem thread, never on
  the bus; TCP sessions get ids ≥ 2 (bus `next_id` starts at 2).
- Inbound: `InMsg::Data(id, bytes)` / `InMsg::Leave(id)` on a bounded
  sync channel (256 deep); `send_in` blocks when full — that IS the TCP
  backpressure point. `SessionGuard` drop unregisters the session and
  sends `Leave` → modem drops that session's parser state.
- Outbound: per-session bounded channel (64 frames); `send_out` and
  `fan_out` use `try_send` — a full queue drops the frame rather than
  ever blocking the modem thread.
- Routing rules on the modem thread (the wiring contract):
  - `Fed.to_sender` → originating session only (id 1 → `usb_write_direct`,
    bus id → `bus.send_out(id)`).
  - `Fed.to_others` → every OTHER session: other TCP sessions via
    `bus.fan_out(except=origin)`; USB via `tx_buf` only when other
    sessions exist (echoing a host's own data violates half-duplex).
  - `modem.radio_rx(data)` returns ONE frame per session, aligned with
    `modem.session_ids()` — ZIP frames with ids (id 1 → USB, others →
    `send_out`), never concatenate. Equivalent view: USB copy + fan-out
    to every TCP session.
  - `Fed.ops` → radio on the modem thread, unchanged (`apply_op`).
- `Modem::feed` auto-creates parser state for unseen ids, so TCP
  sessions need no separate registration handshake with the modem.

### WiFi (wifi.rs)
- Raw `esp-idf-sys` only (esp-idf-svc conflicts with esp-idf-hal 0.47):
  `nvs_flash_init` (erase + retry on NO_FREE_PAGES/NEW_VERSION_FOUND) →
  `esp_netif_init` → `esp_event_loop_create_default` →
  `esp_netif_create_default_wifi_sta` → `esp_wifi_init(...)` →
  register `WIFI_EVENT`(ANY) + `IP_EVENT`(GOT_IP) BEFORE start →
  `set_mode(STA)` → `set_config` → `esp_wifi_start`; `esp_wifi_connect()`
  fires from the poll loop once STA_START latches.
- `esp_wifi_init` takes a FIELD-BY-FIELD `wifi_init_config_t` literal of
  `WIFI_INIT_CONFIG_DEFAULT()` — the bindings' `Default` impl is
  bindgen ZERO-INIT (osi_funcs=NULL, magic=0, guaranteed init failure).
  Reviewer-verified values incl. `WIFI_INIT_CONFIG_MAGIC`, plus the
  plan's deliberate `ampdu_rx_enable=0` heap mitigation.
- `wifi::start()` BLOCKS main() until the `wifi: got ip` line actually
  printed or ~15 s elapse (an early host FEND would silence it
  otherwise); the watchdog is therefore spawned only after WiFi
  bring-up — `LOOP_COUNT` stays 0 during the wait and the WDT reboots
  on a stalled count.
- KISS console safety covers BOTH print stacks: `clog!` gates Rust
  println, and `mark_kiss()` also calls `esp_log_level_set("*", NONE)`
  on the first FEND — ESP-IDF wifi/netif ESP_LOGx shares the same
  USB-Serial-JTAG wire and would corrupt the stream identically.
- Event handlers run on the esp_event task and touch ONLY atomics
  (link state, disconnect count, reason, IP); the 16 KB thread polls
  those every 50 ms and makes all `esp_wifi_*` calls — never from
  handler context.
- Credentials are BUILD-time: `C6L_WIFI_SSID` / `C6L_WIFI_PASSWORD` via
  `option_env!`; unset ⇒ WiFi stays off (one `clog!` note). GOTCHA:
  cargo does NOT rebuild on env-var change — `touch src/main.rs`, then
  verify with `strings` on the binary. Empty password ⇒ open network
  (authmode threshold OPEN), else WPA2_PSK; SSID/password truncated to
  32/64 bytes.
- Reconnect (Phase 4): on disconnect, log the 802.11 reason code, wait
  1 s doubling to a 30 s cap, then `esp_wifi_connect()`; backoff resets
  to 1 s on a fresh GOT_IP and the address is re-logged after each
  reconnect.
- Free heap is logged before/after bring-up (plan risk #1: WiFi+lwIP
  eats ~70-120 KB of the 512 KB C6). Bring-up failure is survivable:
  `clog!` + thread exit; USB/LoRa keep running, only TCP is unreachable.
- lwIP quirk: `esp_ip4_addr` stores octet1 in the LSB — byte-swap on
  store, `to_be_bytes()` on read.

### TCP listener (tcp_bridge.rs)
- `std::net::TcpListener` on 0.0.0.0:7633 (BSD sockets over lwIP);
  binds at thread start — before DHCP is fine, clients simply can't
  connect until an IP exists — and retries every 5 s on bind failure.
  Accept errors back off 100 ms; the accept thread never dies.
- `TCP_NODELAY` on every accepted stream (KISS is tiny frames); failure
  is logged, not fatal.
- Max 2 concurrent sessions; a 3rd client is accepted, logged
  `[tcp] busy`, then `shutdown(Both)` immediately — a polite reject,
  never a half-open socket. The count is incremented only on the accept
  thread (serialized check-then-add) and decremented by an RAII slot.
- Per session: a 10 ms `SO_RCVTIMEO` read poll doubles as the outbound
  drain cadence (`try_recv` → `write_all` of pre-framed KISS); worst
  case +10 ms latency, harmless next to RNS's 250 ms config-echo window.
  A 30 s `SO_SNDTIMEO` is best-effort — lwIP may not support it, falling
  back to blocking writes (the intended backpressure). WouldBlock /
  TimedOut / Interrupted read errors are poll ticks, not failures.
- The KISS parser does NOT live here: raw bytes go to `bus.send_in`,
  outbound frames arrive pre-framed. Every exit path (peer close,
  read/write error, channel disconnect) → `shutdown(Both)` + slot
  decrement + guard drop (`InMsg::Leave`).

### rnsd / clients
- `demo/c6l-tcp-rnsd.config`: `RNodeInterface` with
  `port = tcp://<c6l-ip>` — NOT TCPClientInterface (the C6L IS the
  RNode, not a transport hop). The URI must carry NO `:port` suffix:
  RNS's RNodeInterface treats the whole post-`tcp://` string as a
  hostname and hardcodes `TCPConnection.TARGET_PORT = 7633` (RNS 1.5.4,
  RNodeInterface.py). Bench-verified: `tcp://ip:4990` → gaierror
  "Name or service not known". The bridge therefore listens on 7633.
  Update the IP when the DHCP lease changes (or pin it in the router).
- `demo/README.md` — build/flash with baked-in credentials + run steps.
- `tests/tcp_kiss_acceptance.py <c6l_ip> [freq_hz]` — the same 10-check
  acceptance flow as the USB test, over TCP; the Heltec RNode stays on
  /dev/ttyUSB1 for the over-the-air leg. No DTR/RTS reset exists over
  TCP: each connection is a fresh session with fresh parser state.

### Deviations from BRIDGE_PLAN (as built)
- ONE 12 KB thread per session owning both directions — not a
  reader/writer pair, and 4 KB over plan budget. Reasons: `SessionGuard`'s
  `Drop` must run exactly once (a separate writer parked in `recv()`
  could never be woken by the reader's exit — the stuck-session bug);
  and 8 KB + 1 KB read buf + error formatting was stack-tight on
  ESP-IDF std::net (overflow = silent reboot). The plan's Phase-2
  wording ("dedicated reader thread, KISS parser") is doubly superseded:
  parsing stays on the modem thread, session threads ship raw bytes.
- Listener binds at thread start, not "after DHCP" (equivalent given
  the 5 s retry).
- Watchdog thread (16 KB) is pre-existing and absent from the plan's
  thread table.
- `src/main.rs` integration landed after this entry was drafted:
  `wifi::start()` runs before the modem thread (IP prints pre-FEND),
  `Bus::new` + `in_rx` drain (32 msgs/tick cap) feed TCP bytes into the
  same `feed_session` path as USB, the to_sender/to_others/radio_rx-zip
  routing above is in place, and the local `SAW_KISS` static was
  replaced by `console::mark_kiss()` on first FEND from ANY link.
  (Written mid-integration; updated to the landed state.)
- Port 7633, not the plan's 4990 — see "rnsd / clients" above: stock
  RNS cannot express a non-7633 target port at all.
- `usb_serial_jtag_driver_install` moved BEFORE `wifi::start()` in
  `main()`. Bench finding: with the driver installed only after the
  blocking DHCP wait, nothing drained the USB-JTAG RX FIFO during the
  WiFi window — host writes stalled in write() (CDC-ACM backpressure)
  and the USB acceptance test hung before its first assertion. With
  early install the driver's ISR drains RX into the 2048 B ring buffer
  continuously; early bytes are consumed when the modem loop starts.

### Verification status
- DONE: `cargo +esp check` clean across all bridge modules.
- BENCH 2026-09-18 (codex + orchestrator runs, WiFi at 192.168.1.233):
  - `tests/kiss_modem_acceptance.py` — **10/10 PASS** over USB with
    WiFi active (was FAIL: host writes stalled during the DHCP window;
    fixed by installing the USB driver before `wifi::start()`; test now
    probe-polls KISS readiness instead of a fixed settle or log line).
  - `tests/tcp_kiss_acceptance.py` — **10/10 PASS** over
    `tcp://192.168.1.233:7633`, incl. both LoRa directions.
  - `rnprobe` — **8/8, 0.0% loss** (~1.5 s RTT, RSSI -50 dBm) over the
    real product path: rnsd `RNodeInterface` with `port =
    tcp://192.168.1.233` (port-less URI → RNS's hardcoded 7633) → C6L →
    LoRa ↔ Heltec → rnsd-a → responder. Interface reported
    "configured and powered up".
  - Dual-link concurrency — PASS (codex): interleaved USB+TCP detects,
    USB→TCP and TCP→USB fan-out exact payloads, 2nd TCP client OK, 3rd
    politely rejected (EOF) while existing links stayed responsive.
  - Boot heap — PASS: ~51 KB consumed by WiFi+lwIP (367540 → 316844 B).
  - `rnprobe` (first attempt) — FAIL then FIXED: rnsd could not reach
    port 4990 (RNS hardcodes 7633, no URI port parsing). Bridge moved
    to 7633; config updated to `tcp://<ip>` without port.
- PHONE (Sideband 2.1.0 on Android, same WLAN) — **PASS** 2026-09-18:
  - Hardware → RNode → "Connect using WiFi" + hostname `192.168.1.233`
    (Sideband hardcodes TCP 7633, no port field — matches the bridge).
  - Radio params 867.5 MHz / 125 kHz / 14 dBm / SF9 / CR5 set in-app.
  - `Reticulum Status` shows `RNodeInterface[RNodeInterface] Up`,
    MTU 508, 1.46 kbps — KISS detect + radio config exchanged over TCP.
  - Phone → air: in-app announce reached rnsd-a (Heltec) and was
    rebroadcast at hop 1 — path Sideband → WiFi → C6L → SX1262 → Heltec.
  - Air → phone: laptop `lxmf.delivery` announce via Heltec → LoRa →
    C6L → TCP appeared in Sideband's Announce Stream; interface rx
    counter advanced 0 → 1.12 KB.
- PENDING:
  1. WiFi drop/reconnect: bounded backoff observed in the log
     (1→2→4→8→16 s, correct) but full recovery-after-flap needs the AP
     physically bounced — no safe remote way.
- KNOWN COSMETIC: `clog!("radio up")` is eaten by the USB-JTAG TX path
  (emitted, never reaches the wire — modem verifiably up via KISS).
  A post-print drain delay was added; if it still vanishes, harmless.

## 2026-09-18 (late): split-packet bug found + fixed via LXMF convo

Real Sideband↔laptop LXMF conversation exposed that EVERY >254 B
frame failed while singles worked in both directions. Root causes
(three, all in the firmware's radio layer):

1. **TX chunk-1 abort (the killer)** — `transmit()` waited for TxDone
   with `150 × delay_ms(10)` — but `delay_ms` uses `vTaskDelay(1)`
   at `CONFIG_FREERTOS_HZ=100`, i.e. "until the next tick" = 0–10 ms,
   ~5 ms average → real wait ≈0.75 s. A 255 B chunk at SF9/BW125
   needs ~1.29 s airtime, so the wait expired mid-TX and the NEXT
   chunk's `SetStandby` guillotined the in-flight packet → Heltec saw
   an undecodable burst ("interference at -51 dBm"). Singles survived
   because nothing aborts their TX — the chip finishes autonomously.
   Fix: real-clock deadline `airtime_ms(len)*3/2 + 200` via
   `esp_timer_get_time()`; `airtime_ms()` implements the Semtech
   formula from `last_params` (SF/BW/CR/LDRO aware).
2. **RX 240-byte truncation** — `poll_rx` read `len.min(240)` bytes;
   a full split chunk is 255 B on the wire → last 15 B silently lost.
   Now reads the full packet.
3. **No RX reassembly** — each split chunk was fanned out as its own
   KISS frame (header stripped, flag ignored); hosts dropped both
   fragments. `poll_rx` now keeps `pending_split`/`pending_seq` and
   reassembles with stock semantics (same seq completes, non-split or
   new seq discards a pending chunk).
4. Bonus fix: TX payloads >508 B would have made chunk 2 overflow the
   255 B packet limit (`total as u8` wrapped) — now capped at 2×CHUNK.

Verified end-to-end with the real phone: laptop→phone split message
"second long laptop message..." received in 5 s; phone→laptop
"long phone reply after the split fix..." State: Delivered.

Test-suite bugs found while adding coverage:
- `tests/tcp_kiss_acceptance.py` and `kiss_modem_acceptance.py` both
  had TFEND/TFESC swapped AND unescape appending the transposed byte
  instead of the original (FEND→DB DD instead of DB DC; DB DC→0xDC
  instead of 0xC0). Harmless until payloads contained 0xC0/0xDB —
  the new 300 B split test does (deliberately). Both fixed to
  standard KISS.
- New checks 5+6 in tcp_kiss_acceptance.py: 300 B byte-exact
  round-trip through split/reassembly in both directions.
  Result: **12/12 PASS**.

---

## 2026-09-28: HEAD rebuilt, re-flashed, all gates re-verified

The bench flash turned out to be `v0.1.0-271-ga46954b-dirty` (built from a
dirty tree before d8bffd4 committed it). Rebuilt HEAD clean, recovered the
build-time credentials, re-flashed, and re-ran every gate.

### Findings
1. **esp-println eats console lines by design** — its USB-JTAG printer
   latches `TIMED_OUT` after one full-FIFO timeout and silently DROPS every
   later write that arrives while the FIFO is full again (esp-println 0.13
   `serial_jtag_printer`). This is the true root cause of the "radio up
   never reaches the wire" cosmetic AND of the missing `wifi: disconnected
   (reason N)` lines during the boot/wifi ESP_LOGx flood. Fixes:
   `radio up` now goes through `usb_write_direct` (the proven KISS TX
   path, retries per byte), and the disconnect-reason diagnostic does the
   same, gated on `console::may_log()`.
2. **rx_ba_win must be > 0 when ampdu_rx_enable=1** — the driver rejects
   the whole `esp_wifi_init` ("E wifi:rx ba window 0 error") and WiFi
   never comes up. wifi.rs now mirrors sdkconfig exactly
   (ampdu_rx_enable=1, rx_ba_win=6); the plan's 0/0 heap mitigation also
   worked on the bench but saved only ~5 KB of the ~300 KB free — not
   worth a deviation from the C defaults.
3. **Credentials recovery** — the PSK is not stored anywhere on the host.
   Recovered it from the old flash dump: `esptool read_flash 0x10000`,
   then disassemble the app image, find the `lui/addi + c.li 0xe` pair
   in `wifi::start` that materializes the SSID (&str ptr+len) — the
   adjacent pair is the password (ptr, len). NOTE: naive `strings`
   extraction was WRONG (grabbed 2 junk bytes before the real literal);
   always take the code-referenced (ptr, len). Password NOT recorded here.
4. **The env-var rebuild trap is real and bit this session**: changing
   only `C6L_WIFI_*` does not rebuild (option_env! is not tracked);
   `touch src/main.rs` before `cargo +esp build`, and verify with
   `strings` on the ELF. A stale-credential flash looks exactly like a
   WiFi regression (reason 15 = 4WAY_HANDSHAKE_TIMEOUT loop).
5. `state: run -> init (fc0)` in the net80211 log = the supplicant's
   4-way handshake timing out (event reason 15) — i.e. wrong PSK, not an
   RF/driver problem.

### Verification on the HEAD image (2026-09-28, WiFi at 192.168.1.233)
- Boot console: `wifi: sta up`, `wifi: got ip 192.168.1.233`, `radio up`
  all present (radio up FIXED).
- `tests/tcp_kiss_acceptance.py` — **12/12 PASS** (one transient 8/12
  run right after re-flash: bench RF interference, clean on rerun).
- `tests/kiss_modem_acceptance.py` (USB, WiFi active) — **10/10 PASS**.
- `tests/dual_link_acceptance.py` — NEW permanent Phase-4 gate —
  **13/13 PASS**: detect on USB + 2 TCP sessions, 3rd client politely
  rejected, byte-exact fan-out both directions + cross-TCP, and one RNode
  pong fanned out to all three links.
- Still PENDING (unchanged): full AP-flap reconnect test needs physical
  AP control; the bounded-backoff reconnect logic itself is exercised on
  every boot (observed 1→2→4 s backoff in earlier logs) and the reason-15
  loop during the wrong-PSK incident confirmed reconnect + reason logging
  work continuously for minutes without wedging.
