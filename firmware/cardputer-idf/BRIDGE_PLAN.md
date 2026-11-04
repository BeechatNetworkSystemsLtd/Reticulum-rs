# WiFi-TCP + LoRa Bridge Plan for the M5Stack Unit C6L
## Reviewed and approved by Codex CLI and Grok CLI

## Objective
Devices on the WiFi LAN connect to the C6L via TCP (RNode KISS on port 7633)
and reach LoRa peers through the SX1262 radio. This is the product.

```
[Phone/Laptop on WiFi] ←TCP:7633→ [C6L: WiFi STA + LoRa]
                                        ⇅ 867.5 MHz
                              [Heltec RNode ←USB→ Laptop rnsd/nomadnet]
```

## Architecture (agreed by both reviewers)

### Thread layout
| Thread | Stack | Owns |
|---|---|---|
| modem (existing) | 64 KB | Modem, SX1262 SPI, USB-Serial-JTAG, radio loop |
| wifi bring-up | 16 KB | esp_wifi STA + DHCP + reconnect loop |
| tcp-accept | 16 KB | TcpListener on 0.0.0.0:7633, spawn sessions |
| tcp-session × 2 max | 8 KB each | one TcpStream, KISS parser, channels to modem |

### Data flow
```
TCP bytes --mpsc channel--> modem.feed(tcp_session_id, bytes)
modem Fed{replies, to_others, ops}:
  replies → back to originating session's TcpStream
  to_others → to all OTHER sessions (USB + other TCP)
  ops → radio (Configure/Transmit/RadioOn/RadioOff)

USB bytes → modem.feed(usb_session_id, bytes) → same routing

Radio RX → modem.radio_rx(data) → frames for ALL sessions → fan-out
```

### WiFi initialization (esp-idf-sys, NOT the plan's esp_netif_new path)
1. `nvs_flash_init()` (WiFi calibration data lives in NVS)
2. `esp_netif_init()`
3. `esp_event_loop_create_default()`
4. `esp_netif_create_default_wifi_sta()`
5. `esp_wifi_init(&WIFI_INIT_CONFIG_DEFAULT())`
6. Register WIFI_EVENT + IP_EVENT_STA_GOT_IP handlers
7. `esp_wifi_set_mode(STA)` + set_config + start
8. `esp_wifi_connect()` from the STA_START handler
9. Wait for GOT_IP event → print the DHCP address

### TCP listener
- `std::net::TcpListener::bind("0.0.0.0:7633")` after DHCP
- `TCP_NODELAY` on all accepted streams (KISS is tiny frames)
- Non-blocking reads from dedicated session threads (NOT in the modem loop)
- Max 2 concurrent sessions (one laptop + one debug client)
- If esp-idf-svc (v0.52) can't unify with esp-idf-hal 0.47, write the
  ~80-line wifi.rs using raw esp-idf-sys bindings per the C station example

### rnsd connection config
```ini
[[C6L]]
type = RNodeInterface
enabled = yes
port = tcp://192.168.1.233   # NO :port — RNS hardcodes 7633
frequency = 867500000
bandwidth = 125000
txpower = 14
spreadingfactor = 9
codingrate = 5
```
(NOT TCPClientInterface — that's a transport hop, not an RNode)

## Phased implementation

### Phase 1: WiFi STA (no TCP yet)
- WiFi init on a 16KB thread BEFORE the modem thread
- Print DHCP address on the console
- Verify: KISS acceptance test still 10/10 over USB

### Phase 2: TCP listener (no bridging yet)
- TcpListener on 7633, non-blocking, up to 2 sessions
- Each session: dedicated reader thread, KISS parser, channel to modem
- Verify: host detect burst passes over WiFi (7-frame test from old firmware)

### Phase 3: Full bridge (TCP ↔ LoRa)
- Fix `to_others` routing: TCP data forwards to USB, USB data forwards to TCP
- Fix `radio_rx` fan-out: frames go to ALL sessions (USB + TCP)
- Radio ops still execute on the modem thread
- Verify: rnprobe 8/8 over tcp://C6L_IP against the Heltec

### Phase 4: Dual-link + reliability
- USB + TCP simultaneously
- WiFi reconnect on disconnect (bounded backoff)
- Two concurrent TCP clients
- Verify: USB acceptance 10/10 with WiFi active; simultaneous USB+TCP traffic

## Known risks (both reviewers)

| Risk | Mitigation |
|---|---|
| Heap: WiFi+lwIP needs ~70-120KB on a 512KB C6 | Disable SoftAP, shrink RX AMPDU, measure esp_get_free_heap_size |
| USB console vs KISS: println corrupts USB stream after first FEND | Gate ALL WiFi/TCP logs on SAW_KISS |
| Peripherals::take() must split WiFi modem from SPI pins | Take once in main(), pass modem to WiFi, SPI+pins to radio |
| TCP reader stalls during radio TX (up to 1.5s at SF12) | Dedicated session threads with bounded channels |
| RF coexistence: 2.4GHz WiFi TX near 868MHz LoRa RX | Test with WiFi associated; expect a few dB RSSI degradation |
| Env-var rebuild: cargo won't rebuild on C6L_WIFI_* change | touch src/main.rs + verify strings in binary |
| ~~RNodeInterface TCP URI parses port from hostname~~ CONFIRMED on bench: RNS 1.5.4 takes the whole post-`tcp://` string as hostname and hardcodes TARGET_PORT=7633 — `tcp://ip:4990` -> gaierror | Bridge listens on 7633; rnsd URI carries no port |

## Not a risk (both reviewers confirmed)
- Incoming TCP SYNs: lwIP handles them correctly (old bug was esp-radio/smoltcp)
- GPSPI2 vs WiFi pins: independent peripherals, no mux conflict
- std::net::TcpListener on ESP-IDF: works via BSD sockets over lwIP

## Out of scope for v1
- SoftAP fallback (useful later: phone joins C6L-RNode with no router)
- mDNS (c6l.local)
- More than 2 TCP sessions
- Reverse-connect as default (keep as compile-time fallback)
- Moving the radio to a second thread

---
## Sign-off

**Codex CLI** (2026-09-17):
✓ Plan approved. Key corrections applied: use esp-idf-svc or the C station
example's init sequence (esp_netif_create_default_wifi_sta, NOT
esp_netif_new); std::net works on ESP-IDF; WiFi+GPSPI2 have no pin
conflict; single modem thread + dedicated TCP session threads is correct.

**Grok CLI** (2026-09-17):
✓ Plan approved. Key corrections applied: USB session ID is 1 (not 0);
to_others must route to ALL other sessions (current code wrongly dumps
them onto USB tx_buf); radio_rx returns per-session frames that must be
zipped, not concatenated; bring WiFi up BEFORE the modem so the IP prints
before any FEND corrupts the console; use tcp://C6L_IP URI in rnsd
config, NOT TCPClientInterface.
