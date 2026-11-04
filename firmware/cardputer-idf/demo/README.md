# Two-node Reticulum demo over LoRa (C6L <-> Heltec RNode)

Node A = Heltec RNode on /dev/ttyUSB1 (Reticulum transport node).
Node B = M5Stack C6L on /dev/ttyACM1|2 (our c6l-modem-idf firmware).

## One-time setup
```
mkdir -p ~/demo/node-a ~/demo/node-b
cp node-a-rnsd.config ~/demo/node-a/config   # enable_transport = True
cp node-b-rnsd.config ~/demo/node-b/config   # C6L RNodeInterface
```

## Run
```
setsid python3 -m RNS.Utilities.rnsd --config ~/demo/node-a -v &  # wait for "powered up"
setsid python3 -m RNS.Utilities.rnsd --config ~/demo/node-b -v &
```
Watch logs: `tail -f /tmp/rnsd-*.log`. Status: `rnstatus -a --config ~/demo/node-a`.

## Message-level demo (LXMF / nomadnet)
Terminal 1: `nomadnet --config ~/demo/node-a`
Terminal 2: `nomadnet --config ~/demo/node-b`
Compose a message on one side (Conversations -> Write); it travels
over LoRa to the other node's inbox.

## Phone demo (Sideband)
Plug the C6L into the phone via a USB-OTG adapter. In Sideband:
Connectivity -> RNode -> select the serial device; set frequency
867500000, bandwidth 125000, TX power 14, SF 9, CR 5. The C6L answers
Sideband's detect burst (fw 1.90) and acts as the phone's RNode. The
laptop side runs nomadnet on the Heltec RNode; messages flow
phone <-> LoRa <-> laptop.

## IMPORTANT — interference
The rfsight rid_sniffer (USB hub neighbour) scans the 868 MHz band
continuously at ~-51 dBm at desk range. This adds 1-2s CSMA deferral
to every RNode transmission and can drop small packets entirely. For
reliable demos/videos, power the C6L+phone or the Heltec from a
different room / power bank, away from the rfsight node.

## Proven working (see tests/kiss_modem_acceptance.py)
- KISS detect/config/radio-on/echo round trip: 10/10
- Bidirectional LoRa data (RNode wire format incl. split packets)
- RNS detect + validateRadioState + interface Up on both nodes
- Announce propagation + path discovery over the air

## C6L WiFi-TCP bridge

The same firmware also speaks KISS over WiFi: clients on the LAN
connect to the C6L on TCP port 7633 and reach LoRa peers through the
SX1262 — no USB cable.

- Build/flash with credentials baked in: `C6L_WIFI_SSID=mynet
  C6L_WIFI_PASSWORD=secret cargo +esp flash --release` (or your usual
  flash command). Gotcha: cargo does NOT rebuild on env-var change
  alone — `touch src/main.rs` after editing them, or the old
  credentials stay in the binary.
- The console prints the DHCP address once associated; clients connect
  to `tcp://<that-ip>:7633`. For rnsd's RNodeInterface the URI must be
  `tcp://<that-ip>` with NO port — RNS hardcodes target port 7633 and
  treats a `:port` suffix as part of the hostname.
- Max 2 concurrent TCP sessions; USB KISS keeps working in parallel.
- Dual-link gate (USB + two TCP clients + 3rd-client reject + fan-out
  both ways + radio fan-out to all links):
  `python3 tests/dual_link_acceptance.py <c6l_ip>`
- rnsd: `cp c6l-tcp-rnsd.config ~/demo/node-b/config` — RNodeInterface
  with a `tcp://` port URI (NOT TCPClientInterface; see BRIDGE_PLAN).
- Acceptance over WiFi (same 10-check flow as the USB test, RNode still
  on /dev/ttyUSB1):
  `python3 tests/tcp_kiss_acceptance.py <c6l_ip>`
