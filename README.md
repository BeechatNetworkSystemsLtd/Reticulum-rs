
# Reticulum-rs

**Reticulum-rs** is a Rust implementation of the [Reticulum Network Stack](https://reticulum.network/) — a cryptographic, decentralised, and resilient mesh networking protocol designed for communication over any physical layer.

This project brings Reticulum's capabilities to the Rust ecosystem, enabling embedded, and constrained deployments with maximum performance and minimal dependencies.

## Features

- 📡 Cryptographic mesh networking
- 🔐 Trustless routing via identity-based keys
- 📦 Resource transfers: arbitrary-size payloads over links with windowing,
  compression (bzip2), retries and automatic segmentation — wire-compatible
  with Python `RNS.Resource`
- 🔄 Requests & responses over links, including resource-backed transfers of
  large responses (Python `Link.request` compatible)
- 🧱 Support for multiple transport layers (TCP, UDP, serial)
- 🔌 Easily embeddable in embedded devices and tactical radios
- 🎯 `reticulum-core` is fully `no_std`: verified linking for Cortex-M4
  (`thumbv7em-none-eabihf`) with an external heap — bring your own RNG via
  the `_with_rng` APIs on bare metal; the tokio-based `reticulum` crate and
  the `lxmf`/`lxst` layers stay std-only
- ✅ Python interop test-suite: resources, requests, links, announces
- 🧪 Example clients for testnets and real deployments
- 📨 `lxmf` crate: the LXMF messaging layer (byte-exact Python LXMF format)
- 🎙 `lxst` crate: LXST audio streaming, codecs and calls
- 📻 RNode + RNodeMulti: the full RNode KISS command protocol (detect,
  firmware gate, radio config with echo validation, RSSI/SNR telemetry,
  READY flow control) over serial or TCP, virtual-port multi-radios
- 🕸 I2P (SAMv3): direct bridge sessions and streams, connectable
  servers and autoconnecting peers
- 🧵 Backbone links: high-throughput TCP backbones with fast-flapping
  connection suppression
- 🛡 Interface access codes (IFAC): access-code-protected interfaces with
  HKDF masking, byte-exact against Python
- 🚦 Transport control parity: per-interface ingress limiting (burst
  detection, held announces), announce-cap airtime budgeting with queued
  announces, interface-mode announce forwarding policy, path-request
  timing gates and `await_path`
- 🕳 Tunnels (synthesize/void/restore), blackholes and packet cache requests
- 📡 Network interface discovery: `reticulum-discovery` crate with LXMF
  work-function-stamped announces, discovered-interface tracking and TCP
  autoconnect
- 🛠 Remote management & probe destinations (`rnstransport.remote.management`,
  `rnstransport.probe`), remote-management allow lists, blackhole `/list`
  publishing and discovery-side list updates
- 🧰 `rn` utilities: id, path, status, cp, probe, x (remote exec),
  sh (remote shell sessions), nodeconf (RNode diagnostics)
- 🏗 `Reticulum` facade: the Python `RNS.Reticulum` entrypoint surface for
  embedding
- 🔍 Fuzz/property tests for all wire decoders and criterion benchmarks
  for the transport hot paths

## Structure

```
Reticulum-rs/
├── src/                 # Core Reticulum protocol implementation
│   ├── transport.rs     #   transport instance, routing, path requests
│   ├── resource/        #   resource transfers (outbound/inbound/manager)
│   ├── channel.rs       #   reliable channel streams over links
│   ├── iface/           #   interfaces (tcp client/server, udp, hdlc)
│   └── buffer.rs
├── reticulum-core/      # no_std protocol core (crypto, identity, packet)
├── reticulum-daemon/    # RNS daemon + config conversion
├── reticulum-utils/     # rn* utilities (rnid, rnpath, rnstatus, rncp, rnprobe)
├── reticulum-discovery/ # network interface discovery + blackhole updater
├── lxmf/                # LXMF message format, stamps, peers, router
├── lxst/                # LXST audio streaming, codecs, calls
├── tests/               # unit, interop and parity tests
│   ├── resource_transfer.rs
│   ├── parity.rs        #   ports of the Python tests/ suite vectors
│   ├── python_resources.rs  # Python interop: resources + requests
│   └── python.rs        # Python interop: announce/link/identify
├── examples/            # Example clients and servers
├── docs/                # implementation plan and notes
├── Cargo.toml           # Workspace configuration
└── LICENSE
```

### Interface message ownership

Host interface messages (`RxMessage` and `TxMessage`) own a `Box<Packet>` so
channel and inbound-queue slots do not embed packet buffers. Construct receive
messages with `packet: Box::new(packet)`, borrow packets with `&message.packet`,
or recover an owned `Packet` with `*message.packet`. `RxMessage` is `Clone`, not
`Copy`; cloning it also clones the packet allocation.

`Packet` itself and its `StaticBuffer<N>` payload backing are likewise no
longer `Copy`: the buffer lives in a `Box`, so cloning a `Packet` or a
`StaticBuffer` allocates and copies the contents.

### Memory-constrained tuning

For small targets (no PSRAM, ~hundreds of KB heap) the transport and
LXMF router expose public capacity knobs; the defaults assume a host
and are too large for, e.g., an ESP32-S3:

- `TransportConfig.channel_capacity` (default 16) — capacity of the
  internal announce/link/received-data/iface-message broadcast
  channels (it also scales the interface-ingress queue to at least 4);
  lower values trade memory for lagged/dropped events under bursts.
- `TransportConfig.enable_resource_watchdog` (default `true`) — set to
  `false` to skip spawning the resource-watchdog task when no resource
  transfers will run.
- `TransportConfig.announce_cache_capacity` (default 8192) — bound on
  retained announce packets; each cached announce costs a full packet
  buffer. 0 disables announce caching; the cache evicts oldest-first
  (FIFO) at capacity.
- `TransportConfig.phy_cache_capacity` (default 512) — per-packet
  RSSI/SNR/quality sample history retained per metric (~40 bytes per
  sample across the three series). 0 disables the history; aggregate
  interface statistics are unaffected.
- `TransportConfig::set_inbound_queue_length(class, len)` — per
  `TrafficClass` inbound queue length (a configured 0 keeps the
  default).
- `RouterConfig::event_channel_capacity` (`lxmf`, default 256) —
  broadcast capacity of the router event channel.

## Getting Started

### Prerequisites

* Rust (edition 2021+)

### Build

```bash
cargo build --release
```

### Reticulum daemon

#### Converting config from Python Reticulum

Reticulum-rs uses TOML for configuration, whereas the original Python Reticulum uses a custom format parsed by configobj, a Python-only library. If you have an existing Python Reticulum configuration, it will be read and converted to TOML in-memory. If you want to apply the conversion and save a TOML copy, run the `convert-config` subcommand:

```bash
cargo run -p reticulum-daemon -- convert-config <config_file>
```

This leaves the original file and creates a copy with .toml extension. The converter handles boolean normalization (True/False/Yes/No → true/false), quotes string values, transforms interface declarations to TOML array-of-tables syntax, and comments out None/nil values which TOML does not support.

#### Running the daemon

```bash
# Use default config search paths (~/.config/reticulum, ~/.reticulum, /etc/reticulum)
cargo run -p reticulum-daemon

# Specify a custom config directory
cargo run -p reticulum-daemon -- --config /path/to/config/dir
cargo run -p reticulum-daemon -- -c /path/to/config/dir
```

The daemon searches for either `config` (legacy filename) or `config.toml` in the specified directory.

The daemon persists its identity as a hex key file (`identity` in the config
directory) so the instance — and any destination derived from it — stays
stable across restarts. Unknown configuration keys produce warnings instead
of failing, and serial/KISS/pipe/local interface entries are parsed (they
log "not yet supported" until the corresponding interface modules land).
`--version` prints the version; SIGINT/SIGTERM trigger a clean shutdown.

### Utilities (`rn` binary)

The Python `rn*` utilities are ported as subcommands of one multi-call
binary, `rn` (crate `reticulum-utils`). All tools accept `--config <dir>`
like the Python versions (default `~/.reticulum`) and run their own
transport with the interfaces configured there.

```bash
# rnid: generate an identity, save it, and inspect it later
cargo run -p reticulum-utils --bin rn -- id --generate /tmp/my.rid
cargo run -p reticulum-utils --bin rn -- id --identity /tmp/my.rid
cargo run -p reticulum-utils --bin rn -- id --identity /tmp/my.rid --public

# rnpath: look up a path (or dump the path table as text/JSON)
cargo run -p reticulum-utils --bin rn -- path -w 20 <destination_hash>
cargo run -p reticulum-utils --bin rn -- path --table
cargo run -p reticulum-utils --bin rn -- path --table --json

# rnstatus: interface table, path table, link counts, instance identity
cargo run -p reticulum-utils --bin rn -- status
cargo run -p reticulum-utils --bin rn -- status --json

# rncp: receive into a directory (accept anyone), then send a file to it
cargo run -p reticulum-utils --bin rn -- cp --serve /tmp/incoming --no-auth
cargo run -p reticulum-utils --bin rn -- cp /tmp/file.bin <listener_hash>

# rncp: fetch from a listener that allows fetching
cargo run -p reticulum-utils --bin rn -- cp --serve /tmp/shared --no-auth --allow-fetch --jail /tmp/shared
cargo run -p reticulum-utils --bin rn -- cp --fetch /tmp/shared/hello.txt <listener_hash>
```

`rn cp` speaks the same protocol as `python3 Utilities/rncp.py`
(`rncp.receive` destinations, resource metadata `{"name": ...}`, link
identification, `fetch_file` requests), so Rust and Python tools can
exchange files in both directions.

### Run Examples

```bash
# TCP client/server examples
cargo run --example tcp_client
cargo run --example tcp_server

# Channel examples
cargo run --example channel_server
cargo run --example channel_client

# Multi-hop transport example
cargo run --example multihop
```

### Resource transfers and requests

```rust,ignore
use reticulum::resource::{ResourceOptions, ResourceStrategy, ResourceStatus};

// Accept incoming resources on a link
transport.set_resource_strategy(link_id, ResourceStrategy::All).await;

// Send an arbitrary-size payload as a resource
transport.send_resource(&link, data).await?;

// Send a request and await the response (resource-backed when large)
let rid = transport.request(&link, "my.path", b"payload").await?;
let response = transport.await_request_response(rid, Duration::from_secs(30)).await;
```

### Python integration tests

Integration tests against the Python implementation (announces, links,
identify, resource transfers and requests) can be run with the `python-tests`
feature and setting `RETICULUM_TEST_PYTHON_DIR` (and `PYTHONPATH`) to the
location of the checked out Python Reticulum source tree. Example:
```
RETICULUM_TEST_PYTHON_DIR=../Reticulum PYTHONPATH=../Reticulum \
    cargo test python --features="python-tests"
```

## Use Cases

* 🛰 Tactical radio mesh over LoRa/serial transceivers
* 🕵️‍♂️ Covert communication using serial or sub-GHz transceivers
* 🚁 UAV-to-ground resilient C2 and telemetry
* 🧱 Decentralized infrastructure-free messaging

## License

This project is licensed under the MIT license.

---

© Beechat Network Systems Ltd. All rights reserved.
https://beechat.network/

## Buffer streams

```rust,ignore
use reticulum::buffer_stream::{create_bidirectional_buffer, StreamDataMessage};

// Both ends upgrade a link to a channel of stream frames:
let (channel, incoming) = transport.mk_channel::<StreamDataMessage>(link).await?;
let stream = create_bidirectional_buffer(&channel, incoming, 1, 2);
// stream.reader: AsyncRead, stream.writer: AsyncWrite — wire-compatible
// with Python RNS.Buffer readers/writers.
```

## Feature flags

- `bz2` (default, `reticulum` and `lxmf`) — bzip2 compression for
  resources and buffer streams; `lxmf/bz2` forwards to `reticulum/bz2`
  and delivery announces advertise compression support only when it is
  enabled. Building with `default-features = false` drops the codec.
- `iface-serial` — Serial/KISS/AX.25 KISS interfaces
- `iface-pipe` — subprocess pipe interface
- `iface-auto` — AutoInterface (Linux, IPv6 link-local multicast)
- `python-tests` — Python interop tests (`RETICULUM_TEST_PYTHON_DIR` + `PYTHONPATH`)
