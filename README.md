
# Reticulum-rs

**Reticulum-rs** is a Rust implementation of the [Reticulum Network Stack](https://reticulum.network/) — a cryptographic, decentralised, and resilient mesh networking protocol designed for communication over any physical layer.

This project brings Reticulum's capabilities to the Rust ecosystem, enabling embedded, and constrained deployments with maximum performance and minimal dependencies.

## Features

- 📡 Cryptographic mesh networking
- 🔐 Trustless routing via identity-based keys
- 📁 Lightweight and modular design
- 🧱 Support for multiple transport layers (TCP, serial, Kaonic)
- 🔌 Easily embeddable in embedded devices and tactical radios
- 🧪 Example clients for testnets and real deployments

## Structure


```
Reticulum-rs/
├── src/                 # Core Reticulum protocol implementation
│   ├── buffer.rs
│   ├── crypt.rs
│   ├── destination.rs
│   ├── error.rs
│   ├── hash.rs
│   ├── identity.rs
│   ├── iface.rs
│   ├── lib.rs
│   ├── transport.rs
│   └── packet.rs
├── proto/               # Protocol definitions (e.g. for Kaonic)
│   └── kaonic/
│       └── kaonic.proto
├── examples/            # Example clients and servers
│   ├── kaonic_client.rs
│   ├── link_client.rs
│   ├── tcp_client.rs
│   ├── tcp_server.rs
│   └── testnet_client.rs
├────── daemon/           # RNS Daemon 
│       ├── config.rs
│       ├── main.rs 
│       └── convert_config.rs
    
├── Cargo.toml           # Crate configuration
├── LICENSE              # License (MIT/Apache)
└── build.rs             
````
## Getting Started

### Prerequisites

* Rust (edition 2021+)
* `protoc` for compiling `.proto` files (if using gRPC/Kaonic modules)

### Build

```bash
cargo build --release
```

### Configuration

Reticulum-rs uses TOML for configuration, whereas the original Python Reticulum uses a custom format parsed by configobj, a Python-only library. If you have an existing Python Reticulum configuration, you must convert it before use.

#### Converting from Python Reticulum config
```bash
cargo run --example convert_config -- ~/.reticulum/config
```

This creates a backup at `~/.reticulum/config.backup` and converts the original file in place. The converter handles boolean normalization (True/False/Yes/No → true/false), quotes string values, transforms interface declarations to TOML array-of-tables syntax, and comments out None/nil values which TOML does not support.

### Running the Daemon
```bash
# Use default config search paths (~/.config/reticulum, ~/.reticulum, /etc/reticulum)
cargo run --example daemon

# Specify a custom config directory
cargo run --example daemon -- --config /path/to/config/dir
cargo run --example daemon -- -c /path/to/config/dir
```

The daemon searches for either `config` (legacy filename) or `config.toml` in the specified directory.

### Run Examples

```bash
# TCP client example
cargo run --example tcp_client

# Kaonic mesh test client
cargo run --example kaonic_client
```

## Use Cases

* 🛰 Tactical radio mesh with Kaonic
* 🕵️‍♂️ Covert communication using serial or sub-GHz transceivers
* 🚁 UAV-to-ground resilient C2 and telemetry
* 🧱 Decentralized infrastructure-free messaging

## License

This project is licensed under the MIT license.

---

© Beechat Network Systems Ltd. All rights reserved.
https://beechat.network/
