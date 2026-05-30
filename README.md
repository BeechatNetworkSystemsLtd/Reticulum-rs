
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

## Integration tests

Integration tests that run against the Python RNS reference implementation (`tests/python.rs`)
require the Reticulum source to be checked out and the path set in the `RETICULUM_TEST_PYTHON_DIR`
environment variable.

## License

This project is licensed under the MIT license.

---

© Beechat Network Systems Ltd. All rights reserved.
https://beechat.network/
