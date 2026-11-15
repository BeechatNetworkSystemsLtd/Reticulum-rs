//! reticulum-daemon library surface: the config module is exposed so the
//! daemon's integration tests (and external tooling) can exercise config
//! parsing and migration without spawning the binary.

pub mod config;
pub mod rpc;
