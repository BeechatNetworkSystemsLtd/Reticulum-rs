//! `reticulum-utils` — the `rn*` utility tools for Reticulum-rs.
//!
//! Ports of the Python `RNS/Utilities` tools (Phase 8 of the implementation
//! plan):
//!
//! * [`rnid`] — identity generation/inspection (`Utilities/rnid.py`)
//! * [`rnpath`] — path lookup / path table (`Utilities/rnpath.py`)
//! * [`rnstatus`] — instance status (`Utilities/rnstatus.py`)
//! * [`rnprobe`] — round-trip probes (`Utilities/rnprobe.py`)
//! * [`rnx`] — remote command execution (`Utilities/rnx.py`)
//! * [`rnsh`] — remote shell sessions (`Utilities/rnsh/`)
//! * [`rnodeconf`] — RNode probe, radio validation, and host configuration frames
//! * [`rnir`] / [`rnpkg`] — reference stub utilities
//! * [`rncp`] — file transfer over resources (`Utilities/rncp.py`)
//!
//! The tools are exposed both as a library (used by the integration tests
//! and embeddable elsewhere) and as one multi-call binary, `rn`
//! (`rn id`, `rn path`, `rn status`, `rn cp`).
//!
//! All tools take `--config <dir>` like the Python versions (default
//! `~/.reticulum`). When a shared instance is reachable they attach to it;
//! otherwise they keep a direct transport.
//! [`common::build_tool_transport_requiring_shared`] fails when that attach
//! cannot happen.
//!
//! [`rpc`] speaks the shared-instance control channel: Python's
//! `multiprocessing.connection` authkey handshake, then one length-prefixed
//! msgpack request.

pub mod common;
pub mod rncp;
pub mod rngit;
pub mod rnid;
pub mod rnir;
#[cfg(feature = "iface-rnode")]
pub mod rnode_sim;
#[cfg(feature = "iface-rnode")]
pub mod rnodeconf;
pub mod rnpath;
pub mod rnpkg;
pub mod rnprobe;
pub mod rnsh;
pub mod rnstatus;
pub mod rnx;
pub mod rpc;
