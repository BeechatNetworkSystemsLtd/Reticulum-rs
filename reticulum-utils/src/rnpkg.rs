//! `rnpkg` — Reticulum Meta Package Manager
//! (Python `RNS/Utilities/rnpkg.py`).
//!
//! The reference utility currently initialises a Reticulum instance from
//! the configuration and exits (package handling is pending upstream);
//! this port matches that behaviour.

use std::path::PathBuf;

use crate::common::{build_tool_transport, resolve_config_dir, ToolTransportOptions};

pub const APP_NAME: &str = "rnpkg";

pub struct Options {
    pub config_dir: PathBuf,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
        }
    }
}

/// Initialise the instance from the configuration and exit
/// (Python `rnpkg.program_setup`).
pub async fn run(options: &Options) -> Result<(), String> {
    let _transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: APP_NAME,
        enable_transport: true,
        udp_loopback: None,
    })
    .await;

    log::info!("{APP_NAME} initialised, package manager active");
    Ok(())
}
