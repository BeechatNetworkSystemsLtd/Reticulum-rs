//! `rnprobe` — probe a destination by measuring round-trip times
//! (Python `RNS/Utilities/rnprobe.py`).
//!
//! This port treats the destination name as optional. When a name is
//! given, the probe errors if the recalled identity does not hash to
//! the given destination under that name.
//!
//! Python requires the name and sends the probe to the destination
//! built from it. It does not compare that destination hash to the
//! argument. `rnstransport.probe` is the transport probe destination,
//! not a default `rnprobe` argument.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::common::{build_tool_transport, resolve_config_dir, ToolTransportOptions};
use reticulum::destination::DestinationName;
use reticulum::hash::AddressHash;
use reticulum::identity::Identity;
use reticulum::transport::Transport;

/// Default probe payload size in bytes (Python `DEFAULT_PROBE_SIZE`).
pub const DEFAULT_PROBE_SIZE: usize = 16;

/// Default timeout in seconds (Python `DEFAULT_TIMEOUT`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct ProbeOptions {
    /// Config directory (usually from `--config`).
    pub config_dir: std::path::PathBuf,
    pub size: usize,
    pub timeout: Duration,
    pub probes: usize,
    /// UDP loopback fallback ports when the config has no interfaces.
    pub udp_loopback: Option<(u16, u16)>,
    /// Delay before each probe after the first (`--wait`).
    pub wait: Duration,
    /// Full destination name in dotted notation (`app.aspects`).
    /// When set, this port errors if the recalled identity does not hash
    /// to `destination` under this name.
    pub full_name: Option<String>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            config_dir: resolve_config_dir(None),
            size: DEFAULT_PROBE_SIZE,
            timeout: DEFAULT_TIMEOUT,
            probes: 1,
            udp_loopback: Some((4996, 4997)),
            wait: Duration::ZERO,
            full_name: None,
        }
    }
}

/// Split `app.aspect.more` into the app name and the aspect string.
pub fn split_destination_name(full_name: &str) -> Result<(String, String), String> {
    let Some((app, aspects)) = full_name.split_once('.') else {
        return Err(
            "The full destination name including application name aspects must be specified"
                .to_string(),
        );
    };
    if app.is_empty() || aspects.is_empty() || aspects.split('.').any(|part| part.is_empty()) {
        return Err(
            "The full destination name including application name aspects must be specified"
                .to_string(),
        );
    }
    Ok((app.to_string(), aspects.to_string()))
}

/// Address hash of `full_name` for `identity`.
pub fn destination_for_aspect_name(
    full_name: &str,
    identity: &Identity,
) -> Result<AddressHash, String> {
    let (app, aspects) = split_destination_name(full_name)?;
    Ok(DestinationName::new(&app, &aspects).address_hash_for(identity))
}

/// Sleep between probes. The first probe (`already_sent == 0`) does not wait.
pub async fn await_probe_gap(already_sent: usize, wait: Duration) {
    if already_sent > 0 && !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

pub struct ProbeResult {
    /// Round-trip time until the proof arrived.
    pub rtt: Duration,
    /// Full hash of the proved packet.
    pub packet_hash: reticulum::hash::Hash,
}

/// Send probes to a probe destination and measure the round-trip time of
/// the returned proof.
pub async fn probe(
    destination: &AddressHash,
    options: &ProbeOptions,
) -> Result<Vec<ProbeResult>, reticulum::error::RnsError> {
    let transport = build_tool_transport(ToolTransportOptions {
        config_dir: &options.config_dir,
        instance_name: "rnprobe",
        enable_transport: false,
        udp_loopback: options.udp_loopback,
    })
    .await;

    probe_with(&transport, destination, options).await
}

/// Probe using an existing transport instance.
pub async fn probe_with(
    transport: &Transport,
    destination: &AddressHash,
    options: &ProbeOptions,
) -> Result<Vec<ProbeResult>, reticulum::error::RnsError> {
    // Wait for the path to the probe destination
    // (Python prints a spinner while requesting the path).
    if !transport
        .await_path(destination, Some(options.timeout), None)
        .await
    {
        return Err(reticulum::error::RnsError::LinkNotReady);
    }

    let destination = if let Some(name) = options.full_name.as_deref() {
        let identity = transport
            .recall(destination)
            .await
            .ok_or(reticulum::error::RnsError::LinkNotReady)?;
        let addressed = destination_for_aspect_name(name, &identity)
            .map_err(|_| reticulum::error::RnsError::InvalidArgument)?;
        if addressed != *destination {
            return Err(reticulum::error::RnsError::InvalidArgument);
        }
        addressed
    } else {
        *destination
    };

    let mut receipts = transport.receipt_events();
    let mut results = Vec::new();

    for sent in 0..options.probes {
        await_probe_gap(sent, options.wait).await;
        let payload: Vec<u8> = (0..options.size).map(|i| (i % 251) as u8).collect();

        let started = Instant::now();
        transport
            .send_to_destination(&destination, &payload)
            .await?;

        let proof = tokio::time::timeout(options.timeout, receipts.recv()).await;
        match proof {
            Ok(Ok(event)) => {
                results.push(ProbeResult {
                    rtt: started.elapsed(),
                    packet_hash: event.packet_hash,
                });
            }
            _ => return Err(reticulum::error::RnsError::LinkNotReady),
        }
    }

    Ok(results)
}

/// Run a probe *server*: a transport that proves packets to its probe
/// destination (what remote `rnprobe` instances probe against).
pub async fn serve(config_dir: &Path, instance_name: &str) -> std::sync::Arc<Transport> {
    let transport = std::sync::Arc::new(
        build_tool_transport(ToolTransportOptions {
            config_dir,
            instance_name,
            enable_transport: false,
            udp_loopback: Some((4997, 4996)),
        })
        .await,
    );

    let probe = transport.enable_probe_destination().await;
    transport.send_announce(&probe, None).await;

    transport
}

/// Render probe results like the Python utility
/// ("Probe sent to <hash> :: valid proof received in X ms").
pub fn render_results(destination: &AddressHash, results: &[ProbeResult]) -> String {
    let mut out = String::new();
    for result in results {
        out.push_str(&format!(
            "Probe sent to {} :: valid proof received in {:.2} ms\n",
            destination,
            result.rtt.as_secs_f64() * 1000.0
        ));
    }
    if results.is_empty() {
        out.push_str(&format!("No valid proofs received from {destination}\n"));
    }
    out
}

/// UDP loopback probe demo (`rn probe --loopback`): a probe server on
/// the forward port and one probe against it. Returns the probed
/// destination alongside the results.
pub async fn run_loopback() -> Result<(AddressHash, Vec<ProbeResult>), reticulum::error::RnsError> {
    let server = build_tool_transport(ToolTransportOptions {
        config_dir: resolve_config_dir(None).as_path(),
        instance_name: "rnprobe-server",
        enable_transport: false,
        udp_loopback: Some((4997, 4996)),
    })
    .await;

    let probe_destination = server.enable_probe_destination().await;
    server.send_announce(&probe_destination, None).await;

    let client = build_tool_transport(ToolTransportOptions {
        config_dir: resolve_config_dir(None).as_path(),
        instance_name: "rnprobe-client",
        enable_transport: false,
        udp_loopback: Some((4996, 4997)),
    })
    .await;

    let destination = probe_destination.lock().await.desc.address_hash;
    let results = probe_with(&client, &destination, &ProbeOptions::default()).await?;
    Ok((destination, results))
}
