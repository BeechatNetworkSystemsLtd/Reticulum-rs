//! The `Reticulum` facade — Python `RNS/Reticulum.py` parity (Phase 7.1).
//!
//! Python's `Reticulum` class owns instance lifecycle: configuration,
//! the transport identity, interface setup, the shared instance, and
//! delegates routing/state queries to `RNS.Transport`. This facade
//! wraps a [`Transport`] with the same responsibilities for embedders:
//!
//! ```no_run
//! use rand_core::OsRng;
//! use reticulum::identity::PrivateIdentity;
//! use reticulum::reticulum::Reticulum;
//! use reticulum::transport::TransportConfig;
//!
//! #[tokio::main]
//! async fn main() {
//!     let reticulum = Reticulum::new(
//!         TransportConfig::new("my-app", &PrivateIdentity::new_from_rand(OsRng))
//!     );
//!     assert!(!reticulum.is_transport_enabled().await);
//! }
//! ```

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::destination::DestinationName;
use crate::destination::SingleInputDestination;
use crate::hash::AddressHash;
use crate::identity::PrivateIdentity;
use crate::iface::InterfaceManager;
use crate::iface::InterfaceStats;
use crate::transport::{
    PathTableSnapshotEntry, Transport, TransportConfig, TunnelTableSnapshotEntry,
};

/// A Reticulum instance (Python `RNS.Reticulum`).
#[derive(Clone)]
pub struct Reticulum {
    transport: Arc<Transport>,
    transport_enabled: bool,
}

impl Reticulum {
    /// Create a Reticulum instance from a transport configuration
    /// (Python `RNS.Reticulum(configdir=...)`).
    pub fn new(config: TransportConfig) -> Self {
        let transport_enabled = config.is_transport_enabled();
        Self {
            transport: Arc::new(config.build()),
            transport_enabled,
        }
    }

    /// Whether this instance routes traffic for other peers
    /// (Python `Reticulum.transport_enabled`).
    pub fn is_transport_enabled(&self) -> impl std::future::Future<Output = bool> + '_ {
        std::future::ready(self.transport_enabled)
    }

    /// The transport instance owned by this Reticulum instance.
    pub fn transport(&self) -> &Arc<Transport> {
        &self.transport
    }

    /// The interface manager (Python `Reticulum.get_interface_manager`).
    pub fn interface_manager(&self) -> Arc<Mutex<InterfaceManager>> {
        self.transport.iface_manager()
    }

    /// Snapshot of all interface statistics
    /// (Python `Reticulum.get_interface_stats`).
    pub async fn interface_stats(&self) -> Vec<InterfaceStats> {
        self.transport.interface_stats().await
    }

    /// Snapshot of the path table (Python `Reticulum.get_path_table`).
    pub async fn path_table(&self) -> Vec<PathTableSnapshotEntry> {
        self.transport.path_table_snapshot().await
    }

    /// Snapshot of the tunnel table (Python `Reticulum.get_tunnel_table`).
    pub async fn tunnel_table(&self) -> Vec<TunnelTableSnapshotEntry> {
        self.transport.tunnel_table_snapshot().await
    }

    /// Whether a path to the destination is known
    /// (Python `RNS.Transport.has_path`).
    pub async fn has_path(&self, destination: &AddressHash) -> bool {
        self.transport.has_path(destination).await
    }

    /// Hops to a destination, if known (Python `RNS.Transport.hops_to`).
    pub async fn hops_to(&self, destination: &AddressHash) -> Option<u8> {
        self.transport.hops_to(destination).await
    }

    /// Request a path from the network (Python `RNS.Transport.request_path`).
    pub async fn request_path(&self, destination: &AddressHash) {
        self.transport.request_path(destination, None, None).await;
    }

    /// Request a path and wait for it (Python `RNS.Transport.await_path`).
    pub async fn await_path(
        &self,
        destination: &AddressHash,
        timeout: Option<std::time::Duration>,
    ) -> bool {
        self.transport.await_path(destination, timeout, None).await
    }

    /// The instance transport identity hash
    /// (Python `Reticulum.transport_id`).
    pub async fn identity_hash(&self) -> AddressHash {
        self.transport.identity_hash().await
    }

    /// Add a local SINGLE destination served by this instance
    /// (Python `RNS.Destination(...)` + `register_destination`-side
    /// handling).
    pub async fn add_destination(
        &self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<SingleInputDestination>> {
        self.transport.add_destination(identity, name).await
    }

    /// Announce a local destination (Python `Destination.announce`).
    pub async fn announce(
        &self,
        destination: &Arc<Mutex<SingleInputDestination>>,
        app_data: Option<&[u8]>,
    ) {
        self.transport.send_announce(destination, app_data).await;
    }

    /// Enable the remote management destination
    /// (Python `enable_remote_management = Yes`).
    pub async fn enable_remote_management(&self) -> Arc<Mutex<SingleInputDestination>> {
        self.transport.enable_remote_management().await
    }

    /// Enable the probe destination (Python `enable_remote_probe = Yes`).
    pub async fn enable_probe_destination(&self) -> Arc<Mutex<SingleInputDestination>> {
        self.transport.enable_probe_destination().await
    }

    /// Enable blackhole list publishing (Python `publish_blackhole = Yes`).
    pub async fn enable_blackhole_publishing(&self) -> Arc<Mutex<SingleInputDestination>> {
        self.transport.enable_blackhole_publishing().await
    }
}
