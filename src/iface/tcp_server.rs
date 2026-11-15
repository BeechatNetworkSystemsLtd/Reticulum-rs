use alloc::string::String;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::error::RnsError;

use super::tcp_client::{resolve_bind_target, BindTarget, TcpClient, TcpOptions};
use super::{Interface, InterfaceContext, InterfaceManager};

pub struct TcpServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    options: TcpOptions,
}

impl TcpServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self::from_parts(addr.into(), iface_manager, TcpOptions::default())
    }

    /// `new` plus Python TCP server knobs. `fixed_mtu` below `Reticulum.MTU`
    /// is rejected; omitted options match [`TcpServer::new`].
    pub fn with_options<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        options: TcpOptions,
    ) -> Result<Self, RnsError> {
        options.validate()?;
        Ok(Self::from_parts(addr.into(), iface_manager, options))
    }

    fn from_parts(
        addr: String,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
        options: TcpOptions,
    ) -> Self {
        Self {
            addr,
            iface_manager,
            options,
        }
    }

    pub fn options(&self) -> &TcpOptions {
        &self.options
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let options = { context.inner.lock().unwrap().options.clone() };
        let stats = context.channel.stats.clone();
        let iface_stop = context.channel.stop.clone();
        let exited = context.channel.exited.clone();

        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let server_ifac = context.channel.ifac.clone();
        let parent = context.channel.address;

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));
        let mut spawned_peers = Vec::new();

        loop {
            if context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                stats.set_online(false);
                break;
            }

            let bind_target = match resolve_bind_target(&addr, &options).await {
                Some(target) => target,
                None => {
                    log::warn!("tcp_server: couldn't resolve bind address for <{}>", addr);
                    tokio::select! {
                        _ = iface_stop.cancelled() => break,
                        _ = context.cancel.cancelled() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => continue,
                    }
                }
            };
            let listener = match &bind_target {
                BindTarget::Literal(name) => TcpListener::bind(name.clone()).await,
                BindTarget::Resolved(socket_addr) => TcpListener::bind(*socket_addr).await,
            }
            .map_err(|_| RnsError::ConnectionError);

            if listener.is_err() {
                log::warn!("tcp_server: couldn't bind to <{}>", addr);
                tokio::select! {
                    _ = iface_stop.cancelled() => break,
                    _ = context.cancel.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => continue,
                }
            }

            log::info!("tcp_server: listen on <{}>", addr);
            stats.set_online(true);

            let listener = listener.unwrap();

            let tx_task = {
                let cancel = context.cancel.clone();
                let iface_stop = iface_stop.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        if cancel.is_cancelled() || iface_stop.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            _ = iface_stop.cancelled() => {
                                break;
                            }
                            // Skip all tx messages
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            let cancel = context.cancel.clone();

            loop {
                if cancel.is_cancelled() || iface_stop.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }
                    _ = iface_stop.cancelled() => {
                        break;
                    }

                    client = listener.accept() => {
                        if let Ok(client) = client {
                            log::info!(
                                "tcp_server: new client <{}> connected to <{}>",
                                client.1,
                                addr
                            );

                            let mut iface_manager = iface_manager.lock().await;

                            // Spawned connection interfaces inherit the
                            // server's interface access code
                            // (Python TCPServerInterface inheritance). The
                            // key is installed BEFORE the worker is
                            // spawned: on a multithreaded runtime the
                            // worker may otherwise begin decoding a frame
                            // before the slot is populated.
                            let inherited = server_ifac.read().expect("ifac lock").clone();
                            // Name the client with its peer before the worker
                            // can learn a path. Every accepted client would
                            // otherwise share the `TcpClient` type name.
                            // Server options were already validated. The
                            // accepted client only copies framing and
                            // fixed_mtu, so this cannot fail.
                            let peer_endpoint = client.1.to_string();
                            let peer = TcpClient::from_parts(
                                peer_endpoint.clone(),
                                Some(client.0),
                                options.for_accepted_client(),
                            );

                            let peer_context = if let Some(key) = inherited {
                                iface_manager.open_with_ifac(peer, key)
                            } else {
                                iface_manager.open_named(&peer_endpoint, peer)
                            };
                            let address = peer_context.channel.address;
                            iface_manager.copy_spawned_control(&parent, &address);
                            iface_manager.note_spawned(&parent, &address);
                            spawned_peers.push(address);
                            iface_manager.launch(peer_context, TcpClient::spawn);
                        }
                    }
                }
            }

            drop(listener);
            stats.set_online(false);
            let _ = tokio::join!(tx_task);
            // A peer accepted after `stop_iface` snapshotted children is
            // still in this list. Cancel it only after the listener is
            // gone, so nothing accepted during teardown stays up.
            for child in spawned_peers.drain(..) {
                iface_manager.lock().await.stop_iface(&child);
            }
            if context.cancel.is_cancelled() || iface_stop.is_cancelled() {
                break;
            }
        }
        for child in spawned_peers.drain(..) {
            iface_manager.lock().await.stop_iface(&child);
        }
        let _ = exited.send(true);
    }
}

impl Interface for TcpServer {
    fn mtu() -> usize {
        2048
    }

    fn endpoint(&self) -> &str {
        &self.addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_tcp_server_options_keep_current_behavior() {
        let server = TcpServer::new(
            "0.0.0.0:4242",
            Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(1))),
        );
        assert_eq!(server.options(), &TcpOptions::default());
        assert!(!server.options().kiss_framing);
        assert!(!server.options().prefer_ipv6);
        assert!(server.options().device.is_none());
        assert!(server.options().fixed_mtu.is_none());
        assert!(server.options().max_reconnect_tries.is_none());
        assert!(server.options().connect_timeout.is_none());
        assert_eq!(server.options().hardware_mtu(), 262_144);
        assert_eq!(<TcpServer as Interface>::mtu(), 2048);
    }

    #[test]
    fn server_rejects_fixed_mtu_below_protocol_mtu() {
        let manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(1)));
        let options = TcpOptions {
            fixed_mtu: Some(499),
            ..TcpOptions::default()
        };
        assert!(TcpServer::with_options("0.0.0.0:1", manager, options).is_err());
    }
}
