use alloc::string::String;
use std::sync::Arc;

use tokio::net::UnixListener;

use crate::error::RnsError;

use super::unix_socket_client::UnixSocketClient;
use super::{Interface, InterfaceContext, InterfaceManager};

pub struct UnixSocketServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl UnixSocketServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };

        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = UnixListener::bind(addr.clone())
                .map_err(|_| RnsError::ConnectionError);

            if let Err(_) = listener {
                log::warn!("tcp_server: couldn't bind to <{}>", addr);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            log::info!("tcp_server: listen on <{}>", addr);

            let listener = listener.unwrap();

            let tx_task = {
                let cancel = context.cancel.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        if cancel.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
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
                if cancel.is_cancelled() {
                    break;
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }

                    client = listener.accept() => {
                        if let Ok(client) = client {
                            log::info!(
                                "tcp_server: new client <{:?}> connected to <{}>",
                                client.1,
                                addr
                            );

                            let mut iface_manager = iface_manager.lock().await;

                            iface_manager.spawn(
                                UnixSocketClient::new_from_stream(&addr, client.0),
                                UnixSocketClient::spawn,
                            );
                        }
                    }
                }
            }

            let _ = tokio::join!(tx_task);
        }
    }
}

impl Interface for UnixSocketServer {
    fn mtu() -> usize {
        2048
    }
}
