use std::sync::Arc;
use super::{Interface, InterfaceContext, InterfaceManager};

pub struct UdpInterface {
    bind_addr: String,
    forward_addr: Option<String>,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl UdpInterface {
    pub fn new<T: Into<String>>(
        bind_addr: T,
        forward_addr: Option<T>,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            forward_addr: forward_addr.map(Into::into),
            iface_manager
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let bind_addr = { context.inner.lock().unwrap().bind_addr.clone() };
        unimplemented!("FIXME: todo")
    }
}

impl Interface for UdpInterface {
    fn mtu() -> usize {
        2048
    }
}
