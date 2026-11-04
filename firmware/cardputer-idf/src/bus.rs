//! Session bus: inbound (session -> modem thread) queue plus per-session
//! outbound channels for routed KISS frames.
//!
//! Session id 1 (`USB_SESSION`) is reserved for the built-in
//! USB-Serial-JTAG link which lives inside the modem thread itself;
//! bus-registered sessions (TCP sockets) get ids >= 2. The modem thread
//! feeds `InMsg`s into `Modem::feed` and writes routed frames back via
//! `send_out` / `fan_out`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

/// Outbound frames queued per session before we start dropping.
const OUT_BOUND: usize = 64;
/// Inbound queue bound: session readers block (TCP backpressure) past this.
const IN_BOUND: usize = 256;

/// Session id reserved for the internal USB link.
pub const USB_SESSION: u64 = 1;

/// Message from a host session to the modem thread.
pub enum InMsg {
    /// Raw KISS bytes read from the session's link.
    Data(u64, Vec<u8>),
    /// The session's link went away; drop its parser state.
    Leave(u64),
}

pub struct Bus {
    next_id: AtomicU32,
    in_tx: SyncSender<InMsg>,
    out: Mutex<HashMap<u64, SyncSender<Vec<u8>>>>,
}

impl Bus {
    /// Create the bus; the returned receiver belongs to the modem thread.
    pub fn new() -> (Arc<Self>, Receiver<InMsg>) {
        let (in_tx, in_rx) = sync_channel(IN_BOUND);
        (
            Arc::new(Self {
                next_id: AtomicU32::new((USB_SESSION + 1) as u32),
                in_tx,
                out: Mutex::new(HashMap::new()),
            }),
            in_rx,
        )
    }

    /// Register a session; returns the guard holding its id and the
    /// receiver for outbound KISS frames. Dropping the guard unregisters
    /// the session and notifies the modem thread.
    pub fn register(self: &Arc<Self>) -> SessionGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
        let (tx, rx) = sync_channel(OUT_BOUND);
        self.out.lock().expect("bus out map poisoned").insert(id, tx);
        SessionGuard {
            id,
            rx,
            bus: Arc::clone(self),
        }
    }

    /// Queue inbound bytes for the modem thread (blocks when the queue is
    /// full — that's the TCP backpressure point).
    pub fn send_in(&self, id: u64, bytes: Vec<u8>) {
        let _ = self.in_tx.send(InMsg::Data(id, bytes));
    }

    /// Deliver one outbound frame to a session. False when the session is
    /// gone or its queue is full (frame dropped — never block the modem).
    pub fn send_out(&self, id: u64, frame: &[u8]) -> bool {
        let tx = self.out.lock().expect("bus out map poisoned").get(&id).cloned();
        match tx {
            Some(tx) => tx.try_send(frame.to_vec()).is_ok(),
            None => false,
        }
    }

    /// Deliver a frame to every session except `except`
    /// (`USB_SESSION` is not on the bus, so it never receives this way).
    pub fn fan_out(&self, except: u64, frame: &[u8]) {
        let txs: Vec<SyncSender<Vec<u8>>> = self
            .out
            .lock()
            .expect("bus out map poisoned")
            .iter()
            .filter(|(id, _)| **id != except)
            .map(|(_, tx)| tx.clone())
            .collect();
        for tx in txs {
            let _ = tx.try_send(frame.to_vec());
        }
    }
}

/// RAII session handle: unregisters and notifies the modem on drop.
pub struct SessionGuard {
    pub id: u64,
    pub rx: Receiver<Vec<u8>>,
    bus: Arc<Bus>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.bus.out.lock().expect("bus out map poisoned").remove(&self.id);
        // Blocking send (NOT try_send): it can only stall while the
        // inbound queue is full (256 deep — bounded, worst case ~1.6 s
        // during an SF12 TX; the modem drains 32 msgs/10 ms tick). A lost
        // Leave would leave a phantom session in the modem's parser table
        // forever (unbounded growth over reconnect cycles). The session-
        // count slot is already released by this point (in tcp_bridge,
        // SessionSlot drops before the `guard` parameter — function
        // params drop last), so new clients are never blocked by it.
        let _ = self.bus.in_tx.send(InMsg::Leave(self.id));
    }
}
