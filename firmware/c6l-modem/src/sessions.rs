//! Session plumbing: routes byte chunks between link tasks (USB, TCP
//! sessions) and the modem actor task that owns `Modem`.

use alloc::vec::Vec;
use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_sync::mutex::Mutex;

/// USB is always session 0; TCP sessions start at 1.
pub const USB_SESSION: u64 = 0;

/// Inbound bytes from any link → modem actor.
static TO_MODEM: Channel<CriticalSectionRawMutex, (u64, Vec<u8>), 8> = Channel::new();

pub fn to_modem() -> Sender<'static, CriticalSectionRawMutex, (u64, Vec<u8>), 8> {
    TO_MODEM.sender()
}

pub fn to_modem_rx() -> Receiver<'static, CriticalSectionRawMutex, (u64, Vec<u8>), 8> {
    TO_MODEM.receiver()
}

/// One outbound channel per session. Capacity bounds queued reply data;
/// TCP writers drain promptly, USB is drained by the actor's TX queue.
#[allow(dead_code)] // used by the gated wifi task
pub type Outbound = Channel<CriticalSectionRawMutex, Vec<u8>, 8>;

static REGISTRY: Mutex<
    CriticalSectionRawMutex,
    RefCell<Vec<(u64, Sender<'static, CriticalSectionRawMutex, Vec<u8>, 8>)>>,
> = Mutex::new(RefCell::new(Vec::new()));

fn registry(
) -> &'static Mutex<
    CriticalSectionRawMutex,
    RefCell<Vec<(u64, Sender<'static, CriticalSectionRawMutex, Vec<u8>, 8>)>>,
> {
    &REGISTRY
}

/// Register a session's outbound sender. `Outbound` must live in a
/// `static_cell` — senders borrowed from it live forever.
#[allow(dead_code)] // used by the gated wifi task
pub async fn register(id: u64, out: &'static Outbound) {
    let sender: Sender<'static, CriticalSectionRawMutex, Vec<u8>, 8> = out.sender();
    registry().lock().await.borrow_mut().push((id, sender));
}

#[allow(dead_code)] // used by the gated wifi task
pub async fn unregister(id: u64) {
    registry().lock().await.borrow_mut().retain(|(sid, _)| *sid != id);
}

/// Send `bytes` to one session's link task. Lossy on a full channel —
/// TCP readers drain continuously, so drops only occur under host
/// backpressure, where dropping stale telemetry is preferable to
/// wedging the radio path.
pub async fn send_to(id: u64, bytes: Vec<u8>) {
    if id == USB_SESSION {
        return; // handled by the actor's USB TX queue
    }
    let guard = registry().lock().await;
    if let Some((_, sender)) = guard.borrow().iter().find(|(sid, _)| *sid == id) {
        let sender: &Sender<'static, CriticalSectionRawMutex, Vec<u8>, 8> = sender;
        sender.try_send(bytes).ok();
    }
    drop(guard);
}
