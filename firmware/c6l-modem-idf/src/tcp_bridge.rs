//! TCP listener + session threads for the KISS bridge
//! (BRIDGE_PLAN Phase 2 + Phase 4).
//!
//! Contract (pinned — do not change signatures):
//!   - `start(bus)` spawns the 16 KB accept thread and returns
//!     immediately. The listener binds 0.0.0.0:7633 (std::net over
//!     lwIP — binding before DHCP is fine; clients just can't connect
//!     until we have an IP). A failed bind (e.g. netif not up yet)
//!     retries every 5 s instead of killing the thread.
//!   - Max 2 concurrent sessions (one laptop + one debug client);
//!     further connections are accepted, logged, shut down and dropped
//!     (polite reject — never left half-open).
//!   - TCP_NODELAY on every accepted stream (KISS is tiny frames).
//!   - ALL logging via `crate::clog!` — never `println!`.
//!
//! Session layout — ONE 12 KB thread per session (deviation from the
//! plan's 8 KB: the 8 KB budget + 1 KB read buffer + error-format
//! frames proved tight, and an ESP-IDF stack overflow in the std::net
//! paths is a silent reboot, not a catchable error), not a
//! reader/writer pair: `SessionGuard` owns the outbound `Receiver` and
//! its `Drop` must run exactly once, so it cannot be handed to a second
//! thread — a separate writer parked in `recv()` could never be woken
//! by the reader's exit (the classic stuck-session bug). One thread
//! owning BOTH directions removes the coordination entirely:
//!   - inbound: blocking `read` with a 10 ms SO_RCVTIMEO (returns the
//!     instant the host sends) -> `bus.send_in(id, bytes)` (blocks when
//!     the modem queue is full = intended TCP backpressure)
//!   - outbound: after every read attempt, drain `guard.rx` with
//!     `try_recv` -> `write_all` of the pre-framed KISS frame (worst
//!     case 10 ms extra latency — harmless next to RNS's 250 ms
//!     config-echo validation window)
//! On ANY exit path: `shutdown(Both)` (FIN/RST to the peer), the RAII
//! slot decrements the session count, and the `SessionGuard` drop
//! unregisters the session and notifies the modem (`InMsg::Leave`).
//!
//! The KISS parser does NOT live here: raw bytes go to the modem thread
//! which owns `Modem::feed`; outbound frames arrive pre-framed.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::time::Duration;

use crate::bus::{Bus, SessionGuard};

/// TCP port for the RNode KISS bridge. RNS's RNodeInterface treats the
/// whole string after `tcp://` as a HOSTNAME — it has no port parsing
/// and hardcodes TCPConnection.TARGET_PORT = 7633 (RNS 1.5.4,
/// RNodeInterface.py). So `port = tcp://<c6l_ip>` in the rnsd config
/// reaches us ONLY on 7633; the plan's original 4990 was unreachable
/// by stock rnsd (verified on the bench: gaierror "Name or service not
/// known"). Non-RNS clients can still reach any port we choose — we
/// choose the RNS-compatible one.
pub const LISTEN_PORT: u16 = 7633;
/// Max concurrent TCP sessions (plan: laptop + debug client).
pub const MAX_SESSIONS: usize = 2;

/// Read timeout = outbound poll cadence. Data reads return immediately;
/// the expiry only bounds how long an outbound frame waits in the
/// channel before the drain pass picks it up (10 ms << RNS's 250 ms
/// config-echo window).
const POLL: Duration = Duration::from_millis(10);

/// Active-session count gating accepts. Only the accept thread
/// increments (check-then-add serialized there), so it cannot
/// over-admit; session threads decrement via `SessionSlot` on exit.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Spawn the accept thread. Returns immediately.
pub fn start(bus: Arc<Bus>) {
    std::thread::Builder::new()
        .name("tcp-accept".to_string())
        .stack_size(16 * 1024)
        .spawn(move || accept_loop(bus))
        .expect("tcp accept thread spawn"); // pre-KISS panic is safe
}

fn accept_loop(bus: Arc<Bus>) {
    // Bind with retry: if esp_netif/WiFi bring-up races us the socket
    // layer may refuse; that's fine, it will succeed on a later pass.
    let listener = loop {
        match TcpListener::bind(("0.0.0.0", LISTEN_PORT)) {
            Ok(l) => break l,
            Err(e) => {
                crate::clog!("[tcp] bind 0.0.0.0:{} failed: {:?} — retrying in 5s", LISTEN_PORT, e);
                unsafe { esp_idf_sys::vTaskDelay(500) }; // 100 Hz ticks
            }
        }
    };
    crate::clog!("[tcp] listening on 0.0.0.0:{} (max {} sessions)", LISTEN_PORT, MAX_SESSIONS);

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => accept_session(Arc::clone(&bus), stream),
            // Transient errors (netif flap, resource exhaustion): back
            // off briefly and keep serving — never kill the accept thread.
            Err(e) => {
                crate::clog!("[tcp] accept error: {:?}", e);
                unsafe { esp_idf_sys::vTaskDelay(10) }; // 100 ms
            }
        }
    }
}

fn accept_session(bus: Arc<Bus>, stream: TcpStream) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());

    if ACTIVE.load(Ordering::Acquire) >= MAX_SESSIONS {
        // Polite reject: FIN + close NOW — a queued-but-never-served
        // socket would hang half-open at the host.
        crate::clog!("[tcp] busy: rejecting {} (max {} sessions)", peer, MAX_SESSIONS);
        let _ = stream.shutdown(Shutdown::Both);
        return; // drop closes the fd
    }

    // KISS is tiny frames; Nagle would batch replies behind the poll
    // cadence. Perf-only — failure is logged, not fatal.
    if let Err(e) = stream.set_nodelay(true) {
        crate::clog!("[tcp] {} nodelay failed: {:?} (continuing)", peer, e);
    }
    // The read timeout IS the outbound poll cadence; without it this
    // single-thread design would stall outbound frames whenever the
    // host goes quiet. Failure is fatal for the session.
    if let Err(e) = stream.set_read_timeout(Some(POLL)) {
        crate::clog!("[tcp] {} read timeout unavailable: {:?} — rejecting", peer, e);
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    // Belt-and-braces against a peer that stops reading: bound write
    // stalls so a zombie can't pin its session slot forever. SO_SNDTIMEO
    // may be unsupported on this lwIP build — non-fatal, falls back to
    // pure blocking writes (the plan's intended backpressure behavior).
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let guard = bus.register();
    let id = guard.id;
    // Increment on the accept thread (before spawning) so the MAX check
    // above and the increment are serialized — no over-admission race.
    ACTIVE.fetch_add(1, Ordering::AcqRel);
    crate::clog!("[tcp] session {} from {}", id, peer);

    match std::thread::Builder::new()
        .name("tcp-sess".to_string())
        // 12 KB, up from the plan's 8 KB: 8 KB + the 1 KB read buffer
        // + error-format frames was tight, and a stack overflow on
        // ESP-IDF's std::net paths is a silent reboot — not worth the
        // 4 KB of heap on a 512 KB part.
        .stack_size(12 * 1024)
        .spawn(move || session(bus, guard, stream))
    {
        Ok(_) => {}
        Err(e) => {
            // The move closure was dropped => guard dropped => the modem
            // already got InMsg::Leave; just give the slot back.
            crate::clog!("[tcp] session {} spawn failed: {:?} (heap?)", id, e);
            ACTIVE.fetch_sub(1, Ordering::Release);
        }
    }
}

/// One session: one thread owning both socket directions and the guard.
/// Every exit path (peer close, socket error, write failure, channel
/// disconnect) tears the whole session down — no cross-thread unblock
/// coordination to get wrong.
fn session(bus: Arc<Bus>, guard: SessionGuard, mut stream: TcpStream) {
    let _slot = SessionSlot; // RAII: decrements ACTIVE on any exit
    let id = guard.id;
    let mut buf = [0u8; 1024]; // ~1 KB stack buffer covers any KISS frame

    'sess: loop {
        // ---- inbound: raw host bytes -> modem thread ----
        match stream.read(&mut buf) {
            Ok(0) => {
                crate::clog!("[tcp] session {}: peer closed", id);
                break 'sess;
            }
            Ok(n) => bus.send_in(id, buf[..n].to_vec()),
            // Poll-tick expiry: lwIP reports EWOULDBLOCK or ETIMEDOUT
            // depending on version; both just mean "nothing yet".
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            Err(e) => {
                crate::clog!("[tcp] session {}: read error: {}", id, e);
                break 'sess;
            }
        }
        // ---- outbound: drain pre-framed KISS frames -> host ----
        loop {
            match guard.rx.try_recv() {
                Ok(frame) => {
                    if let Err(e) = stream.write_all(&frame) {
                        crate::clog!("[tcp] session {}: write error: {}", id, e);
                        break 'sess;
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break 'sess,
            }
        }
    }

    // Teardown: FIN/RST to the peer. Drop order at scope end is locals
    // (reverse decl) then parameters (reverse decl): `_slot` ->
    // ACTIVE decrement FIRST, then `guard` -> bus unregister +
    // InMsg::Leave. The count is free before the (bounded) Leave send,
    // so a queued Leave never blocks a new client.
    // Connect/disconnect bursts cannot leak sessions.
    let _ = stream.shutdown(Shutdown::Both);
    crate::clog!("[tcp] session {} down", id);
}

/// RAII active-session slot: decrements the count when the session
/// thread exits, whatever the reason (incl. early return above).
struct SessionSlot;

impl Drop for SessionSlot {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::Release);
    }
}
