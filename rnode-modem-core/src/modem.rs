//! Multi-session modem: routes frames between any number of host links
//! (USB-CDC, WiFi-TCP sockets, ...) and one radio.
//!
//! Host data from any session goes to the air; over-the-air data is
//! fanned out to every session. Sessions are identified by a caller
//! supplied id (e.g. socket handle); the sender does not hear its own
//! transmissions back, matching real half-duplex radio behaviour (a
//! configurable `echo_self` exists for host-side tests).

use alloc::vec::Vec;

use crate::frame::{kiss_frame, FrameParser};
use crate::protocol::{CMD_DATA, Handled, Protocol, RadioOp};

/// One host link's parser state.
pub struct Session {
    parser: FrameParser,
}

impl Session {
    pub fn new() -> Self {
        Self {
            parser: FrameParser::new(),
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of feeding one session: bytes to write back to that session,
/// bytes to write to every *other* session, and radio operations.
pub struct Fed {
    pub to_sender: Vec<Vec<u8>>,
    pub to_others: Vec<Vec<u8>>,
    pub ops: Vec<RadioOp>,
}

impl Fed {
    fn empty() -> Self {
        Self {
            to_sender: Vec::new(),
            to_others: Vec::new(),
            ops: Vec::new(),
        }
    }
}

/// The modem: shared protocol state plus per-session parsers.
pub struct Modem {
    pub protocol: Protocol,
    sessions: Vec<(u64, Session)>,
    next_session: u64,
    echo_self: bool,
}

impl Modem {
    pub fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            sessions: Vec::new(),
            next_session: 1,
            echo_self: false,
        }
    }

    /// Enable self-echo of transmitted data (host tests only).
    pub fn with_echo_self(mut self, echo: bool) -> Self {
        self.echo_self = echo;
        self
    }

    /// Register a new host link; returns its session id.
    pub fn add_session(&mut self) -> u64 {
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.push((id, Session::new()));
        id
    }

    /// Session ids in creation order (for RX fan-out routing).
    pub fn session_ids(&self) -> Vec<u64> {
        self.sessions.iter().map(|(id, _)| *id).collect()
    }

    pub fn remove_session(&mut self, id: u64) {
        self.sessions.retain(|(sid, _)| *sid != id);
    }

    /// Feed bytes from a session into the modem.
    pub fn feed(&mut self, id: u64, bytes: &[u8]) -> Fed {
        let mut out = Fed::empty();
        // Auto-create sessions we haven't seen before (TCP sessions
        // register themselves with the session registry but not the
        // modem's internal parser — this was the TCP data blocker).
        if !self.sessions.iter().any(|(sid, _)| *sid == id) {
            self.sessions.push((id, Session::new()));
        }
        let Some((_, session)) = self.sessions.iter_mut().find(|(sid, _)| *sid == id) else {
            return out;
        };

        let protocol = &mut self.protocol;
        let echo_self = self.echo_self;
        let mut handled: Vec<Handled> = Vec::new();
        let mut forwarded: Vec<Vec<u8>> = Vec::new();

        session.parser.feed(bytes, |command, payload| {
            if command == CMD_DATA && !payload.is_empty() {
                // Data frames ride the shared channel: forward the frame
                // to the other hosts, and hand the payload to the radio.
                forwarded.push(kiss_frame(CMD_DATA, payload));
                handled.push(protocol.handle(command, payload));
            } else {
                handled.push(protocol.handle(command, payload));
            }
        });

        for h in handled {
            out.to_sender.extend(h.replies);
            out.ops.extend(h.ops);
        }
        for frame in forwarded {
            if echo_self {
                out.to_sender.push(frame.clone());
            }
            out.to_others.push(frame);
        }
        out
    }

    /// Push an over-the-air received packet out to every session.
    pub fn radio_rx(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.protocol.rx_packet();
        // One data frame per session; callers write each to its link.
        let n = self.sessions.len();
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(Protocol::data_frame(data));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DETECT_REQ;
    use crate::protocol::CMD_DETECT;

    #[test]
    fn two_sessions_share_the_channel_without_self_echo() {
        let mut modem = Modem::new(Protocol::new(0xC6));
        let a = modem.add_session();
        let b = modem.add_session();

        let fed = modem.feed(a, &kiss_frame(CMD_DATA, &[1, 2, 3]));
        // No CMD_DATA echo back to the sender (half-duplex radio), but
        // the flow-control READY reply is sender-bound by design.
        assert!(!fed
            .to_sender
            .iter()
            .any(|f| f.first() == Some(&0xC0) && f.get(1) == Some(&0x00)),
            "sender must not hear its own data back");
        assert_eq!(fed.to_others, vec![kiss_frame(CMD_DATA, &[1, 2, 3])]);
        assert_eq!(fed.ops.len(), 1);

        // Control replies still go to the sender only.
        let fed = modem.feed(a, &kiss_frame(CMD_DETECT, &[DETECT_REQ]));
        assert_eq!(fed.to_sender.len(), 4);
        assert!(fed.to_others.is_empty());
        let _ = b;
    }
}
