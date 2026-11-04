// The caller spawns the UI thread with Display, keys from keyboard::spawn, and action/event channels from chat_stack::spawn.

use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use embedded_graphics::prelude::*;

use crate::chat_stack::{ChatAction, ChatEvent};
use crate::display::Display;
use crate::keyboard::Key;
use crate::ui::{ChatLine, ChatUi, PeerInfo, MSG_LINES};

// Fits the 29-column status strip; ; . navigate without Fn on this screen.
const PEER_HINT: &str = "; up  . down  enter open";
const TICK: Duration = Duration::from_millis(50);
const REDRAW: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
enum Screen {
    Peers,
    Chat { peer_idx: usize },
}

struct Peer {
    hash: [u8; 16],
    name: String,
    hash_hex: String,
    lines: Vec<ChatLine>,
}

struct State {
    screen: Screen,
    peers: Vec<Peer>,
    compose: String,
    selected: usize,
    status: String,
}

impl State {
    fn new() -> Self {
        Self {
            screen: Screen::Peers,
            peers: Vec::new(),
            compose: String::new(),
            selected: 0,
            status: PEER_HINT.into(),
        }
    }

    fn upsert(&mut self, hash: [u8; 16], name: String) -> usize {
        if let Some(idx) = self.peers.iter().position(|peer| peer.hash == hash) {
            self.peers[idx].name = name;
            return idx;
        }
        self.peers.push(Peer {
            hash,
            name,
            hash_hex: format!("{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3]),
            lines: Vec::new(),
        });
        self.peers.len() - 1
    }

    fn key(&mut self, key: Key, actions: &Sender<ChatAction>) -> bool {
        // Peer list is a menu (Meshtastic parity on this keyboard): the
        // arrow-printed keys ; . and the Esc key ` work without Fn there.
        // In the chat screen they type characters; Fn+key still works.
        let key = match (self.screen, key) {
            (Screen::Peers, Key::Char(';')) => Key::Up,
            (Screen::Peers, Key::Char('.')) => Key::Down,
            (Screen::Peers, Key::Char('`')) => Key::Esc,
            _ => key,
        };
        match (self.screen, key) {
            (Screen::Peers, Key::Up | Key::Down) if !self.peers.is_empty() => {
                let count = self.peers.len();
                self.selected = if key == Key::Up {
                    (self.selected + count - 1) % count
                } else {
                    (self.selected + 1) % count
                };
            }
            (Screen::Peers, Key::Enter) if !self.peers.is_empty() => {
                self.screen = Screen::Chat { peer_idx: self.selected };
            }
            (Screen::Peers, Key::Esc) => {
                self.status = if actions.send(ChatAction::Announce).is_ok() {
                    "announcing..."
                } else {
                    "chat stack disconnected"
                }.into();
            }
            (Screen::Chat { .. }, Key::Char(ch)) if self.compose.chars().count() < 240 => {
                self.compose.push(ch);
            }
            (Screen::Chat { .. }, Key::Backspace) => {
                return self.compose.pop().is_some();
            }
            (Screen::Chat { peer_idx }, Key::Enter) if !self.compose.is_empty() => {
                let body = std::mem::take(&mut self.compose);
                let action = ChatAction::Send {
                    dest_hash: self.peers[peer_idx].hash,
                    body: body.clone(),
                };
                if actions.send(action).is_ok() {
                    self.peers[peer_idx].lines.push(ChatLine::Me { text: body, ack: false });
                } else {
                    self.compose = body;
                    self.status = "chat stack disconnected".into();
                }
            }
            (Screen::Chat { .. }, Key::Esc) => self.screen = Screen::Peers,
            _ => return false,
        }
        true
    }

    fn event(&mut self, event: ChatEvent) {
        match event {
            ChatEvent::Peer { dest_hash, name } => {
                self.upsert(dest_hash, name);
            }
            ChatEvent::Received { from, name, body } => {
                let idx = self.upsert(from, name);
                self.peers[idx].lines.push(ChatLine::Them { text: body });
            }
            ChatEvent::Receipt { dest_hash } => {
                if let Some(peer) = self.peers.iter_mut().find(|peer| peer.hash == dest_hash) {
                    for line in peer.lines.iter_mut().rev() {
                        if let ChatLine::Me { ack, .. } = line {
                            if !*ack {
                                *ack = true;
                                break;
                            }
                        }
                    }
                }
            }
            ChatEvent::Status(status) => self.status = status,
        }
    }

    fn render(&self, ui: &mut ChatUi<Display>) -> Result<(), <Display as DrawTarget>::Error> {
        match self.screen {
            Screen::Peers => {
                let mut rows: [PeerInfo<'_>; MSG_LINES] = std::array::from_fn(|_| PeerInfo {
                    name: "", hash_hex: "", active: false,
                });
                let start = self.selected.saturating_sub(rows.len() - 1);
                let visible = (self.peers.len() - start).min(rows.len());
                for (row, (idx, peer)) in rows.iter_mut().zip(self.peers.iter().enumerate().skip(start)) {
                    *row = PeerInfo {
                        name: prefix(&peer.name, 16),
                        hash_hex: &peer.hash_hex,
                        active: idx == self.selected,
                    };
                }
                ui.peers(&rows[..visible], self.status.lines().next().unwrap_or(""))
            }
            Screen::Chat { peer_idx } => {
                let peer = &self.peers[peer_idx];
                ui.chat(&peer.name, &peer.lines, &self.compose, &self.status)
            }
        }
    }
}

fn prefix(text: &str, chars: usize) -> &str {
    &text[..text.char_indices().nth(chars).map_or(text.len(), |(idx, _)| idx)]
}

pub fn run(
    display: crate::display::Display,
    keys: Receiver<crate::keyboard::Key>,
    actions: Sender<crate::chat_stack::ChatAction>,
    events: Receiver<crate::chat_stack::ChatEvent>,
) -> anyhow::Result<()> {
    let mut ui = ChatUi::new(display);
    if let Err(error) = ui.boot_splash("reticulum chat\ninitializing...") {
        crate::clog!("chat UI: splash draw failed: {error:?}");
    }
    let mut state = State::new();
    let mut dirty = match state.render(&mut ui) {
        Ok(()) => false,
        Err(error) => {
            crate::clog!("chat UI: draw failed: {error:?}");
            true
        }
    };
    let mut last_render = Instant::now();
    loop {
        let tick = Instant::now();
        while let Ok(key) = keys.try_recv() {
            dirty |= state.key(key, &actions);
        }
        while let Ok(event) = events.try_recv() {
            state.event(event);
            dirty = true;
        }
        if dirty && last_render.elapsed() >= REDRAW {
            dirty = match state.render(&mut ui) {
                Ok(()) => false,
                Err(error) => {
                    crate::clog!("chat UI: draw failed: {error:?}");
                    true
                }
            };
            last_render = Instant::now();
        }
        thread::sleep(TICK.saturating_sub(tick.elapsed()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    #[test]
    fn menu_keys_navigate_but_remain_text_in_chat() {
        let mut state = State::new();
        let (tx, rx) = channel();
        state.upsert([1; 16], "first".into());
        state.upsert([2; 16], "second".into());
        state.key(Key::Char(';'), &tx);
        assert_eq!(state.selected, 1);
        state.key(Key::Char('.'), &tx);
        assert_eq!(state.selected, 0);
        state.key(Key::Enter, &tx);
        assert!(matches!(state.screen, Screen::Chat { peer_idx: 0 }));
        for ch in ";.`".chars() {
            state.key(Key::Char(ch), &tx);
        }
        assert_eq!(state.compose, ";.`");
        assert!(matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
        state.key(Key::Esc, &tx);
        assert!(matches!(state.screen, Screen::Peers));
    }

    #[test]
    fn empty_enter_does_not_send_and_nonempty_enter_does() {
        let mut state = State::new();
        let (tx, rx) = channel();
        state.upsert([1; 16], "peer".into());
        state.key(Key::Enter, &tx);
        assert!(!state.key(Key::Enter, &tx));
        assert!(state.peers[0].lines.is_empty());
        assert!(matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
        state.key(Key::Char('h'), &tx);
        state.key(Key::Enter, &tx);
        assert!(matches!(rx.try_recv(), Ok(ChatAction::Send { dest_hash, body })
            if dest_hash == [1; 16] && body == "h"));
        assert!(state.compose.is_empty());
        assert!(matches!(&state.peers[0].lines[0],
            ChatLine::Me { text, ack: false } if text == "h"));
    }

    #[test]
    fn peers_dedupe_and_receipts_ack_latest_pending_message() {
        let mut state = State::new();
        let hash = [1; 16];
        state.event(ChatEvent::Peer { dest_hash: hash, name: "old".into() });
        state.event(ChatEvent::Received { from: hash, name: "new".into(), body: "hello".into() });
        assert_eq!(state.peers.len(), 1);
        assert_eq!(state.peers[0].name, "new");
        state.peers[0].lines.push(ChatLine::Me { text: "first".into(), ack: false });
        state.peers[0].lines.push(ChatLine::Me { text: "second".into(), ack: false });
        state.event(ChatEvent::Receipt { dest_hash: hash });
        assert!(matches!(state.peers[0].lines[1], ChatLine::Me { ack: false, .. }));
        assert!(matches!(state.peers[0].lines[2], ChatLine::Me { ack: true, .. }));
    }

    #[test]
    fn compose_limits_characters_and_preserves_text_on_disconnected_send() {
        let mut state = State::new();
        let (tx, rx) = channel();
        state.upsert([1; 16], "peer".into());
        state.key(Key::Enter, &tx);
        for _ in 0..241 {
            state.key(Key::Char('é'), &tx);
        }
        assert_eq!(state.compose.chars().count(), 240);
        state.key(Key::Backspace, &tx);
        assert_eq!(state.compose.chars().count(), 239);
        assert_eq!(prefix("ééé", 2), "éé");
        drop(rx);
        state.key(Key::Enter, &tx);
        assert_eq!(state.compose.chars().count(), 239);
        assert!(state.peers[0].lines.is_empty());
    }
}
