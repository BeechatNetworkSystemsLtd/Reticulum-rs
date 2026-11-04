//! 240x135 chat UI on embedded-graphics, mono 8x13 font, full redraw
//! per call (no framebuffer — 40 MHz SPI makes that cheap).
//!
//! Layout (all derived from the font size): 1 px border, one text-row
//! header, MSG_LINES message rows, one text-row compose/status strip.

use embedded_graphics::mono_font::{ascii::FONT_8X13, MonoTextStyle};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::{Line, PrimitiveStyle, Rectangle};
use embedded_graphics::text::{Baseline, Text};

const CHAR_W: i32 = FONT_8X13.character_size.width as i32;
const LINE_H: i32 = FONT_8X13.character_size.height as i32;
const W: i32 = 240;
const H: i32 = 135;
/// Usable chars per row inside the border and 3 px side margins (29).
const COLS: usize = ((W - 8) / CHAR_W) as usize;
const HEADER_Y: i32 = LINE_H + 2; // divider under the header row
const MSG_TOP: i32 = HEADER_Y + 2;
const COMPOSE_Y: i32 = H - LINE_H - 2; // divider above the compose strip
/// Message (or peer) rows between the dividers (7).
pub const MSG_LINES: usize = ((COMPOSE_Y - MSG_TOP) / LINE_H) as usize;

/// One peer list row: display name, hex hash, active-selection flag.
pub struct PeerInfo<'a> {
    pub name: &'a str,
    pub hash_hex: &'a str,
    pub active: bool,
}

/// One chat log entry.
pub enum ChatLine {
    Me { text: String, ack: bool },
    Them { text: String },
}

pub struct ChatUi<D: DrawTarget<Color = Rgb565>> {
    pub display: D,
    style: MonoTextStyle<'static, Rgb565>,
    dim: MonoTextStyle<'static, Rgb565>,
}

impl<D: DrawTarget<Color = Rgb565>> ChatUi<D> {
    pub fn new(display: D) -> Self {
        Self {
            display,
            style: MonoTextStyle::new(&FONT_8X13, Rgb565::WHITE),
            dim: MonoTextStyle::new(&FONT_8X13, Rgb565::CSS_DIM_GRAY),
        }
    }

    fn frame(&mut self) -> Result<(), D::Error> {
        self.display.clear(Rgb565::BLACK)?;
        Rectangle::new(Point::zero(), Size::new(W as u32, H as u32))
            .into_styled(PrimitiveStyle::with_stroke(Rgb565::CSS_DIM_GRAY, 1))
            .draw(&mut self.display)?;
        Ok(())
    }

    /// y is the glyph top.
    fn text(&mut self, x: i32, y: i32, s: &str, style: MonoTextStyle<'_, Rgb565>) -> Result<(), D::Error> {
        Text::with_baseline(s, Point::new(x, y), style, Baseline::Top).draw(&mut self.display)?;
        Ok(())
    }

    /// Boot screen: title + status line.
    pub fn boot_splash(&mut self, status: &str) -> Result<(), D::Error> {
        self.frame()?;
        self.text(4, H / 2 - LINE_H - 1, "reticulum // cardputer", self.style)?;
        let mut row = Row::new("");
        row.append(status);
        self.text(4, H / 2 + 2, row.as_str(), self.dim)?;
        Ok(())
    }

    /// Peer list. `active` rows get a '*' marker; `status` fills the
    /// bottom strip (key hint or the latest stack status line).
    pub fn peers(&mut self, peers: &[PeerInfo<'_>], status: &str) -> Result<(), D::Error> {
        self.frame()?;
        self.text(4, 1, "peers", self.style)?;
        self.hline(HEADER_Y)?;
        for (i, p) in peers.iter().enumerate().take(MSG_LINES) {
            let mut row = Row::new(if p.active { "* " } else { "  " });
            row.append(p.name);
            row.append("  ");
            row.append(p.hash_hex);
            self.text(4, MSG_TOP + i as i32 * LINE_H, row.as_str(), self.style)?;
        }
        self.hline(COMPOSE_Y)?;
        let mut row = Row::new("");
        row.append(status);
        self.text(4, COMPOSE_Y + 1, row.as_str(), self.dim)?;
        Ok(())
    }

    /// Chat view for one peer. Renders the tail of `lines` (hard char
    /// wrap at COLS), "> " prefix for our messages (+ for acked),
    /// "< " for theirs. `compose` gets a trailing '_' cursor.
    pub fn chat(
        &mut self,
        peer_name: &str,
        lines: &[ChatLine],
        compose: &str,
        info: &str,
    ) -> Result<(), D::Error> {
        self.frame()?;
        let mut hdr = Row::new("");
        for c in peer_name.chars().take(20) {
            hdr.push(c);
        }
        hdr.append("  ");
        hdr.append(info);
        self.text(4, 1, hdr.as_str(), self.style)?;
        self.hline(HEADER_Y)?;

        // Only retain the visible rows; rendering never allocates.
        let mut rows = [Row::new(""); MSG_LINES];
        let mut total = 0usize;
        for line in lines {
            let (prefix, text) = match line {
                ChatLine::Me { text, ack } => (if *ack { ">+" } else { "> " }, text.as_str()),
                ChatLine::Them { text } => ("< ", text.as_str()),
            };
            let mut row = Row::new(prefix);
            for c in text.chars() {
                if c == '\n' || row.len == COLS {
                    rows[total % MSG_LINES] = row;
                    total += 1;
                    row = Row::new("  ");
                    if c == '\n' {
                        continue;
                    }
                }
                row.push(c);
            }
            rows[total % MSG_LINES] = row;
            total += 1;
        }
        for (y, i) in (total.saturating_sub(MSG_LINES)..total).enumerate() {
            self.text(4, MSG_TOP + y as i32 * LINE_H, rows[i % MSG_LINES].as_str(), self.style)?;
        }

        self.hline(COMPOSE_Y)?;
        let mut line = Row::new(">");
        // Show the tail so the cursor follows long input.
        let skip = compose.chars().count().saturating_sub(COLS - 2);
        for c in compose.chars().skip(skip) {
            line.push(c);
        }
        line.push('_');
        self.text(4, COMPOSE_Y + 1, line.as_str(), self.style)?;
        Ok(())
    }

    fn hline(&mut self, y: i32) -> Result<(), D::Error> {
        Line::new(Point::new(1, y), Point::new(W - 2, y))
            .into_styled(PrimitiveStyle::with_stroke(Rgb565::CSS_DIM_GRAY, 1))
            .draw(&mut self.display)?;
        Ok(())
    }
}

/// The builtin font is ASCII: replace unsupported/control characters.
#[derive(Clone, Copy)]
struct Row {
    bytes: [u8; COLS],
    len: usize,
}

impl Row {
    const fn new(prefix: &str) -> Self {
        let mut row = Self { bytes: [b' '; COLS], len: 0 };
        let bytes = prefix.as_bytes();
        let mut i = 0;
        while i < bytes.len() && i < COLS {
            row.bytes[i] = bytes[i];
            i += 1;
        }
        row.len = i;
        row
    }

    fn push(&mut self, c: char) {
        if self.len < COLS {
            self.bytes[self.len] = if c.is_ascii_graphic() || c == ' ' { c as u8 } else { b'?' };
            self.len += 1;
        }
    }

    fn append(&mut self, s: &str) {
        for c in s.chars().take(COLS - self.len) {
            self.push(c);
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("ASCII row")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_clip_and_replace_unsupported_glyphs() {
        let mut row = Row::new("> ");
        row.append("é\n");
        assert_eq!(row.as_str(), "> ??");
        row.append(&"x".repeat(COLS));
        assert_eq!(row.len, COLS);
    }
}
