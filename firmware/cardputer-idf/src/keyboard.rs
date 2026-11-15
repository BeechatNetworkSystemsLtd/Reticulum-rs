//! TCA8418 keyboard scanner at I2C 0x34 (Cardputer ADV 7x8 matrix).
//! Register map and init sequence mirror Meshtastic's
//! TCA8418KeyboardBase::reset(). Polled on a 15 ms thread; the INT pin
//! (GPIO11) is left unconnected by design.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use esp_idf_hal::i2c::I2cDriver;

const ADDR: u8 = 0x34;
const TIMEOUT: u32 = 50; // FreeRTOS ticks

const REG_CFG: u8 = 0x01;
const REG_INT_STAT: u8 = 0x02;
const REG_KEY_LCK_EC: u8 = 0x03;
const REG_KEY_EVENT_A: u8 = 0x04;
const REG_GPIO_INT_STAT_1: u8 = 0x11;
const REG_INT_EN_1: u8 = 0x1A;
const REG_KP_GPIO_1: u8 = 0x1D;
const REG_KP_GPIO_2: u8 = 0x1E;
const REG_GPI_EM_1: u8 = 0x20;
const REG_GPIO_DIR_1: u8 = 0x23;
const REG_GPIO_INT_LVL_1: u8 = 0x26;
const REG_DEBOUNCE_DIS_1: u8 = 0x29;

/// Key events delivered to the UI thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Backspace,
    Enter,
    Esc,
    Left,
    Right,
    Up,
    Down,
}

// Encoded map entries: (base, shifted, fn'ed). ASCII bytes map to
// Key::Char; the codes below map to editing keys. 0 = ignore.
const K_NONE: u8 = 0x00;
const K_BS: u8 = 0x08;
const K_ENTER: u8 = 0x0D;
const K_ESC: u8 = 0x1B;
const K_LEFT: u8 = 0x80;
const K_RIGHT: u8 = 0x81;
const K_UP: u8 = 0x82;
const K_DOWN: u8 = 0x83;

// Matrix index = row*8 + col (event code k -> (k-1)/10 * 8 + (k-1)%10).
// 2 = Fn modifier, 6 = Shift modifier; 1, 3, 7, 11 unused/Tab.
#[rustfmt::skip]
const MAP: [(u8, u8, u8); 56] = [
    (b'`', b'~',  K_ESC ), // 0  `
    (K_NONE,K_NONE,K_NONE), // 1  Tab (ignored)
    (K_NONE,K_NONE,K_NONE), // 2  Fn
    (K_NONE,K_NONE,K_NONE), // 3
    (b'1', b'!',  K_NONE), // 4
    (b'q', b'Q',  K_NONE), // 5
    (K_NONE,K_NONE,K_NONE), // 6  Shift
    (K_NONE,K_NONE,K_NONE), // 7
    (b'2', b'@',  K_NONE), // 8
    (b'w', b'W',  K_NONE), // 9
    (b'a', b'A',  K_NONE), // 10
    (K_NONE,K_NONE,K_NONE), // 11
    (b'3', b'#',  K_NONE), // 12
    (b'e', b'E',  K_NONE), // 13
    (b's', b'S',  K_NONE), // 14
    (b'z', b'Z',  K_NONE), // 15
    (b'4', b'$',  K_NONE), // 16
    (b'r', b'R',  K_NONE), // 17
    (b'd', b'D',  K_NONE), // 18
    (b'x', b'X',  K_NONE), // 19
    (b'5', b'%',  K_NONE), // 20
    (b't', b'T',  K_NONE), // 21
    (b'f', b'F',  K_NONE), // 22
    (b'c', b'C',  K_NONE), // 23
    (b'6', b'^',  K_NONE), // 24
    (b'y', b'Y',  K_NONE), // 25
    (b'g', b'G',  K_NONE), // 26
    (b'v', b'V',  K_NONE), // 27
    (b'7', b'&',  K_NONE), // 28
    (b'u', b'U',  K_NONE), // 29
    (b'h', b'H',  K_NONE), // 30
    (b'b', b'B',  K_NONE), // 31
    (b'8', b'*',  K_NONE), // 32
    (b'i', b'I',  K_NONE), // 33
    (b'j', b'J',  K_NONE), // 34
    (b'n', b'N',  K_NONE), // 35
    (b'9', b'(',  K_NONE), // 36
    (b'o', b'O',  K_NONE), // 37
    (b'k', b'K',  K_NONE), // 38
    (b'm', b'M',  K_NONE), // 39
    (b'0', b')',  K_NONE), // 40
    (b'p', b'P',  K_NONE), // 41
    (b'l', b'L',  K_NONE), // 42
    (b',', b'<',  K_LEFT), // 43
    (b'_', b'-',  K_NONE), // 44
    (b'[', b'{',  K_NONE), // 45
    (b';', b':',  K_UP  ), // 46
    (b'.', b'>',  K_DOWN), // 47
    (b'=', b'+',  K_NONE), // 48
    (b']', b'}',  K_NONE), // 49
    (b'\'',b'"',  K_NONE), // 50
    (b'/', b'?',  K_RIGHT),// 51
    (K_BS, K_BS,  K_BS  ), // 52  Backspace
    (b'\\',b'|',  K_NONE), // 53
    (K_ENTER,K_ENTER,K_ENTER), // 54 Enter
    (b' ', b' ',  K_NONE), // 55  Space
];

const IDX_FN: usize = 2;
const IDX_SHIFT: usize = 6;
const MOD_EXPIRY: Duration = Duration::from_millis(1500);

/// ACK probe for the TCA8418 — run against each candidate bus driver;
/// first `true` wins. Mirrors the PI4IOE probe in main.rs.
pub fn probe(i2c: &mut I2cDriver<'_>) -> bool {
    i2c.write(ADDR, &[], TIMEOUT).is_ok()
}

fn write_reg(i2c: &mut I2cDriver<'_>, reg: u8, val: u8) -> anyhow::Result<()> {
    i2c.write(ADDR, &[reg, val], TIMEOUT).map_err(Into::into)
}

fn read_reg(i2c: &mut I2cDriver<'_>, reg: u8) -> anyhow::Result<u8> {
    let mut b = [0u8; 1];
    i2c.write_read(ADDR, &[reg], &mut b, TIMEOUT)?;
    Ok(b[0])
}

/// Meshtastic reset(): pin muxing into keypad mode, then FIFO drain.
fn init(i2c: &mut I2cDriver<'_>) -> anyhow::Result<()> {
    for i in 0..3 {
        write_reg(i2c, REG_GPIO_DIR_1 + i, 0x00)?; // all GPIO as inputs
        write_reg(i2c, REG_GPI_EM_1 + i, 0xFF)?; // GPI events enabled
        write_reg(i2c, REG_GPIO_INT_LVL_1 + i, 0x00)?; // int on rising
        write_reg(i2c, REG_INT_EN_1 + i, 0xFF)?; // GPI int enable
        write_reg(i2c, REG_DEBOUNCE_DIS_1 + i, 0x00)?; // debounce ON
    }
    write_reg(i2c, REG_KP_GPIO_1, 0x7F)?; // rows 0-6 in keypad matrix
    write_reg(i2c, REG_KP_GPIO_2, 0xFF)?; // cols 0-7 in keypad matrix
    write_reg(i2c, REG_CFG, 0x11)?; // KE_IEN | INT_CFG (level int)

    // Drain any events queued during init, then clear pending ints.
    for _ in 0..10 {
        if read_reg(i2c, REG_KEY_EVENT_A)? == 0 {
            break;
        }
    }
    for i in 0..3 {
        let _ = read_reg(i2c, REG_GPIO_INT_STAT_1 + i)?;
    }
    write_reg(i2c, REG_INT_STAT, 0x03)
}

struct Mods {
    shift: bool,
    fn_: bool,
    since: Instant,
}

impl Mods {
    fn new() -> Self {
        Self { shift: false, fn_: false, since: Instant::now() }
    }

    fn toggle(&mut self, m: Modifier) {
        if self.since.elapsed() > MOD_EXPIRY {
            self.shift = false;
            self.fn_ = false;
        }
        match m {
            Modifier::Shift => self.shift = !self.shift,
            Modifier::Fn => self.fn_ = !self.fn_,
        }
        self.since = Instant::now();
    }

    /// Layer for a fresh keypress; clears both latches (one-shot) and
    /// the 1500 ms expiry.
    fn take(&mut self) -> u8 /* column into MAP */ {
        if self.since.elapsed() > MOD_EXPIRY {
            self.shift = false;
            self.fn_ = false;
        }
        let col = if self.fn_ { 2 } else if self.shift { 1 } else { 0 };
        self.shift = false;
        self.fn_ = false;
        col
    }
}

#[derive(Clone, Copy)]
enum Modifier {
    Shift,
    Fn,
}

fn decode(code: u8) -> Option<Key> {
    Some(match code {
        K_NONE => return None,
        K_BS => Key::Backspace,
        K_ENTER => Key::Enter,
        K_ESC => Key::Esc,
        K_LEFT => Key::Left,
        K_RIGHT => Key::Right,
        K_UP => Key::Up,
        K_DOWN => Key::Down,
        c => Key::Char(c as char),
    })
}

fn matrix_index(code: u8) -> Option<usize> {
    let k = code.checked_sub(1)?;
    let (row, col) = (k / 10, k % 10);
    (row < 7 && col < 8).then_some(row as usize * 8 + col as usize)
}

fn run(i2c: Arc<Mutex<I2cDriver<'static>>>, tx: Sender<Key>) {
    let mut mods = Mods::new();
    loop {
        thread::sleep(Duration::from_millis(15));
        let mut i2c = match i2c.lock() {
            Ok(g) => g,
            Err(_) => return, // poisoned: owner panicked, nothing to do
        };
        let count = read_reg(&mut i2c, REG_KEY_LCK_EC)
            .map(|v| v & 0x0F)
            .unwrap_or(0);
        for _ in 0..count {
            let Ok(event) = read_reg(&mut i2c, REG_KEY_EVENT_A) else {
                break;
            };
            let code = event & 0x7F;
            if code == 0 || event & 0x80 == 0 {
                continue; // release events and empty reads: ignore
            }
            let Some(index) = matrix_index(code) else {
                continue;
            };
            let key = match index {
                IDX_SHIFT => {
                    mods.toggle(Modifier::Shift);
                    continue;
                }
                IDX_FN => {
                    mods.toggle(Modifier::Fn);
                    continue;
                }
                i => {
                    let (b, s, f) = MAP[i];
                    decode(match mods.take() {
                        2 => f,
                        1 => s,
                        _ => b,
                    })
                }
            };
            if let Some(key) = key {
                // shortcut: emit on each hardware press, add timed
                // hold repeat only if the TCA does not repeat on-device.
                if tx.send(key).is_err() {
                    return; // UI went away
                }
            }
        }
        if count != 0 {
            let _ = write_reg(&mut i2c, REG_INT_STAT, 0x03);
        }
    }
}

/// Initialize the TCA8418 on the shared bus, then spawn the 'kb'
/// polling thread. The driver must live behind `'static` ownership —
/// the returned receiver is the only keyboard handle.
pub fn spawn(i2c: Arc<Mutex<I2cDriver<'static>>>) -> anyhow::Result<Receiver<Key>> {
    {
        let mut guard = i2c.lock().map_err(|_| anyhow::anyhow!("i2c mutex poisoned"))?;
        init(&mut guard)?;
    }
    let (tx, rx) = channel();
    thread::Builder::new()
        .name("kb".into())
        .stack_size(4096)
        .spawn(move || run(i2c, tx))?;
    Ok(rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_rejects_unwired_columns_and_maps_last_key() {
        assert_eq!(matrix_index(0), None);
        assert_eq!(matrix_index(9), None);
        assert_eq!(matrix_index(68), Some(55));
        assert_eq!(matrix_index(71), None);
        assert_eq!(decode(MAP[52].0), Some(Key::Backspace));
        assert_eq!(decode(MAP[54].0), Some(Key::Enter));
        assert_eq!(decode(MAP[43].2), Some(Key::Left));
        assert_eq!(decode(MAP[5].1), Some(Key::Char('Q')));
    }

    #[test]
    fn modifiers_are_one_shot_toggleable_and_expire() {
        let mut mods = Mods::new();
        mods.toggle(Modifier::Shift);
        assert_eq!(mods.take(), 1);
        assert_eq!(mods.take(), 0);
        mods.toggle(Modifier::Fn);
        mods.toggle(Modifier::Fn);
        assert_eq!(mods.take(), 0);
        mods.toggle(Modifier::Shift);
        mods.since = Instant::now() - MOD_EXPIRY - Duration::from_millis(1);
        assert_eq!(mods.take(), 0);
        mods.toggle(Modifier::Shift);
        mods.since = Instant::now() - MOD_EXPIRY - Duration::from_millis(1);
        mods.toggle(Modifier::Shift);
        assert_eq!(mods.take(), 1);
    }
}
