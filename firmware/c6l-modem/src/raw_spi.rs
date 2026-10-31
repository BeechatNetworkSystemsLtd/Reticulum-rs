// shortcut: whole-module bringup diagnostic feeding init_bitbang; not in the serving path
#![allow(dead_code)]

//! Raw GPSPI2 register-level SPI driver for the ESP32-C6.
//!
//! Bypasses the esp-hal SPI driver's per-transfer configuration entirely.
//! The peripheral is initially set up by esp-hal's `Spi::new()` (clock
//! source, pin routing, etc.), but every data transfer below uses direct
//! register access mirroring ESP-IDF's `spi_master` sequence:
//!
//! 1. wait for idle (CMD.USR == 0)
//! 2. configure USER/USER1/USER2/MS_DLEN
//! 3. fill the FIFO (W0..W15)
//! 4. sync registers (CMD.UPDATE pulse)
//! 5. start (CMD.USR = 1) and wait for completion
//! 6. drain the FIFO
//!
//! CS is handled by the caller (GPIO output), matching the SX1262's
//! requirement that NCS stay LOW for the entire opcode+payload sequence.

/// GPSPI2 register block base on ESP32-C6 (from the PAC).
const BASE: usize = 0x6008_1000;

// Offsets verified from esp32c6 PAC field docs.
const CMD: usize = BASE + 0x00;
const ADDR: usize = BASE + 0x04;
const CTRL: usize = BASE + 0x08;
const CLOCK: usize = BASE + 0x0C;
const USER: usize = BASE + 0x10;
const USER1: usize = BASE + 0x14;
const USER2: usize = BASE + 0x18;
const MS_DLEN: usize = BASE + 0x1C;
const MISC: usize = BASE + 0x20;
const DIN_MODE: usize = BASE + 0x24;
const DIN_NUM: usize = BASE + 0x28;
const DOUT_MODE: usize = BASE + 0x2C;
const DMA_INT_CLR: usize = BASE + 0x38;
const W: usize = BASE + 0x98; // W[0..16], 4 bytes each

// CMD register bits (PAC: UPDATE at 23, USR at 24).
const CMD_UPDATE: u32 = 1 << 23;
const CMD_USR: u32 = 1 << 24;

// USER register bits (PAC: DOUTDIN 0, CS_HOLD 6, CS_SETUP 7,
// USR_MISO 28, USR_MOSI 27, USR_DUMMY 29, USR_ADDR 30, USR_COMMAND 31).
const USER_DOUTDIN: u32 = 1 << 0;
const USER_CS_HOLD: u32 = 1 << 6;
const USER_CS_SETUP: u32 = 1 << 7;
const USER_USR_MOSI: u32 = 1 << 27;
const USER_USR_MISO: u32 = 1 << 28;

/// Good default USER value: full-duplex, MOSI+MISO phases only, CS
/// setup/hold enabled, no dummy/address/command phases, no QPI/OPI.
const USER_FULL_DUPLEX: u32 =
    USER_DOUTDIN | USER_USR_MOSI | USER_USR_MISO;

#[inline(always)]
fn read(reg: usize) -> u32 {
    unsafe { core::ptr::read_volatile(reg as *const u32) }
}

#[inline(always)]
fn write(reg: usize, val: u32) {
    unsafe { core::ptr::write_volatile(reg as *mut u32, val) }
}

/// Blocking full-duplex transfer of `buf.len()` bytes (max 64).
///
/// On return, `buf` contains the data received on MISO while the
/// original contents were shifted out on MOSI.
/// Initialize the SPI bus to match ESP-IDF's spi_master defaults.
/// Call once after Spi::new() but before any transfers.
pub fn bus_init() {
    // Ensure master mode (SLAVE register = 0)
    write(BASE + 0xE0, 0); // SLAVE
    // Clear any stale address
    write(BASE + 0x04, 0); // ADDR
    // MISC: enable CS0, disable CS1-5, normal clock
    write(BASE + 0x20, 0); // MISC
    // Clear DMA configuration (CPU-controlled FIFO mode)
    let dma = read(BASE + 0x30); // DMA_CONF
    write(BASE + 0x30, dma & !((1 << 27) | (1 << 28))); // clear DMA_RX_ENA, DMA_TX_ENA
    // USER: set full-duplex with proper defaults
    write(USER, USER_FULL_DUPLEX);
    // USER1: CS setup/hold times (ESP-IDF default: 0 for both)
    write(USER1, 0);
    // USER2: no command
    write(USER2, 0);
}

pub fn transfer(buf: &mut [u8]) -> Result<(), &'static str> {
    let len = buf.len();
    if len == 0 || len > 64 {
        return Err("len out of range");
    }

    // 1. Wait for the SPI to be idle.
    let mut t = 0u32;
    while read(CMD) & CMD_USR != 0 {
        t += 1;
        if t > 1_000_000 {
            return Err("busy timeout");
        }
    }

    // 2. Set data length (this is ALL the per-transaction config we do,
    //    matching ESP-IDF's spi_device_polling_transmit for single bytes).
    write(MS_DLEN, (len as u32) * 8 - 1);


    // 3. Fill TX FIFO (little-endian: byte 0 at bits [7:0], matching ESP-IDF).
    for (i, chunk) in buf.chunks(4).enumerate() {
        let mut word: u32 = 0;
        for (j, &b) in chunk.iter().enumerate() {
            word |= (b as u32) << (j * 8);
        }
        write(W + i * 4, word);
    }

    // 4. Sync (UPDATE pulse — this is what ESP-IDF does before each transfer).
    let cmd = read(CMD);
    write(CMD, cmd | CMD_UPDATE);
    t = 0;
    while read(CMD) & CMD_UPDATE != 0 {
        t += 1;
        if t > 1_000_000 {
            return Err("update timeout");
        }
    }

    // Clear stale interrupt.
    write(DMA_INT_CLR, 1 << 9);

    // 5. Start.
    write(CMD, CMD_USR);

    t = 0;
    while read(CMD) & CMD_USR != 0 {
        t += 1;
        if t > 10_000_000 {
            return Err("transfer timeout");
        }
    }

    // 6. Read RX FIFO (little-endian, matching ESP-IDF).
    for (i, chunk) in buf.chunks_mut(4).enumerate() {
        let word = read(W + i * 4);
        for (j, b) in chunk.iter_mut().enumerate() {
            *b = ((word >> (j * 8)) & 0xFF) as u8;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Bit-bang SPI fallback: manually toggle SCK/MOSI via GPIO registers.
// Used to verify the hardware path works independently of the SPI peripheral.
// Pins: SCK=GPIO20, MOSI=GPIO21, MISO=GPIO22, CS=GPIO23.
// ---------------------------------------------------------------------------

// GPIO peripheral (base 0x6009_1000, verified offsets).
const GPIO_OUT: usize = 0x6009_1004;
const GPIO_OUT_W1TS: usize = 0x6009_1008;
const GPIO_OUT_W1TC: usize = 0x6009_100C;
const GPIO_ENABLE: usize = 0x6009_1020;
const GPIO_IN: usize = 0x6009_103C;

// IO_MUX (base 0x6009_0004 + n*4) — MCU_SEL=1 for GPIO function.
const IO_MUX_BASE: usize = 0x6009_0004;

const PIN_SCK: u32 = 20;
const PIN_MOSI: u32 = 21;
const PIN_MISO: u32 = 22;
const PIN_CS: u32 = 23;

#[inline(always)]
pub fn gpio_set(pin: u32) {
    unsafe { core::ptr::write_volatile(GPIO_OUT_W1TS as *mut u32, 1 << pin) };
}

#[inline(always)]
pub fn gpio_clr(pin: u32) {
    unsafe { core::ptr::write_volatile(GPIO_OUT_W1TC as *mut u32, 1 << pin) };
}

#[inline(always)]
pub fn gpio_read(pin: u32) -> u32 {
    (unsafe { core::ptr::read_volatile(GPIO_IN as *const u32) } >> pin) & 1
}

/// Reconfigure SCK/MOSI/MISO pads from SPI function to plain GPIO.
/// The SPI peripheral loses its pins; call `bitbang_restore_spi_pins` to
/// give them back (usually requires re-running `with_sck` etc., so a
/// reset is the practical way).
pub fn bitbang_claim_pins() {
    unsafe {
        for &pin in &[PIN_SCK, PIN_MOSI, PIN_MISO] {
            // 1. IO_MUX: set MCU_SEL=1 (GPIO function via GPIO matrix)
            let reg = (IO_MUX_BASE + pin as usize * 4) as *mut u32;
            let cur = core::ptr::read_volatile(reg);
            core::ptr::write_volatile(reg, (cur & !0x1F) | 1 | (1 << 5)); // MCU_SEL=1, FUN_IE=1
            // 2. GPIO matrix: set OUT_SEL=128 (GPIO_OUT_REG controls the pad)
            let func_out = (0x6009_1000 + 0x554 + pin as usize * 4) as *mut u32;
            core::ptr::write_volatile(func_out, 128);
        }
        // 3. GPIO_ENABLE: enable output for SCK and MOSI, disable for MISO
        let en = core::ptr::read_volatile(GPIO_ENABLE as *const u32);
        core::ptr::write_volatile(
            GPIO_ENABLE as *mut u32,
            (en | (1 << PIN_SCK) | (1 << PIN_MOSI)) & !(1 << PIN_MISO),
        );
        // Idle levels
        gpio_clr(PIN_SCK);
        gpio_clr(PIN_MOSI);
    }
}

/// Bit-bang a full-duplex SPI Mode 0 transfer (slow, ~200 kHz).
/// CS must be handled by the caller.
pub fn bitbang_transfer(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        let mut rx: u8 = 0;
        let tx = *byte;
        for bit in (0..8u32).rev() {
            // Drive MOSI while SCK is low (CPHA=0).
            if (tx >> bit) & 1 == 1 {
                gpio_set(PIN_MOSI);
            } else {
                gpio_clr(PIN_MOSI);
            }
            // Small setup delay (~1 µs at 160 MHz: ~160 nops).
            let mut d = 0u32; while d < 10 { d += 1; }
            gpio_set(PIN_SCK);
            let mut d = 0u32; while d < 10 { d += 1; }
            rx = (rx << 1) | gpio_read(PIN_MISO) as u8;
            gpio_clr(PIN_SCK);
            let mut d = 0u32; while d < 10 { d += 1; }
        }
        *byte = rx;
    }
}
