//! cardputer-idf: RNode-compatible KISS modem for the M5Stack Cardputer Advanced (ESP32-S3).
//!
//! Thread layout (BRIDGE_PLAN): the modem thread below owns the single
//! half-duplex radio chain — USB-Serial-JTAG + TCP:7633 sessions
//! <-> rnode-modem-core (KISS protocol) <-> SX1262. WiFi bring-up
//! (src/wifi.rs), the TCP listener + sessions (src/tcp_bridge.rs) and
//! the watchdog run on their own threads; host links reach the modem
//! through the session bus (src/bus.rs).
//!
//! Radio driver conventions verified on hardware (see TECHNICAL_NOTES.md):
//! - byte-by-byte SPI with CS (GPIO5) held LOW for the whole command
//! - RNode init sequence: calibrate, image-cal, TCXO 1.8V, sync [0x14,0x24],
//!   preamble 18, CRC on, IQ-errata RMW after EVERY SetPacketParams
//! - SetTx(0x000000) single-shot; TX length via SetPacketParams
//! - RNode wire format: [header(seq<<4|flags), payload...]
//! - ReadBuffer data at buf[3]; GetRxBufferStatus len@3 off@4

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::spi::{config::Config, config::DriverConfig, SpiDeviceDriver, SpiSingleDeviceDriver};
use esp_idf_hal::i2c::{I2cConfig, I2cDriver};

use rnode_modem_core::frame::FEND;
use rnode_modem_core::modem::{Fed, Modem};
use rnode_modem_core::protocol::{Protocol, RadioOp};
use rnode_modem_core::radio::RadioParams;
use rnode_modem_core::MCU_ESP32_S3;

mod bus;
mod chat_app;
mod chat_stack;
mod console;
mod display;
mod keyboard;
mod tcp_bridge;
mod ui;
mod wifi;

use crate::bus::{Bus, InMsg, USB_SESSION};
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

static LOOP_COUNT: AtomicU32 = AtomicU32::new(0);

fn main() {
    // Install the USB-Serial-JTAG driver BEFORE the blocking WiFi wait:
    // its ISR drains the host->device RX FIFO into the ring buffer while
    // wifi::start() blocks below. Without this, host writes during the
    // WiFi window stall (FIFO unclaimed -> CDC-ACM backpressure) — seen
    // on the bench as the USB acceptance test blocking in write() until
    // killed. Bytes buffered here are consumed once the modem loop
    // starts polling.
    let mut usb_cfg = esp_idf_sys::usb_serial_jtag_driver_config_t {
        rx_buffer_size: 1024,
        tx_buffer_size: 2048,
    };
    let usb_r = unsafe { esp_idf_sys::usb_serial_jtag_driver_install(&mut usb_cfg) };
    if usb_r != 0 {
        crate::clog!("usb driver install failed: {}", usb_r);
    } else {
        crate::clog!("usb driver ok");
    }
    // WiFi BEFORE the modem thread (plan Phase 1): the DHCP address
    // must reach the console before any FEND traffic can silence it.
    // wifi::start() uses raw esp-idf-sys init and consumes no HAL
    // peripherals, so Peripherals::take() safely stays in modem_run
    // (the plan's split risk only applies to esp-idf-svc paths).
    // It BLOCKS until the address prints or a ~15s timeout elapses —
    // which is why the watchdog must not be armed yet: LOOP_COUNT
    // stays at 0 during the wait and a stalled count means "reboot".
    wifi::start();
    // Keep the session bus available for the USB-only path.
    let (bus, in_rx) = Bus::new();
    // No WiFi means no socket calls: lwIP's mailbox may not exist.
    if wifi::is_up() {
        tcp_bridge::start(bus.clone());
    } else {
        crate::clog!("tcp bridge: off (no wifi)");
    }


    // ---- Hardware split: one Peripherals take feeds radio, LCD, keyboard ----
    let peripherals = Peripherals::take().unwrap();
    let pins = peripherals.pins;

    // Both I2C buses (Wire1 = SDA2/SCL1 internal, Wire = SDA8/SCL9).
    let i2c_cfg = I2cConfig::new().baudrate(100_000.into());
    let mut i2c_wire1 = I2cDriver::new(peripherals.i2c1, pins.gpio2, pins.gpio1, &i2c_cfg)
        .expect("i2c1 (sda2/scl1)");
    let mut i2c_wire = I2cDriver::new(peripherals.i2c0, pins.gpio8, pins.gpio9, &i2c_cfg)
        .expect("i2c0 (sda8/scl9)");

    // PI4IOE5V6408 @0x43 gates the Cap LoRa module (antenna path):
    // drive P0 high BEFORE the SX1262 wakes. Probe Wire1 first, then
    // Wire — Meshtastic's exact order (m5stack_cardputer_adv variant.cpp).
    // Register map (Zephyr gpio_pi4ioe5v6408): IO_DIR 0x03 bit SET =
    // output, OUT_SET 0x05 = drive level, OUT_H_IM 0x07 = hi-Z.
    // An SHT2X sensor ALSO answers at 0x43 on one bus (Meshtastic's
    // boot scan shows both devices at that address). A bare ACK probe
    // cannot tell them apart — and writing config registers to the
    // sensor left the real expander unconfigured (dead RF path).
    // Verify with register semantics: only the PI4IOE echoes a written
    // output value from register 0x05.
    let pi4ioe_verify = |i2c: &mut I2cDriver, tag: &str| -> bool {
        let ok = (|| -> Option<bool> {
            i2c.write(0x43, &[0x05, 0x01], 100).ok()?;
            let mut buf = [0u8; 1];
            i2c.write_read(0x43, &[0x05], &mut buf, 100).ok()?;
            Some(buf[0] & 0x01 == 0x01)
        })()
        .unwrap_or(false);
        crate::clog!("pi4ioe: {} on {tag}: {}", if ok { "CONFIRMED" } else { "not a PI4IOE" }, ok);
        ok
    };
    let (mut pi4ioe_bus, pi4ioe_found) = if pi4ioe_verify(&mut i2c_wire1, "Wire1(sda2/scl1)") {
        (&mut i2c_wire1, true)
    } else if pi4ioe_verify(&mut i2c_wire, "Wire(sda8/scl9)") {
        (&mut i2c_wire, true)
    } else {
        crate::clog!("pi4ioe: no PI4IOE confirmed on either bus — RF path may be gated off");
        (&mut i2c_wire, false)
    };
    for (reg, val) in [(0x03u8, 0x01u8), (0x07, 0x00), (0x05, 0x01)] {
        match pi4ioe_bus.write(0x43, &[reg, val], 100) {
            Ok(()) => {}
            Err(e) if pi4ioe_found => panic!("pi4ioe write failed: {e:?}"),
            Err(_) => {}
        }
    }

    // Radio parts (SPI2 bus + SX1262 wiring) — consumed by modem_run.
    let radio_parts = RadioParts {
        spi: peripherals.spi2,
        sck: pins.gpio40,
        miso: pins.gpio39,
        mosi: pins.gpio14,
        cs: pins.gpio5,
        dio1: pins.gpio4,
        rst: pins.gpio3,
        busy: pins.gpio6,
    };
    unsafe { esp_idf_sys::vTaskDelay(1) }; // ~10ms settle (100Hz tick)

    // Keyboard: TCA8418 @0x34 on whichever bus ACKs; share that driver
    // behind a mutex for the polling thread.
    let keys_rx = if keyboard::probe(&mut i2c_wire1) {
        crate::clog!("kb: TCA8418 on Wire1 (sda2/scl1)");
        keyboard::spawn(Arc::new(std::sync::Mutex::new(i2c_wire1)))
    } else if keyboard::probe(&mut i2c_wire) {
        crate::clog!("kb: TCA8418 on Wire (sda8/scl9)");
        keyboard::spawn(Arc::new(std::sync::Mutex::new(i2c_wire)))
    } else {
        crate::clog!("kb: no TCA8418 at 0x34 on either bus — chat input disabled");
        Err(anyhow::anyhow!("no keyboard"))
    }
    .unwrap_or_else(|e| {
        crate::clog!("kb: keyboard start failed ({e:?}) — chat input disabled");
        let (tx, rx) = std::sync::mpsc::channel();
        std::mem::forget(tx); // never-sending placeholder input
        rx
    });

    // LCD on SPI3 (SPI2 belongs to the radio).
    let display = display::Display::init(display::DisplayParts {
        spi: peripherals.spi3,
        sck: pins.gpio36,
        mosi: pins.gpio35,
        cs: pins.gpio37,
        dc: pins.gpio34,
        rst: pins.gpio33,
        backlight: pins.gpio38,
    });

    // ---- Chat stack: littlefs storage, identity, in-process KISS session ----
    if !chat_stack::mount_storage() {
        crate::clog!("chat: storage mount failed — NVS fallback in use");
    }
    let chat = chat_stack::start(&bus, "/reticulum");
    match chat {
        Ok((action_tx, event_rx, gate_tx)) => {
            // Spawn-order contract: the UI and modem thread stacks are
            // allocated BEFORE the gate opens and the chat thread runs
            // its heap-heavy transport/router init (see chat_stack::run).
            let display = match display {
                Ok(d) => d,
                Err(e) => {
                    crate::clog!("chat: LCD init failed ({e:?}) — running headless");
                    // A chat without a screen cannot run the UI loop;
                    // keep the stack (announces on air) but idle the UI.
                    std::thread::Builder::new()
                        .stack_size(4096)
                        .spawn(move || {
                            for ev in event_rx.iter() {
                                crate::clog!("chat(event): {ev:?}");
                            }
                        })
                        .unwrap();
                    crate::clog!("chat: stack up (headless)");
                    let _ = gate_tx.send(());
                    return run_modem_and_join(bus, in_rx, radio_parts);
                }
            };
            let spawned = std::thread::Builder::new()
                .name("ui".into())
                .stack_size(20 * 1024)
                .spawn(move || {
                    if let Err(e) = chat_app::run(display, keys_rx, action_tx, event_rx) {
                        crate::clog!("chat app exited: {e:?}");
                    }
                });
            if spawned.is_err() {
                crate::clog!("chat: UI thread spawn failed — running headless");
            }
            // Modem + watchdog stacks come up inside; the gate opens
            // once every stack is standing.
            let joined = run_modem_and_join_gated(bus, in_rx, radio_parts, gate_tx);
            return joined;
        }
        Err(e) => {
            crate::clog!("chat: stack start failed ({e:?}) — modem only");
        }
    }

    run_modem_and_join(bus, in_rx, radio_parts)
}

struct RadioParts {
    spi: esp_idf_hal::spi::SPI2<'static>,
    sck: esp_idf_hal::gpio::Gpio40<'static>,
    miso: esp_idf_hal::gpio::Gpio39<'static>,
    mosi: esp_idf_hal::gpio::Gpio14<'static>,
    cs: esp_idf_hal::gpio::Gpio5<'static>,
    dio1: esp_idf_hal::gpio::Gpio4<'static>,
    rst: esp_idf_hal::gpio::Gpio3<'static>,
    busy: esp_idf_hal::gpio::Gpio6<'static>,
}

fn run_modem_and_join(bus: Arc<Bus>, in_rx: Receiver<InMsg>, radio: RadioParts) {
    // Watchdog thread: detects modem thread hangs (spawned only once
    // the modem thread is about to start ticking LOOP_COUNT).
    std::thread::Builder::new()
        .stack_size(2048)
        .spawn(|| {
            let mut last = 0u32;
            let mut beats = 0u32;
            loop {
                unsafe { esp_idf_sys::vTaskDelay(200) }; // 2s
                let cur = LOOP_COUNT.load(AtomicOrdering::Relaxed);
                beats += 1;
                if cur == last && beats > 3 {
                    crate::clog!("[WDT] MODEM THREAD HUNG at loop {} ({}s) — rebooting", cur, beats * 2);
                    unsafe { esp_idf_sys::esp_restart() };
                }
                last = cur;
            }
        })
        .unwrap();
    let handle = std::thread::Builder::new()
        .name("modem".into())
        .stack_size(36 * 1024)
        .spawn(move || {
            if let Err(e) = modem_run(bus, in_rx, radio) {
                crate::clog!("modem error: {:?} — rebooting", e);
                unsafe { esp_idf_sys::esp_restart() };
            }
        })
        .unwrap();
    handle.join().unwrap();
    // If we get here the modem thread exited — reboot to recover
    unsafe { esp_idf_sys::esp_restart() };
}

/// `run_modem_and_join` + release the chat stack's init gate once every
/// thread stack (watchdog, modem) is allocated.
fn run_modem_and_join_gated(
    bus: Arc<Bus>,
    in_rx: Receiver<InMsg>,
    radio: RadioParts,
    gate: std::sync::mpsc::Sender<()>,
) {
    std::thread::Builder::new()
        .stack_size(4096)
        .spawn(|| {
            let mut last = 0u32;
            let mut beats = 0u32;
            loop {
                unsafe { esp_idf_sys::vTaskDelay(200) }; // 2s
                let cur = LOOP_COUNT.load(AtomicOrdering::Relaxed);
                beats += 1;
                if cur == last && beats > 3 {
                    crate::clog!("[WDT] MODEM THREAD HUNG at loop {} ({}s) — rebooting", cur, beats * 2);
                    unsafe { esp_idf_sys::esp_restart() };
                }
                last = cur;
            }
        })
        .unwrap();
    let handle = std::thread::Builder::new()
        .name("modem".into())
        .stack_size(36 * 1024)
        .spawn(move || {
            if let Err(e) = modem_run(bus, in_rx, radio) {
                crate::clog!("modem error: {:?} — rebooting", e);
                unsafe { esp_idf_sys::esp_restart() };
            }
        })
        .unwrap();
    let _ = gate.send(()); // all stacks standing — chat init may proceed
    handle.join().unwrap();
    unsafe { esp_idf_sys::esp_restart() };
}

// ---- Radio driver ----
fn bandwidth_code(bw: u32) -> u8 {
    match bw {
        0..=7_800 => 0x00,
        7_801..=10_400 => 0x08,
        10_401..=15_600 => 0x01,
        15_601..=20_800 => 0x09,
        20_801..=31_250 => 0x02,
        31_251..=41_700 => 0x0A,
        41_701..=62_500 => 0x03,
        62_501..=125_000 => 0x04,
        125_001..=250_000 => 0x05,
        _ => 0x06,
    }
}

fn esp_random() -> u32 {
    unsafe { esp_idf_sys::esp_random() }
}

/// USB-Serial-JTAG direct TX (esp-println's backend for the S3).
/// FIFO 0x6003_8000 (u32 per byte), CONF 0x6003_8004:
/// bit0 write = flush, bit1 clear = FIFO full.
fn usb_write_direct(bytes: &[u8]) {
    const FIFO: *mut u32 = 0x6003_8000 as *mut u32;
    const CONF: *mut u32 = 0x6003_8004 as *mut u32;
    unsafe {
        for &b in bytes {
            let mut timeout = 50_000usize;
            while (CONF.read_volatile() & 0b010) == 0 {
                if timeout == 0 {
                    return; // no host draining — drop the rest
                }
                timeout -= 1;
            }
            FIFO.write_volatile(b as u32);
        }
        CONF.write_volatile(0b001); // flush
    }
}

/// RNode wire-format split flag (header low bit); header high nibble
/// is the chunk sequence. Payloads > 254 bytes go out as two packets
/// sharing one sequence, matching stock RNode_Firmware.
const FLAG_SPLIT: u8 = 0x01;
const CHUNK: usize = 254; // max payload per LoRa packet

struct Radio {
    cs: PinDriver<'static, esp_idf_hal::gpio::InputOutput>,
    busy: PinDriver<'static, esp_idf_hal::gpio::Input>,
    spi: SpiSingleDeviceDriver<'static>,
    last_params: RadioParams,
    pending_split: Vec<u8>,
    pending_seq: u8,
}

impl Radio {
    /// SX1262 datasheet protocol: the chip raises BUSY while processing;
    /// commands issued while BUSY is high are DROPPED silently. The C6L
    /// build substituted fixed delays (no BUSY pin wired there) and got
    /// away with it — on the Cap LoRa-1262 module the timings differ and
    /// TX never completed (5x "no TxDone" with config reads intact).
    fn wait_ready(&self) -> anyhow::Result<()> {
        let t0 = unsafe { esp_idf_sys::esp_timer_get_time() };
        while self.busy.is_high() {
            if unsafe { esp_idf_sys::esp_timer_get_time() } - t0 > 20_000 {
                return Err(anyhow::anyhow!("sx1262 busy timeout"));
            }
            unsafe { esp_idf_sys::vTaskDelay(1) };
        }
        Ok(())
    }
    fn cmd(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.wait_ready()?;
        self.cs.set_low()?;
        let r = self.spi.transfer_in_place(buf);
        self.cs.set_high()?;
        r?;
        self.wait_ready()?;
        Ok(())
    }
    fn xfer(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.wait_ready()?;
        self.cs.set_low()?;
        for i in 0..buf.len() {
            let mut b = [buf[i]];
            self.spi.transfer_in_place(&mut b)?;
            buf[i] = b[0];
        }
        self.cs.set_high()?;
        self.wait_ready()?;
        Ok(())
    }
    fn delay_ms(&self, ms: u32) {
        // vTaskDelay takes TICKS (100Hz => 1 tick = 10ms)
        let ticks = (ms / 10).max(1);
        unsafe { esp_idf_sys::vTaskDelay(ticks) }
    }

    /// Full RNode-matching init at the given parameters.
    fn init(&mut self, p: &RadioParams) -> anyhow::Result<()> {
        self.last_params = p.clone();
        let freq = p.frequency.max(1);
        let rf = ((freq as u64) << 25) / 32_000_000;
        let f3 = (rf >> 24) as u8;
        let f2 = ((rf >> 16) & 0xFF) as u8;
        let f1 = ((rf >> 8) & 0xFF) as u8;
        let f0 = (rf & 0xFF) as u8;
        let bw_code = bandwidth_code(p.bandwidth);
        let sf = p.sf.clamp(5, 12);
        let cr = p.cr.clamp(5, 8) - 4;

        self.xfer(&mut [0x00])?; // NOP
        // Liveness: a live SX1262 answers GetStatus with a nonzero mode
        // byte (0x2A = STDBY_RC). 0x00 means MISO reads nothing — the
        // signature of the swapped MOSI/MISO bring-up bug, or no module
        // (the Cap LoRa is detachable; keep booting, like Meshtastic).
        let mut st = [0xC0u8, 0x00, 0x00];
        self.xfer(&mut st)?;
        if st[1] == 0x00 || st[1] == 0xFF {
            crate::clog!("radio: SX1262 not responding (GetStatus {:#04x}) — check module/SPI", st[1]);
        }
        self.delay_ms(2);
        self.xfer(&mut [0x80, 0x00])?; // SetStandby(STBY_RC)
        self.delay_ms(10); // let the PLL/TCXO settle from any previous state
        // DIO3-TCXO 1.8V, 5 ms timeout (Meshtastic variant value). This
        // module HAS a TCXO: with the command removed (an experiment run
        // while MISO/MOSI were still swapped, proving nothing) DIO3
        // floats, the 32 MHz reference never starts, and the chip sits
        // in standby forever — no TX, no RX.
        self.cmd(&mut [0x97, 0x02, 0x00, 0x00, 0x14])?;
        self.delay_ms(50);
        self.xfer(&mut [0x89, 0x7F])?; // Calibrate all (on TCXO reference)
        self.delay_ms(5);
        // Image calibration: band-select pair depends on the operating
        // frequency (SX1262 datasheet table 9-2). This unit is the EU
        // Cap LoRa868 (863-870 MHz); the 902-928 MHz pair serves the
        // Cap LoRa-1262 915 variant. Image-cal lives only here in init,
        // so last_params at init time drives the branch.
        let (cal1, cal2) = if (902_000_000..=928_000_000).contains(&freq) {
            (0xD7, 0xE4)
        } else {
            (0xD7, 0xDB) // 863-870 MHz (RNode default)
        };
        self.xfer(&mut [0x98, cal1, cal2])?;
        self.delay_ms(5);
        self.xfer(&mut [0x8A, 0x01])?; // SetPacketType(LoRa)
        self.delay_ms(2);
        self.xfer(&mut [0x86, f3, f2, f1, f0])?; // SetRfFrequency
        self.delay_ms(2);
        // RNode sync word [0x14, 0x24]
        self.xfer(&mut [0x0D, 0x07, 0x40, 0x14])?;
        self.xfer(&mut [0x0D, 0x07, 0x41, 0x24])?;
        self.xfer(&mut [0x9D, 0x01])?; // DIO2 as RF switch
        self.xfer(&mut [0x8B, sf, bw_code, cr, 0x00])?; // ModParams (LDRO off)
        self.delay_ms(2);
        // optimizeModemSensitivity: reg 0x0889 bit 2 SET (read-modify-write!)
        let mut ms = [0x1D, 0x08, 0x89, 0x00, 0x00];
        self.xfer(&mut ms)?;
        self.xfer(&mut [0x0D, 0x08, 0x89, ms[4] | 0x04])?;
        // PacketParams: preamble 18, explicit, len 0xFF, CRC on, std IQ (+3 unused)
        self.xfer(&mut [0x8C, 0x00, 0x12, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00])?;
        self.delay_ms(2);
        // IQ errata 15.4 (RMW) — SetPacketParams resets this register
        let mut iq = [0x1D, 0x07, 0x36, 0x00, 0x00];
        self.xfer(&mut iq)?;
        self.xfer(&mut [0x0D, 0x07, 0x36, iq[4] | 0x04])?;
        // Buffer base TX=0 RX=0
        self.xfer(&mut [0x8F, 0x00, 0x00, 0x00, 0x00])?;
        // Regulator DC-DC — RadioLib's default, which Meshtastic runs on
        // this exact module (its variant sets no SX126X_USE_REGULATOR_LDO).
        self.xfer(&mut [0x96, 0x01])?;
        // PA config: SX1262 high power
        self.xfer(&mut [0x95, 0x04, 0x07, 0x00, 0x01])?;
        // TX power + ramp 40us
        let txp = p.txpower.min(22);
        self.xfer(&mut [0x8E, txp, 0x02])?;
        // OCP 140mA
        self.xfer(&mut [0x0D, 0x08, 0xE7, 0x38])?;
        // TX clamp errata (RMW)
        let mut clamp = [0x1D, 0x08, 0xD8, 0x00, 0x00];
        self.xfer(&mut clamp)?;
        self.xfer(&mut [0x0D, 0x08, 0xD8, clamp[4] | 0x1E])?;
        // IRQ: enable all, route none to DIO1 (we poll)
        self.xfer(&mut [0x08, 0x00, 0x3F, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x00])?;
        self.xfer(&mut [0x02, 0x03, 0xFF])?; // ClearIrq
        if p.radio_on {
            self.start_rx()?;
            // HARDWARE QUIRK (empirical): after a full re-init the RX
            // front end stays dead (RSSI -127, nothing received) until
            // one SetTx->TxDone cycle runs — the trailing start_rx of a
            // transmission is what reliably re-arms reception. Real RNodes
            // mask this because RNS sends its id_callsign packet right
            // after radio-on. Mirror that: one header-only packet per
            // reconfigure.
            self.transmit(&[])?;
        }
        Ok(())
    }

    fn start_rx(&mut self) -> anyhow::Result<()> {
        // RX packet params (payload len 0xFF) + IQ fix, then SetRx continuous
        self.xfer(&mut [0x8C, 0x00, 0x12, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00])?;
        let mut iq = [0x1D, 0x07, 0x36, 0x00, 0x00];
        self.xfer(&mut iq)?;
        self.xfer(&mut [0x0D, 0x07, 0x36, iq[4] | 0x04])?;
        self.xfer(&mut [0x8F, 0x00, 0x00, 0x00, 0x00])?; // FIFO pointers 0,0
        self.xfer(&mut [0x02, 0x03, 0xFF])?; // clear latched IRQs
        self.delay_ms(10); // let the chip settle (post-TX shutdown)
        self.cmd(&mut [0x82, 0xFF, 0xFF, 0xFF])?; // SetRx continuous
        Ok(())
    }

    /// Poll IRQ flags; on RxDone read the packet and return it
    /// (RNode header byte stripped).
    fn poll_rx(&mut self, out: &mut Vec<u8>) -> anyhow::Result<bool> {
        let mut irq = [0x12u8, 0x00, 0x00, 0x00];
        self.xfer(&mut irq)?;
        let flags = ((irq[2] as u16) << 8) | irq[3] as u16;
        if flags & 0x0002 == 0 {
            // Do NOT clear latched preamble/header flags here: clearing
            // during an active reception ABORTS the packet (hardware-
            // verified). Latched flags are harmless.
            return Ok(false);
        }
        // GetRxBufferStatus: standard Semtech layout —
        // buf[0]=opcode, buf[1]=dummy, buf[2]=LENGTH, buf[3]=OFFSET.
        // (We previously read length from buf[3] — it "worked" because
        // the first packet's length == offset; they diverge once the
        // FIFO write pointer advances.)
        let mut rbs = [0x13u8, 0x00, 0x00, 0x00, 0x00];
        self.xfer(&mut rbs)?;
        let len = rbs[2] as usize;
        let rx_offset = rbs[3];
        let mut got = false;
        if len > 0 && len < 256 {
            // Read the FULL packet — a split chunk is 255 bytes on the
            // wire; the earlier min(240) cap silently dropped the tail
            // of every max-size chunk.
            let mut pkt = [0u8; 4 + 255];
            pkt[0] = 0x1E; // ReadBuffer
            pkt[1] = rx_offset; // read from the packet's ACTUAL offset
            self.xfer(&mut pkt[..4 + len])?;
            let data = &pkt[3..3 + len];
            // RNode wire format: first byte is the header (seq<<4|flags).
            // Split frames arrive as two packets sharing the seq nibble:
            // buffer the first, emit the reassembled payload on the
            // second. A non-split packet (or a new seq) discards a
            // pending chunk — stock RNode_Firmware semantics.
            if data.len() > 1 {
                let header = data[0];
                let payload = &data[1..];
                if header & FLAG_SPLIT != 0 {
                    let seq = header >> 4;
                    if self.pending_seq == seq && !self.pending_split.is_empty() {
                        self.pending_split.extend_from_slice(payload);
                        out.extend_from_slice(&self.pending_split);
                        self.pending_split.clear();
                        self.pending_seq = 0xFF;
                        got = true;
                    } else {
                        self.pending_split.clear();
                        self.pending_split.extend_from_slice(payload);
                        self.pending_seq = seq;
                    }
                } else {
                    self.pending_split.clear();
                    self.pending_seq = 0xFF;
                    out.extend_from_slice(payload);
                    got = true;
                }
            }
        }
        // Post-RX: absolute minimum — clear RxDone and re-enter RX.
        // CRITICAL: do NOT call SetBufferBaseAddress here! The modem is
        // concurrently writing the next packet to the FIFO; resetting the
        // base address mid-reception corrupts the state machine and kills
        // the radio (hardware-verified: pure-RX one-way test died after
        // 12 packets with the buffer reset, survives without it).
        // The SX1262 FIFO auto-wraps at 256 bytes; we read relative to
        // whatever offset GetRxBufferStatus reports.
        self.cmd(&mut [0x02, 0x00, 0x02])?; // ClearIrqStatus(RxDone only)
        self.cmd(&mut [0x82, 0xFF, 0xFF, 0xFF])?; // SetRx continuous
        Ok(got)
    }

    /// LoRa airtime in ms for an on-wire packet of `len` bytes at the
    /// current params (explicit header, CRC on, preamble 18 symbols).
    /// Semtech formula; used to size the TxDone wait — see transmit().
    fn airtime_ms(&self, len: usize) -> u32 {
        let p = &self.last_params;
        let sf = p.sf.clamp(5, 12) as i64;
        let bw = p.bandwidth.max(1) as i64;
        let cr = (p.cr.clamp(5, 8) - 4) as i64;
        let ts_us = ((1i64 << sf) * 1_000_000) / bw; // symbol period
        let de: i64 = if ts_us >= 16_000 { 1 } else { 0 }; // LDRO
        let pl = len as i64;
        let num = 8 * pl - 4 * sf + 28 + 16; // IH=0, CRC on
        let denom = 4 * (sf - 2 * de);
        let n_payload = 8 + ((num.max(0) + denom - 1) / denom) * (cr + 4);
        (((18 + 4 + n_payload) * ts_us) / 1000) as u32
    }

    /// Transmit with RNode wire format (header + payload), honoring
    /// split packets for payloads > 254 bytes.
    fn transmit(&mut self, payload: &[u8]) -> anyhow::Result<()> {
        // Stock receivers only reassemble TWO chunks; a host payload
        // beyond 2*CHUNK can't be represented on the wire — drop the
        // whole frame rather than air a truncated prefix.
        if payload.len() > 2 * CHUNK {
            return Ok(());
        }

        let mut seq: u8 = 0;
        let chunks: Vec<&[u8]> = if payload.len() <= CHUNK {
            vec![payload]
        } else {
            seq = (esp_random() & 0x0F) as u8;
            vec![&payload[..CHUNK], &payload[CHUNK..]]
        };
        let split = payload.len() > CHUNK;

        for chunk in chunks {
            let header = (seq << 4) | if split { FLAG_SPLIT } else { 0 };
            let total = 1 + chunk.len();
            // standby
            self.xfer(&mut [0x80, 0x00])?;
            self.delay_ms(2);
            // TX packet params with the ACTUAL length
            self.xfer(&mut [
                0x8C, 0x00, 0x12, 0x00, total as u8, 0x01, 0x00, 0x00, 0x00, 0x00,
            ])?;
            let mut iq = [0x1D, 0x07, 0x36, 0x00, 0x00];
            self.xfer(&mut iq)?;
            self.xfer(&mut [0x0D, 0x07, 0x36, iq[4] | 0x04])?;
            // WriteBuffer: opcode + offset + [header, data...]
            let mut wr = [0u8; 2 + 1 + CHUNK];
            wr[0] = 0x0E;
            wr[1] = 0x00;
            wr[2] = header;
            wr[3..3 + chunk.len()].copy_from_slice(chunk);
            self.xfer(&mut wr[..3 + chunk.len()])?;
            self.xfer(&mut [0x8F, 0x00, 0x00, 0x00, 0x00])?;
            // SetTx(0x000000) single-shot (RNode endPacket)
            self.xfer(&mut [0x83, 0x00, 0x00, 0x00, 0x00])?;
            // Wait for TxDone against a REAL deadline — airtime + 50%
            // margin. CRITICAL for splits: the next chunk's SetStandby
            // aborts any in-flight TX, so expiring early corrupts the
            // chunk on the air. The old fixed 150×vTaskDelay(1) loop
            // averaged ~0.75 s (vTaskDelay(1) at 100 Hz is 0–10 ms) vs
            // ~1.29 s needed for a 255 B packet at SF9/BW125.
            let budget_us = (self.airtime_ms(total) * 3 / 2 + 200) as i64 * 1000;
            let t0 = unsafe { esp_idf_sys::esp_timer_get_time() };
            let mut done = false;
            loop {
                // Slow-SF airtime can exceed the 8s software watchdog
                // (SF12/255B ≈ 4s per chunk) — keep LOOP_COUNT ticking
                // so a legitimately long TX isn't read as a hang.
                LOOP_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
                let mut ti = [0x12u8, 0x00, 0x00, 0x00];
                self.xfer(&mut ti)?;
                let tflags = ((ti[2] as u16) << 8) | ti[3] as u16;
                if tflags & 0x0001 != 0 {
                    done = true;
                    break;
                }
                if unsafe { esp_idf_sys::esp_timer_get_time() } - t0 > budget_us {
                    break;
                }
                // NOTE: 0x0004 is PreambleDetected (latches under
                // interference) — do NOT treat it as a TX timeout.
                self.delay_ms(10);
            }
            let _ = done;
            self.xfer(&mut [0x02, 0x03, 0xFF])?; // clear IRQs
        }
        // Post-TX: absolute minimum recovery — ClearIrq + SetRx only.
        // The chip auto-transitions to standby after TX; a direct SetRx
        // should re-enter RX. All elaborate recovery attempts (standby,
        // sleep+restart, verified mode) either didn't help or made it worse.
        self.xfer(&mut [0x02, 0x03, 0xFF])?; // ClearIrq
        self.delay_ms(5);
        self.cmd(&mut [0x82, 0xFF, 0xFF, 0xFF])?; // SetRx continuous
        Ok(())
    }

    /// Read the last packet's RSSI/SNR (GetPacketStatus).
    fn packet_status(&mut self) -> anyhow::Result<(i16, i8)> {
        let mut ps = [0x14u8, 0x00, 0x00, 0x00, 0x00];
        self.xfer(&mut ps)?;
        Ok((-(ps[2] as i16) / 2, ps[3] as i8))
    }
}


fn modem_run(bus: Arc<Bus>, in_rx: Receiver<InMsg>, parts: RadioParts) -> anyhow::Result<()> {
    // PI4IOE radio power-gate init happened in main() before this
    // thread started (the winning I2C driver stays alive there).

    let RadioParts { spi: spi2, sck, miso, mosi, cs: cs_pin, dio1, rst: rst_pin, busy: busy_pin } = parts;
    let mut cs = PinDriver::input_output(cs_pin, esp_idf_hal::gpio::Pull::Floating)?;
    cs.set_high()?;
    let _dio1 = PinDriver::input(dio1, esp_idf_hal::gpio::Pull::Down)?;
    // BUSY (GPIO6): wired on this board and now part of the command
    // protocol (see Radio::wait_ready) — commands issued while the chip
    // is busy are silently dropped, which is exactly the failure the
    // fixed-delay C6L flow hit here ("TX TIMEOUT, no TxDone").
    let busy = PinDriver::input(busy_pin, esp_idf_hal::gpio::Pull::Up)?;
    // Real NRESET exists on this board (GPIO3, unlike the C6L) — pulse
    // it before Radio::init: low >=1ms, release, then recover.
    let mut rst = PinDriver::input_output(rst_pin, esp_idf_hal::gpio::Pull::Floating)?;
    rst.set_low()?;
    unsafe { esp_idf_sys::vTaskDelay(1) }; // 1 tick = 10ms (>= 2ms)
    rst.set_high()?;
    unsafe { esp_idf_sys::vTaskDelay(1) }; // ~10ms recovery

    // HAL ARGUMENT ORDER: (host, sclk, sdo=MOSI, sdi=MISO, cs, ...) —
    // the C6L original listed pins as (sck, miso-line-label, mosi-label)
    // and worked because that board's 21/22 mapped onto sdo/sdi the
    // other way round. Passing this board's MISO(39) as sdo and
    // MOSI(14) as sdi made the radio WRITE-ONLY: every register read
    // returned 0x00, so init "succeeded" while the chip never even
    // saw a command (TX never fired, RX never possible).
    let spi = SpiDeviceDriver::new_single(
        spi2,
        sck,
        mosi,
        Some(miso),
        Option::<esp_idf_hal::gpio::Gpio5>::None,
        &DriverConfig::new(),
        &Config::new().baudrate(2_000_000.into()),
    )?;



    // ---- Modem core + USB session ----
    let mut params = RadioParams::default();
    params.frequency = 869_525_000; // EU868 10%-duty sub-band (see chat_stack radio config)
    params.bandwidth = 125_000;
    params.sf = 9;
    params.cr = 5;
    params.txpower = 22;
    params.radio_on = true;

    let mut radio = Radio {
        cs,
        busy,
        spi,
        last_params: params.clone(),
        pending_split: Vec::new(),
        pending_seq: 0xFF,
    };
    radio.init(&params)?;
    usb_write_direct(b"radio up\r\n");
    // esp-println's jtag printer latches TIMED_OUT and silently drops any
    // write that lands while the FIFO is full (e.g. right after the boot/
    // wifi log burst) — as a clog! this line never reached the wire. The
    // direct-FIFO writer above (the proven KISS TX path) retries per byte
    // and flushes, so the boot signal survives.

    // The USB-Serial-JTAG driver was already installed in main() BEFORE
    // the blocking WiFi wait (its ISR must drain host->device RX while
    // the modem isn't polling yet — see the install site for why).
    // read_bytes/write_bytes below use that driver's buffers/ISR.

    let mut config_dirty = false;
    let mut modem = Modem::new(Protocol::new(MCU_ESP32_S3));
    let usb = modem.add_session();
    // First modem session is the built-in USB link; the bus reserves
    // id 1 for it and hands TCP sessions ids >= 2 (bus::USB_SESSION).
    // A real assert: route_fed keys USB output on USB_SESSION, so a
    // broken id convention must not slip into a release build.
    assert_eq!(usb, USB_SESSION);
    let mut tx_buf: Vec<u8> = Vec::new();
    let mut rx_payload: Vec<u8> = Vec::new();

    let mut usb_in = [0u8; 64];
    loop {
        LOOP_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        // ---- read host bytes (10 ms timeout tick) ----
        let n = unsafe {
            esp_idf_sys::usb_serial_jtag_read_bytes(
                usb_in.as_mut_ptr() as *mut _,
                usb_in.len() as u32,
                0, // non-blocking: the driver's timeout does not fire
                   // reliably (blocks until data!); poll instead, then
                   // vTaskDelay(1) at the loop tail for cadence.
            )
        };
        if n > 0 {
            feed_session(
                &mut modem, &mut radio, &bus, &mut params, &mut config_dirty,
                usb, &usb_in[..n as usize], &mut tx_buf,
            )?;
        }

        // ---- drain TCP-session input (non-blocking) ----
        // Capped at 32 msgs/tick so a TCP byte flood can't starve the
        // radio poll — leftovers simply wait one 10ms tick.
        for _ in 0..32 {
            match in_rx.try_recv() {
                Ok(InMsg::Data(id, bytes)) => {
                    feed_session(
                        &mut modem, &mut radio, &bus, &mut params, &mut config_dirty,
                        id, &bytes, &mut tx_buf,
                    )?;
                }
                Ok(InMsg::Leave(id)) => {
                    modem.remove_session(id); // drop the dead link's parser
                }
                Err(_) => break, // drained (or the accept side is gone)
            }
        }

        // Apply a pending config change once the burst has settled
        // (config commands arrive within 1ms; re-init 5 loops later).
        if config_dirty {
            config_dirty = false;
            unsafe { esp_idf_sys::vTaskDelay(5) }; // 50ms quiet period
            if config_dirty == false {
                // only re-init if no new config arrived during the wait
                radio.init(&params.clone())?;
            }
        }

        // ---- poll radio ----
        rx_payload.clear();
        if radio.poll_rx(&mut rx_payload)? {
            let (rssi, snr) = radio.packet_status().unwrap_or((0, 0));
            modem.protocol.stats.rssi = rssi;
            modem.protocol.stats.snr = snr as f32;
            // radio_rx returns ONE frame PER internal session, in
            // session_ids() order — zip them to their links (NOT a
            // concatenated stream: every session gets its own frame,
            // e.g. its own detect/echo replies).
            let frames = modem.radio_rx(&rx_payload);
            let sids = modem.session_ids();
            for (sid, frame) in sids.iter().zip(frames) {
                if *sid == USB_SESSION {
                    tx_buf.extend_from_slice(&frame);
                } else {
                    bus.send_out(*sid, &frame);
                }
            }
        }

        // ---- write host bytes (direct EP1 FIFO, like esp-println) ----
        if !tx_buf.is_empty() {
            usb_write_direct(&tx_buf);
            tx_buf.clear();
        }

        unsafe { esp_idf_sys::vTaskDelay(1); } // 10ms cadence, feeds the watchdog
    }
}

/// Feed one host link's bytes and service the result: route frames,
/// flush USB replies BEFORE radio work (RNS validates config echoes
/// within 250ms of sending them; radio re-inits take longer than that),
/// then run the radio ops (this thread owns the radio).
fn feed_session(
    modem: &mut Modem,
    radio: &mut Radio,
    bus: &Bus,
    params: &mut RadioParams,
    config_dirty: &mut bool,
    id: u64,
    bytes: &[u8],
    tx_buf: &mut Vec<u8>,
) -> anyhow::Result<()> {
    if bytes.contains(&FEND) {
        console::mark_kiss(); // any link's first FEND silences clog!
    }
    let fed = modem.feed(id, bytes);
    route_fed(bus, id, &fed, tx_buf);
    if !tx_buf.is_empty() {
        usb_write_direct(tx_buf);
        tx_buf.clear();
    }
    for op in fed.ops {
        apply_op(radio, modem, params, config_dirty, op)?;
    }
    Ok(())
}

/// Route a `Fed` result onto the host links (plan Phase 3):
/// - to_sender: straight back to the sender's own link — USB via
///   tx_buf, TCP via the bus (send_out == false: session already
///   gone, drop the frame).
/// - to_others: every OTHER link. USB is an "other" for TCP senders
///   (mirrored onto tx_buf); a USB sender gets NO tx_buf copy
///   (half-duplex: echoing the host's own data back at it is wrong) —
///   only the bus fan-out runs, and since USB_SESSION is never
///   bus-registered it cannot be fanned back into either.
fn route_fed(bus: &Bus, id: u64, fed: &Fed, tx_buf: &mut Vec<u8>) {
    for frame in fed.to_sender.iter() {
        if id == USB_SESSION {
            tx_buf.extend_from_slice(frame);
        } else {
            bus.send_out(id, frame);
        }
    }
    for frame in fed.to_others.iter() {
        if id != USB_SESSION {
            tx_buf.extend_from_slice(frame);
        }
        bus.fan_out(id, frame);
    }
}

fn apply_op(
    radio: &mut impl RadioOps,
    _modem: &mut Modem,
    params: &mut RadioParams,
    config_dirty: &mut bool,
    op: RadioOp,
) -> anyhow::Result<()> {
    match op {
        // rnsd sends freq/bw/txp/sf/cr/state as a 1ms burst. Each used to
        // trigger a FULL radio re-init (calibrate + TCXO + callsign TX);
        // the six-deep storm of re-inits hard-wedged the SX1262 (dead SPI,
        // only power cycle recovers) and degraded RX before dying. Now:
        // config commands only mark params dirty; ONE re-init runs on
        // RadioOn/RadioOff (always last in the burst) or lazily in the
        // main loop.
        RadioOp::Configure(p) => {
            *params = p;
            *config_dirty = true;
        }
        RadioOp::RadioOn => {
            params.radio_on = true;
            *config_dirty = true;
            radio.reconfigure(params)?;
            *config_dirty = false;
        }
        RadioOp::RadioOff => {
            params.radio_on = false;
            radio.reconfigure(params)?;
            *config_dirty = false;
        }
        RadioOp::Transmit(data) => {
            // Apply any pending config before transmitting (e.g. a
            // frequency change followed immediately by data).
            if *config_dirty {
                radio.reconfigure(params)?;
                *config_dirty = false;
            }
            radio.transmit_pub(&data)?;
            _modem.protocol.tx_complete(data.len());
        }
    }
    Ok(())
}

// Small trait indirection so apply_op can live outside modem_run
trait RadioOps {
    fn reconfigure(&mut self, p: &RadioParams) -> anyhow::Result<()>;
    fn transmit_pub(&mut self, data: &[u8]) -> anyhow::Result<()>;
}

impl RadioOps for Radio {
    fn reconfigure(&mut self, p: &RadioParams) -> anyhow::Result<()> {
        self.init(p)
    }
    fn transmit_pub(&mut self, data: &[u8]) -> anyhow::Result<()> {
        self.transmit(data)
    }
}
