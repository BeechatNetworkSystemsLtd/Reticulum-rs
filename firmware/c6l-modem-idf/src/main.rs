//! c6l-modem-idf v2: RNode-compatible KISS modem for the M5Stack Unit C6L.
//!
//! Thread layout (BRIDGE_PLAN): the modem thread below owns the single
//! half-duplex radio chain — USB-Serial-JTAG + TCP:7633 sessions
//! <-> rnode-modem-core (KISS protocol) <-> SX1262. WiFi bring-up
//! (src/wifi.rs), the TCP listener + sessions (src/tcp_bridge.rs) and
//! the watchdog run on their own threads; host links reach the modem
//! through the session bus (src/bus.rs).
//!
//! Radio driver conventions verified on hardware (see TECHNICAL_NOTES.md):
//! - byte-by-byte SPI with CS (GPIO23) held LOW for the whole command
//! - RNode init sequence: calibrate, image-cal, TCXO 3.0V, sync [0x14,0x24],
//!   preamble 18, CRC on, IQ-errata RMW after EVERY SetPacketParams
//! - SetTx(0x000000) single-shot; TX length via SetPacketParams
//! - RNode wire format: [header(seq<<4|flags), payload...]
//! - ReadBuffer data at buf[3]; GetRxBufferStatus len@3 off@4

use esp_idf_hal::gpio::PinDriver;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_hal::spi::{config::Config, config::DriverConfig, SpiDeviceDriver, SpiSingleDeviceDriver};

use rnode_modem_core::frame::FEND;
use rnode_modem_core::modem::{Fed, Modem};
use rnode_modem_core::protocol::{Protocol, RadioOp};
use rnode_modem_core::radio::RadioParams;
use rnode_modem_core::MCU_ESP32_C6;

mod bus;
mod console;
mod tcp_bridge;
mod wifi;

use crate::bus::{Bus, InMsg, USB_SESSION};
use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

static LOOP_COUNT: AtomicU32 = AtomicU32::new(0);

fn main() {
    crate::clog!("c6l-modem v2.0 (KISS/RNode)");
    // Install the USB-Serial-JTAG driver BEFORE the blocking WiFi wait:
    // its ISR drains the host->device RX FIFO into the ring buffer while
    // wifi::start() blocks below. Without this, host writes during the
    // WiFi window stall (FIFO unclaimed -> CDC-ACM backpressure) — seen
    // on the bench as the USB acceptance test blocking in write() until
    // killed. Bytes buffered here are consumed once the modem loop
    // starts polling.
    let mut usb_cfg = esp_idf_sys::usb_serial_jtag_driver_config_t {
        rx_buffer_size: 2048,
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
    // Session bus + TCP listener: binding races DHCP on purpose —
    // clients just can't connect until the netif is up.
    let (bus, in_rx) = Bus::new();
    tcp_bridge::start(bus.clone());
    // Watchdog thread: detects modem thread hangs (spawned only once
    // the modem thread is about to start ticking LOOP_COUNT).
    std::thread::Builder::new()
        .stack_size(16384)
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
        .stack_size(65536)
        .spawn(move || {
            if let Err(e) = modem_run(bus, in_rx) {
                crate::clog!("modem error: {:?} — rebooting", e);
                unsafe { esp_idf_sys::esp_restart() };
            }
        })
        .unwrap();
    handle.join().unwrap();
    // If we get here the modem thread exited — reboot to recover
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

/// USB-Serial-JTAG direct TX (esp-println's backend for the C6).
/// FIFO 0x6000_F000 (u32 per byte), CONF 0x6000_F004:
/// bit0 write = flush, bit1 clear = FIFO full.
fn usb_write_direct(bytes: &[u8]) {
    const FIFO: *mut u32 = 0x6000_F000 as *mut u32;
    const CONF: *mut u32 = 0x6000_F004 as *mut u32;
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
    spi: SpiSingleDeviceDriver<'static>,
    last_params: RadioParams,
    pending_split: Vec<u8>,
    pending_seq: u8,
}

impl Radio {
    fn cmd(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.cs.set_low()?;
        let r = self.spi.transfer_in_place(buf);
        self.cs.set_high()?;
        r?;
        Ok(())
    }
    fn xfer(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.cs.set_low()?;
        for i in 0..buf.len() {
            let mut b = [buf[i]];
            self.spi.transfer_in_place(&mut b)?;
            buf[i] = b[0];
        }
        self.cs.set_high()?;
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
        self.delay_ms(2);
        self.xfer(&mut [0x80, 0x00])?; // SetStandby(STBY_RC)
        self.delay_ms(10); // let the PLL/TCXO settle from any previous state
        // TCXO FIRST (RadioLib order: accurate clock before calibration)
        self.cmd(&mut [0x97, 0x06, 0x00, 0x00, 0xFF])?;
        self.delay_ms(50);
        self.xfer(&mut [0x89, 0x7F])?; // Calibrate all (on TCXO reference)
        self.delay_ms(5);
        // Image calibration 863-870 MHz
        self.xfer(&mut [0x98, 0xD7, 0xDB])?;
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
        // Regulator DC-DC
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


fn modem_run(bus: Arc<Bus>, in_rx: Receiver<InMsg>) -> anyhow::Result<()> {
    let peripherals = Peripherals::take()?;
    let pins = peripherals.pins;
    let mut cs = PinDriver::input_output(pins.gpio23, esp_idf_hal::gpio::Pull::Floating)?;
    cs.set_high()?;
    let _dio1 = PinDriver::input(pins.gpio7, esp_idf_hal::gpio::Pull::Down)?;
    // NOTE: GPIO19 (SX1262 BUSY) is a flash-shared pin on ESP32-C6. Taking
    // it via the HAL *and* rewriting its IO_MUX register broke the radio
    // RX entirely (hardware-verified) — so we deliberately do NOT touch it.
    // The driver relies on command settle delays instead of BUSY polling.

    let spi = SpiDeviceDriver::new_single(
        peripherals.spi2,
        pins.gpio20,
        pins.gpio21,
        Some(pins.gpio22),
        Option::<esp_idf_hal::gpio::Gpio23>::None,
        &DriverConfig::new(),
        &Config::new().baudrate(2_000_000.into()),
    )?;



    // ---- Modem core + USB session ----
    let mut params = RadioParams::default();
    params.frequency = 867_500_000;
    params.bandwidth = 125_000;
    params.sf = 9;
    params.cr = 5;
    params.txpower = 14;
    params.radio_on = true;

    let mut radio = Radio {
        cs,
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
    let mut modem = Modem::new(Protocol::new(MCU_ESP32_C6));
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

