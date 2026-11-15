//! Modem actor task: owns the modem core, the SX1262 and the USB
//! console link. All other links (WiFi TCP sessions) reach it through
//! the session channels.
//!
//! Loop shape: poll USB + IRQ + telemetry every pass, wait on the next
//! inbound session message or a 5 ms cadence timer — whichever comes
//! first. Radio operations run inline; a transmission blocks this task
//! (and thus other sessions) for the packet airtime, which is the
//! intended single-radio behaviour.

use embassy_time::Duration;

use alloc::vec::Vec;

use esp_hal::{
    delay::Delay,
    gpio::{Input, Level, Output, Pull},
    peripherals::Peripherals,
    spi::master::{Config as SpiConfig, Spi},
    usb_serial_jtag::UsbSerialJtag,
};
use rnode_modem_core::frame::kiss_frame;
use rnode_modem_core::modem::Modem;
use rnode_modem_core::protocol::{Protocol, RadioOp, CMD_READY};
use rnode_modem_core::MCU_ESP32_C6;

use crate::sessions;
use crate::sx1262::{self, RadioConfig, Sx1262};

/// Console-safe logging. esp_println busy-waits for console space (and
/// so deadlocks with no reader attached), and interleaving text with a
/// live KISS stream corrupts the protocol — so log lines go into a
/// small ring buffer that the modem actor drains to USB, and only
/// while no KISS traffic has been seen.
use core::sync::atomic::{AtomicBool, Ordering};

static SAW_KISS: AtomicBool = AtomicBool::new(false);

pub fn note_kiss_traffic() {
    SAW_KISS.store(true, Ordering::Relaxed);
}

pub(crate) fn logs_allowed() -> bool {
    !SAW_KISS.load(Ordering::Relaxed)
}

pub mod logq {
    use core::sync::atomic::{AtomicUsize, Ordering};

    const CAP: usize = 1024;
    // Mutable backing store: a plain  lands in flash-mapped
    // .rodata and stores fault (hardware-verified the hard way).
    static mut BUF: [u8; CAP] = [0; CAP];
    static HEAD: AtomicUsize = AtomicUsize::new(0);
    static TAIL: AtomicUsize = AtomicUsize::new(0);

    /// Push bytes, dropping the tail when full (never blocks).
    pub fn push(bytes: &[u8]) {
        for &b in bytes {
            let head = HEAD.load(Ordering::Relaxed);
            let next = (head + 1) % CAP;
            let tail = TAIL.load(Ordering::Relaxed);
            if next == tail {
                return; // full — drop the rest of the line
            }
            // SAFETY: single producer regions are unique under the
            // head/tail protocol; byte writes are atomic-sized.
            unsafe {
                (core::ptr::addr_of_mut!(BUF) as *mut u8).add(head).write_volatile(b);
            }
            HEAD.store(next, Ordering::Relaxed);
        }
    }

    /// Drain pending bytes (single consumer: the modem actor).
    pub fn drain_into(out: &mut dyn FnMut(u8)) {
        loop {
            let tail = TAIL.load(Ordering::Relaxed);
            if tail == HEAD.load(Ordering::Relaxed) {
                return;
            }
            let b = unsafe { *(core::ptr::addr_of!(BUF) as *const u8).add(tail) };
            out(b);
            TAIL.store((tail + 1) % CAP, Ordering::Relaxed);
        }
    }
}

#[macro_export]
macro_rules! clog {
    ($($arg:tt)*) => {{
        if $crate::modem_tasks::logs_allowed() {
            use alloc::format;
            let line = format!($($arg)*);
            $crate::modem_tasks::logq::push(line.as_bytes());
            $crate::modem_tasks::logq::push(b"\r\n");
        }
    }};
}

/// Everything the actor task owns.
/// Send-wrapper for the modem HAL. The contained peripherals are only
/// ever touched by `modem_task` on a single executor; the `Async`
/// driver-mode marker is !Send by construction (single-context
/// assumption), which we preserve by never sharing the HAL.
pub struct SendHal(pub ModemHal);
// SAFETY: see struct docs — exclusive ownership by one task.
unsafe impl Send for SendHal {}


// shortcut: hardware-CS experiment kept for the next bringup session
#[allow(dead_code)]
/// A SpiDevice that relies on the SPI peripheral's hardware chip-select.
/// The ESP32-C6's GPSPI2 controls CS timing precisely, which the
/// software-CS path (ExclusiveDevice) cannot match for multi-byte
/// transfers to the SX1262.
pub struct HwCsSpiDevice {
    pub spi: Spi<'static, esp_hal::Blocking>,
    pub _delay: Delay,
}

impl embedded_hal::spi::ErrorType for HwCsSpiDevice {
    type Error = esp_hal::spi::Error;
}

impl embedded_hal::spi::SpiDevice<u8> for HwCsSpiDevice {
    fn transaction(
        &mut self,
        operations: &mut [embedded_hal::spi::Operation<'_, u8>],
    ) -> Result<(), Self::Error> {
        use embedded_hal::spi::{Operation, SpiBus};
        // Hardware CS is asserted by the SPI peripheral for each
        // start_operation() call, staying LOW for chunks < FIFO_SIZE.
        for op in operations {
            match op {
                Operation::Write(buf) => self.spi.write(buf)?,
                Operation::Read(buf) => self.spi.read(buf)?,
                Operation::TransferInPlace(buf) => self.spi.transfer_in_place(buf)?,
                Operation::Transfer(read, write) => { let _ = write; self.spi.transfer_in_place(read)?; }
                Operation::DelayNs(_) => {}
            }
        }
        Ok(())
    }
}

pub struct ModemHal {
    pub usb_rx: esp_hal::usb_serial_jtag::UsbSerialJtagRx<'static, esp_hal::Async>,
    pub usb_tx: esp_hal::usb_serial_jtag::UsbSerialJtagTx<'static, esp_hal::Async>,
    pub radio: Sx1262<
        embedded_hal_bus::spi::ExclusiveDevice<
            Spi<'static, esp_hal::Blocking>,
            Output<'static>,
            Delay,
        >,
        Input<'static>,
    >,
    pub irq: Input<'static>,
}

/// WiFi-side peripherals.
pub struct WifiHal {
    pub wifi: esp_hal::peripherals::WIFI<'static>,
}

/// Scheduler inputs for `esp_rtos::start`.

/// Chip-select driver that bypasses the broken esp-hal 1.1.2 GPIO output
/// path on ESP32-C6. All writes go straight to the GPIO_OUT_W1TS/W1TC
/// registers, which do work. The HAL pin is consumed so the pad stays
/// configured (output enabled, IO_MUX set to GPIO) for the lifetime of
/// this object.

pub struct RtosHal {
    pub timg0_timer: esp_hal::timer::timg::Timer<'static>,
    pub sw_interrupt0: esp_hal::interrupt::software::SoftwareInterrupt<'static, 0>,
    pub sw_interrupt1: esp_hal::interrupt::software::SoftwareInterrupt<'static, 1>,
}

/// Consume `Peripherals` and split it into the modem radio/USB half,
/// the WiFi half and the scheduler inputs.
pub fn split(peris: Peripherals) -> (ModemHal, WifiHal, RtosHal) {
    let spi = Spi::new(
        peris.SPI2,
        SpiConfig::default().with_frequency(esp_hal::time::Rate::from_mhz(2)),
    )
    .expect("spi config")
    .with_sck(peris.GPIO20)
    .with_mosi(peris.GPIO21)
    .with_miso(peris.GPIO22);
    let cs = Output::new(peris.GPIO23, Level::High, esp_hal::gpio::OutputConfig::default());
    let delay = Delay::new();

    let bus =
        embedded_hal_bus::spi::ExclusiveDevice::new(spi, cs, delay).expect("spi device");
    let irq = Input::new(peris.GPIO7, esp_hal::gpio::InputConfig::default().with_pull(Pull::Down));
    let busy = Input::new(peris.GPIO19, esp_hal::gpio::InputConfig::default().with_pull(Pull::Down));
    // CRITICAL: Force GPIO19 (BUSY) to GPIO function.
    // GPIO19 is a SPI flash pin (SPID) on ESP32-C6. The default IO_MUX
    // has MCU_SEL=0 (Function 1 = flash), which means the flash controller
    // owns the pin. We must set MCU_SEL=1 (GPIO) AND FUN_IE=1 to read it.
    {
        let reg = 0x60090050 as *mut u32; // GPIO19 IO_MUX
        unsafe { core::ptr::write_volatile(reg, (1 << 5) | 1) }; // FUN_IE=1, MCU_SEL=1
    }

    let radio = Sx1262::new(bus, busy);
    let (usb_rx, usb_tx) = UsbSerialJtag::new(peris.USB_DEVICE).into_async().split();

    let timg0 = esp_hal::timer::timg::TimerGroup::new(peris.TIMG0);
    let sw_ints = esp_hal::interrupt::software::SoftwareInterruptControl::new(peris.SW_INTERRUPT);

    (
        ModemHal { usb_rx, usb_tx, radio, irq },
        WifiHal { wifi: peris.WIFI },
        RtosHal {
            timg0_timer: timg0.timer0,
            sw_interrupt0: sw_ints.software_interrupt0,
            sw_interrupt1: sw_ints.software_interrupt1,
        },
    )
}

const TXQ_SIZE: usize = 4096;

struct TxQueue {
    buf: [u8; TXQ_SIZE],
    head: usize,
    tail: usize,
}

impl TxQueue {
    const fn new() -> Self {
        Self { buf: [0; TXQ_SIZE], head: 0, tail: 0 }
    }

    fn push(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let next = (self.head + 1) % TXQ_SIZE;
            if next == self.tail {
                return;
            }
            self.buf[self.head] = b;
            self.head = next;
        }
    }

    async fn drain(&mut self, usb: &mut esp_hal::usb_serial_jtag::UsbSerialJtagTx<'static, esp_hal::Async>) {
        use embedded_io_async::Write as _;
        if self.tail != self.head {
            let start = self.tail;
            let end = if self.head > self.tail { self.head } else { TXQ_SIZE };
            if usb.write_all(&self.buf[start..end]).await.is_ok() {
                self.tail = end % TXQ_SIZE;
            }
            let _ = usb.flush().await;
        }
    }
}

static TXQ: static_cell::StaticCell<TxQueue> = static_cell::StaticCell::new();

/// USB reader task: a dedicated task so the async `read` future is
/// never cancelled (select-cancellation drops in-flight reads and the
/// bytes they consumed — the cause of lost KISS frames).
#[embassy_executor::task]
pub async fn usb_rx_task(usb_rx: crate::modem_tasks::SendUsbRx) {
    let SendUsbRx(mut rx) = usb_rx;
    let mut buf = [0u8; 256];
    loop {
        match embedded_io_async::Read::read(&mut rx, &mut buf).await {
            Ok(n) if n > 0 => {
                note_kiss_traffic();
                let sid = USB_SID.load(core::sync::atomic::Ordering::Relaxed) as u64;
                let chunk: alloc::vec::Vec<u8> = buf[..n].to_vec();
                if sessions::to_modem().try_send((sid, chunk)).is_err() {
                    // modem backlogged; drop (host will retry at KISS level)
                }
            }
            _ => {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
            }
        }
    }
}

/// Actual session id of the USB link (assigned by `Modem::add_session`
/// in `modem_task`); `sessions::USB_SESSION` is a routing constant and
/// must not be used as a feed id.
pub static USB_SID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub struct SendUsbRx(pub esp_hal::usb_serial_jtag::UsbSerialJtagRx<'static, esp_hal::Async>);
// SAFETY: exclusively owned by usb_rx_task.
unsafe impl Send for SendUsbRx {}

#[embassy_executor::task]
pub async fn modem_task(hal: SendHal, _task_spawner: embassy_executor::SendSpawner) {
    esp_println::println!("modem: actor up");
    let SendHal(ModemHal {
        usb_rx,
        mut usb_tx,
        mut radio,
        mut irq,
    }) = hal;

    // SAFETY: this task is running on an embassy executor.
    let spawner = unsafe { embassy_executor::Spawner::for_current_executor() }.await;
    spawner.spawn(usb_rx_task(SendUsbRx(usb_rx)).unwrap());

    let mut modem = Modem::new(Protocol::new(MCU_ESP32_C6));
    let usb_sid = modem.add_session();
    USB_SID.store(usb_sid as u32, core::sync::atomic::Ordering::Relaxed);
    esp_println::println!("MODEM: session {}", usb_sid);




    // (SSD1306 deselect now in main() before radio.init)
    // SPI bus configured by main() before radio.init

    // Note: SPI pins are in IO_MUX direct mode (MCU_SEL=0) which provides the
    // fastest, most direct connection to the SX1262. Do NOT switch to GPIO
    // matrix mode (MCU_SEL=1) — that breaks MISO input routing.
    esp_println::println!("MODEM: entering loop");

    let txq = TXQ.init(TxQueue::new());
    let txq: &mut TxQueue = unsafe { &mut *(txq as *const TxQueue as *mut TxQueue) };


    let mut pkt = [0u8; 256];

    let mut ticker = embassy_time::Ticker::every(Duration::from_millis(50));
    let _loop_count: u64 = 0;
    let inbound_rx = sessions::to_modem_rx();

    let mut loop_n: u64 = 0;
    loop {
        loop_n += 1;
        if loop_n <= 5 {
            esp_println::println!("LOOP-#{}", loop_n);
        }
        // Drain pending USB TX and log queue first.
        txq.drain(&mut usb_tx).await;
        if logs_allowed() {
            let mut sink = |b: u8| txq.push(&[b]);
            logq::drain_into(&mut sink);
        }

        // Drain the channel (for USB messages from same executor).
        while let Ok((sid, bytes)) = sessions::to_modem_rx().try_receive() {

            let fed = modem.feed(sid, &bytes);
            handle_ops(&mut radio, &mut modem, txq, fed.ops, sid, usb_sid).await;
            let is_usb = sid == usb_sid;
            for frame in fed.to_sender.iter() {
                if is_usb {
                    txq.push(frame);
                } else {
                    sessions::send_to(sid, frame.clone()).await;
                }
            }
            for frame in fed.to_others {
                if !is_usb {
                    sessions::send_to(sid, frame.clone()).await;
                }
            }
        }

        // Telemetry tick.
        if loop_n % 40 == 0 {
            let irq_st = radio.irq_status().unwrap_or(0);
            let rssi = radio.current_rssi().unwrap_or(0);
            let st = radio.get_status().unwrap_or(0); let mode = (st >> 4) & 0x7; // RadioLib: mode at bits [6:4]
        // Raw SPI probe: send GetIrqStatus opcode + 3 NOPs via transfer_in_place
        
        
            modem.protocol.stats.rssi = rssi;
            // Radio telemetry: print IRQ/RSSI/mode for debugging
            let busy_raw: u32 = unsafe { core::ptr::read_volatile(0x6009_103C as *const u32) };
            let busy_bit = (busy_raw >> 19) & 1;
            let busy_iomux: u32 = unsafe { core::ptr::read_volatile(0x60090050 as *const u32) };
            esp_println::println!(
                "RT: irq={:04x} rssi={} mode={} busy={} ie={}",
                irq_st, rssi, mode, busy_bit, (busy_iomux >> 5) & 1
            );
            // DEFINITIVE TEST: Send SetSleep(0x84, 0x04=cold start).
            // If the radio sleeps, GetStatus will return garbage/0.
            let before = radio.get_status().unwrap_or(0);
            let _ = radio.cmd(0x84, &[0x04]); // SetSleep(cold start)
            let mut d = 0u32; while d < 160_000 { d += 1; } // 2ms
            let after_sleep = radio.get_status().unwrap_or(0);
            esp_println::println!("RT: before={:02x} after_sleep={:02x}", before, after_sleep);
            // Wake it back up with NOP
            let _ = radio.cmd(0x00, &[]); // NOP (wake from sleep)
            d = 0; while d < 160_000 { d += 1; } // 2ms
            let after_wake = radio.get_status().unwrap_or(0);
            esp_println::println!("RT: after_wake={:02x}", after_wake);
            // SPLIT-BYTE TEST: send SetStandby as two 1-byte transfers under one CS
            if loop_n % 40 == 20 { // alternate with the clear test
                radio.cs_low();
                let mut op = [0x80u8];
                let _ = crate::raw_spi::transfer(&mut op);
                let mut param = [0x00u8];
                let _ = crate::raw_spi::transfer(&mut param);
                radio.cs_high();
                let mut d = 0u32; while d < 8_000 { d += 1; }
                let after_sb = radio.get_status().unwrap_or(0);
                let sb_mode = (after_sb >> 4) & 0x7;
                esp_println::println!("RT: after_setstandby mode={} (was {})", sb_mode, mode);
                // Go back to RX
                let _ = radio.start_rx();
            }
            // Print esp-rtos diagnostic counters
            let d = &esp_rtos::RTOS_DIAG;
            esp_println::println!(
                "DIAG set={} nowait={} haswait={} resumed={} wait={} sleep={} poll={} woke={}",
                d[0].load(core::sync::atomic::Ordering::Relaxed),
                d[1].load(core::sync::atomic::Ordering::Relaxed),
                d[2].load(core::sync::atomic::Ordering::Relaxed),
                d[3].load(core::sync::atomic::Ordering::Relaxed),
                d[4].load(core::sync::atomic::Ordering::Relaxed),
                d[5].load(core::sync::atomic::Ordering::Relaxed),
                d[6].load(core::sync::atomic::Ordering::Relaxed),
                d[7].load(core::sync::atomic::Ordering::Relaxed),
            );
        }

        // Wait for the next event: USB bytes, session message, radio IRQ
        // edge or the cadence tick.
        use embassy_futures::select::{select3, Either3};
        let inbound = inbound_rx.receive();
        let irq_edge = embedded_hal_async::digital::Wait::wait_for_rising_edge(&mut irq);
        match select3(inbound, irq_edge, ticker.next()).await {
            Either3::First((sid, bytes)) => {
                if sid != usb_sid {
                    esp_println::println!("SELECT3-TCP: sid={} len={}", sid, bytes.len());
                }
                let fed = modem.feed(sid, &bytes);
                if sid != usb_sid {
                    esp_println::println!("SELECT3-FED: replies={}", fed.to_sender.len());
                }
                handle_ops(&mut radio, &mut modem, txq, fed.ops, sid, usb_sid).await;
                let is_usb = sid == usb_sid;
                for frame in fed.to_sender.iter() {
                    if is_usb {
                        txq.push(frame);
                    } else {
                                                sessions::send_to(sid, frame.clone()).await;
                    }
                }
                for frame in fed.to_others {
                    if !is_usb {
                        sessions::send_to(sid, frame.clone()).await;
                    }
                }
            }
            Either3::Second(_) => {
                // Radio IRQ edge: packet received (or TX done/CRC error).
                if let Ok(flags) = radio.irq_status() {
                    if sx1262::rx_done(flags) && !sx1262::crc_error(flags) {
                        if let Ok((len, rssi, snr)) = radio.read_packet(&mut pkt) {
                            modem.protocol.stats.rssi = rssi;
                            modem.protocol.stats.snr = snr as f32 / 4.0;
                            let ids = modem.session_ids();
                            let frames = modem.radio_rx(&pkt[..len]);
                            for (sid, frame) in ids.iter().zip(frames) {
                                if *sid == usb_sid {
                                    txq.push(&frame);
                                } else {
                                    sessions::send_to(*sid, frame).await;
                                }
                            }
                        }
                    }
                    let _ = radio.clear_irq();
                    let _ = radio.start_rx();
                }
            }
            Either3::Third(_) => {}
        }
    }
}

/// Perform radio operations requested by the protocol layer. Transmits
/// wait asynchronously for TX-done (or the ~2 s radio timeout).
async fn handle_ops(
    radio: &mut Sx1262<
        embedded_hal_bus::spi::ExclusiveDevice<
            Spi<'static, esp_hal::Blocking>,
            Output<'static>,
            Delay,
        >,
        Input<'static>,
    >,
    modem: &mut Modem,
    txq: &mut TxQueue,
    ops: Vec<RadioOp>,
    session: u64,
    usb_sid: u64,
) {
    for op in ops {
        match op {
            RadioOp::Transmit(data) => {
                if radio.transmit(&data).is_err() {
                    clog!("radio: tx start failed");
                }
                loop {
                    if let Ok(flags) = radio.irq_status() {
                        if sx1262::tx_done(flags) || sx1262::timed_out(flags) {
                            break;
                        }
                    }
                    embassy_futures::yield_now().await;
                }
                let _ = radio.start_rx();
                modem.protocol.tx_complete(data.len());
                let ready = kiss_frame(CMD_READY, &[0x01]);
                if session == usb_sid {
                    txq.push(&ready);
                } else {
                    sessions::send_to(session, ready).await;
                }
            }
            RadioOp::Configure(params) => {
                let cfg = RadioConfig {
                    frequency: params.frequency,
                    bandwidth: params.bandwidth,
                    sf: params.sf,
                    cr: params.cr,
                    txpower: params.txpower as i8,
                    preamble_syms: 8,
                };
                if radio.apply(&cfg).is_ok() {
                    let _ = radio.start_rx();
                }
            }
            RadioOp::RadioOn => {
                let _ = radio.start_rx();
            }
            RadioOp::RadioOff => {
                let _ = radio.sleep();
            }
        }
    }
}
