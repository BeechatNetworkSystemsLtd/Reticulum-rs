//! c6l-modem — RNode-class LoRa modem firmware for the M5Stack Unit C6L
//! (ESP32-C6 + SX1262), with USB-CDC and WiFi-TCP host links.
//!
//! Architecture: dual executor.
//! - Modem (USB + LoRa + sessions) on the INTERRUPT executor (always responsive)
//! - WiFi (association + TCP) on a dedicated THREAD executor

#![no_std]
#![no_main]

extern crate alloc;

use esp_backtrace as _;
use esp_hal::{clock::CpuClock, Config};

mod board;
mod modem_tasks;
mod raw_spi;
mod sessions;
mod sx1262;
mod wifi;

esp_bootloader_esp_idf::esp_app_desc!();

#[embassy_executor::task]
async fn interrupt_ticker() {
    esp_println::println!("INT-TICK: started");
    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
        esp_println::println!("INT-TICK");
    }
}

#[esp_hal::main]
fn main() -> ! {
    esp_alloc::heap_allocator!(size: 160_000);
    esp_println::println!("c6l-modem boot");

    let config = Config::default().with_cpu_clock(CpuClock::max());
    let peris = esp_hal::init(config);

    let (mut modem_hal, wifi_hal, rtos_hal) = modem_tasks::split(peris);

    // CRITICAL: Deselect the SSD1306 OLED BEFORE any SPI communication!
    // The M5Stack Unit C6L has the SSD1306 on the same SPI bus (SCK=20,
    // MOSI=21, MISO=22) with CS on GPIO 6. If GPIO 6 floats LOW, the OLED
    // drives MISO and corrupts all SX1262 communication.
    {
        // GPIO 6 (CS) = OUTPUT HIGH (deselect)
        let en = unsafe { core::ptr::read_volatile(0x6009_1020 as *const u32) };
        unsafe { core::ptr::write_volatile(0x6009_1020 as *mut u32, en | (1 << 6) | (1 << 18) | (1 << 15)) };
        unsafe { core::ptr::write_volatile(0x6009_1008 as *mut u32, (1 << 6) | (1 << 18)) }; // CS,DC HIGH
        unsafe { core::ptr::write_volatile(0x6009_100C as *mut u32, 1 << 15) }; // RESET LOW
    }
    // CRITICAL: Disable the SPI hardware's CS outputs (CS0-CS5)!
    // The GPSPI2's CS0 is on GPIO 6 (same as SSD1306 CS). By default,
    // the SPI hardware drives CS0, overriding our GPIO writes. Setting
    // CS0_DIS-CS5_DIS in the MISC register frees GPIO 6 for our control.
    unsafe { core::ptr::write_volatile(0x6008_1020 as *mut u32, 0x3F) }; // disable CS0-CS5
    esp_println::println!("OLED: deselected + SPI CS outputs disabled");

    // Radio bring-up: wait for the SX1262 power-on sequence, then init.
    esp_hal::delay::Delay::new().delay_millis(50);

        match modem_hal.radio.init(&esp_hal::delay::Delay::new()) {
        Ok(()) => {
            esp_println::println!("radio: SX1262 init ok");
            // Post-init SPI register dump
            let user2: u32 = unsafe { core::ptr::read_volatile(0x6008_1010 as *const u32) };
            let dlen2: u32 = unsafe { core::ptr::read_volatile(0x6008_101C as *const u32) };
            let ctrl2: u32 = unsafe { core::ptr::read_volatile(0x6008_1008 as *const u32) };
            let misc: u32 = unsafe { core::ptr::read_volatile(0x6008_1020 as *const u32) };
            let din_mode: u32 = unsafe { core::ptr::read_volatile(0x6008_1024 as *const u32) };
            let din_num: u32 = unsafe { core::ptr::read_volatile(0x6008_1028 as *const u32) };
            let dout_mode: u32 = unsafe { core::ptr::read_volatile(0x6008_102C as *const u32) };
            let w0: u32 = unsafe { core::ptr::read_volatile(0x6008_1058 as *const u32) };
            esp_println::println!("POST-INIT SPI: user={:x} doutdin={} ctrl={:x} dlen={:x} misc={:x} din={:x}/{:x} dout={:x} w0={:x}",
                user2, user2 & 1, ctrl2, dlen2, misc, din_mode, din_num, dout_mode, w0);
        }
        Err(_e) => esp_println::println!("radio: init failed at step, continuing"),
    }

    // Scheduler + embassy time driver
    esp_rtos::start(rtos_hal.timg0_timer, rtos_hal.sw_interrupt0);

    // WiFi bring-up on main thread (blocking calls need thread context)
    let wifi_stack = wifi::bringup(wifi_hal.wifi);

    // INTERRUPT executor: modem (always responsive)
    static IEXEC: static_cell::StaticCell<esp_rtos::embassy::InterruptExecutor<1>> =
        static_cell::StaticCell::new();
    let iexec = IEXEC.init(esp_rtos::embassy::InterruptExecutor::new(
        rtos_hal.sw_interrupt1,
    ));
    let modem_spawner = iexec.start(esp_hal::interrupt::Priority::Priority2);
    modem_spawner.spawn(modem_tasks::modem_task(modem_tasks::SendHal(modem_hal), modem_spawner).unwrap());
    modem_spawner.spawn(interrupt_ticker().unwrap());
    esp_println::println!("stage: modem on interrupt executor");

    // THREAD executor: WiFi (association + TCP)
    if let Some((controller, station)) = wifi_stack {
        static WEXEC: static_cell::StaticCell<esp_rtos::embassy::Executor> =
            static_cell::StaticCell::new();
        let wexec = WEXEC.init(esp_rtos::embassy::Executor::new());
        wexec.spawn("wifi-net", 24 * 1024, 1, move |spawner| {
            spawner.spawn(wifi::wifi_task(controller, station, spawner).unwrap());
        });
    }

    loop {
        esp_rtos::CurrentThreadHandle::get().delay(esp_hal::time::Duration::from_secs(60));
    }
}
