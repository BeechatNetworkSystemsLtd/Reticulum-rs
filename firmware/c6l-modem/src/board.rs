#![allow(dead_code)]
//! Board pin tables. C6L radio pins verified from the shipped
//! firmware boot log: SX1262(cs=23, irq=7, rst=-1, busy=19),
//! SPI SCK=20 MISO=22 MOSI=21, TCXO 3.0 V via DIO3, DIO2 RF switch.

/// M5Stack Unit C6L (ESP32-C6 + SX1262 + SSD1306).
pub mod c6l {
    pub const SX_NSS: u8 = 23;
    pub const SX_DIO1_IRQ: u8 = 7;
    pub const SX_BUSY: u8 = 19;
    /// RST not wired (shipped firmware reports rst=-1).
    pub const SX_RST: Option<u8> = None;
    pub const SPI_SCK: u8 = 20;
    pub const SPI_MISO: u8 = 22;
    pub const SPI_MOSI: u8 = 21;
    /// DIO3 TCXO reference voltage.
    pub const TCXO_VOLTS: f32 = 3.0;
}

/// Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262 + SSD1306) — pin map from
/// the rfsight firmware source; a future Xtensa build uses this table.
pub mod heltec_v3 {
    pub const SX_NSS: u8 = 8;
    pub const SX_DIO1_IRQ: u8 = 14;
    pub const SX_RST: Option<u8> = Some(12);
    pub const SX_BUSY: u8 = 13;
    pub const SPI_SCK: u8 = 9;
    pub const SPI_MISO: u8 = 11;
    pub const SPI_MOSI: u8 = 10;
}
