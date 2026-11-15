//! SX1262 LoRa radio driver (blocking SPI) for the c6l-modem firmware.
//!
//! Command set and semantics follow the SX126x datasheet / RNode
//! firmware `sx126x.cpp`. Air conventions that matter for sharing a
//! channel with Heltec-class RNodes: sync word 0x1424 (0x0740/0x0741),
//! 8-symbol preamble (matches the modem-core airtime maths), explicit
//! headers, LoRa CRC on.


use crate::board::c6l;

// --- SPI opcodes (SX126x datasheet, sx126x.cpp) ---------------------------
const OP_NOP: u8 = 0x00;
const OP_SET_STANDBY: u8 = 0x80;
const OP_SET_RX: u8 = 0x82;
const OP_SET_TX: u8 = 0x83;
const OP_SET_SLEEP: u8 = 0x84;
const OP_SET_RF_FREQUENCY: u8 = 0x86;
const OP_SET_PACKET_TYPE: u8 = 0x8A;
const OP_SET_MODULATION_PARAMS: u8 = 0x8B;
const OP_SET_PACKET_PARAMS: u8 = 0x8C;
const OP_SET_TX_PARAMS: u8 = 0x8E;
const OP_SET_PA_CONFIG: u8 = 0x95;
const OP_SET_DIO_IRQ_PARAMS: u8 = 0x08;
const OP_GET_IRQ_STATUS: u8 = 0x12;
const OP_CLEAR_IRQ_STATUS: u8 = 0x02;
const OP_SET_BUFFER_BASE_ADDRESS: u8 = 0x8F;
const OP_WRITE_BUFFER: u8 = 0x0E;
const OP_READ_BUFFER: u8 = 0x1E;
const OP_GET_RX_BUFFER_STATUS: u8 = 0x13;
const OP_GET_PACKET_STATUS: u8 = 0x14;
const OP_GET_CURRENT_RSSI: u8 = 0x15;
const OP_REGULATOR_MODE: u8 = 0x96;
const OP_CALIBRATE: u8 = 0x89;
const OP_CALIBRATE_IMAGE: u8 = 0x98;
const OP_DIO3_TCXO_CTRL: u8 = 0x97;
const OP_DIO2_RF_CONTROL: u8 = 0x9D;
const OP_SET_RX_TX_FALLBACK: u8 = 0x93;
const OP_WRITE_REGISTER: u8 = 0x0D;

const REG_SYNC_WORD_MSB: u16 = 0x0740;
/// RNode private-network sync word (`SYNC_WORD_6X`).
const SYNC_WORD_RNODE: [u8; 2] = [0x14, 0x24];

const IRQ_TX_DONE: u16 = 0x0001;
const IRQ_RX_DONE: u16 = 0x0002;
const IRQ_CRC_ERR: u16 = 0x0040;
const IRQ_TIMEOUT: u16 = 0x0080;
const IRQ_ALL: u16 = 0x02FF;

const STANDBY_RC: u8 = 0x00;
const STANDBY_XOSC: u8 = 0x01;
const PACKET_TYPE_LORA: u8 = 0x01;
const XTAL_HZ: u64 = 32_000_000;

#[derive(Debug)]
#[allow(dead_code)]
pub enum RadioError {
    Busy,
    Spi,
}

/// Radio configuration commanded by the host.
#[derive(Clone, Debug)]
pub struct RadioConfig {
    pub frequency: u32,
    pub bandwidth: u32,
    pub sf: u8,
    pub cr: u8,
    pub txpower: i8,
    pub preamble_syms: u16,
}

impl Default for RadioConfig {
    fn default() -> Self {
        Self {
            frequency: 867_500_000,
            bandwidth: 125_000,
            sf: 9,
            cr: 5,
            txpower: 2,
            preamble_syms: 8,
        }
    }
}


pub struct Sx1262<BUS, BUSY>
where
    BUS: embedded_hal::spi::SpiDevice,
    BUSY: embedded_hal::digital::InputPin,
{
    bus: BUS,
    busy: BUSY,

}

impl<BUS, BUSY> Sx1262<BUS, BUSY>
where
    BUS: embedded_hal::spi::SpiDevice,
    BUSY: embedded_hal::digital::InputPin,
{
    pub fn new(bus: BUS, busy: BUSY) -> Self {
        Self { bus, busy }
    }

    /// The SX1262 requires BUSY low before any SPI command (datasheet
    /// 13.2). On the C6L the pin mapped as BUSY in the vendor firmware
    /// reads high at idle while the radio is fully responsive over SPI,
    /// so we do not gate on it at all (logged once at init). If a future
    /// board revision wires a working BUSY, restore the poll here.
    /// Read the BUSY pin via the raw GPIO input register.
    ///
    /// esp-hal 1.1.2's ESP32-C6 GPIO driver returns inverted/garbage levels
    /// for some pins (observed: GPIO19 reads `high` while the pad is
    /// physically low). Reading GPIO_IN_REG directly works reliably.
    #[allow(dead_code)] // shortcut: raw-SPI bringup diagnostic
    #[inline]
    fn busy_raw(&mut self) -> bool {
        self.busy.is_high().unwrap_or(true)
    }

    /// No-op: the raw SPI driver configures the peripheral per-transfer.
    #[inline]
    fn force_full_duplex(&self) {}

    /// Drive the SX1262 NCS (GPIO23) LOW via GPIO_OUT_W1TC.
    /// Includes a ~250ns settle delay (datasheet: 50ns CS setup minimum).
    #[inline]
    pub fn cs_low(&mut self) {
        unsafe { core::ptr::write_volatile(0x6009_100C as *mut u32, 1 << 23) };
        let mut d = 0u32; while d < 40 { d += 1; } // ~250ns at 160MHz
    }

    /// Drive the SX1262 NCS (GPIO23) HIGH via GPIO_OUT_W1TS.
    /// Includes a ~250ns settle delay (datasheet: 50ns CS hold minimum).
    #[inline]
    pub fn cs_high(&mut self) {
        unsafe { core::ptr::write_volatile(0x6009_1008 as *mut u32, 1 << 23) };
        let mut d = 0u32; while d < 40 { d += 1; } // ~250ns at 160MHz
    }

    fn wait_ready(&mut self) -> Result<(), RadioError> {
        // BUSY now reads correctly (MCU_SEL=1 on GPIO19). Wait for it to
        // go LOW before sending commands — the SX1262 ignores writes while
        // BUSY is HIGH. Generous timeout (100ms) matching RadioLib.
        let mut waited = 0u32;
        while self.busy.is_high().unwrap_or(false) {
            waited += 1;
            if waited > 8_000_000 {
                return Err(RadioError::Busy);
            }
        }
        Ok(())
    }

    pub fn cmd(&mut self, opcode: u8, payload: &[u8]) -> Result<(), RadioError> {
        self.wait_ready()?;
        let len = 1 + payload.len().min(11);
        let mut frame = [0u8; 12];
        frame[0] = opcode;
        frame[1..len].copy_from_slice(&payload[..len - 1]);
        // Use the ESP32 HAL SPI driver (ExclusiveDevice) instead of raw_spi.
        // The HAL's fill_fifo + start_operation path might handle something
        // our raw driver misses (bit ordering, FIFO management, etc.).
        self.bus
            .transfer_in_place(&mut frame[..len])
            .map_err(|_| RadioError::Spi)?;
        // Generous settle delay
        for _ in 0..80_000 { core::hint::black_box(()); }
        Ok(())
    }

    /// Read-type command: send `opcode`, clock `out.len()` NOP/status
    /// bytes back. `out[0]` is the radio status byte where applicable —
    /// callers index accordingly (datasheet 13.3).
    fn cmd_read(&mut self, opcode: u8, out: &mut [u8]) -> Result<(), RadioError> {
        self.wait_ready()?;
        let len = 2 + out.len();
        let mut frame = [0u8; 10];
        frame[0] = opcode;
        frame[1] = 0x00; // status byte slot
        self.bus
            .transfer_in_place(&mut frame[..len])
            .map_err(|_| RadioError::Spi)?;
        // Data starts after opcode + status byte
        out.copy_from_slice(&frame[2..2 + out.len()]);
        Ok(())
    }

    fn write_reg(&mut self, reg: u16, data: &[u8]) -> Result<(), RadioError> {
        self.force_full_duplex();
        self.wait_ready()?;
        let mut frame = [0u8; 8];
        frame[0] = OP_WRITE_REGISTER;
        frame[1] = (reg >> 8) as u8;
        frame[2] = reg as u8;
        frame[3..3 + data.len()].copy_from_slice(data);
        self.bus.write(&frame[..3 + data.len()]).map_err(|_| RadioError::Spi)
    }

    /// Full bring-up: TCXO, regulator, calibration, LoRa parameters.
    /// Force the SX1262 SPI interface to a known state by sending NOP
    /// commands. Per datasheet 14.4, NOP resets the SPI state machine and
    /// can be sent at any time (even while BUSY is high).
    pub fn spi_reset(&mut self) {
        for _ in 0..10 {
            let _ = self.bus.write(&[OP_NOP]);
        }
    }

    /// Force a brownout reset of the SX1262 by sinking current from
    /// all GPIO pins simultaneously — this discharges the 3.3V rail's
    /// bulk capacitors enough to trigger the radio's power-on reset.
    /// (No RST pin on this board; USB hub "power cycling" doesn't cut VBUS.)
    // shortcut: raw-SPI bringup diagnostics, not in the serving path
    #[allow(dead_code)]
    pub fn force_brownout_reset(&mut self) {
        // 1. Configure all safe GPIOs as outputs driving LOW
        //    (this creates a load on the 3.3V rail through pull-ups and
        //     the SX1262's own I/O, discharging its supply capacitors)
        unsafe {
            // Set GPIO_ENABLE for all pins 0-30
            let en_addr = 0x6009_1020 as *mut u32;
            core::ptr::write_volatile(en_addr, 0x7FFF_FFFF);
            // Drive all GPIO_OUT LOW
            let out_addr = 0x6009_1004 as *mut u32;
            core::ptr::write_volatile(out_addr, 0x0000_0000);
            // Also clear via W1TC for good measure
            core::ptr::write_volatile(0x6009_100C as *mut u32, 0x7FFF_FFFF);
        }
        // 2. Wait for capacitors to discharge (~500ms)
        for _ in 0..5_000_000 { core::hint::black_box(()); }
        // 3. Release: set all pins back to input (high-Z)
        unsafe {
            let en_addr = 0x6009_1020 as *mut u32;
            core::ptr::write_volatile(en_addr, 0x0000_0000);
        }
        // 4. Wait for the radio to boot (~10ms)
        for _ in 0..1_000_000 { core::hint::black_box(()); }
    }

    /// Full init via GPIO bit-banging (bypasses the SPI peripheral entirely).
    /// Tests whether the SX1262 responds correctly to manual SPI.
    // shortcut: bringup diagnostic kept for the next hardware session, not in the serving path
    #[allow(dead_code)]
    pub fn init_bitbang(&mut self, delay: &esp_hal::delay::Delay) -> Result<(), RadioError> {
        // Claim SPI pins for GPIO control
        crate::raw_spi::bitbang_claim_pins();

        // Helper: send a command via bit-bang with CS control
        macro_rules! bb_cmd {
            ($opcode:expr, $payload:expr) => {{
                crate::raw_spi::gpio_clr(23); // CS LOW
                let mut buf = [0u8; 8];
                buf[0] = $opcode;
                for (i, &b) in $payload.iter().enumerate() {
                    buf[i + 1] = b;
                }
                crate::raw_spi::bitbang_transfer(&mut buf[..1 + $payload.len()]);
                crate::raw_spi::gpio_set(23); // CS HIGH
                // Wait for command to process (~100µs)
                for _ in 0..8000 { core::hint::black_box(()); }
            }};
        }

        // Helper: read status via bit-bang
        let bb_status = || -> u8 {
            crate::raw_spi::gpio_clr(23);
            let mut buf = [0xC0u8];
            crate::raw_spi::bitbang_transfer(&mut buf);
            crate::raw_spi::gpio_set(23);
            for _ in 0..2000 { core::hint::black_box(()); }
            buf[0]
        };

        // Full init sequence via bit-bang
        let st0 = bb_status();
        esp_println::println!("BB: initial status={:x}", st0);

        // NOP to reset SPI state
        crate::raw_spi::gpio_clr(23);
        let mut nop = [0x00u8];
        crate::raw_spi::bitbang_transfer(&mut nop);
        crate::raw_spi::gpio_set(23);
        for _ in 0..4000 { core::hint::black_box(()); }

        // SetStandby(STBY_RC) = [0x80, 0x00]
        bb_cmd!(0x80, [0x00u8]);
        let st1 = bb_status();
        esp_println::println!("BB: after standby={:x}", st1);

        // SetRfFrequency(867.5 MHz) = [0x86, freq_be]
        let freq: u32 = ((867_500_000u64 * (1u64 << 25)) / 32_000_000) as u32;
        bb_cmd!(0x86, freq.to_be_bytes());
        let st2 = bb_status();
        esp_println::println!("BB: after freq={:x}", st2);

        // SetPacketType(LoRa) = [0x88, 0x01]
        bb_cmd!(0x88, [0x01u8]);

        // SetRx(continuous) = [0x82, 0xFF, 0xFF, 0xFF]
        bb_cmd!(0x82, [0xFFu8, 0xFF, 0xFF]);
        let st3 = bb_status();
        esp_println::println!("BB: after setrx={:x}", st3);

        // Read IRQ status via bit-bang: [0x12, NOP, NOP]
        crate::raw_spi::gpio_clr(23);
        let mut irq_buf = [0x12u8, 0x00, 0x00];
        crate::raw_spi::bitbang_transfer(&mut irq_buf);
        crate::raw_spi::gpio_set(23);
        esp_println::println!("BB: irq=[{:02x},{:02x},{:02x}]", irq_buf[0], irq_buf[1], irq_buf[2]);

        let _ = delay;
        Ok(())
    }

    pub fn init(&mut self, delay: &esp_hal::delay::Delay) -> Result<(), RadioError> {
        // Force SPI to known state first (no RST pin on this board)
        self.spi_reset();
        delay.delay_millis(5);
        // DIO3 TCXO: 3.0 V, 20 ms timeout (units of 15.625 us -> 0x0500).
        let timeout_units: u32 = 0x0500; // 20 ms in 15.625 us units
        let volts_units: u32 = (c6l::TCXO_VOLTS * 100.0) as u32; // 3.0 V -> 300 (10 mV steps)
        // SetDio3AsTcxoClock parameter order (datasheet Table 11-8):
        //   byte 1-2: tcxoVoltage (big-endian, 10 mV steps)  <- VOLTAGE FIRST
        //   byte 3-4: delay (big-endian, 15.625 us units)    <- TIMEOUT SECOND
        // We previously had these swapped, sending 12.8 V as the TCXO
        // voltage, which put the SX1262 into permanent BUSY.
        let tcxo = (volts_units << 16) | timeout_units;
        let bytes = tcxo.to_be_bytes();
        // Send TCXO command with CORRECT byte order (voltage first!)
        self.cmd(OP_DIO3_TCXO_CTRL, &bytes)?;
        delay.delay_millis(100); // Wait for TCXO to stabilize (generous)
        esp_println::println!("init: tcxo sent");

        self.cmd(OP_SET_STANDBY, &[STANDBY_XOSC])
            .map_err(|e| {
                match e {
                    RadioError::Busy => esp_println::println!("init: standby BUSY-timeout"),
                    RadioError::Spi => esp_println::println!("init: standby SPI-error"),
                }
                e
            })?;
        esp_println::println!("init: standby ok");
        self.cmd(OP_REGULATOR_MODE, &[0x01])?; // DC-DC
        esp_println::println!("init: regulator ok");
        self.cmd(OP_CALIBRATE, &[0x7F])?;
        delay.delay_millis(50);
        esp_println::println!("init: calib ok");
        self.cmd(OP_CALIBRATE_IMAGE, &[0xD7, 0xDB])?; // 863–870 MHz
        esp_println::println!("init: calib image ok");
        self.cmd(OP_DIO2_RF_CONTROL, &[0x01])?; // DIO2 = RF switch
        esp_println::println!("init: dio2 ok");
        self.cmd(OP_SET_PACKET_TYPE, &[PACKET_TYPE_LORA])?;
        esp_println::println!("init: packet type ok");
        self.write_reg(REG_SYNC_WORD_MSB, &SYNC_WORD_RNODE)?;
        esp_println::println!("init: sync word ok");
        self.cmd(OP_SET_RX_TX_FALLBACK, &[STANDBY_RC])?;
        esp_println::println!("init: fallback ok");

        self.apply(&RadioConfig::default())?;
        esp_println::println!("init: apply ok");
        self.start_rx()?;
        esp_println::println!("init: start rx ok");
        Ok(())
    }

    /// (Re)apply modulation / packet / power parameters.
    pub fn apply(&mut self, cfg: &RadioConfig) -> Result<(), RadioError> {
        let rf = ((cfg.frequency as u64) * (1u64 << 25)) / XTAL_HZ;
        self.cmd(OP_SET_RF_FREQUENCY, &rf.to_be_bytes())?;

        let bw_code = match cfg.bandwidth {
            7_800 => 0x00,
            10_400 => 0x08,
            15_600 => 0x01,
            20_800 => 0x09,
            31_250 => 0x02,
            41_700 => 0x0A,
            62_500 => 0x03,
            125_000 => 0x04,
            250_000 => 0x05,
            500_000 => 0x06,
            _ => 0x04,
        };
        let ldro: u8 = if cfg.sf >= 11 { 1 } else { 0 };
        self.cmd(OP_SET_MODULATION_PARAMS, &[cfg.sf, bw_code, cfg.cr, ldro])?;

        self.cmd(
            OP_SET_PACKET_PARAMS,
            &[
                (cfg.preamble_syms >> 8) as u8,
                cfg.preamble_syms as u8,
                0x00, // explicit header
                0xFF, // dynamic payload length
                0x00, // LoRa CRC OFF — RNode/Reticulum handles integrity at protocol level
                0x00, // standard IQ
            ],
        )?;

        // PA: SX1262 high-power settings, OCP covered by defaults.
        self.cmd(OP_SET_PA_CONFIG, &[0x04, 0x07, 0x00, 0x01])?;
        let power_byte = (cfg.txpower + 18).clamp(0, 22) as u8;
        self.cmd(OP_SET_TX_PARAMS, &[power_byte, 0x04])?;

        let mask = IRQ_TX_DONE | IRQ_RX_DONE | IRQ_CRC_ERR | IRQ_TIMEOUT;
        self.cmd(
            OP_SET_DIO_IRQ_PARAMS,
            &[
                (mask >> 8) as u8,
                mask as u8,
                (mask >> 8) as u8,
                mask as u8,
                0x00,
                0x00,
                0x00,
                0x00,
            ],
        )?;
        Ok(())
    }

    pub fn start_rx(&mut self) -> Result<(), RadioError> {
        self.cmd(OP_SET_BUFFER_BASE_ADDRESS, &[0x00, 0x80])?;
        self.clear_irq()?;
        // Map RxDone + TxDone to DIO1 so the modem task's edge interrupt fires.
        let irq_mask: u16 = 0x03FF; // all common IRQs
        let dio1_mask: u16 = 0x0002 | 0x0001; // RxDone + TxDone
        let mut params = [0u8; 8];
        params[0..2].copy_from_slice(&irq_mask.to_be_bytes());
        params[2..4].copy_from_slice(&dio1_mask.to_be_bytes());
        self.cmd(0x98, &params)?; // OP_SET_DIO_IRQ_PARAMS
        self.cmd(OP_SET_RX, &[0xFF, 0xFF, 0xFF])?; // continuous
        Ok(())
    }

    pub fn clear_irq(&mut self) -> Result<(), RadioError> {
        let all = IRQ_ALL.to_be_bytes();
        self.cmd(OP_CLEAR_IRQ_STATUS, &all)
    }

    pub fn irq_status(&mut self) -> Result<u16, RadioError> {
        let mut out = [0u8; 3]; // status, irq_msb, irq_lsb
        self.cmd_read(OP_GET_IRQ_STATUS, &mut out)?;
        Ok(u16::from_be_bytes([out[0], out[1]]))
    }

    /// Queue `data` for transmission and start TX (2 s timeout).
    /// The caller polls `irq_status` for TX-done.
    pub fn transmit(&mut self, data: &[u8]) -> Result<(), RadioError> {
        self.cmd(OP_SET_BUFFER_BASE_ADDRESS, &[0x80, 0x00])?;
        // Write payload in <=8-byte SPI chunks (frame scratch is small).
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + 8).min(data.len());
            self.wait_ready()?;
            let chunk = &data[offset..end];
            let mut frame = [0u8; 9];
            frame[0] = OP_WRITE_BUFFER;
            frame[1] = offset as u8;
            frame[2..2 + chunk.len()].copy_from_slice(chunk);
            self.bus.write(&frame[..2 + chunk.len()]).map_err(|_| RadioError::Spi)?;
            offset = end;
        }
        self.clear_irq()?;
        self.cmd(OP_SET_TX, &[0x00, 0x1E, 0x84])?; // ~2 s timeout
        Ok(())
    }

    /// Read the last received packet: (length, rssi dBm, snr quarter-dB).
    pub fn read_packet(&mut self, buf: &mut [u8]) -> Result<(usize, i16, i16), RadioError> {
        let mut status = [0u8; 3]; // irq_msb, payload_length, rx_buffer_offset
        self.cmd_read(OP_GET_RX_BUFFER_STATUS, &mut status)?;
        let len = status[0] as usize;
        let mut out = [0u8; 8];
        let mut n = 0;
        while n < len.min(buf.len()) {
            let end = (n + 8).min(len.min(buf.len()));
            self.wait_ready()?;
            self.bus
                .write(&[OP_READ_BUFFER, n as u8])
                .map_err(|_| RadioError::Spi)?;
            self.bus
                .transfer_in_place(&mut out[..end - n])
                .map_err(|_| RadioError::Spi)?;
            buf[n..end].copy_from_slice(&out[..end - n]);
            n = end;
        }

        let mut pkt = [0u8; 3]; // irq_msb, rssi_pkt, snr_pkt
        self.cmd_read(OP_GET_PACKET_STATUS, &mut pkt)?;
        let rssi = -(pkt[1] as i16) / 2;
        let snr = pkt[2] as i8 as i16;
        Ok((n, rssi, snr))
    }

    /// Read the SX1262 status byte: bits 6:4 = chip mode, bits 3:1 = command status.
    /// Chip modes: 2=STBY_RC, 3=STBY_XOSC, 4=FS, 5=RX, 6=TX
    #[allow(dead_code)]
    /// Read back a register (diagnostic: verify bidirectional SPI)
    pub fn read_reg(&mut self, reg: u16) -> Result<u8, RadioError> {
        self.wait_ready()?;
        use embedded_hal::spi::Operation;
        let cmd = [0x1Du8, (reg >> 8) as u8, reg as u8];
        let mut data = [0u8; 1];
        let mut ops = [Operation::Write(&cmd[..]), Operation::Read(&mut data[..])];
        self.bus
            .transaction(&mut ops)
            .map_err(|_| RadioError::Spi)?;
        Ok(data[0])
    }


    // shortcut: raw-SPI bringup diagnostics, not in the serving path
    #[allow(dead_code)]
    /// GetStatus without BUSY wait — for pre-init diagnostics.
    pub fn get_status_noinit(&mut self) -> u8 {
        let mut buf = [0xC0u8];
        self.cs_low();
        let _ = crate::raw_spi::transfer(&mut buf);
        self.cs_high();
        buf[0]
    }

    #[allow(dead_code)]
    /// GetStatus via RAW SPI (bypassing HAL) with manual CS control.
    pub fn get_status_raw(&mut self) -> u8 {
        // CS LOW (GPIO23)
        unsafe { core::ptr::write_volatile(0x6009_100C as *mut u32, 1 << 23) };
        let mut buf = [0xC0u8];
        let _ = crate::raw_spi::transfer(&mut buf);
        // CS HIGH
        unsafe { core::ptr::write_volatile(0x6009_1008 as *mut u32, 1 << 23) };
        buf[0]
    }

    #[allow(dead_code)]
    /// SetStandby via RAW SPI with manual CS.
    pub fn set_standby_raw(&mut self) -> u8 {
        // CS LOW
        unsafe { core::ptr::write_volatile(0x6009_100C as *mut u32, 1 << 23) };
        let mut buf = [0x80u8, 0x00]; // SetStandby(STBY_RC)
        let _ = crate::raw_spi::transfer(&mut buf);
        // CS HIGH
        unsafe { core::ptr::write_volatile(0x6009_1008 as *mut u32, 1 << 23) };
        // Now read status
        self.get_status_raw()
    }

    pub fn get_status(&mut self) -> Result<u8, RadioError> {
        // GetStatus can be sent at ANY time (datasheet 14.3). No BUSY wait.
        let mut buf = [0xC0u8];
        self.cs_low();
        let r = crate::raw_spi::transfer(&mut buf);
        self.cs_high();
        r.map_err(|_| RadioError::Spi)?;
        Ok(buf[0])
    }

    pub fn current_rssi(&mut self) -> Result<i16, RadioError> {
        let mut out = [0u8; 2]; // irq_msb, rssi_curr
        self.cmd_read(OP_GET_CURRENT_RSSI, &mut out)?;
        Ok(-(out[0] as i16) / 2)
    }

    pub fn sleep(&mut self) -> Result<(), RadioError> {
        self.cmd(OP_SET_SLEEP, &[0x04]) // warm start
    }
}

pub fn tx_done(irq: u16) -> bool {
    irq & IRQ_TX_DONE != 0
}
pub fn rx_done(irq: u16) -> bool {
    irq & IRQ_RX_DONE != 0
}
pub fn crc_error(irq: u16) -> bool {
    irq & IRQ_CRC_ERR != 0
}
pub fn timed_out(irq: u16) -> bool {
    irq & IRQ_TIMEOUT != 0
}

const _: () = {
    // keep OP_NOP referenced for future status polling
    let _ = OP_NOP;
    let _ = OP_SET_SLEEP;
};
