//! ST7789 240x135 landscape LCD on SPI3.
//!
//! Wiring (Cardputer ADV): SCK=36, MOSI=35 (no MISO), CS=37, DC=34,
//! RST=33, backlight LEDA=38 (active HIGH). SPI3 — SPI2 belongs to the
//! SX1262 radio. Runs at 40 MHz like the Meshtastic variant.

use esp_idf_hal::delay::Delay;
use esp_idf_hal::gpio::{Gpio33, Gpio34, Gpio35, Gpio36, Gpio37, Gpio38, Output, PinDriver};
use esp_idf_hal::spi::{config::Config, config::DriverConfig, Dma, SpiDeviceDriver, SpiSingleDeviceDriver, SPI3};
use embedded_graphics::prelude::*;
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::primitives::Rectangle;
use mipidsi::interface::SpiInterface;
use mipidsi::models::ST7789;
use mipidsi::options::{ColorInversion, Orientation, Rotation};

// mipidsi 0.10 needs its own SpiInterface (not display-interface-spi);
// the buffer is used to assemble each pixel batch — 1 KiB is plenty
// for 38-char text rows and filled rects.
fn spi_buf() -> &'static mut [u8] {
    Box::leak(vec![0u8; 1024].into_boxed_slice())
}

/// mipidsi driver this struct wraps (it already implements
/// `embedded_graphics::DrawTarget<Color = Rgb565>`).
pub type MipiDisplay = mipidsi::Display<
    SpiInterface<'static, SpiSingleDeviceDriver<'static>, PinDriver<'static, Output>>,
    ST7789,
    PinDriver<'static, Output>,
>;


/// Peripherals handed over by main (kept as a plain struct so the init
/// signature stays a single argument).
pub struct DisplayParts {
    pub spi: SPI3<'static>,
    pub sck: Gpio36<'static>,
    pub mosi: Gpio35<'static>,
    pub cs: Gpio37<'static>,
    pub dc: Gpio34<'static>,
    pub rst: Gpio33<'static>,
    pub backlight: Gpio38<'static>,
}

pub struct Display {
    pub inner: MipiDisplay,
    backlight: PinDriver<'static, Output>,
}

impl Display {
    /// Clocks SPI3 at 40 MHz (Meshtastic SPI_FREQUENCY for this panel);
    /// drop to 20 MHz if the wiring proves marginal.
    pub fn init(parts: DisplayParts) -> anyhow::Result<Self> {
        let spi = SpiDeviceDriver::new_single(
            parts.spi,
            parts.sck,
            parts.mosi,
            Option::<esp_idf_hal::gpio::AnyIOPin>::None, // no MISO
            Some(parts.cs),
            &DriverConfig::new().dma(Dma::Auto(4096)),
            &Config::new().baudrate(40_000_000.into()),
        )?;
        let dc = PinDriver::output(parts.dc)?;
        let rst = PinDriver::output(parts.rst)?;
        let mut backlight = PinDriver::output(parts.backlight)?;
        backlight.set_low()?;
        let di = SpiInterface::new(spi, dc, spi_buf());


        // Panel geometry (verified on hardware: the old 240x135/Deg0/no-
        // offset config painted only ~40% of the glass, white instead of
        // black, rest = uninitialized GRAM noise): the glass is a native
        // 135x240 PORTRAIT panel at offset (52, 40) inside the ST7789's
        // 240x320 GRAM, mounted landscape. Deg90 = MADCTL MV|MX — the
        // orientation Meshtastic drives this exact device with
        // (ST7789Spi::flipScreenVertically). It is an IPS panel: INVON
        // required, or black renders white. mipidsi derives the rotated
        // window offset (40, 53) from the native values.
        let inner = mipidsi::Builder::new(ST7789, di)
            .reset_pin(rst)
            .display_size(135, 240)
            .display_offset(52, 40)
            .orientation(Orientation::new().rotate(Rotation::Deg90))
            .invert_colors(ColorInversion::Inverted)
            .init(&mut Delay::new_default())
            .map_err(|e| anyhow::anyhow!("st7789 init: {:?}", e))?;

        backlight.set_high()?;
        Ok(Self { inner, backlight })
    }

    /// Backlight is active HIGH on GPIO38.
    pub fn backlight_on(&mut self) -> anyhow::Result<()> {
        self.backlight.set_high().map_err(Into::into)
    }

    pub fn backlight_off(&mut self) -> anyhow::Result<()> {
        self.backlight.set_low().map_err(Into::into)
    }
}

impl core::ops::Deref for Display {
    type Target = MipiDisplay;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl core::ops::DerefMut for Display {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl OriginDimensions for Display {
    fn size(&self) -> Size {
        self.inner.size()
    }
}

impl DrawTarget for Display {
    type Color = Rgb565;
    type Error = <MipiDisplay as DrawTarget>::Error;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Rgb565>>,
    {
        self.inner.draw_iter(pixels)
    }

    fn fill_contiguous<I>(&mut self, area: &Rectangle, colors: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Rgb565>,
    {
        self.inner.fill_contiguous(area, colors)
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        self.inner.fill_solid(area, color)
    }

    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        self.inner.clear(color)
    }
}
