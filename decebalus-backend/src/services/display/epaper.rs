//! Waveshare e-paper HAT driver (Raspberry Pi only).
//!
//! Compiled only with `--features hardware`. Targets the Waveshare 2.13" V2 panel
//! (the model used by Bjorn) over SPI on the standard HAT pinout:
//!   RST=BCM17, DC=BCM25, CS=BCM8, BUSY=BCM24, SPI=/dev/spidev0.0.
//!
//! NOTE: this path cannot be compiled or tested off-device (the HAL crates are
//! Linux/Pi-specific). If your panel is a different model (2.13" V3/V4, 2.7", …)
//! or wiring differs, adjust the `epd2in13_v2` type and the pin numbers below.
//! The rendering (embedded-graphics) is panel-agnostic; only init/refresh is
//! hardware-specific.

use embedded_graphics::{
    mono_font::{ascii::FONT_6X12, MonoTextStyleBuilder},
    pixelcolor::BinaryColor,
    prelude::*,
    text::{Baseline, Text},
};
use epd_waveshare::{
    epd2in13_v2::{Display2in13, Epd2in13},
    graphics::DisplayRotation,
    prelude::*,
};
use linux_embedded_hal::{
    spidev::{SpiModeFlags, SpidevOptions},
    sysfs_gpio::Direction,
    Delay, SpidevDevice, SysfsPin,
};

use super::{DisplayDriver, DisplayState};

type Epd = Epd2in13<SpidevDevice, SysfsPin, SysfsPin, SysfsPin, Delay>;

pub struct EpaperDisplay {
    spi: SpidevDevice,
    epd: Epd,
    delay: Delay,
    display: Display2in13,
}

impl EpaperDisplay {
    pub fn new() -> Result<Self, String> {
        let mut spi = SpidevDevice::open("/dev/spidev0.0")
            .map_err(|e| format!("open spidev: {e}"))?;
        let options = SpidevOptions::new()
            .bits_per_word(8)
            .max_speed_hz(4_000_000)
            .mode(SpiModeFlags::SPI_MODE_0)
            .build();
        spi.0
            .configure(&options)
            .map_err(|e| format!("configure spi: {e}"))?;

        let cs = init_pin(8, Direction::High)?;
        let busy = init_pin_in(24)?;
        let dc = init_pin(25, Direction::Low)?;
        let rst = init_pin(17, Direction::High)?;

        let mut delay = Delay {};
        let epd = Epd2in13::new(&mut spi, busy, dc, rst, &mut delay, None)
            .map_err(|e| format!("epd init: {e:?}"))?;

        // Discard cs — it is driven by the SPI device; kept only to reserve the pin.
        let _ = cs;

        let mut display = Display2in13::default();
        display.set_rotation(DisplayRotation::Rotate90);

        Ok(Self { spi, epd, delay, display })
    }
}

fn init_pin(bcm: u64, dir: Direction) -> Result<SysfsPin, String> {
    let pin = SysfsPin::new(bcm);
    pin.export().map_err(|e| format!("export gpio{bcm}: {e}"))?;
    pin.set_direction(dir)
        .map_err(|e| format!("set gpio{bcm} dir: {e}"))?;
    Ok(pin)
}

fn init_pin_in(bcm: u64) -> Result<SysfsPin, String> {
    init_pin(bcm, Direction::In)
}

impl DisplayDriver for EpaperDisplay {
    fn render(&mut self, state: &DisplayState) -> Result<(), String> {
        self.display.clear(BinaryColor::Off).ok();

        let style = MonoTextStyleBuilder::new()
            .font(&FONT_6X12)
            .text_color(BinaryColor::On)
            .build();

        let mut y = 4;
        for line in state.lines() {
            Text::with_baseline(&line, Point::new(2, y), style, Baseline::Top)
                .draw(&mut self.display)
                .map_err(|e| format!("draw: {e:?}"))?;
            y += 14;
        }

        self.epd
            .update_and_display_frame(&mut self.spi, self.display.buffer(), &mut self.delay)
            .map_err(|e| format!("refresh: {e:?}"))?;
        Ok(())
    }
}
