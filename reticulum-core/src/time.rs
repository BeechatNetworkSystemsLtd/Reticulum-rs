#[cfg(feature = "std")]
mod std_only {
    use core::time::Duration;

    use std::sync::OnceLock;
    use std::time::{Instant, UNIX_EPOCH};

    pub fn now() -> Duration {
        static START_TIME: OnceLock<Instant> = OnceLock::new();

        START_TIME.get_or_init(Instant::now).elapsed()
    }

    pub fn unix_time_as_secs() -> u64 {
        UNIX_EPOCH.elapsed().unwrap().as_secs()
    }
}

#[cfg(not(feature = "std"))]
mod no_std_only {
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;
    use core::time::Duration;

    use embassy_time::Duration as EmbassyDuration;
    use embassy_time::Instant;

    // Two 32-bit halves because some embedded targets (e.g. thumbv7em)
    // have no 64-bit atomics.
    static BOOT_UNIX_TIME_LO: AtomicU32 = AtomicU32::new(0);
    static BOOT_UNIX_TIME_HI: AtomicU32 = AtomicU32::new(0);

    fn boot_unix_time() -> u64 {
        let lo = BOOT_UNIX_TIME_LO.load(Ordering::Relaxed) as u64;
        let hi = BOOT_UNIX_TIME_HI.load(Ordering::Relaxed) as u64;
        lo | (hi << 32)
    }

    fn set_boot_unix_time(value: u64) {
        BOOT_UNIX_TIME_LO.store(value as u32, Ordering::Relaxed);
        BOOT_UNIX_TIME_HI.store((value >> 32) as u32, Ordering::Relaxed);
    }

    fn elapsed_since_boot() -> EmbassyDuration {
        Instant::now().duration_since(Instant::from_ticks(0))
    }

    /// Initialize the UNIX time
    ///
    /// Reticulum needs to know the current UNIX timestamp in order to create
    /// announce packets.
    ///
    /// On the `std` build, the system clock is used and this function has no
    /// effect.
    ///
    /// On the `no_std` build, it must be called before any destinations are
    /// created. Creating a destination without having called this function
    /// first will panic.
    ///
    /// `unix_now`: the current UNIX timestamp in seconds.
    pub fn init(unix_now: u64) {
        let boot_unix_time = unix_now - elapsed_since_boot().as_secs();

        set_boot_unix_time(boot_unix_time);
    }

    pub fn now() -> Duration {
        Duration::from_nanos(elapsed_since_boot().as_nanos())
    }

    pub fn unix_time_as_secs() -> u64 {
        let boot_unix_time = boot_unix_time();

        if boot_unix_time == 0 {
            panic!("Unix time not initialized");
        }

        boot_unix_time + elapsed_since_boot().as_secs()
    }
}

#[cfg(feature = "std")]
pub use std_only::*;

#[cfg(not(feature = "std"))]
pub use no_std_only::init;
#[cfg(not(feature = "std"))]
pub(crate) use no_std_only::*;
