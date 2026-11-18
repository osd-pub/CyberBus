use crate::{Error, Result};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
/// Trusted clock dependency. `elapsed` must be monotonic for this process and include suspend.
/// If the platform cannot provide that property, return false from `includes_suspend` and
/// the host MUST call `on_resume` before dispatching any work after suspend.
pub trait Clock: Send + Sync {
    fn elapsed(&self) -> Duration;
    fn unix_seconds(&self) -> u64;
    fn includes_suspend(&self) -> bool;
}
pub struct SystemClock {
    origin: Duration,
}
impl SystemClock {
    pub fn new() -> Result<Self> {
        Ok(Self {
            origin: boot_time()?,
        })
    }
}
impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        boot_time()
            .unwrap_or(Duration::MAX)
            .saturating_sub(self.origin)
    }
    fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    fn includes_suspend(&self) -> bool {
        cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "windows"
        ))
    }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
fn boot_time() -> Result<Duration> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid writable timespec, CLOCK_BOOTTIME is suspend-inclusive.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } != 0 {
        return Err(Error::Unavailable);
    }
    Ok(Duration::new(t.tv_sec as u64, t.tv_nsec as u32))
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn boot_time() -> Result<Duration> {
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut Info) -> i32;
    }
    #[repr(C)]
    struct Info {
        numer: u32,
        denom: u32,
    }
    let mut i = Info { numer: 0, denom: 0 };
    // SAFETY: valid C ABI, valid pointer; continuous time includes sleep on Apple platforms.
    if unsafe { mach_timebase_info(&mut i) } != 0 || i.denom == 0 {
        return Err(Error::Unavailable);
    }
    let ns = unsafe { mach_continuous_time() } as u128 * i.numer as u128 / i.denom as u128;
    Ok(Duration::from_nanos(
        u64::try_from(ns).map_err(|_| Error::Unavailable)?,
    ))
}
#[cfg(target_os = "windows")]
fn boot_time() -> Result<Duration> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTickCount64() -> u64;
    }
    // SAFETY: argument-free system monotonic clock includes sleep.
    Ok(Duration::from_millis(unsafe { GetTickCount64() }))
}
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
fn boot_time() -> Result<Duration> {
    Err(Error::Unsupported)
}
