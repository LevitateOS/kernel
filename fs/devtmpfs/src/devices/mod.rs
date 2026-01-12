//! TEAM_431: Device registry for devtmpfs
//!
//! Manages character device drivers and dispatches I/O operations
//! based on major:minor device numbers.

extern crate alloc;

pub mod console;
pub mod full;
pub mod null;
pub mod urandom;
pub mod zero;

use alloc::vec::Vec;
use los_utils::Mutex;
use los_vfs::VfsResult;

/// Device numbers following Linux convention (major 1 = memory devices)
pub mod devno {
    /// Memory devices major number
    pub const MEM_MAJOR: u32 = 1;
    /// /dev/null minor
    pub const NULL_MINOR: u32 = 3;
    /// /dev/zero minor
    pub const ZERO_MINOR: u32 = 5;
    /// /dev/full minor
    pub const FULL_MINOR: u32 = 7;
    /// /dev/urandom minor
    pub const URANDOM_MINOR: u32 = 9;
    
    /// TEAM_453: TTY devices major number
    pub const TTY_MAJOR: u32 = 5;
    /// /dev/console minor
    pub const CONSOLE_MINOR: u32 = 1;
}

/// Encode major:minor into rdev (Linux makedev format)
#[inline]
pub const fn makedev(major: u32, minor: u32) -> u64 {
    ((major as u64) << 8) | (minor as u64 & 0xff)
}

/// Extract major number from rdev
#[inline]
pub const fn major(rdev: u64) -> u32 {
    ((rdev >> 8) & 0xfff) as u32
}

/// Extract minor number from rdev
#[inline]
pub const fn minor(rdev: u64) -> u32 {
    (rdev & 0xff) as u32
}

/// Character device operations trait
///
/// Implement this for each device type (/dev/null, /dev/zero, etc.)
pub trait CharDeviceOps: Send + Sync {
    /// Read from the device
    fn read(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize>;

    /// Write to the device
    fn write(&self, offset: u64, buf: &[u8]) -> VfsResult<usize>;
}

/// Registry entry for a character device
struct CharDeviceEntry {
    major: u32,
    minor: u32,
    ops: &'static dyn CharDeviceOps,
}

/// Global character device registry
static CHAR_DEVICES: Mutex<Vec<CharDeviceEntry>> = Mutex::new(Vec::new());

/// Register a character device driver
pub fn register_char_device(major: u32, minor: u32, ops: &'static dyn CharDeviceOps) {
    let mut devices = CHAR_DEVICES.lock();
    devices.push(CharDeviceEntry { major, minor, ops });
}

/// Look up a character device by rdev
pub fn lookup_char_device(rdev: u64) -> Option<&'static dyn CharDeviceOps> {
    let maj = major(rdev);
    let min = minor(rdev);
    let devices = CHAR_DEVICES.lock();
    devices
        .iter()
        .find(|e| e.major == maj && e.minor == min)
        .map(|e| e.ops)
}

/// Register all built-in devices
pub fn register_builtin_devices() {
    use devno::*;

    register_char_device(MEM_MAJOR, NULL_MINOR, &null::NULL_DEVICE);
    register_char_device(MEM_MAJOR, ZERO_MINOR, &zero::ZERO_DEVICE);
    register_char_device(MEM_MAJOR, FULL_MINOR, &full::FULL_DEVICE);
    register_char_device(MEM_MAJOR, URANDOM_MINOR, &urandom::URANDOM_DEVICE);
    // TEAM_453: Console device for BusyBox init
    register_char_device(TTY_MAJOR, CONSOLE_MINOR, &console::CONSOLE_DEVICE);
}
