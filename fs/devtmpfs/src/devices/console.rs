//! TEAM_453: /dev/console device implementation
//!
//! Provides console I/O for userspace processes (especially init).
//! - read() returns 0 (EOF) for now - keyboard input not yet implemented
//! - write() sends data to kernel's print output

use super::CharDeviceOps;
use los_vfs::VfsResult;

/// /dev/console device (major 5, minor 1)
pub struct ConsoleDevice;

impl CharDeviceOps for ConsoleDevice {
    fn read(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        // TEAM_453: For now, return EOF
        // Future: integrate with keyboard input subsystem
        Ok(0)
    }

    fn write(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        // TEAM_453: Write to kernel console output
        // Convert bytes to string and print
        if let Ok(s) = core::str::from_utf8(buf) {
            // Use los_hal::print! which goes to serial/GPU
            for c in s.chars() {
                los_hal::print!("{}", c);
            }
        } else {
            // Binary data - just count as written
        }
        Ok(buf.len())
    }
}

/// Static instance for registration
pub static CONSOLE_DEVICE: ConsoleDevice = ConsoleDevice;
