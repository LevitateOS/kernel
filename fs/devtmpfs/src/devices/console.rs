//! TEAM_453: /dev/console device implementation
//! TEAM_454: Added blocking read from serial/keyboard input
//!
//! Provides console I/O for userspace processes (especially init).
//! - read() blocks until input is available from serial or keyboard
//! - write() sends data to kernel's print output

use super::CharDeviceOps;
use los_vfs::VfsResult;

/// /dev/console device (major 5, minor 1)
pub struct ConsoleDevice;

impl CharDeviceOps for ConsoleDevice {
    fn read(&self, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // TEAM_454: Block until we have input from serial/keyboard
        // This enables BusyBox init and ash shell to read user input
        if buf.is_empty() {
            return Ok(0);
        }

        let mut bytes_read = 0;

        loop {
            // Try to get a byte from the HAL console (serial or VirtIO keyboard)
            if let Some(byte) = los_hal::console::read_byte() {
                buf[bytes_read] = byte;
                bytes_read += 1;

                // Return on newline (line-buffered behavior) or buffer full
                if byte == b'\n' || bytes_read >= buf.len() {
                    return Ok(bytes_read);
                }
                // Continue reading more characters if available
                continue;
            }

            // If we have some data and no more available, return what we have
            if bytes_read > 0 {
                return Ok(bytes_read);
            }

            // No data available - yield and try again
            // Enable interrupts briefly to allow input to arrive
            unsafe {
                los_hal::interrupts::enable();
            }
            let _ = los_hal::interrupts::disable();
            los_sched::yield_now();
        }
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
