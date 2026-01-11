//! TEAM_431: /dev/null device implementation
//!
//! - read() returns EOF (0 bytes)
//! - write() accepts all data silently

use super::CharDeviceOps;
use los_vfs::VfsResult;

/// /dev/null device (major 1, minor 3)
pub struct NullDevice;

impl CharDeviceOps for NullDevice {
    fn read(&self, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        // Always return EOF
        Ok(0)
    }

    fn write(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        // Accept all data, return bytes "written"
        Ok(buf.len())
    }
}

/// Static instance for registration
pub static NULL_DEVICE: NullDevice = NullDevice;
