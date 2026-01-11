//! TEAM_431: /dev/zero device implementation
//!
//! - read() returns zero bytes
//! - write() accepts all data silently

use super::CharDeviceOps;
use los_vfs::VfsResult;

/// /dev/zero device (major 1, minor 5)
pub struct ZeroDevice;

impl CharDeviceOps for ZeroDevice {
    fn read(&self, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // Fill buffer with zeros
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        // Accept all data, return bytes "written"
        Ok(buf.len())
    }
}

/// Static instance for registration
pub static ZERO_DEVICE: ZeroDevice = ZeroDevice;
