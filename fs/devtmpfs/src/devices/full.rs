//! TEAM_431: /dev/full device implementation
//!
//! - read() returns zero bytes
//! - write() returns ENOSPC (no space left)

use super::CharDeviceOps;
use los_vfs::{VfsError, VfsResult};

/// /dev/full device (major 1, minor 7)
pub struct FullDevice;

impl CharDeviceOps for FullDevice {
    fn read(&self, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // Fill buffer with zeros (same as /dev/zero)
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        // Always return "no space left on device"
        Err(VfsError::NoSpace)
    }
}

/// Static instance for registration
pub static FULL_DEVICE: FullDevice = FullDevice;
