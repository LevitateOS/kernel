//! TEAM_431: /dev/urandom device implementation
//!
//! - read() returns random bytes
//! - write() accepts all data (could mix into entropy pool)

use super::CharDeviceOps;
use los_vfs::VfsResult;

/// /dev/urandom device (major 1, minor 9)
pub struct UrandomDevice;

impl CharDeviceOps for UrandomDevice {
    fn read(&self, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // Fill buffer with random bytes using shared entropy module
        los_utils::entropy::fill_bytes(buf);
        Ok(buf.len())
    }

    fn write(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        // Accept all data (could mix into entropy pool in future)
        Ok(buf.len())
    }
}

/// Static instance for registration
pub static URANDOM_DEVICE: UrandomDevice = UrandomDevice;
