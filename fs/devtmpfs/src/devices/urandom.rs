//! TEAM_431: /dev/urandom device implementation
//!
//! - read() returns random bytes
//! - write() accepts all data (could mix into entropy pool)

use super::CharDeviceOps;
use core::sync::atomic::{AtomicU64, Ordering};
use los_vfs::VfsResult;

/// /dev/urandom device (major 1, minor 9)
pub struct UrandomDevice;

/// Simple PRNG state (xorshift64)
/// This is the same algorithm used in the getrandom syscall
static PRNG_STATE: AtomicU64 = AtomicU64::new(0x853c49e6748fea9b);

/// Generate next random u64 using xorshift64
fn next_random() -> u64 {
    loop {
        let current = PRNG_STATE.load(Ordering::Relaxed);
        let mut x = current;
        if x == 0 {
            // Seed with a non-zero value if somehow zero
            x = 0x853c49e6748fea9b;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if PRNG_STATE
            .compare_exchange_weak(current, x, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return x;
        }
    }
}

impl CharDeviceOps for UrandomDevice {
    fn read(&self, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        // Fill buffer with random bytes
        for chunk in buf.chunks_mut(8) {
            let rand_val = next_random();
            let rand_bytes = rand_val.to_ne_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&rand_bytes[..len]);
        }
        Ok(buf.len())
    }

    fn write(&self, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        // Accept all data (could mix into entropy pool in future)
        Ok(buf.len())
    }
}

/// Static instance for registration
pub static URANDOM_DEVICE: UrandomDevice = UrandomDevice;
