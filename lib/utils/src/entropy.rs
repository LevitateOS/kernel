//! Kernel entropy and pseudo-random number generation.
//!
//! Provides a consolidated PRNG implementation for use throughout the kernel.
//! Uses xorshift64* algorithm which is fast and has good statistical properties
//! for non-cryptographic purposes.
//!
//! # Usage
//!
//! ```ignore
//! use los_utils::entropy;
//!
//! // Seed the PRNG (call once at boot with timer value)
//! entropy::seed(timer_counter ^ address_entropy);
//!
//! // Get random values
//! let random_u64 = entropy::next_u64();
//! let random_bytes = entropy::fill_bytes(&mut buffer);
//! ```

use core::sync::atomic::{AtomicU64, Ordering};

/// Global PRNG state.
///
/// Uses atomic operations for thread-safety without requiring locks.
/// Initial value is a non-zero constant to ensure valid state even before seeding.
static PRNG_STATE: AtomicU64 = AtomicU64::new(0x853c_49e6_748f_ea9b);

/// Seed the PRNG with an initial value.
///
/// Should be called once at kernel boot with entropy from timer counter,
/// memory addresses, or other sources. Can be called multiple times to
/// mix in additional entropy.
///
/// # Arguments
/// * `seed` - Entropy value to mix into PRNG state
pub fn seed(seed: u64) {
    let current = PRNG_STATE.load(Ordering::Relaxed);
    let new_state = current ^ seed;
    // Ensure non-zero state
    let new_state = if new_state == 0 {
        0x853c_49e6_748f_ea9b
    } else {
        new_state
    };
    PRNG_STATE.store(new_state, Ordering::Relaxed);
}

/// Generate the next random u64 value.
///
/// Uses xorshift64* algorithm with atomic compare-exchange for thread safety.
/// This is not cryptographically secure but provides good statistical
/// properties for HashMap seeds, ASLR, and similar uses.
#[inline]
pub fn next_u64() -> u64 {
    loop {
        let current = PRNG_STATE.load(Ordering::Relaxed);
        let mut x = current;
        // Ensure non-zero (should not happen, but be defensive)
        if x == 0 {
            x = 0x853c_49e6_748f_ea9b;
        }
        // xorshift64*
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        if PRNG_STATE
            .compare_exchange_weak(current, x, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        }
    }
}

/// Fill a byte slice with random data.
///
/// Efficiently fills the buffer by generating u64 values and extracting bytes.
///
/// # Arguments
/// * `buf` - Buffer to fill with random bytes
pub fn fill_bytes(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let rand_val = next_u64();
        let rand_bytes = rand_val.to_ne_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&rand_bytes[..len]);
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_next_u64_nonzero() {
        // Generate many values, none should be zero
        for _ in 0..1000 {
            assert_ne!(next_u64(), 0);
        }
    }

    #[test]
    fn test_next_u64_varies() {
        // Values should vary (not all the same)
        let first = next_u64();
        let mut found_different = false;
        for _ in 0..100 {
            if next_u64() != first {
                found_different = true;
                break;
            }
        }
        assert!(found_different, "PRNG produced identical values");
    }

    #[test]
    fn test_fill_bytes() {
        let mut buf = [0u8; 32];
        fill_bytes(&mut buf);
        // At least some bytes should be non-zero
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_seed_changes_output() {
        let before = next_u64();
        seed(0xDEAD_BEEF_CAFE_BABE);
        let after = next_u64();
        // After seeding, output should differ from before
        // (statistically almost certain)
        assert_ne!(before, after);
    }
}
