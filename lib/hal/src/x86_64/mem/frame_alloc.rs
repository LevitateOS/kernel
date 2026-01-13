use crate::mem::constants::PAGE_SIZE;
use crate::traits::PageAllocator;
use core::sync::atomic::{AtomicUsize, Ordering};

// TEAM_263: Early boot frame allocator for x86_64.
// This is a simple bump allocator used before the buddy allocator is ready.

pub struct EarlyFrameAllocator {
    next_free_frame: AtomicUsize,
    end_address: usize,
}

impl EarlyFrameAllocator {
    /// Create a new bump allocator from a physical address range.
    pub const fn new(start_phys: usize, end_phys: usize) -> Self {
        Self {
            next_free_frame: AtomicUsize::new(start_phys),
            end_address: end_phys,
        }
    }

    /// Set the start address (used if determined dynamically).
    pub fn set_range(&self, start_phys: usize, _end_phys: usize) {
        self.next_free_frame.store(start_phys, Ordering::SeqCst);
        // Note: end_address is not atomic in this simple struct,
        // but for early boot it's usually set once.
        // We can make it atomic if needed.
    }
}

impl PageAllocator for EarlyFrameAllocator {
    fn alloc_page(&self) -> Option<usize> {
        loop {
            let current = self.next_free_frame.load(Ordering::SeqCst);
            // TEAM_462: Use PAGE_SIZE constant instead of magic number
            let next = current + PAGE_SIZE;

            if next > self.end_address {
                return None;
            }

            if self
                .next_free_frame
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                // Return the physical address of the allocated PAGE_SIZE frame
                // Ensure it is page-aligned (should be if start was aligned)
                return Some(current);
            }
        }
    }

    fn free_page(&self, _pa: usize) {
        // Bump allocator doesn't support free.
        // This is intentional for early boot.
    }
}

// TEAM_302: IA32_STAR and early range are critical for syscall/MMU stability.
// CAUTION: The EARLY_ALLOCATOR range must exactly match the reservation in
// kernel memory initialization to avoid physical memory corruption.
// TEAM_464: Use named constants from mem::constants SSOT.
use crate::mem::constants::{EARLY_ALLOC_END, EARLY_ALLOC_START};
pub static EARLY_ALLOCATOR: EarlyFrameAllocator =
    EarlyFrameAllocator::new(EARLY_ALLOC_START, EARLY_ALLOC_END);
