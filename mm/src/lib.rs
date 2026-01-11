//! TEAM_422: Memory Management Crate
//!
//! Provides physical and virtual memory management for the kernel.
//! The actual initialization with BootInfo is done in levitate.

#![no_std]

extern crate alloc;

use los_hal::allocator::{BuddyAllocator, Page};
use los_hal::mmu;
use los_hal::traits::PageAllocator;
use los_utils::Mutex;

pub mod heap; // TEAM_208: Process heap management
pub mod user; // TEAM_208: User-space memory management
pub mod vma; // TEAM_238: VMA tracking for munmap support

// Re-export types needed by levitate
pub use los_hal::allocator::Page as FramePage;

/// Global Frame Allocator
pub struct FrameAllocator(pub Mutex<BuddyAllocator>);

impl PageAllocator for FrameAllocator {
    fn alloc_page(&self) -> Option<usize> {
        self.0.lock().alloc(0)
    }
    fn free_page(&self, pa: usize) {
        self.0.lock().free(pa, 0)
    }
}

pub static FRAME_ALLOCATOR: FrameAllocator = FrameAllocator(Mutex::new(BuddyAllocator::new()));

// =============================================================================
// Helper functions for memory initialization (used by levitate)
// =============================================================================

/// Add a reserved region to the array.
pub fn add_reserved(
    regions: &mut [Option<(usize, usize)>],
    count: &mut usize,
    start: usize,
    end: usize,
) {
    if *count < regions.len() {
        regions[*count] = Some((start & !4095, (end + 4095) & !4095));
        *count += 1;
    }
}

/// Add a RAM range to the allocator, excluding reserved regions.
pub fn add_range_with_holes(
    allocator: &mut BuddyAllocator,
    ram: (usize, usize),
    reserved: &[Option<(usize, usize)>],
) {
    fn add_split(
        allocator: &mut BuddyAllocator,
        ram: (usize, usize),
        reserved: &[Option<(usize, usize)>],
        idx: usize,
    ) {
        if ram.0 >= ram.1 {
            return;
        }

        // Find next valid reserved region
        let mut next_idx = idx;
        while next_idx < reserved.len() && reserved[next_idx].is_none() {
            next_idx += 1;
        }

        if next_idx >= reserved.len() {
            // No more reserved regions to check
            // SAFETY: The range (ram.0, ram.1) has been validated against all reserved
            // regions and is within discovered RAM bounds.
            unsafe {
                allocator.add_range(ram.0, ram.1);
            }
            return;
        }

        let res = reserved[next_idx].as_ref().expect("Checked None above");

        // Check for overlap
        if ram.0 < res.1 && ram.1 > res.0 {
            // Overlap! Split RAM into pieces that don't overlap with THIS reserved range
            // 1. Portion before reserved
            if ram.0 < res.0 {
                add_split(allocator, (ram.0, res.0), reserved, next_idx + 1);
            }
            // 2. Portion after reserved
            if ram.1 > res.1 {
                add_split(allocator, (res.1, ram.1), reserved, next_idx + 1);
            }
            // Portion inside is skipped
        } else {
            // No overlap with this one, try next reserved
            add_split(allocator, ram, reserved, next_idx + 1);
        }
    }

    add_split(allocator, ram, reserved, 0);
}

/// Initialize the frame allocator with a memory map and register with MMU.
///
/// # Safety
/// - `mem_map` must point to valid, zeroed memory for `total_pages` Page structs
/// - `phys_min` must be the base physical address for the memory map
/// - RAM regions must be valid physical memory ranges
/// - Reserved regions must not overlap with RAM that will be used
pub unsafe fn init_allocator(
    mem_map: &'static mut [Page],
    phys_min: usize,
    ram_regions: &[Option<(usize, usize)>],
    reserved_regions: &[Option<(usize, usize)>],
) {
    // Initialize allocator
    let mut allocator = FRAME_ALLOCATOR.0.lock();
    unsafe {
        allocator.init(mem_map, phys_min);
    }

    // Add RAM regions, skipping reserved ones
    for ram in ram_regions.iter().flatten() {
        add_range_with_holes(&mut allocator, *ram, reserved_regions);
    }

    // Register with MMU
    drop(allocator);
    mmu::set_page_allocator(&FRAME_ALLOCATOR);
}
