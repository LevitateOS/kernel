//! AArch64 Memory Management Unit (MMU) support.
//!
//! TEAM_018: Implements page table structures and MMU configuration
//! for AArch64 with 4KB granule, 48-bit virtual addresses.
//!
//! Reference implementations studied:
//! - Theseus: MAIR/TCR config, TLB flush patterns
//! - Redox: RMM abstraction
//!
//! # Module Structure
//!
//! - `constants`: Page sizes, kernel addresses, device addresses
//! - `types`: PageTableEntry, PageFlags, PageTable
//! - `ops`: Virtual address indexing, TLB flush operations
//! - `init`: MMU initialization and enable functions
//! - `mapping`: Page table mapping and translation functions

mod constants;
mod init;
mod mapping;
mod ops;
mod types;

#[cfg(all(test, feature = "std"))]
mod tests;

// Re-export all public items
pub use constants::*;
pub use init::*;
pub use mapping::*;
pub use ops::*;
pub use types::*;

use los_error::define_kernel_error;

use crate::traits::PageAllocator;

define_kernel_error! {
    /// TEAM_152: MMU error type with error codes (0x01xx) per unified error system plan.
    /// TEAM_155: Migrated to define_kernel_error! macro.
    pub enum MmuError(0x01) {
        /// Page table allocation failed
        AllocationFailed = 0x01 => "Page table allocation failed",
        /// Address not mapped
        NotMapped = 0x02 => "Address not mapped",
        /// Invalid virtual address or target level
        InvalidVirtualAddress = 0x03 => "Invalid virtual address",
        /// Address not properly aligned
        Misaligned = 0x04 => "Address not properly aligned",
        /// Page table walk failed at intermediate level
        WalkFailed = 0x05 => "Page table walk failed",
    }
}

/// Pointer to the dynamic page allocator, set once during boot.
pub(crate) static mut PAGE_ALLOCATOR_PTR: Option<&'static dyn PageAllocator> = None;

/// [M25] Set the global page allocator for MMU use.
/// Called once during boot after Buddy Allocator is initialized.
pub fn set_page_allocator(allocator: &'static dyn PageAllocator) {
    // SAFETY: Single-threaded boot context
    unsafe {
        PAGE_ALLOCATOR_PTR = Some(allocator);
    }
}
