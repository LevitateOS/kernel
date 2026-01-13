//! TEAM_462: Central memory constants for LevitateOS kernel
//!
//! Single source of truth for PAGE_SIZE and related values.
//! All other modules must import from here to prevent desync bugs.
//!
//! # Usage
//!
//! ```rust
//! use los_hal::mem::constants::{PAGE_SIZE, page_align_up, page_align_down};
//!
//! let addr = 0x1234;
//! let aligned_down = page_align_down(addr);  // 0x1000
//! let aligned_up = page_align_up(addr);      // 0x2000
//! ```

/// Page size in bytes (4 KiB)
pub const PAGE_SIZE: usize = 4096;

/// Page size as a power of 2 (2^12 = 4096)
pub const PAGE_SHIFT: usize = 12;

/// Mask for page offset bits (lower 12 bits)
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

/// Align address down to page boundary
///
/// # Examples
/// ```
/// use los_hal::mem::constants::page_align_down;
/// assert_eq!(page_align_down(0x1234), 0x1000);
/// assert_eq!(page_align_down(0x1000), 0x1000);
/// assert_eq!(page_align_down(0x0), 0x0);
/// ```
#[inline]
pub const fn page_align_down(addr: usize) -> usize {
    addr & !PAGE_MASK
}

/// Align address up to page boundary
///
/// # Examples
/// ```
/// use los_hal::mem::constants::page_align_up;
/// assert_eq!(page_align_up(0x1234), 0x2000);
/// assert_eq!(page_align_up(0x1000), 0x1000);
/// assert_eq!(page_align_up(0x0), 0x0);
/// ```
#[inline]
pub const fn page_align_up(addr: usize) -> usize {
    (addr + PAGE_MASK) & !PAGE_MASK
}

/// Check if address is page-aligned
///
/// # Examples
/// ```
/// use los_hal::mem::constants::is_page_aligned;
/// assert!(is_page_aligned(0x1000));
/// assert!(is_page_aligned(0x0));
/// assert!(!is_page_aligned(0x1234));
/// ```
#[inline]
pub const fn is_page_aligned(addr: usize) -> bool {
    addr & PAGE_MASK == 0
}

/// Convert address to page number (page frame number)
#[inline]
pub const fn addr_to_pfn(addr: usize) -> usize {
    addr >> PAGE_SHIFT
}

/// Convert page number to address
#[inline]
pub const fn pfn_to_addr(pfn: usize) -> usize {
    pfn << PAGE_SHIFT
}

/// Calculate number of pages needed to cover `size` bytes
#[inline]
pub const fn pages_needed(size: usize) -> usize {
    (size + PAGE_MASK) >> PAGE_SHIFT
}

/// 2 MiB block size (for huge pages on x86_64, L2 blocks on aarch64)
pub const BLOCK_SIZE_2MB: usize = 2 * 1024 * 1024;

/// 1 GiB block size (for L1 blocks on aarch64)
pub const BLOCK_SIZE_1GB: usize = 1024 * 1024 * 1024;

// ============================================================================
// x86_64 Early Boot Memory Constants
// ============================================================================

/// x86_64 early frame allocator start address (8 MiB).
///
/// Physical memory range [EARLY_ALLOC_START, EARLY_ALLOC_END) is reserved for
/// the early bump allocator before the buddy allocator is ready.
/// Must match the reservation in kernel memory initialization.
#[cfg(target_arch = "x86_64")]
pub const EARLY_ALLOC_START: usize = 0x0080_0000; // 8 MiB

/// x86_64 early frame allocator end address (16 MiB).
#[cfg(target_arch = "x86_64")]
pub const EARLY_ALLOC_END: usize = 0x0100_0000; // 16 MiB

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_constants() {
        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(PAGE_SHIFT, 12);
        assert_eq!(PAGE_MASK, 0xFFF);
        assert_eq!(1 << PAGE_SHIFT, PAGE_SIZE);
    }

    #[test]
    fn test_page_align_down() {
        assert_eq!(page_align_down(0x0), 0x0);
        assert_eq!(page_align_down(0x1), 0x0);
        assert_eq!(page_align_down(0xFFF), 0x0);
        assert_eq!(page_align_down(0x1000), 0x1000);
        assert_eq!(page_align_down(0x1001), 0x1000);
        assert_eq!(page_align_down(0x1FFF), 0x1000);
        assert_eq!(page_align_down(0x2000), 0x2000);
        assert_eq!(page_align_down(0x12345678), 0x12345000);
    }

    #[test]
    fn test_page_align_up() {
        assert_eq!(page_align_up(0x0), 0x0);
        assert_eq!(page_align_up(0x1), 0x1000);
        assert_eq!(page_align_up(0xFFF), 0x1000);
        assert_eq!(page_align_up(0x1000), 0x1000);
        assert_eq!(page_align_up(0x1001), 0x2000);
        assert_eq!(page_align_up(0x1FFF), 0x2000);
        assert_eq!(page_align_up(0x2000), 0x2000);
        assert_eq!(page_align_up(0x12345678), 0x12346000);
    }

    #[test]
    fn test_is_page_aligned() {
        assert!(is_page_aligned(0x0));
        assert!(is_page_aligned(0x1000));
        assert!(is_page_aligned(0x2000));
        assert!(is_page_aligned(0x12345000));
        assert!(!is_page_aligned(0x1));
        assert!(!is_page_aligned(0xFFF));
        assert!(!is_page_aligned(0x1001));
        assert!(!is_page_aligned(0x12345678));
    }

    #[test]
    fn test_addr_pfn_conversion() {
        assert_eq!(addr_to_pfn(0x0), 0);
        assert_eq!(addr_to_pfn(0x1000), 1);
        assert_eq!(addr_to_pfn(0x12345000), 0x12345);

        assert_eq!(pfn_to_addr(0), 0x0);
        assert_eq!(pfn_to_addr(1), 0x1000);
        assert_eq!(pfn_to_addr(0x12345), 0x12345000);

        // Round-trip
        assert_eq!(pfn_to_addr(addr_to_pfn(0x5000)), 0x5000);
    }

    #[test]
    fn test_pages_needed() {
        assert_eq!(pages_needed(0), 0);
        assert_eq!(pages_needed(1), 1);
        assert_eq!(pages_needed(0xFFF), 1);
        assert_eq!(pages_needed(0x1000), 1);
        assert_eq!(pages_needed(0x1001), 2);
        assert_eq!(pages_needed(0x2000), 2);
        assert_eq!(pages_needed(0x10000), 16);
    }

    #[test]
    fn test_block_sizes() {
        assert_eq!(BLOCK_SIZE_2MB, 0x200000);
        assert_eq!(BLOCK_SIZE_1GB, 0x40000000);
    }

    // === TEAM_462: Re-export verification tests ===

    #[test]
    fn test_reexport_through_mem_module() {
        // Verify constants are accessible through crate::mem
        use crate::mem::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
        use crate::mem::{is_page_aligned, page_align_down, page_align_up, pages_needed};

        assert_eq!(PAGE_SIZE, 4096);
        assert_eq!(PAGE_SHIFT, 12);
        assert_eq!(PAGE_MASK, 0xFFF);

        assert_eq!(page_align_down(0x1234), 0x1000);
        assert_eq!(page_align_up(0x1234), 0x2000);
        assert!(is_page_aligned(0x1000));
        assert_eq!(pages_needed(0x2001), 3);
    }

    #[test]
    fn test_const_fn_compile_time() {
        // Verify these are const fn by using them in const context
        const ALIGNED_DOWN: usize = page_align_down(0x1234);
        const ALIGNED_UP: usize = page_align_up(0x1234);
        const IS_ALIGNED: bool = is_page_aligned(0x1000);
        const PAGES: usize = pages_needed(0x3000);
        const PFN: usize = addr_to_pfn(0x5000);
        const ADDR: usize = pfn_to_addr(5);

        assert_eq!(ALIGNED_DOWN, 0x1000);
        assert_eq!(ALIGNED_UP, 0x2000);
        assert!(IS_ALIGNED);
        assert_eq!(PAGES, 3);
        assert_eq!(PFN, 5);
        assert_eq!(ADDR, 0x5000);
    }

    #[test]
    fn test_alignment_edge_cases() {
        // Zero
        assert_eq!(page_align_down(0), 0);
        assert_eq!(page_align_up(0), 0);
        assert!(is_page_aligned(0));
        assert_eq!(pages_needed(0), 0);

        // Exactly one page
        assert_eq!(page_align_down(PAGE_SIZE), PAGE_SIZE);
        assert_eq!(page_align_up(PAGE_SIZE), PAGE_SIZE);
        assert!(is_page_aligned(PAGE_SIZE));
        assert_eq!(pages_needed(PAGE_SIZE), 1);

        // One byte over page boundary
        assert_eq!(page_align_down(PAGE_SIZE + 1), PAGE_SIZE);
        assert_eq!(page_align_up(PAGE_SIZE + 1), PAGE_SIZE * 2);
        assert!(!is_page_aligned(PAGE_SIZE + 1));
        assert_eq!(pages_needed(PAGE_SIZE + 1), 2);

        // Maximum page-aligned address that fits in usize
        // We can't test usize::MAX directly as page_align_up would overflow
        // but we can test a large page-aligned value
        let large = 0xFFFF_FFFF_FFFF_F000usize;
        assert!(is_page_aligned(large));
        assert_eq!(page_align_down(large), large);
    }

    #[test]
    fn test_page_mask_relationships() {
        // Verify the relationships between constants
        assert_eq!(PAGE_SIZE, 1 << PAGE_SHIFT);
        assert_eq!(PAGE_MASK, PAGE_SIZE - 1);
        assert_eq!(!PAGE_MASK & 0xFFFF_FFFF_FFFF_FFFF, !0xFFFusize);

        // page_align_down uses !PAGE_MASK
        for addr in [0x0, 0x1, 0xFFF, 0x1000, 0x1234, 0x12345678] {
            assert_eq!(page_align_down(addr), addr & !PAGE_MASK);
        }
    }

    #[test]
    fn test_pages_needed_formula() {
        // pages_needed(size) = (size + PAGE_MASK) >> PAGE_SHIFT
        // This is equivalent to ceiling division: (size + PAGE_SIZE - 1) / PAGE_SIZE

        for size in [0, 1, 0xFFF, 0x1000, 0x1001, 0x2000, 0x12345] {
            let expected = if size == 0 {
                0
            } else {
                (size + PAGE_SIZE - 1) / PAGE_SIZE
            };
            assert_eq!(
                pages_needed(size),
                expected,
                "pages_needed({}) failed",
                size
            );
        }
    }
}
