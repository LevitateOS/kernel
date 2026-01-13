//! TEAM_422: User Page Mapping Functions
//!
//! Functions for mapping and validating user address space pages.

use crate::FRAME_ALLOCATOR;
use los_hal::mmu::{
    self, MmuError, PAGE_MASK, PAGE_SIZE, PageFlags, PageTable, page_align_down, page_align_up,
};
use los_hal::traits::PageAllocator;

use super::layout;

/// TEAM_415: Allocate, zero, and map a single page.
///
/// Common pattern used by setup_user_stack, setup_user_tls, and alloc_and_map_heap_page.
pub fn alloc_zero_map_page(
    ttbr0_phys: usize,
    user_va: usize,
    flags: PageFlags,
) -> Result<(), MmuError> {
    // Allocate physical page
    let phys = FRAME_ALLOCATOR
        .alloc_page()
        .ok_or(MmuError::AllocationFailed)?;

    // Zero the page for security
    let page_ptr = mmu::phys_to_virt(phys) as *mut u8;
    // SAFETY: phys was just allocated and is valid
    unsafe {
        core::ptr::write_bytes(page_ptr, 0, PAGE_SIZE);
    }

    // Map into user address space
    // SAFETY: caller ensures ttbr0_phys and user_va are valid
    unsafe { map_user_page(ttbr0_phys, user_va, phys, flags) }
}

/// TEAM_073: Map a single user page.
///
/// Maps a page in the user's TTBR0 page table.
///
/// # WARNING: VMA Tracking Required (GOTCHA #38)
///
/// This function ONLY updates the page table. It does NOT track the mapping
/// in the process's VMA list. Callers MUST ensure VMA tracking is performed
/// separately, otherwise:
/// - `fork()` will not copy the mapped pages (see TEAM_455)
/// - `munmap()` will not know about the mapping
///
/// For allocating new anonymous mappings, prefer using the higher-level
/// mmap syscall implementation which handles VMA tracking automatically.
///
/// # Arguments
/// * `ttbr0_phys` - Physical address of user L0 page table
/// * `user_va` - Virtual address in user space (must be < 0x8000_0000_0000)
/// * `phys` - Physical address to map
/// * `flags` - Page flags (should use USER_CODE or USER_DATA)
///
/// # Safety
/// - `ttbr0_phys` must point to a valid L0 page table
/// - `user_va` must be in valid user address range
/// - Caller must ensure corresponding VMA is tracked (see warning above)
pub unsafe fn map_user_page(
    ttbr0_phys: usize,
    user_va: usize,
    phys: usize,
    flags: PageFlags,
) -> Result<(), MmuError> {
    // TEAM_152: Updated to use MmuError
    // Validate user address
    if user_va >= layout::USER_SPACE_END {
        return Err(MmuError::InvalidVirtualAddress);
    }

    // Get the L0 table
    let l0_va = mmu::phys_to_virt(ttbr0_phys);
    // SAFETY: ttbr0_phys is provided by the caller and must be a valid L0 page table.
    let l0 = unsafe { &mut *(l0_va as *mut PageTable) };

    // Use MMU's map_page function
    mmu::map_page(l0, user_va, phys, flags)
}

/// TEAM_073: Map a range of user pages.
///
/// # Arguments
/// * `ttbr0_phys` - Physical address of user L0 page table
/// * `user_va_start` - Starting virtual address (page-aligned)
/// * `phys_start` - Starting physical address (page-aligned)
/// * `len` - Length in bytes to map
/// * `flags` - Page flags
#[allow(dead_code)]
pub unsafe fn map_user_range(
    ttbr0_phys: usize,
    user_va_start: usize,
    phys_start: usize,
    len: usize,
    flags: PageFlags,
) -> Result<(), MmuError> {
    // TEAM_152: Updated to use MmuError
    // Validate user address
    if user_va_start >= layout::USER_SPACE_END {
        return Err(MmuError::InvalidVirtualAddress);
    }
    if user_va_start.saturating_add(len) > layout::USER_SPACE_END {
        return Err(MmuError::InvalidVirtualAddress);
    }

    let l0_va = mmu::phys_to_virt(ttbr0_phys);
    // SAFETY: ttbr0_phys is provided by the caller and must be a valid L0 page table.
    let l0 = unsafe { &mut *(l0_va as *mut PageTable) };

    // TEAM_462: Use helper functions instead of magic numbers
    let mut va = page_align_down(user_va_start);
    let mut pa = page_align_down(phys_start);
    let end_va = page_align_up(user_va_start + len);

    while va < end_va {
        mmu::map_page(l0, va, pa, flags)?;
        va += PAGE_SIZE;
        pa += PAGE_SIZE;
    }

    Ok(())
}

/// TEAM_073: Allocate physical pages and map them for user code/data.
#[allow(dead_code)]
pub unsafe fn alloc_and_map_user_range(
    ttbr0_phys: usize,
    user_va_start: usize,
    len: usize,
    flags: PageFlags,
) -> Result<usize, MmuError> {
    // TEAM_152: Updated to use MmuError
    if len == 0 {
        return Err(MmuError::InvalidVirtualAddress);
    }

    // TEAM_462: Use helper functions instead of magic numbers
    let va_start = page_align_down(user_va_start);
    let pages_needed = (len + (user_va_start - va_start) + PAGE_SIZE - 1) / PAGE_SIZE;

    let mut first_phys = 0;

    for i in 0..pages_needed {
        let page_va = va_start + i * PAGE_SIZE;

        // Allocate physical page
        let phys = FRAME_ALLOCATOR
            .alloc_page()
            .ok_or(MmuError::AllocationFailed)?;

        if i == 0 {
            first_phys = phys;
        }

        // Zero the page
        let page_ptr = mmu::phys_to_virt(phys) as *mut u8;
        unsafe {
            core::ptr::write_bytes(page_ptr, 0, PAGE_SIZE);
        }

        // Map into user address space
        // SAFETY: The page was just allocated and the VA is validated.
        unsafe {
            map_user_page(ttbr0_phys, page_va, phys, flags)?;
        }
    }

    Ok(first_phys)
}

/// TEAM_166: Allocate and map a single heap page for sbrk.
/// TEAM_415: Now delegates to alloc_zero_map_page helper.
pub fn alloc_and_map_heap_page(ttbr0_phys: usize, user_va: usize) -> Result<(), MmuError> {
    alloc_zero_map_page(ttbr0_phys, user_va, PageFlags::USER_DATA)
}

/// TEAM_166: Internal helper - map a page at a specific physical address.
/// Renamed from the original map_user_page to avoid confusion.
#[allow(dead_code)]
pub(super) unsafe fn map_user_page_at(
    ttbr0_phys: usize,
    user_va: usize,
    phys: usize,
    flags: PageFlags,
) -> Result<(), MmuError> {
    // Validate user address
    if user_va >= layout::USER_SPACE_END {
        return Err(MmuError::InvalidVirtualAddress);
    }

    // Get the L0 table
    let l0_va = mmu::phys_to_virt(ttbr0_phys);
    // SAFETY: ttbr0_phys is an internal physical address of a user page table,
    // guaranteed to be valid by the process management logic.
    let l0 = unsafe { &mut *(l0_va as *mut PageTable) };

    // Use MMU's map_page function
    mmu::map_page(l0, user_va, phys, flags)
}

/// TEAM_156: Translate a user virtual address to a kernel-accessible pointer.
///
/// This walks the user's page table to find the physical address,
/// then converts it to a kernel VA that can be safely accessed.
///
/// # Safety
/// - `ttbr0_phys` must be a valid user page table
/// - The user VA must be mapped
/// - Caller must ensure proper synchronization
pub fn user_va_to_kernel_ptr(ttbr0_phys: usize, user_va: usize) -> Option<*mut u8> {
    // Get L0 table
    let l0_va = mmu::phys_to_virt(ttbr0_phys);
    // SAFETY: ttbr0_phys is a valid page table physical address managed by the process.
    let l0 = unsafe { &mut *(l0_va as *mut PageTable) };

    // TEAM_462: Walk page tables to find physical address
    let page_va = page_align_down(user_va);
    let page_offset = user_va & PAGE_MASK;

    if let Ok(walk) = mmu::walk_to_entry(l0, page_va, 3, false) {
        let entry = walk.table.entry(walk.index);
        if entry.is_valid() {
            let entry_phys = entry.address();
            let dst_phys = entry_phys + page_offset;
            let kernel_va = mmu::phys_to_virt(dst_phys);
            return Some(kernel_va as *mut u8);
        }
    }
    None
}

/// TEAM_137: Validate a user buffer range.
/// Checks that all pages in the range are mapped and have correct permissions for EL0.
pub fn validate_user_buffer(
    ttbr0_phys: usize,
    ptr: usize,
    len: usize,
    writable: bool,
) -> Result<(), MmuError> {
    // TEAM_152: Updated to use MmuError
    // 1. Check user address space bounds
    if ptr >= layout::USER_SPACE_END {
        return Err(MmuError::InvalidVirtualAddress);
    }
    // Check for overflow or exceeding user space
    if let Some(end) = ptr.checked_add(len) {
        if end > layout::USER_SPACE_END {
            return Err(MmuError::InvalidVirtualAddress);
        }
    } else {
        return Err(MmuError::InvalidVirtualAddress);
    }

    if len == 0 {
        return Ok(());
    }

    // 2. Get L0 table (Read-Only access pattern)
    let l0_va = mmu::phys_to_virt(ttbr0_phys);
    // SAFETY: ttbr0_phys is guaranteed to be a valid page table by caller (process struct)
    let l0 = unsafe { &*(l0_va as *const PageTable) };

    // 3. Iterate over every page touched by the buffer
    let mut current = ptr;
    let end = ptr + len;

    while current < end {
        // Translate VA -> PA + Flags
        match mmu::translate(l0, current) {
            Some((_pa, flags)) => {
                // Check VALID bit (implicit in translate, but good to be explicit)
                if !flags.contains(PageFlags::VALID) {
                    return Err(MmuError::NotMapped);
                }

                if !flags.is_user() {
                    return Err(MmuError::NotMapped);
                }

                // Check Write Permission if requested
                if writable && !flags.is_writable() {
                    return Err(MmuError::NotMapped);
                }
            }
            None => return Err(MmuError::NotMapped),
        }

        // TEAM_462: Move to next page boundary using helper
        let next_page = page_align_down(current) + PAGE_SIZE;
        current = next_page;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // === TEAM_462: Tests for page alignment helper usage ===

    #[test]
    fn test_page_alignment_imports() {
        // Verify the alignment functions are properly imported and work
        assert_eq!(page_align_down(0x1234), 0x1000);
        assert_eq!(page_align_up(0x1234), 0x2000);
        assert_eq!(PAGE_MASK, 0xFFF);
        assert_eq!(PAGE_SIZE, 0x1000);
    }

    #[test]
    fn test_map_user_range_page_calculation() {
        // Test that map_user_range would calculate pages correctly
        // (without actually mapping - that requires allocator)

        let test_cases = [
            // (va_start, len, expected_pages)
            (0x1000, 0x1000, 1), // Aligned, 1 page
            (0x1000, 0x2000, 2), // Aligned, 2 pages
            (0x1234, 0x1000, 2), // Unaligned start: 0x1000 to 0x3000
            (0x1000, 0x1, 1),    // 1 byte = 1 page
            (0x1FFF, 0x2, 2),    // 2 bytes crossing page boundary
        ];

        for (va_start, len, expected_pages) in test_cases {
            let aligned_start = page_align_down(va_start);
            let aligned_end = page_align_up(va_start + len);
            let actual_pages = (aligned_end - aligned_start) / PAGE_SIZE;
            assert_eq!(
                actual_pages, expected_pages,
                "va_start=0x{:x}, len=0x{:x}: expected {} pages, got {}",
                va_start, len, expected_pages, actual_pages
            );
        }
    }

    #[test]
    fn test_user_va_to_kernel_ptr_alignment() {
        // Test that page offset extraction works correctly
        let test_addrs = [
            (0x1234, 0x1000, 0x234), // (addr, expected_page, expected_offset)
            (0x1000, 0x1000, 0x000),
            (0x1FFF, 0x1000, 0xFFF),
            (0x12345678, 0x12345000, 0x678),
        ];

        for (addr, expected_page, expected_offset) in test_addrs {
            let page = page_align_down(addr);
            let offset = addr & PAGE_MASK;
            assert_eq!(page, expected_page, "page_align_down(0x{:x})", addr);
            assert_eq!(offset, expected_offset, "offset of 0x{:x}", addr);
        }
    }

    #[test]
    fn test_validate_buffer_page_iteration() {
        // Test that validate_user_buffer would iterate pages correctly
        // The function iterates: current = page_align_down(ptr), then current += PAGE_SIZE

        let ptr = 0x1234;
        let len = 0x3000; // Spans ~4 pages (0x1000 to 0x5000 due to offset)

        // Simulate the iteration logic
        let mut current = ptr;
        let end = ptr + len;
        let mut pages_checked = 0;

        while current < end {
            pages_checked += 1;
            let next_page = page_align_down(current) + PAGE_SIZE;
            current = next_page;
        }

        // Expected: 0x1234 -> 0x2000 -> 0x3000 -> 0x4000 -> 0x5000 (>= end 0x4234)
        assert_eq!(pages_checked, 4);
    }

    #[test]
    fn test_alloc_and_map_user_range_pages_needed() {
        // Test the pages_needed calculation in alloc_and_map_user_range
        // Formula: (len + (user_va_start - va_start) + PAGE_SIZE - 1) / PAGE_SIZE

        let test_cases = [
            // (va_start, len, expected_pages)
            (0x1000, 0x1000, 1), // Aligned, exactly 1 page
            (0x1000, 0x1001, 2), // Aligned, 1 byte over
            (0x1234, 0x1000, 2), // 0x234 offset + 0x1000 len = needs 2 pages
            (0x1001, 0xFFF, 1),  // 1 byte offset + 0xFFF len = fits in 1 page
            (0x1001, 0x1000, 2), // 1 byte offset + 0x1000 len = needs 2 pages
        ];

        for (va_start, len, expected_pages) in test_cases {
            let aligned_start = page_align_down(va_start);
            let offset = va_start - aligned_start;
            let pages_needed = (len + offset + PAGE_SIZE - 1) / PAGE_SIZE;
            assert_eq!(
                pages_needed, expected_pages,
                "va_start=0x{:x}, len=0x{:x}: expected {} pages, got {}",
                va_start, len, expected_pages, pages_needed
            );
        }
    }
}
