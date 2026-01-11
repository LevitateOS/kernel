//! TEAM_422: User Page Table Management
//!
//! Creation and destruction of user address space page tables.

use crate::memory::FRAME_ALLOCATOR;
use los_hal::mmu::{self, MmuError, PageTable, ENTRIES_PER_TABLE};
use los_hal::traits::PageAllocator;

/// TEAM_073: Create a new user page table.
///
/// Allocates an L0 page table for a user process's TTBR0.
/// The table is initially empty - caller must map user segments.
///
/// # Returns
/// Physical address of the new L0 page table, or None if allocation fails.
pub fn create_user_page_table() -> Option<usize> {
    log::trace!("[MMU] Creating user page table...");
    // Allocate a page for L0 table
    let l0_phys = FRAME_ALLOCATOR.alloc_page()?;

    log::trace!("[MMU] Allocated L0 table at phys [MASKED]");

    // Zero the table
    let l0_va = mmu::phys_to_virt(l0_phys);
    log::trace!("[MMU] Zeroing L0 table at va [MASKED]");
    // SAFETY: l0_phys was just allocated and is valid. We are zeroing it to
    // initialize a new page table.
    let l0 = unsafe { &mut *(l0_va as *mut PageTable) };
    l0.zero();

    // TEAM_296: Copy kernel higher-half mappings for x86_64
    // This is required because x86_64 uses a single CR3 for both user and kernel.
    #[cfg(target_arch = "x86_64")]
    {
        let current_root_phys: usize;
        // SAFETY: Reading CR3 is a standard privileged operation to get the
        // current page table root.
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) current_root_phys);
        }
        // Mask out PCID and flags (bits 0-11)
        let current_root_phys = current_root_phys & !0xFFF;
        let current_root_va = mmu::phys_to_virt(current_root_phys);
        // SAFETY: current_root_phys is the active page table and is guaranteed to be valid.
        let current_root = unsafe { &*(current_root_va as *const PageTable) };
        mmu::copy_kernel_mappings(l0, current_root);
    }

    // Return physical address for TTBR0
    Some(l0_phys)
}

/// TEAM_238: Recursively walk a page table and collect entries for cleanup.
///
/// # Arguments
/// * `table_phys` - Physical address of the page table
/// * `level` - Current level (0=L0, 1=L1, 2=L2, 3=L3)
/// * `pages_to_free` - Accumulator for leaf page physical addresses
/// * `tables_to_free` - Accumulator for table physical addresses (freed last)
///
/// # Safety
/// - `table_phys` must be a valid page table at the given level
unsafe fn collect_page_table_entries(
    table_phys: usize,
    level: usize,
    pages_to_free: &mut alloc::vec::Vec<usize>,
    tables_to_free: &mut alloc::vec::Vec<usize>,
) {
    let table_va = mmu::phys_to_virt(table_phys);
    // SAFETY: table_phys must be a valid page table at the given level.
    let table = unsafe { &*(table_va as *const PageTable) };

    for i in 0..ENTRIES_PER_TABLE {
        let entry = table.entry(i);

        if !entry.is_valid() {
            continue;
        }

        let entry_phys = entry.address();

        if level == 3 {
            // L3: These are leaf pages - add to free list
            pages_to_free.push(entry_phys);
        } else if entry.is_table() {
            // Intermediate table descriptor - recurse
            unsafe {
                collect_page_table_entries(entry_phys, level + 1, pages_to_free, tables_to_free);
            }
            // Add child table to free list (will be freed after its contents)
            tables_to_free.push(entry_phys);
        } else {
            // Block mapping (L1 1GB or L2 2MB) - add to free list
            // Note: User space typically doesn't use blocks, but handle anyway
            pages_to_free.push(entry_phys);
        }
    }
}

/// TEAM_073: Free a user page table and all its mappings.
/// TEAM_238: Implemented full page table teardown.
///
/// Walks the page table hierarchy, frees all mapped pages,
/// then frees the page tables themselves bottom-up.
///
/// # Safety
/// - `ttbr0_phys` must be a valid user L0 page table
/// - Must not be called while the page table is active (TTBR0)
pub unsafe fn destroy_user_page_table(ttbr0_phys: usize) -> Result<(), MmuError> {
    let mut pages_to_free = alloc::vec::Vec::new();
    let mut tables_to_free = alloc::vec::Vec::new();

    // 1. Collect all entries starting from L0
    // SAFETY: ttbr0_phys must be a valid user L0 page table.
    unsafe {
        collect_page_table_entries(
            ttbr0_phys,
            0, // Start at L0
            &mut pages_to_free,
            &mut tables_to_free,
        );
    }

    // 2. Free all leaf pages first
    for page_phys in pages_to_free {
        FRAME_ALLOCATOR.free_page(page_phys);
    }

    // 3. Free intermediate tables (already in bottom-up order from recursion)
    for table_phys in tables_to_free {
        FRAME_ALLOCATOR.free_page(table_phys);
    }

    // 4. Free the L0 table itself
    FRAME_ALLOCATOR.free_page(ttbr0_phys);

    // 5. Flush TLB to ensure no stale entries
    mmu::tlb_flush_all();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::mapping::map_user_page;
    use los_hal::mmu::PageFlags;

    /// TEAM_238: Test that destroy_user_page_table properly cleans up.
    ///
    /// This test verifies:
    /// 1. Page table creation works
    /// 2. Page mapping works
    /// 3. Teardown doesn't panic
    /// 4. No double-free errors
    #[test]
    #[ignore = "Requires kernel allocator - run as integration test"]
    fn test_destroy_user_page_table() {
        // 1. Create a user page table
        let ttbr0 = create_user_page_table().expect("Failed to create user page table");

        // 2. Map a few test pages
        let test_vas = [0x1000, 0x2000, 0x3000, 0x10000];
        for &va in &test_vas {
            // Allocate a physical page
            let phys = FRAME_ALLOCATOR
                .alloc_page()
                .expect("Failed to allocate page");

            // Map it
            unsafe {
                map_user_page(ttbr0, va, phys, PageFlags::USER_DATA).expect("Failed to map page");
            }
        }

        // 3. Destroy the page table
        unsafe {
            destroy_user_page_table(ttbr0).expect("Failed to destroy page table");
        }

        // 4. If we get here without panic, the test passes
        // A more thorough test would check allocator stats
    }
}
