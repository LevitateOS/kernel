//! TEAM_422: User Page Table Management
//!
//! Creation and destruction of user address space page tables.
//! TEAM_432: Added copy_user_address_space for fork() support.

use alloc::vec::Vec;

use crate::FRAME_ALLOCATOR;
use crate::vma::{VmaFlags, VmaList};
use los_hal::mmu::{
    self, page_align_down, ENTRIES_PER_TABLE, MmuError, PAGE_SIZE, PageFlags, PageTable,
};
use los_hal::traits::PageAllocator;

use super::mapping::map_user_page;

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
        // TEAM_462: Mask out PCID and flags (bits 0-11) using helper
        let current_root_phys = page_align_down(current_root_phys);
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
    pages_to_free: &mut Vec<usize>,
    tables_to_free: &mut Vec<usize>,
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
    let mut pages_to_free = Vec::new();
    let mut tables_to_free = Vec::new();

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

/// TEAM_432: Copy a parent's user address space for fork().
///
/// Creates a new page table and copies all mapped pages from the parent's
/// address space. This performs an eager (full) copy - not copy-on-write.
///
/// # Arguments
/// * `parent_ttbr0` - Physical address of parent's page table root
/// * `vmas` - Parent's VMA list describing mapped regions
///
/// # Returns
/// Physical address of the new child page table, or None if allocation fails.
///
/// # Safety
/// - `parent_ttbr0` must be a valid user L0/PML4 page table
/// - `vmas` must accurately describe the parent's mapped regions
pub fn copy_user_address_space(parent_ttbr0: usize, vmas: &VmaList) -> Option<usize> {
    log::trace!("[FORK] Copying user address space...");

    // 1. Create a new page table for the child
    let child_ttbr0 = create_user_page_table()?;

    // 2. Get the parent's root page table for translation
    let parent_root_va = mmu::phys_to_virt(parent_ttbr0);
    // SAFETY: parent_ttbr0 is a valid page table provided by caller
    let parent_root = unsafe { &*(parent_root_va as *const PageTable) };

    // TEAM_455: Debug - count VMAs and pages copied
    let mut vma_count = 0usize;
    let mut total_pages = 0usize;

    // 3. For each VMA, copy all mapped pages
    for vma in vmas.iter() {
        vma_count += 1;
        log::trace!(
            "[FORK] VMA {}: 0x{:x}-0x{:x} flags={:?}",
            vma_count,
            vma.start,
            vma.end,
            vma.flags
        );

        // Iterate over each page in the VMA
        let mut va = vma.start;
        while va < vma.end {
            // Try to translate the VA to get the parent's physical page
            if let Some((parent_pa, _flags)) = mmu::translate(parent_root, va) {
                // Page is mapped in parent - copy it

                // a. Allocate a new physical frame for the child
                let child_pa = match FRAME_ALLOCATOR.alloc_page() {
                    Some(pa) => pa,
                    None => {
                        log::error!("[FORK] Failed to allocate page at VA 0x{:x}", va);
                        // Cleanup: destroy the partially-created child page table
                        // SAFETY: child_ttbr0 was just created and is valid
                        unsafe {
                            let _ = destroy_user_page_table(child_ttbr0);
                        }
                        return None;
                    }
                };

                // TEAM_462: Copy page contents from parent to child
                let parent_page_va = mmu::phys_to_virt(page_align_down(parent_pa));
                let child_page_va = mmu::phys_to_virt(child_pa);
                // SAFETY: Both addresses point to valid, allocated pages
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        parent_page_va as *const u8,
                        child_page_va as *mut u8,
                        PAGE_SIZE,
                    );
                }

                // c. Map the new page in the child's page table with same permissions
                let flags = vma_flags_to_page_flags(vma.flags);
                // SAFETY: child_ttbr0 is valid, va is in user space, child_pa is valid
                if let Err(e) = unsafe { map_user_page(child_ttbr0, va, child_pa, flags) } {
                    log::error!("[FORK] Failed to map page at VA 0x{:x}: {:?}", va, e);
                    // Free the page we just allocated
                    FRAME_ALLOCATOR.free_page(child_pa);
                    // Cleanup child page table
                    unsafe {
                        let _ = destroy_user_page_table(child_ttbr0);
                    }
                    return None;
                }
                total_pages += 1;
            }
            // If page not mapped in parent, skip (sparse mapping)

            va += PAGE_SIZE;
        }
    }

    log::trace!(
        "[FORK] Address space copy complete, child_ttbr0=0x{:x}, {} pages copied",
        child_ttbr0,
        total_pages
    );
    Some(child_ttbr0)
}

/// TEAM_454: Refresh kernel mappings in a user page table.
///
/// This should be called after all kernel allocations are done when forking,
/// to ensure the child's page table includes any new kernel heap mappings
/// that were created after the initial `create_user_page_table()` call.
///
/// # Arguments
/// * `child_ttbr0` - Physical address of the child's page table root
///
/// # Safety
/// - `child_ttbr0` must be a valid PML4 page table
#[cfg(target_arch = "x86_64")]
pub fn refresh_kernel_mappings(child_ttbr0: usize) {
    // Get current CR3 (which has the latest kernel mappings)
    let current_root_phys: usize;
    // SAFETY: Reading CR3 is a standard privileged operation.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) current_root_phys);
    }
    // TEAM_462: Mask out PCID and flags using helper
    let current_root_phys = page_align_down(current_root_phys);

    log::trace!(
        "[FORK] refresh_kernel_mappings: current CR3=0x{:x}, child=0x{:x}",
        current_root_phys,
        child_ttbr0
    );

    // Get references to both page tables
    let current_root_va = mmu::phys_to_virt(current_root_phys);
    let child_root_va = mmu::phys_to_virt(child_ttbr0);
    // SAFETY: Both addresses are valid page tables.
    let current_root = unsafe { &*(current_root_va as *const PageTable) };
    let child_root = unsafe { &mut *(child_root_va as *mut PageTable) };

    // Re-copy kernel mappings (PML4 entries 256-511)
    mmu::copy_kernel_mappings(child_root, current_root);

    // TEAM_454: Debug - verify entry 511 (kernel higher-half) was copied
    log::trace!(
        "[FORK] PML4[511] after refresh: parent=0x{:x}, child=0x{:x}",
        current_root.entries[511].address(),
        child_root.entries[511].address()
    );
}

/// TEAM_454: Stub for aarch64 (no-op since kernel mappings work differently)
#[cfg(target_arch = "aarch64")]
pub fn refresh_kernel_mappings(_child_ttbr0: usize) {
    // On aarch64, kernel and user page tables are separate (TTBR0/TTBR1)
    // so this is a no-op
}

/// TEAM_432: Convert VMA flags to page table flags.
fn vma_flags_to_page_flags(vma_flags: VmaFlags) -> PageFlags {
    let mut flags = PageFlags::VALID;

    // User pages are always accessible from user mode
    #[cfg(target_arch = "x86_64")]
    {
        flags |= PageFlags::USER_ACCESSIBLE;
    }

    if vma_flags.contains(VmaFlags::WRITE) {
        #[cfg(target_arch = "x86_64")]
        {
            flags |= PageFlags::WRITABLE;
        }
    }

    // For now, use USER_DATA which includes user-accessible and writable
    // More refined permissions can be added later
    if vma_flags.contains(VmaFlags::WRITE) {
        PageFlags::USER_DATA
    } else if vma_flags.contains(VmaFlags::EXEC) {
        PageFlags::USER_CODE
    } else {
        // Read-only data - use USER_CODE (no write bit)
        PageFlags::USER_CODE
    }
}

#[cfg(test)]
mod tests {
    use super::super::mapping::map_user_page;
    use super::*;
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
