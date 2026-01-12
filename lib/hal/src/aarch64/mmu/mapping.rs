//! MMU mapping functions for AArch64.
//!
//! Contains page table mapping, translation, and MmuInterface trait implementation.

use super::constants::{
    BLOCK_1GB_SIZE, BLOCK_2MB_MASK, BLOCK_2MB_SIZE, PAGE_MASK, PAGE_SIZE, page_align_down,
    page_align_up, phys_to_virt, virt_to_phys,
};
use super::init::{alloc_page_table, switch_ttbr0};
use super::ops::{tlb_flush_page, va_l0_index, va_l1_index, va_l2_index, va_l3_index};
use super::types::{PageFlags, PageTable};
use super::{MmuError, PAGE_ALLOCATOR_PTR};

// ============================================================================
// MmuInterface Implementation
// ============================================================================

impl crate::traits::MmuInterface for PageTable {
    fn map_page(&mut self, va: usize, pa: usize, flags: PageFlags) -> Result<(), MmuError> {
        map_page(self, va, pa, flags)
    }

    fn unmap_page(&mut self, va: usize) -> Result<(), MmuError> {
        unmap_page(self, va)
    }

    fn switch_to(&self) {
        let pa = virt_to_phys(self as *const PageTable as usize);
        unsafe {
            switch_ttbr0(pa);
        }
    }
}

// ============================================================================
// Page Table Walk
// ============================================================================

/// Result of a page table walk.
/// TEAM_070: Added for UoW 1 refactoring to support reclamation.
pub struct WalkResult<'a> {
    /// The table containing the leaf entry.
    pub table: &'a mut PageTable,
    /// The index of the leaf entry within the table.
    pub index: usize,
    /// The path of tables and indices taken to reach the leaf.
    /// Index 0 = L0, Index 1 = L1, Index 2 = L2.
    /// Each entry contains the table and the index into it that points to the NEXT level.
    pub breadcrumbs: Breadcrumbs,
}

/// Path information used for table reclamation.
/// TEAM_070: Added for UoW 1.
pub struct Breadcrumbs {
    pub tables: [Option<usize>; 3], // Virtual addresses of tables
    pub indices: [usize; 3],        // Indices used at each level
}

/// Walk the page table to find the entry for a virtual address at a specific level.
///
/// TEAM_070: Refactored from map_page to support reuse and unmap.
pub fn walk_to_entry<'a>(
    root: &'a mut PageTable,
    va: usize,
    target_level: usize,
    create: bool,
) -> Result<WalkResult<'a>, MmuError> {
    if target_level > 3 {
        return Err(MmuError::InvalidVirtualAddress);
    }

    let indices = [
        va_l0_index(va),
        va_l1_index(va),
        va_l2_index(va),
        va_l3_index(va),
    ];

    let mut current_table = root;
    let mut breadcrumbs = Breadcrumbs {
        tables: [None; 3],
        indices: [0; 3],
    };

    // Walk level by level until we reach the level ABOVE the target_level
    for level in 0..target_level {
        let index = indices[level];
        breadcrumbs.tables[level] = Some(current_table as *mut PageTable as usize);
        breadcrumbs.indices[level] = index;

        let entry = current_table.entry(index);
        if !entry.is_table() {
            if create {
                // Need to allocate a new table
                current_table = get_or_create_table(current_table, index)?;
            } else {
                return Err(MmuError::WalkFailed);
            }
        } else {
            // Already a table, just descend
            let child_pa = entry.address();
            let child_va = phys_to_virt(child_pa);
            current_table = unsafe { &mut *(child_va as *mut PageTable) };
        }
    }

    // Now current_table is the table containing the leaf entry at target_level
    let leaf_index = indices[target_level];

    Ok(WalkResult {
        table: current_table,
        index: leaf_index,
        breadcrumbs,
    })
}

/// Translate a virtual address to physical address and flags.
/// Returns None if not mapped.
pub fn translate(root: &PageTable, va: usize) -> Option<(usize, PageFlags)> {
    let indices = [
        va_l0_index(va),
        va_l1_index(va),
        va_l2_index(va),
        va_l3_index(va),
    ];

    let mut current_table = root;

    // Walk L0 -> L1 -> L2
    for level in 0..3 {
        let index = indices[level];
        let entry = current_table.entry(index);

        if !entry.is_valid() {
            return None;
        }

        if !entry.is_table() {
            // Block mapping (L1 1GB or L2 2MB)
            let block_pa = entry.address();
            let flags = entry.flags();

            // Calculate offset based on level
            let (mask, _size) = if level == 1 {
                (0x3FFF_FFFF, BLOCK_1GB_SIZE) // L1 = 1GB
            } else if level == 2 {
                (0x1F_FFFF, BLOCK_2MB_SIZE) // L2 = 2MB
            } else {
                return None; // L0 blocks not supported on 4KB granule
            };

            let offset = va & mask;
            return Some((block_pa + offset, flags));
        }

        let child_pa = entry.address();
        let child_va = phys_to_virt(child_pa);
        // SAFETY: We are just reading. The PA is valid RAM.
        current_table = unsafe { &*(child_va as *const PageTable) };
    }

    // L3 (Leaf Page)
    let index = indices[3];
    let entry = current_table.entry(index);
    if !entry.is_valid() {
        return None;
    }

    let pa = entry.address();
    // TEAM_462: Use PAGE_MASK constant
    let offset = va & PAGE_MASK;
    let flags = entry.flags();

    Some((pa + offset, flags))
}

// ============================================================================
// Page Mapping
// ============================================================================

/// Map a single 4KB page.
///
/// Creates intermediate table entries as needed.
/// Returns Err if page table allocation fails.
pub fn map_page(
    root: &mut PageTable,
    va: usize,
    pa: usize,
    flags: PageFlags,
) -> Result<(), MmuError> {
    // TEAM_070: Using refactored walk_to_entry
    let walk = walk_to_entry(root, va, 3, true)?;
    walk.table
        .entry_mut(walk.index)
        .set(pa, flags | PageFlags::TABLE); // L3 entries use TABLE bit = 1 for pages
    Ok(())
}

/// Unmap a single 4KB page.
///
/// TEAM_070: Implementing unmap support (UoW 2) and reclamation (UoW 3).
/// Returns Err if page is not mapped (Rule 14).
pub fn unmap_page(root: &mut PageTable, va: usize) -> Result<(), MmuError> {
    // Walk to L3 entry. Don't create if missing.
    let walk = walk_to_entry(root, va, 3, false)?;

    if !walk.table.entry(walk.index).is_valid() {
        return Err(MmuError::NotMapped);
    }

    // Clear leaf entry
    walk.table.entry_mut(walk.index).clear();

    // TLB invalidation is critical after clearing entry
    tlb_flush_page(va);

    // TEAM_070: Table Reclamation (UoW 3)
    // If the leaf table (L3) is now empty, we can potentially free it and recurse.
    if walk.table.is_empty() {
        if let Some(allocator) = unsafe { PAGE_ALLOCATOR_PTR } {
            let mut current_table_to_free = walk.table;

            // Iterate backwards through breadcrumbs:
            // breadcrumbs.tables[2] is L2 (points to L3), [1] is L1, [0] is L0.
            for level in (0..3).rev() {
                if let Some(parent_va) = walk.breadcrumbs.tables[level] {
                    let parent = unsafe { &mut *(parent_va as *mut PageTable) };
                    let index_in_parent = walk.breadcrumbs.indices[level];

                    // 1. Free the current child table
                    let child_pa = virt_to_phys(current_table_to_free as *mut PageTable as usize);

                    // SAFETY: We only free if we have a dynamic allocator.
                    // The allocator should handle PAs it doesn't own gracefully or we must check.
                    // For now, we trust the allocator or the fact that dynamic tables are only
                    // allocated when allocator is present.
                    allocator.free_page(child_pa);

                    // 2. Clear the entry in the parent pointing to this table
                    parent.entry_mut(index_in_parent).clear();

                    // 3. If parent is now empty and NOT the root (L0), continue reclamation
                    if level > 0 && parent.is_empty() {
                        current_table_to_free = parent;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Get or create a child table at the given index.
/// TEAM_070: Internal helper now, could be folded into walk_to_entry if needed.
fn get_or_create_table(
    parent: &mut PageTable,
    index: usize,
) -> Result<&'static mut PageTable, MmuError> {
    let entry = parent.entry(index);

    if entry.is_table() {
        // Entry exists, get the child table address (Physical)
        let child_pa = entry.address();
        // Convert PA to VA for Rust access
        let child_va = phys_to_virt(child_pa);
        unsafe { Ok(&mut *(child_va as *mut PageTable)) }
    } else {
        // Need to allocate a new table
        // [M26] Try dynamic allocator first, [M27] fallback to static pool
        let new_table = if let Some(allocator) = unsafe { PAGE_ALLOCATOR_PTR } {
            allocator.alloc_page().map(|pa| {
                // crate::verbose!("MMU: Allocated dynamic page table at 0x{:x}", pa);
                let va = phys_to_virt(pa);
                let pt = unsafe { &mut *(va as *mut PageTable) };
                pt.zero();
                pt
            })
        } else {
            alloc_page_table()
        }
        .ok_or(MmuError::AllocationFailed)?;

        let new_va = new_table as *mut PageTable as usize;
        let new_pa = virt_to_phys(new_va);

        // Set parent entry to point to new table (Physical Address)
        parent
            .entry_mut(index)
            .set(new_pa, PageFlags::VALID | PageFlags::TABLE);

        Ok(new_table)
    }
}

// ============================================================================
// Range Mapping
// ============================================================================

/// Identity map a range of physical addresses (VA == PA).
pub fn identity_map_range(
    root: &mut PageTable,
    start: usize,
    end: usize,
    flags: PageFlags,
) -> Result<(), MmuError> {
    // TEAM_462: Use central page alignment helpers
    let start_page = page_align_down(start);
    let end_page = page_align_up(end);

    let mut addr = start_page;
    while addr < end_page {
        map_page(root, addr, addr, flags)?;
        addr += PAGE_SIZE;
    }

    Ok(())
}

// TEAM_019: 2MB Block Mapping Support
// ============================================================================

/// Map a single 2MB block at L2 level.
///
/// # Arguments
/// - `root`: L0 page table
/// - `va`: Virtual address (must be 2MB aligned)
/// - `pa`: Physical address (must be 2MB aligned)
/// - `flags`: Page flags (should use KERNEL_DATA_BLOCK or DEVICE_BLOCK)
///
/// # Returns
/// Ok(()) on success, Err if allocation fails or misaligned
pub fn map_block_2mb(
    root: &mut PageTable,
    va: usize,
    pa: usize,
    flags: PageFlags,
) -> Result<(), MmuError> {
    // Verify 2MB alignment
    if (va & BLOCK_2MB_MASK) != 0 {
        return Err(MmuError::Misaligned);
    }
    if (pa & BLOCK_2MB_MASK) != 0 {
        return Err(MmuError::Misaligned);
    }

    // TEAM_070: Using refactored walk_to_entry at level 2
    let walk = walk_to_entry(root, va, 2, true)?;
    walk.table.entry_mut(walk.index).set(pa, flags);

    Ok(())
}

/// Map a range using 2MB blocks where possible, otherwise 4KB pages.
pub fn map_range(
    root: &mut PageTable,
    va_start: usize,
    pa_start: usize,
    len: usize,
    flags: PageFlags,
) -> Result<MappingStats, MmuError> {
    // TEAM_462: Use central page alignment helpers
    let mut va = page_align_down(va_start);
    let mut pa = page_align_down(pa_start);
    let end_va = page_align_up(va_start + len);

    let mut stats = MappingStats {
        blocks_2mb: 0,
        pages_4kb: 0,
    };

    while va < end_va {
        let remaining = end_va - va;

        // Check if we can use 2MB block:
        // 1. Both VA and PA are 2MB aligned
        // 2. At least 2MB remaining
        if (va & BLOCK_2MB_MASK) == 0 && (pa & BLOCK_2MB_MASK) == 0 && remaining >= BLOCK_2MB_SIZE {
            let block_flags = flags.difference(PageFlags::TABLE);
            map_block_2mb(root, va, pa, block_flags)?;
            stats.blocks_2mb += 1;
            va += BLOCK_2MB_SIZE;
            pa += BLOCK_2MB_SIZE;
        } else {
            map_page(root, va, pa, flags)?;
            stats.pages_4kb += 1;
            va += PAGE_SIZE;
            pa += PAGE_SIZE;
        }
    }

    Ok(stats)
}

/// Identity map a range using 2MB blocks where possible, otherwise 4KB pages.
pub fn identity_map_range_optimized(
    root: &mut PageTable,
    start: usize,
    end: usize,
    flags: PageFlags,
) -> Result<MappingStats, MmuError> {
    map_range(root, start, start, end - start, flags)
}

/// Statistics from an optimized identity mapping operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingStats {
    /// Number of 2MB blocks mapped
    pub blocks_2mb: usize,
    /// Number of 4KB pages mapped
    pub pages_4kb: usize,
}

impl MappingStats {
    /// Total bytes mapped
    pub fn total_bytes(&self) -> usize {
        self.blocks_2mb * BLOCK_2MB_SIZE + self.pages_4kb * PAGE_SIZE
    }
}
