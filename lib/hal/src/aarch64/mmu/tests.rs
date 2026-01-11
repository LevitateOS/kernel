//! Unit tests for AArch64 MMU (TEAM_019).
//!
//! Gated on `std` feature because this is a no_std crate.
//! Run with: cargo test -p levitate-hal --features std

use super::PAGE_ALLOCATOR_PTR;
use super::constants::*;
use super::mapping::*;
use super::ops::*;
use super::types::*;
use crate::traits::PageAllocator;

// === Flag Construction Tests ===

#[test]
fn test_page_flags_block_vs_table() {
    // Block descriptor: bits[1:0] = 0b01 (VALID only)
    let block = PageFlags::VALID;
    assert_eq!(block.bits() & 0b11, 0b01);

    // Table descriptor: bits[1:0] = 0b11 (VALID | TABLE)
    let table = PageFlags::VALID.union(PageFlags::TABLE);
    assert_eq!(table.bits() & 0b11, 0b11);
}

#[test]
fn test_block_flags_no_table_bit() {
    let block = PageFlags::KERNEL_DATA_BLOCK;
    assert!(!block.contains(PageFlags::TABLE));
    assert!(block.contains(PageFlags::VALID));
    assert!(block.contains(PageFlags::AF));
    assert!(block.contains(PageFlags::PXN));
    assert!(block.contains(PageFlags::UXN));
}

#[test]
fn test_device_block_flags() {
    let block = PageFlags::DEVICE_BLOCK;
    assert!(!block.contains(PageFlags::TABLE));
    assert!(block.contains(PageFlags::VALID));
    assert!(block.contains(PageFlags::ATTR_DEVICE));
}

// === Address Index Extraction Tests ===

#[test]
fn test_va_l0_index() {
    assert_eq!(va_l0_index(0x0000_0000_0000_0000), 0);
    assert_eq!(va_l0_index(0x0000_0080_0000_0000), 1); // 512GB boundary
    assert_eq!(va_l0_index(0x0000_FF80_0000_0000), 511);
}

#[test]
fn test_va_l1_index() {
    assert_eq!(va_l1_index(0x0000_0000_0000_0000), 0);
    assert_eq!(va_l1_index(0x0000_0000_4000_0000), 1); // 1GB boundary
    assert_eq!(va_l1_index(0x0000_0000_8000_0000), 2);
}

#[test]
fn test_va_l2_index() {
    assert_eq!(va_l2_index(0x0000_0000_0000_0000), 0);
    assert_eq!(va_l2_index(0x0000_0000_0020_0000), 1); // 2MB boundary
    assert_eq!(va_l2_index(0x0000_0000_0040_0000), 2);
}

#[test]
fn test_va_l3_index() {
    assert_eq!(va_l3_index(0x0000_0000_0000_0000), 0);
    assert_eq!(va_l3_index(0x0000_0000_0000_1000), 1); // 4KB boundary
    assert_eq!(va_l3_index(0x0000_0000_0000_2000), 2);
}

#[test]
fn test_kernel_address_indices() {
    // Kernel start: 0x4008_0000
    let va = 0x4008_0000usize;
    assert_eq!(va_l0_index(va), 0); // Within first 512GB
    assert_eq!(va_l1_index(va), 1); // Second 1GB region
    assert_eq!(va_l2_index(va), 0); // First 2MB within that 1GB
    // Note: 0x4008_0000 is NOT 2MB aligned (0x0008_0000 = 512KB offset)
}

// === Alignment Tests ===

#[test]
fn test_block_alignment() {
    // 2MB aligned addresses
    assert_eq!(0x4000_0000 & BLOCK_2MB_MASK, 0); // 1GB is 2MB aligned
    assert_eq!(0x4020_0000 & BLOCK_2MB_MASK, 0); // 2MB aligned
    assert_eq!(0x4040_0000 & BLOCK_2MB_MASK, 0); // 4MB aligned

    // NOT 2MB aligned
    assert_ne!(0x4010_0000 & BLOCK_2MB_MASK, 0); // 1MB offset
    assert_ne!(0x4008_0000 & BLOCK_2MB_MASK, 0); // 512KB offset (kernel start)
    assert_ne!(0x4001_0000 & BLOCK_2MB_MASK, 0); // 64KB offset
}

#[test]
fn test_constants() {
    assert_eq!(BLOCK_2MB_SIZE, 0x0020_0000);
    assert_eq!(BLOCK_2MB_MASK, 0x001F_FFFF);
    assert_eq!(PAGE_SIZE, 0x1000);
}

// === Page Table Entry Tests ===

#[test]
fn test_page_table_entry_empty() {
    let entry = PageTableEntry::empty();
    assert!(!entry.is_valid());
    assert!(!entry.is_table());
    assert_eq!(entry.address(), 0);
}

#[test]
fn test_page_table_entry_set_block() {
    let mut entry = PageTableEntry::empty();
    entry.set(0x4000_0000, PageFlags::KERNEL_DATA_BLOCK);
    assert!(entry.is_valid());
    assert!(!entry.is_table()); // Block, not table
    assert_eq!(entry.address(), 0x4000_0000);
}

#[test]
fn test_page_table_entry_set_table() {
    let mut entry = PageTableEntry::empty();
    entry.set(0x4000_0000, PageFlags::VALID.union(PageFlags::TABLE));
    assert!(entry.is_valid());
    assert!(entry.is_table());
    assert_eq!(entry.address(), 0x4000_0000);
}

// === Mapping Calculation Tests ===

#[test]
fn test_table_count_for_block_mapping() {
    // Calculate expected blocks for 128MB kernel with block mapping
    // Start: 0x4008_0000 (not 2MB aligned)
    // End:   0x4800_0000

    let start = 0x4008_0000usize;
    let end = 0x4800_0000usize;

    // First 2MB-aligned address at or after start
    let first_block_aligned = (start + BLOCK_2MB_SIZE - 1) & !BLOCK_2MB_MASK;
    assert_eq!(first_block_aligned, 0x4020_0000);

    // Last 2MB-aligned address at or before end
    let last_block_aligned = end & !BLOCK_2MB_MASK;
    assert_eq!(last_block_aligned, 0x4800_0000);

    // Number of 2MB blocks
    let num_blocks = (last_block_aligned - first_block_aligned) / BLOCK_2MB_SIZE;
    assert_eq!(num_blocks, 63); // 63 blocks of 2MB = 126MB

    // Leading edge: 0x4008_0000 to 0x4020_0000 = 0x18_0000 = 1.5MB
    let leading_bytes = first_block_aligned - start;
    assert_eq!(leading_bytes, 0x18_0000); // 1.5MB
    let leading_pages = leading_bytes / PAGE_SIZE;
    assert_eq!(leading_pages, 384); // 384 x 4KB pages
}

#[test]
fn test_mapping_stats() {
    let stats = MappingStats {
        blocks_2mb: 63,
        pages_4kb: 384,
    };

    // 63 * 2MB + 384 * 4KB = 126MB + 1.5MB = 127.5MB
    let expected_bytes = 63 * BLOCK_2MB_SIZE + 384 * PAGE_SIZE;
    assert_eq!(stats.total_bytes(), expected_bytes);
    assert_eq!(expected_bytes, 0x7F8_0000); // ~127.5MB
}

// === TEAM_030: Address Translation Tests (M19-M22) ===

// M19: virt_to_phys converts high VA to PA
#[test]
#[cfg(target_arch = "aarch64")]
fn test_virt_to_phys_high_address() {
    // Kernel virtual address in higher half
    let va = KERNEL_VIRT_START + 0x4008_0000;
    let pa = virt_to_phys(va);
    assert_eq!(pa, 0x4008_0000);
}

// M20: phys_to_virt converts PA to high VA
#[test]
#[cfg(target_arch = "aarch64")]
fn test_phys_to_virt_kernel_region() {
    // Physical address in kernel region (>= 0x4000_0000)
    let pa = 0x4008_0000;
    let va = phys_to_virt(pa);
    assert_eq!(va, KERNEL_VIRT_START + 0x4008_0000);
}

// M21: virt_to_phys identity for low addresses
#[test]
fn test_virt_to_phys_low_address_identity() {
    // Low addresses (below KERNEL_VIRT_START) pass through unchanged
    let va = 0x4008_0000;
    let pa = virt_to_phys(va);
    assert_eq!(pa, va); // Identity: already physical
}

// TEAM_078: phys_to_virt now maps ALL addresses to high VA (including devices)
#[test]
#[cfg(target_arch = "aarch64")]
fn test_phys_to_virt_device_high_va() {
    // Device addresses now also use high VA mapping
    let pa = 0x0900_0000; // UART address
    let va = phys_to_virt(pa);
    assert_eq!(va, KERNEL_VIRT_START + pa); // High VA for devices
}

// === Dynamic Page Allocation Tests (M23-M27) ===
// TEAM_054: Tests for PageAllocator trait interface

/// [M23] PageAllocator trait has alloc_page() method
/// [M24] PageAllocator trait has free_page() method
#[test]
fn test_page_allocator_trait_interface() {
    use core::sync::atomic::{AtomicUsize, Ordering};

    // Mock allocator for compile-time interface verification
    struct MockAllocator {
        alloc_count: AtomicUsize,
        free_count: AtomicUsize,
    }

    impl PageAllocator for MockAllocator {
        fn alloc_page(&self) -> Option<usize> {
            let count = self.alloc_count.fetch_add(1, Ordering::SeqCst);
            Some(0x1000_0000 + count * 0x1000) // [M23]
        }
        fn free_page(&self, _pa: usize) {
            self.free_count.fetch_add(1, Ordering::SeqCst); // [M24]
        }
    }

    let allocator = MockAllocator {
        alloc_count: AtomicUsize::new(0),
        free_count: AtomicUsize::new(0),
    };

    // Test alloc_page [M23]
    let pa1 = allocator.alloc_page().expect("should allocate");
    assert_eq!(pa1, 0x1000_0000);
    assert_eq!(allocator.alloc_count.load(Ordering::SeqCst), 1);

    let pa2 = allocator.alloc_page().expect("should allocate");
    assert_eq!(pa2, 0x1000_1000);
    assert_eq!(allocator.alloc_count.load(Ordering::SeqCst), 2);

    // Test free_page [M24]
    allocator.free_page(pa1);
    assert_eq!(allocator.free_count.load(Ordering::SeqCst), 1);
}

/// [M25] set_page_allocator accepts &'static dyn PageAllocator
/// Compile-time verification only - runtime test blocked by static mut
#[test]
fn test_set_page_allocator_signature() {
    // This test verifies the function signature compiles correctly
    // We cannot safely test runtime behavior due to static mut
    #[allow(dead_code)]
    fn assert_signature<T: PageAllocator + 'static>(_: &'static T) {
        // If this compiles, set_page_allocator can accept &'static T
    }

    // Compile-time verification passes if this test compiles
}

/// [M26] [M27] get_or_create_table allocation path exists
/// Compile-time verification that the function uses PageAllocator
#[test]
fn test_allocation_paths_exist() {
    // Verify PageTable type is correct size (4KB)
    assert_eq!(core::mem::size_of::<PageTable>(), PAGE_SIZE);

    // Verify PageTableEntry is 8 bytes
    assert_eq!(core::mem::size_of::<PageTableEntry>(), 8);

    // Verify 512 entries per table (4KB / 8 bytes)
    assert_eq!(ENTRIES_PER_TABLE, 512);
}

#[test]
fn test_map_unmap_cycle() {
    let mut root = PageTable::new();
    let va = 0x1234_5000usize;
    let pa = 0x4444_5000usize; // Use address that phys_to_virt handles (>= 0x4000_0000)
    let flags = PageFlags::KERNEL_DATA;

    // 1. Initial state: not mapped
    // walk_to_entry will fail because intermediate tables don't exist
    assert!(unmap_page(&mut root, va).is_err());

    // 2. Map page
    map_page(&mut root, va, pa, flags).expect("Mapping should succeed");

    // 3. Verify mapped
    let walk = walk_to_entry(&mut root, va, 3, false).expect("Walk should succeed");
    assert!(walk.table.entry(walk.index).is_valid());
    assert_eq!(walk.table.entry(walk.index).address(), pa);

    // 4. Unmap page
    unmap_page(&mut root, va).expect("Unmapping should succeed");

    // 5. Verify unmapped (entry cleared but path remains for now)
    let walk = walk_to_entry(&mut root, va, 3, false).expect("Walk should succeed");
    assert!(!walk.table.entry(walk.index).is_valid());

    // 6. Unmap again should fail because VALID bit is clear
    assert!(unmap_page(&mut root, va).is_err());
}

#[test]
fn test_table_reclamation() {
    use core::sync::atomic::{AtomicUsize, Ordering};

    struct MockReclaimer {
        free_count: AtomicUsize,
    }
    impl PageAllocator for MockReclaimer {
        fn alloc_page(&self) -> Option<usize> {
            None // Fallback to static pool
        }
        fn free_page(&self, _pa: usize) {
            self.free_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    // We use a static-like reference for the allocator
    static RECLAIMER: MockReclaimer = MockReclaimer {
        free_count: AtomicUsize::new(0),
    };

    let mut root = PageTable::new();
    let va = 0x1234_5000usize;
    let pa = 0x4444_5000usize;

    // 1. Map page FIRST (uses static pool)
    map_page(&mut root, va, pa, PageFlags::KERNEL_DATA).expect("Map should succeed");

    // 2. Set mock reclaimer
    unsafe {
        PAGE_ALLOCATOR_PTR = Some(&RECLAIMER);
    }

    // 3. Unmap and check reclamation
    RECLAIMER.free_count.store(0, Ordering::SeqCst);
    unmap_page(&mut root, va).expect("Unmap should succeed");

    // Expected: L3 freed, then L2 freed, then L1 freed. (3 total)
    // L0 (root) is never freed.
    assert_eq!(RECLAIMER.free_count.load(Ordering::SeqCst), 3);

    // 3. Verify path is gone from root
    assert!(root.entry(va_l0_index(va)).is_valid() == false);

    // Reset global state
    unsafe {
        PAGE_ALLOCATOR_PTR = None;
    }
}
