//! TEAM_238: Virtual Memory Area tracking for user processes.
//!
//! Tracks mapped regions to enable proper munmap and mprotect.
//!
//! TEAM_461: Optimized with binary search for O(log n) lookups.
//! The VMA list is kept sorted by start address, enabling efficient
//! point queries and overlap detection.

extern crate alloc;

use alloc::vec::Vec;
use bitflags::bitflags;
// TEAM_462: Import from central constants module
use los_hal::mmu::is_page_aligned;

bitflags! {
    /// VMA permission flags (matches mmap prot flags).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VmaFlags: u32 {
        /// Region is readable
        const READ = 1 << 0;
        /// Region is writable
        const WRITE = 1 << 1;
        /// Region is executable
        const EXEC = 1 << 2;
    }
}

/// A contiguous virtual memory region.
#[derive(Debug, Clone)]
pub struct Vma {
    /// Start address (page-aligned)
    pub start: usize,
    /// End address (exclusive, page-aligned)
    pub end: usize,
    /// Permission flags
    pub flags: VmaFlags,
}

impl Vma {
    /// Create a new VMA.
    #[must_use]
    pub fn new(start: usize, end: usize, flags: VmaFlags) -> Self {
        debug_assert!(start < end, "VMA start must be < end");
        // TEAM_462: Use helper function for page alignment check
        debug_assert!(is_page_aligned(start), "VMA start must be page-aligned");
        debug_assert!(is_page_aligned(end), "VMA end must be page-aligned");
        Self { start, end, flags }
    }

    /// Length of the VMA in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Check if VMA is empty (shouldn't happen in practice).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    /// Check if address is within this VMA.
    #[must_use]
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Check if this VMA overlaps with a range.
    #[must_use]
    pub fn overlaps(&self, start: usize, end: usize) -> bool {
        self.start < end && start < self.end
    }
}

use los_error::define_kernel_error;

define_kernel_error! {
    /// VMA operation errors.
    pub enum VmaError(0x05) {
        /// Attempted to insert overlapping VMA
        Overlapping = 0x01 => "VMA overlaps existing region",
        /// VMA not found
        NotFound = 0x02 => "VMA not found",
    }
}

/// List of VMAs for a process.
///
/// Maintains a sorted list of non-overlapping VMAs.
/// TEAM_432: Added Clone for fork() support.
/// TEAM_461: Optimized with binary search for O(log n) lookups.
#[derive(Debug, Default, Clone)]
pub struct VmaList {
    /// VMAs sorted by start address
    vmas: Vec<Vma>,
}

impl VmaList {
    /// Create an empty VMA list.
    #[must_use]
    pub fn new() -> Self {
        Self { vmas: Vec::new() }
    }

    /// TEAM_461: Binary search to find insertion point for a given start address.
    /// Returns the index where a VMA with this start address should be inserted.
    #[inline]
    fn search_insert_point(&self, start: usize) -> usize {
        self.vmas
            .binary_search_by(|v| v.start.cmp(&start))
            .unwrap_or_else(|i| i)
    }

    /// TEAM_461: Binary search to find a VMA that might contain the given address.
    /// Returns the index of the VMA with the largest start <= addr, or None if no such VMA.
    #[inline]
    fn search_containing(&self, addr: usize) -> Option<usize> {
        if self.vmas.is_empty() {
            return None;
        }

        // Find first VMA with start > addr
        let idx = self
            .vmas
            .binary_search_by(|v| {
                if v.start <= addr {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Greater
                }
            })
            .unwrap_or_else(|i| i);

        // The VMA at idx-1 (if exists) has start <= addr
        if idx > 0 {
            Some(idx - 1)
        } else {
            None
        }
    }

    /// Insert a new VMA. Returns error if it overlaps existing.
    /// TEAM_461: Uses binary search for O(log n) insertion.
    pub fn insert(&mut self, vma: Vma) -> Result<(), VmaError> {
        // Find insertion point using binary search
        let pos = self.search_insert_point(vma.start);

        // TEAM_461: Only need to check adjacent VMAs for overlap since list is sorted.
        // Check VMA before insertion point (if exists) - might extend past vma.start
        if pos > 0 {
            let prev = &self.vmas[pos - 1];
            if prev.overlaps(vma.start, vma.end) {
                return Err(VmaError::Overlapping);
            }
        }

        // Check VMA at insertion point (if exists) - might start before vma.end
        if pos < self.vmas.len() {
            let next = &self.vmas[pos];
            if next.overlaps(vma.start, vma.end) {
                return Err(VmaError::Overlapping);
            }
        }

        self.vmas.insert(pos, vma);
        Ok(())
    }

    /// Remove VMA(s) covering the given range.
    ///
    /// Handles partial overlaps by splitting VMAs.
    pub fn remove(&mut self, start: usize, end: usize) -> Result<(), VmaError> {
        let mut i = 0;
        let mut found_any = false;

        while i < self.vmas.len() {
            let vma = &self.vmas[i];

            if !vma.overlaps(start, end) {
                i += 1;
                continue;
            }

            found_any = true;
            let vma = self.vmas.remove(i);

            // Case 1: Range covers entire VMA - just remove
            if start <= vma.start && end >= vma.end {
                // Already removed, continue
                continue;
            }

            // Case 2: Range is inside VMA - split into two
            if start > vma.start && end < vma.end {
                // Left portion
                self.vmas.insert(i, Vma::new(vma.start, start, vma.flags));
                i += 1;
                // Right portion
                self.vmas.insert(i, Vma::new(end, vma.end, vma.flags));
                i += 1;
                continue;
            }

            // Case 3: Range overlaps left side
            if start <= vma.start && end < vma.end {
                self.vmas.insert(i, Vma::new(end, vma.end, vma.flags));
                i += 1;
                continue;
            }

            // Case 4: Range overlaps right side
            if start > vma.start && end >= vma.end {
                self.vmas.insert(i, Vma::new(vma.start, start, vma.flags));
                i += 1;
                continue;
            }
        }

        if found_any {
            Ok(())
        } else {
            Err(VmaError::NotFound)
        }
    }

    /// Find VMA containing the given address.
    /// TEAM_461: Uses binary search for O(log n) lookup.
    #[must_use]
    pub fn find(&self, addr: usize) -> Option<&Vma> {
        // Binary search for VMA with largest start <= addr
        let idx = self.search_containing(addr)?;
        let vma = &self.vmas[idx];

        // Check if addr is actually within this VMA's range
        if vma.contains(addr) {
            Some(vma)
        } else {
            None
        }
    }

    /// Find all VMAs overlapping the given range.
    /// TEAM_461: Uses binary search to find starting point, then scans O(k) overlapping VMAs.
    pub fn find_overlapping(&self, start: usize, end: usize) -> Vec<&Vma> {
        if self.vmas.is_empty() {
            return Vec::new();
        }

        // Find first VMA that could possibly overlap: one with start < end
        // Binary search for first VMA with start >= end (first non-overlapping on right)
        let search_start = self
            .vmas
            .binary_search_by(|v| {
                if v.end <= start {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Greater
                }
            })
            .unwrap_or_else(|i| i);

        // Collect all overlapping VMAs from this point
        self.vmas[search_start..]
            .iter()
            .take_while(|v| v.start < end)
            .filter(|v| v.overlaps(start, end))
            .collect()
    }

    /// Iterate over all VMAs.
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.iter()
    }

    /// TEAM_239: Update protection flags for VMAs in the given range.
    ///
    /// Updates the flags of VMAs that overlap with [start, end).
    /// If a VMA partially overlaps, it is split and only the overlapping
    /// portion gets the new flags.
    pub fn update_protection(&mut self, start: usize, end: usize, new_flags: VmaFlags) {
        let mut i = 0;

        while i < self.vmas.len() {
            let vma = &self.vmas[i];

            if !vma.overlaps(start, end) {
                i += 1;
                continue;
            }

            let old_flags = vma.flags;
            let vma_start = vma.start;
            let vma_end = vma.end;

            // Remove the existing VMA - we'll re-insert modified version(s)
            self.vmas.remove(i);

            // Case 1: Range covers entire VMA
            if start <= vma_start && end >= vma_end {
                // Re-insert with new flags
                self.vmas.insert(i, Vma::new(vma_start, vma_end, new_flags));
                i += 1;
                continue;
            }

            // Case 2: Range is inside VMA - split into three
            if start > vma_start && end < vma_end {
                // Left portion with old flags
                self.vmas.insert(i, Vma::new(vma_start, start, old_flags));
                i += 1;
                // Middle portion with new flags
                self.vmas.insert(i, Vma::new(start, end, new_flags));
                i += 1;
                // Right portion with old flags
                self.vmas.insert(i, Vma::new(end, vma_end, old_flags));
                i += 1;
                continue;
            }

            // Case 3: Range overlaps left side
            if start <= vma_start && end < vma_end {
                // Left portion (overlapping) with new flags
                self.vmas.insert(i, Vma::new(vma_start, end, new_flags));
                i += 1;
                // Right portion with old flags
                self.vmas.insert(i, Vma::new(end, vma_end, old_flags));
                i += 1;
                continue;
            }

            // Case 4: Range overlaps right side
            if start > vma_start && end >= vma_end {
                // Left portion with old flags
                self.vmas.insert(i, Vma::new(vma_start, start, old_flags));
                i += 1;
                // Right portion (overlapping) with new flags
                self.vmas.insert(i, Vma::new(start, vma_end, new_flags));
                i += 1;
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_vma_contains() {
        let vma = Vma::new(0x1000, 0x3000, VmaFlags::READ);
        assert!(vma.contains(0x1000));
        assert!(vma.contains(0x2FFF));
        assert!(!vma.contains(0x0FFF));
        assert!(!vma.contains(0x3000));
    }

    #[test]
    fn test_vma_overlaps() {
        let vma = Vma::new(0x2000, 0x4000, VmaFlags::READ);

        // Overlapping cases
        assert!(vma.overlaps(0x1000, 0x3000)); // Partial left
        assert!(vma.overlaps(0x3000, 0x5000)); // Partial right
        assert!(vma.overlaps(0x2500, 0x3500)); // Inside
        assert!(vma.overlaps(0x1000, 0x5000)); // Contains

        // Non-overlapping
        assert!(!vma.overlaps(0x0000, 0x2000)); // Before
        assert!(!vma.overlaps(0x4000, 0x5000)); // After
    }

    #[test]
    fn test_vma_len() {
        let vma = Vma::new(0x1000, 0x5000, VmaFlags::empty());
        assert_eq!(vma.len(), 0x4000);
    }

    #[test]
    fn test_insert_non_overlapping() {
        let mut list = VmaList::new();
        assert!(
            list.insert(Vma::new(0x1000, 0x2000, VmaFlags::READ))
                .is_ok()
        );
        assert!(
            list.insert(Vma::new(0x3000, 0x4000, VmaFlags::READ))
                .is_ok()
        );
        assert!(
            list.insert(Vma::new(0x2000, 0x3000, VmaFlags::READ))
                .is_ok()
        );
    }

    #[test]
    fn test_insert_overlapping_rejected() {
        let mut list = VmaList::new();
        list.insert(Vma::new(0x2000, 0x4000, VmaFlags::READ))
            .unwrap();
        assert!(
            list.insert(Vma::new(0x3000, 0x5000, VmaFlags::READ))
                .is_err()
        );
    }

    #[test]
    fn test_find() {
        let mut list = VmaList::new();
        list.insert(Vma::new(0x1000, 0x2000, VmaFlags::READ))
            .unwrap();
        list.insert(Vma::new(0x3000, 0x4000, VmaFlags::WRITE))
            .unwrap();

        assert!(list.find(0x1500).is_some());
        assert!(list.find(0x2500).is_none());
        assert!(list.find(0x3500).is_some());
    }

    #[test]
    fn test_remove_exact() {
        let mut list = VmaList::new();
        list.insert(Vma::new(0x1000, 0x2000, VmaFlags::READ))
            .unwrap();
        assert!(list.remove(0x1000, 0x2000).is_ok());
        assert!(list.find(0x1500).is_none());
    }

    #[test]
    fn test_remove_split() {
        let mut list = VmaList::new();
        list.insert(Vma::new(0x1000, 0x4000, VmaFlags::READ))
            .unwrap();

        // Remove middle portion
        assert!(list.remove(0x2000, 0x3000).is_ok());

        // Should have left and right portions
        assert!(list.find(0x1500).is_some()); // Left portion
        assert!(list.find(0x2500).is_none()); // Removed
        assert!(list.find(0x3500).is_some()); // Right portion
    }

    // TEAM_461: Tests for binary search optimization
    #[test]
    fn test_binary_search_many_vmas() {
        let mut list = VmaList::new();

        // Insert 100 non-overlapping VMAs
        for i in 0..100 {
            let start = i * 0x2000;
            let end = start + 0x1000;
            list.insert(Vma::new(start, end, VmaFlags::READ)).unwrap();
        }

        // Verify all can be found
        for i in 0..100 {
            let addr = i * 0x2000 + 0x500;
            assert!(list.find(addr).is_some(), "VMA {} not found", i);
        }

        // Verify gaps return None
        for i in 0..100 {
            let gap_addr = i * 0x2000 + 0x1500;
            assert!(list.find(gap_addr).is_none(), "Gap {} incorrectly found", i);
        }
    }

    #[test]
    fn test_find_overlapping_many() {
        let mut list = VmaList::new();

        // Insert VMAs: [0x1000-0x2000], [0x3000-0x4000], [0x5000-0x6000], etc.
        for i in 0..10 {
            let start = 0x1000 + i * 0x2000;
            let end = start + 0x1000;
            list.insert(Vma::new(start, end, VmaFlags::READ)).unwrap();
        }

        // Range that overlaps VMAs 2, 3, 4 (0x5000-0x6000, 0x7000-0x8000, 0x9000-0xA000)
        let overlapping = list.find_overlapping(0x5500, 0x9500);
        assert_eq!(overlapping.len(), 3);

        // Range that overlaps nothing (in a gap)
        let overlapping = list.find_overlapping(0x2000, 0x3000);
        assert!(overlapping.is_empty());

        // Range that overlaps everything
        let overlapping = list.find_overlapping(0x0000, 0x20000);
        assert_eq!(overlapping.len(), 10);
    }

    #[test]
    fn test_insert_maintains_sorted() {
        let mut list = VmaList::new();

        // Insert in random order
        list.insert(Vma::new(0x5000, 0x6000, VmaFlags::READ)).unwrap();
        list.insert(Vma::new(0x1000, 0x2000, VmaFlags::READ)).unwrap();
        list.insert(Vma::new(0x9000, 0xA000, VmaFlags::READ)).unwrap();
        list.insert(Vma::new(0x3000, 0x4000, VmaFlags::READ)).unwrap();

        // Verify sorted order
        let starts: Vec<_> = list.iter().map(|v| v.start).collect();
        assert_eq!(starts, vec![0x1000, 0x3000, 0x5000, 0x9000]);
    }

    #[test]
    fn test_overlap_detection_edge_cases() {
        let mut list = VmaList::new();
        list.insert(Vma::new(0x2000, 0x4000, VmaFlags::READ)).unwrap();

        // Adjacent (should succeed - no overlap)
        assert!(list.insert(Vma::new(0x4000, 0x5000, VmaFlags::READ)).is_ok());
        assert!(list.insert(Vma::new(0x1000, 0x2000, VmaFlags::READ)).is_ok());

        // Overlapping with existing [0x2000-0x4000] (should fail)
        // Use page-aligned addresses
        assert!(list.insert(Vma::new(0x3000, 0x5000, VmaFlags::READ)).is_err());
        assert!(list.insert(Vma::new(0x0000, 0x3000, VmaFlags::READ)).is_err());
    }

    // === TEAM_462: Tests for is_page_aligned helper usage ===

    #[test]
    fn test_is_page_aligned_import() {
        // Verify is_page_aligned is accessible through los_hal::mmu
        use los_hal::mmu::is_page_aligned;

        assert!(is_page_aligned(0x0));
        assert!(is_page_aligned(0x1000));
        assert!(is_page_aligned(0x2000));
        assert!(!is_page_aligned(0x1));
        assert!(!is_page_aligned(0xFFF));
        assert!(!is_page_aligned(0x1001));
    }

    #[test]
    fn test_vma_requires_page_alignment() {
        // VMA::new has debug_assert for page alignment
        // In release builds, unaligned addresses would be accepted
        // but the semantic contract is that VMAs must be page-aligned

        // These should work (page-aligned)
        let vma = Vma::new(0x1000, 0x2000, VmaFlags::READ);
        assert_eq!(vma.start, 0x1000);
        assert_eq!(vma.end, 0x2000);

        let vma = Vma::new(0x0, 0x1000, VmaFlags::READ);
        assert_eq!(vma.start, 0x0);
        assert_eq!(vma.end, 0x1000);

        // Large addresses
        let vma = Vma::new(0x7FFF_FFFF_F000, 0x8000_0000_0000, VmaFlags::READ);
        assert_eq!(vma.len(), 0x1000);
    }

    #[test]
    fn test_vma_alignment_helper_consistency() {
        use los_hal::mmu::{is_page_aligned, page_align_down, page_align_up};

        // Verify that helpers are consistent
        let test_addrs = [0x0, 0x1, 0xFFF, 0x1000, 0x1001, 0x12345678];

        for addr in test_addrs {
            let down = page_align_down(addr);
            let up = page_align_up(addr);

            // Aligned results should pass is_page_aligned
            assert!(is_page_aligned(down), "page_align_down(0x{:x}) = 0x{:x} should be aligned", addr, down);
            assert!(is_page_aligned(up), "page_align_up(0x{:x}) = 0x{:x} should be aligned", addr, up);

            // down <= addr <= up
            assert!(down <= addr, "page_align_down should not exceed input");
            assert!(up >= addr, "page_align_up should not be less than input");

            // If already aligned, down == up == addr
            if is_page_aligned(addr) {
                assert_eq!(down, addr);
                assert_eq!(up, addr);
            }
        }
    }

    #[test]
    fn test_vma_list_with_realistic_addresses() {
        // Test VMA list with addresses that might come from real page alignment
        use los_hal::mmu::{page_align_down, page_align_up};

        let mut list = VmaList::new();

        // Simulate ELF segment: unaligned input, aligned for VMA
        let elf_start = 0x400078;  // Typical ELF entry point
        let elf_end = 0x401234;
        let aligned_start = page_align_down(elf_start);
        let aligned_end = page_align_up(elf_end);

        list.insert(Vma::new(aligned_start, aligned_end, VmaFlags::READ | VmaFlags::EXEC))
            .expect("Should insert ELF text segment VMA");

        // Verify the VMA covers the original range
        assert!(list.find(elf_start).is_some());
        assert!(list.find(elf_end - 1).is_some());

        // Simulate stack: already page-aligned
        let stack_bottom = 0x7FFF_FFF7_0000;
        let stack_top = 0x7FFF_FFFF_0000;
        list.insert(Vma::new(stack_bottom, stack_top, VmaFlags::READ | VmaFlags::WRITE))
            .expect("Should insert stack VMA");

        assert!(list.find(stack_bottom).is_some());
        assert!(list.find(stack_top - 1).is_some());
    }
}
