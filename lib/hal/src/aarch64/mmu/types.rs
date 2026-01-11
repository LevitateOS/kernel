//! MMU type definitions for AArch64.
//!
//! Contains PageTableEntry, PageFlags, and PageTable structures.

use bitflags::bitflags;

use super::constants::ENTRIES_PER_TABLE;

// ============================================================================
// Page Table Entry
// ============================================================================

/// A 64-bit page table entry.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Create an empty (invalid) entry.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if entry is valid.
    #[inline]
    pub fn is_valid(&self) -> bool {
        (self.0 & PageFlags::VALID.bits()) != 0
    }

    /// Check if entry is a table descriptor (vs block).
    #[inline]
    pub fn is_table(&self) -> bool {
        self.is_valid() && (self.0 & PageFlags::TABLE.bits()) != 0
    }

    /// Get the physical address from this entry.
    #[inline]
    pub fn address(&self) -> usize {
        (self.0 & 0x0000_FFFF_FFFF_F000) as usize
    }

    /// Set the entry with address and flags.
    #[inline]
    pub fn set(&mut self, addr: usize, flags: PageFlags) {
        self.0 = ((addr as u64) & 0x0000_FFFF_FFFF_F000) | flags.bits();
    }

    /// Get flags from the entry.
    #[inline]
    pub fn flags(&self) -> PageFlags {
        PageFlags::from_bits_truncate(self.0)
    }

    /// Clear the entry.
    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

// ============================================================================
// Page Flags
// ============================================================================

bitflags! {
    /// AArch64 Stage 1 page table entry flags.
    /// Behaviors: [M1] VALID bit 0, [M2] TABLE bit 1, [M3] block has TABLE=0, [M4] table has TABLE=1
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageFlags: u64 {
        /// [M1] Entry is valid (bit 0)
        const VALID       = 1 << 0;
        /// [M2] Table descriptor (bit 1) - [M3] blocks have this unset, [M4] tables have this set
        const TABLE       = 1 << 1;

        // MAIR index (AttrIndx[2:0] at bits [4:2])
        /// Normal memory (MAIR index 0)
        const ATTR_NORMAL = 0b000 << 2;
        /// Device memory (MAIR index 1)
        const ATTR_DEVICE = 0b001 << 2;

        /// Non-secure
        const NS          = 1 << 5;

        // Access Permissions (AP[2:1] at bits [7:6])
        /// R/W at EL1, none at EL0
        const AP_RW_EL1   = 0b00 << 6;
        /// R/W at all ELs
        const AP_RW_ALL   = 0b01 << 6;
        /// RO at EL1, none at EL0
        const AP_RO_EL1   = 0b10 << 6;
        /// RO at all ELs
        const AP_RO_ALL   = 0b11 << 6;

        // Shareability (SH[1:0] at bits [9:8])
        /// Inner Shareable
        const SH_INNER    = 0b11 << 8;

        /// Access Flag - must be set or HW will fault
        const AF          = 1 << 10;
        /// Not Global
        const NG          = 1 << 11;

        // Upper attributes
        /// Privileged Execute Never
        const PXN         = 1 << 53;
        /// User Execute Never
        const UXN         = 1 << 54;
    }
}

impl PageFlags {
    /// Standard flags for kernel code (executable, read-only)
    pub const KERNEL_CODE: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::SH_INNER)
        .union(PageFlags::AP_RO_EL1)
        .union(PageFlags::UXN);

    /// Standard flags for kernel data (read-write, not executable)
    pub const KERNEL_DATA: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::SH_INNER)
        .union(PageFlags::AP_RW_EL1)
        .union(PageFlags::PXN)
        .union(PageFlags::UXN);

    /// Standard flags for device memory (read-write, not executable, not cached)
    pub const DEVICE: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::ATTR_DEVICE)
        .union(PageFlags::AP_RW_EL1)
        .union(PageFlags::PXN)
        .union(PageFlags::UXN);

    // TEAM_019: Block descriptor flags (bits[1:0] = 0b01, no TABLE bit)
    /// Kernel data as 2MB block (VALID but NOT TABLE)
    pub const KERNEL_DATA_BLOCK: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::SH_INNER)
        .union(PageFlags::AP_RW_EL1)
        .union(PageFlags::PXN)
        .union(PageFlags::UXN);

    /// Kernel code as 2MB block (VALID but NOT TABLE, executable)
    pub const KERNEL_CODE_BLOCK: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::SH_INNER)
        .union(PageFlags::AP_RO_EL1)
        .union(PageFlags::UXN);

    /// Device memory as 2MB block (VALID but NOT TABLE)
    pub const DEVICE_BLOCK: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::ATTR_DEVICE)
        .union(PageFlags::AP_RW_EL1)
        .union(PageFlags::PXN)
        .union(PageFlags::UXN);

    // TEAM_073: User-mode page flags (Phase 8: Userspace)
    // AP_RW_ALL (bits [7:6] = 01) = R/W access at all exception levels

    /// User code (executable, read-only from user perspective)
    /// - Accessible from EL0 (user)
    /// - PXN set (not executable in kernel mode for security)
    pub const USER_CODE: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::SH_INNER)
        .union(PageFlags::AP_RO_ALL) // RO from EL0/EL1
        .union(PageFlags::NG) // Not Global (per-process)
        .union(PageFlags::PXN); // Don't execute in kernel

    /// User data (read-write, not executable)
    /// - Accessible from EL0 (user)
    /// - UXN and PXN set (not executable anywhere)
    pub const USER_DATA: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::SH_INNER)
        .union(PageFlags::AP_RW_ALL) // R/W from EL0/EL1
        .union(PageFlags::NG) // Not Global (per-process)
        .union(PageFlags::PXN) // Don't execute in kernel
        .union(PageFlags::UXN); // Don't execute in user

    /// User stack (same as USER_DATA, explicit name for clarity)
    pub const USER_STACK: PageFlags = Self::USER_DATA;

    /// TEAM_212: User code+data (RWX) for pages shared between code and data segments
    /// This is less secure but necessary when segments share pages.
    /// - Accessible from EL0 (user)
    /// - Read-write AND executable in user mode
    pub const USER_CODE_DATA: PageFlags = PageFlags::VALID
        .union(PageFlags::AF)
        .union(PageFlags::SH_INNER)
        .union(PageFlags::AP_RW_ALL) // R/W from EL0/EL1
        .union(PageFlags::NG) // Not Global (per-process)
        .union(PageFlags::PXN); // Don't execute in kernel (but allow in user - no UXN)

    pub fn is_user(&self) -> bool {
        self.contains(PageFlags::AP_RW_ALL) || self.contains(PageFlags::AP_RO_ALL)
    }

    pub fn is_writable(&self) -> bool {
        self.contains(PageFlags::AP_RW_ALL) || self.contains(PageFlags::AP_RW_EL1)
    }
}

// ============================================================================
// Page Table
// ============================================================================

/// A 4KB-aligned page table with 512 entries.
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// Create a new empty page table.
    pub const fn new() -> Self {
        Self {
            entries: [PageTableEntry::empty(); ENTRIES_PER_TABLE],
        }
    }

    /// Zero all entries.
    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.clear();
        }
    }

    /// Get entry at index.
    #[inline]
    pub fn entry(&self, index: usize) -> &PageTableEntry {
        &self.entries[index]
    }

    /// Get mutable entry at index.
    #[inline]
    pub fn entry_mut(&mut self, index: usize) -> &mut PageTableEntry {
        &mut self.entries[index]
    }

    /// Check if all entries in the table are invalid.
    /// TEAM_070: Added for UoW 3 table reclamation.
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| !e.is_valid())
    }
}
