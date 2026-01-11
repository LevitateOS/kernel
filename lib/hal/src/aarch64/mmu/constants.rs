//! MMU constants for AArch64.
//!
//! Contains page sizes, kernel addresses, device addresses, and block sizes.

/// Page size: 4KB
pub const PAGE_SIZE: usize = 4096;
/// Page shift (log2 of page size)
pub const PAGE_SHIFT: usize = 12;
/// Entries per page table (512 for 4KB pages with 8-byte entries)
pub const ENTRIES_PER_TABLE: usize = 512;

/// Kernel physical start address (from linker.ld)
pub const KERNEL_PHYS_START: usize = 0x4008_0000;
/// Kernel physical end address (matches __heap_end in linker.ld)
/// Note: linker.ld sets __heap_end = _kernel_virt_base + 0x41F00000
pub const KERNEL_PHYS_END: usize = 0x41F0_0000;

/// Kernel virtual start address (Higher-half base)
pub const KERNEL_VIRT_START: usize = 0xFFFF_8000_0000_0000;

// TEAM_078: Device virtual addresses (mapped via TTBR1)
// These allow device access regardless of TTBR0 state (critical for userspace)
/// Device virtual address base (same as kernel base for simplicity)
pub const DEVICE_VIRT_BASE: usize = KERNEL_VIRT_START;
/// UART PL011 virtual address (PA: 0x0900_0000)
pub const UART_VA: usize = DEVICE_VIRT_BASE + 0x0900_0000;
/// VirtIO MMIO base virtual address (PA: 0x0A00_0000)
pub const VIRTIO_MMIO_VA: usize = DEVICE_VIRT_BASE + 0x0A00_0000;
/// GIC Distributor virtual address (PA: 0x0800_0000)
pub const GIC_DIST_VA: usize = DEVICE_VIRT_BASE + 0x0800_0000;
/// GIC CPU Interface virtual address (PA: 0x0801_0000)
pub const GIC_CPU_VA: usize = DEVICE_VIRT_BASE + 0x0801_0000;
/// GIC Redistributor virtual address (PA: 0x080A_0000)
pub const GIC_REDIST_VA: usize = DEVICE_VIRT_BASE + 0x080A_0000;

// TEAM_114: PCI ECAM (Enhanced Configuration Access Mechanism) for VirtIO PCI
/// PCI ECAM base physical address (QEMU virt machine Highmem PCIe)
/// From DTB: reg = <0x40 0x10000000 0x00 0x10000000> = PA 0x4010000000, size 256MB
pub const ECAM_PA: usize = 0x40_1000_0000;
/// PCI ECAM virtual address (high half mapping)
/// Note: This creates a VA in the upper 48-bit space
pub const ECAM_VA: usize = KERNEL_VIRT_START + ECAM_PA;
/// ECAM size: 256MB for 256 buses (1MB per bus)
pub const ECAM_SIZE: usize = 256 * 1024 * 1024;

// TEAM_114: PCI 32-bit memory region for BAR allocation (from QEMU virt DTB)
/// PCI 32-bit MMIO base physical address
pub const PCI_MEM32_PA: usize = 0x1000_0000;
/// PCI 32-bit MMIO size
pub const PCI_MEM32_SIZE: usize = 0x2EFF_0000;
/// PCI 32-bit MMIO virtual address
pub const PCI_MEM32_VA: usize = KERNEL_VIRT_START + PCI_MEM32_PA;

// TEAM_019: 2MB block mapping constants
/// 2MB block size (for L2 block mappings)
pub const BLOCK_2MB_SIZE: usize = 2 * 1024 * 1024;
/// 2MB block alignment mask
pub const BLOCK_2MB_MASK: usize = BLOCK_2MB_SIZE - 1;
/// 1GB block size (for L1 block mappings, future use)
pub const BLOCK_1GB_SIZE: usize = 1024 * 1024 * 1024;

// MAIR_EL1 configuration (from Theseus)
// Attr0: Normal memory (WriteBack, Non-Transient, ReadWriteAlloc)
// Attr1: Device memory (nGnRE)

/// [M19] Converts high VA to PA, [M21] identity for low addresses
#[inline]
pub fn virt_to_phys(va: usize) -> usize {
    #[cfg(not(target_arch = "aarch64"))]
    {
        va
    }
    #[cfg(target_arch = "aarch64")]
    if va >= KERNEL_VIRT_START {
        va - KERNEL_VIRT_START // [M19] high VA to PA
    } else {
        va // [M21] identity for low addresses
    }
}

/// [M20] Converts PA to high VA
/// TEAM_078: Now maps ALL physical addresses to high VA (including devices)
/// This ensures devices are accessible via TTBR1 regardless of TTBR0 state.
#[inline]
pub fn phys_to_virt(pa: usize) -> usize {
    #[cfg(not(target_arch = "aarch64"))]
    {
        pa
    }
    #[cfg(target_arch = "aarch64")]
    {
        pa + KERNEL_VIRT_START // [M20] All PA to high VA
    }
}
