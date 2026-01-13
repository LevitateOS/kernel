//! TEAM_282: Device Tree Blob → BootInfo Parser
//!
//! Converts DTB (Device Tree Blob) information to the unified BootInfo format.
//! Used for AArch64 boot path from QEMU or real ARM hardware.
//!
//! This is a transitional module - will be unified with Limine once implemented.

use super::{BootInfo, BootProtocol, FirmwareInfo, MemoryKind, MemoryRegion};
use los_hal::aarch64::fdt::{self, Fdt};
use los_hal::mmu::{KERNEL_PHYS_END, KERNEL_PHYS_START};

/// TEAM_282: Parse DTB into BootInfo.
///
/// Extracts memory map and other boot information from Device Tree.
///
/// # Arguments
/// * `dtb_ptr` - Physical address of the DTB
///
/// # Safety
/// The `dtb_ptr` must point to a valid Device Tree Blob.
pub unsafe fn parse(dtb_ptr: usize) -> BootInfo {
    let mut boot_info = BootInfo::empty();
    boot_info.protocol = BootProtocol::DeviceTree;
    boot_info.firmware = FirmwareInfo::DeviceTree { dtb: dtb_ptr };

    // Try to parse the DTB
    // SAFETY: dtb_ptr is provided by the bootloader and is expected to be a valid
    // pointer to a Device Tree Blob in memory.
    let dtb_slice = unsafe { core::slice::from_raw_parts(dtb_ptr as *const u8, 1024 * 1024) };

    if let Ok(fdt_obj) = Fdt::new(dtb_slice) {
        // TEAM_428: Split memory regions around kernel to avoid overwriting boot page tables
        fdt::for_each_memory_region(&fdt_obj, |region| {
            add_memory_region_with_kernel_split(&mut boot_info, region.start, region.end);
        });

        // Try to find initramfs
        if let Ok((start, end)) = fdt::get_initrd_range(dtb_slice) {
            if end > start {
                boot_info.initramfs = Some(MemoryRegion::new(
                    start,
                    end - start,
                    MemoryKind::Bootloader,
                ));
            }
        }
    }

    boot_info
}

/// TEAM_282: Parse DTB from a slice.
///
/// Alternative parser that takes a pre-validated DTB slice.
pub fn parse_from_slice(dtb_slice: &[u8], dtb_phys: usize) -> BootInfo {
    let mut boot_info = BootInfo::empty();
    boot_info.protocol = BootProtocol::DeviceTree;
    boot_info.firmware = FirmwareInfo::DeviceTree { dtb: dtb_phys };

    if let Ok(fdt_obj) = Fdt::new(dtb_slice) {
        // TEAM_428: Split memory regions around kernel to avoid overwriting boot page tables
        fdt::for_each_memory_region(&fdt_obj, |region| {
            add_memory_region_with_kernel_split(&mut boot_info, region.start, region.end);
        });

        // Try to find initramfs
        if let Ok((start, end)) = fdt::get_initrd_range(dtb_slice) {
            if end > start {
                boot_info.initramfs = Some(MemoryRegion::new(
                    start,
                    end - start,
                    MemoryKind::Bootloader,
                ));
            }
        }
    }

    boot_info
}

/// TEAM_428: Add a memory region to boot_info, splitting around the kernel physical region.
///
/// This prevents the page array allocation from overlapping with the kernel and
/// boot page tables, which would cause an L0 translation fault when memory::init()
/// zeros the page array.
fn add_memory_region_with_kernel_split(boot_info: &mut BootInfo, start: usize, end: usize) {
    // Check if this region overlaps with kernel
    if end <= KERNEL_PHYS_START || start >= KERNEL_PHYS_END {
        // No overlap - add as usable
        let _ =
            boot_info
                .memory_map
                .push(MemoryRegion::new(start, end - start, MemoryKind::Usable));
    } else {
        // Region overlaps with kernel - split into parts
        // Part before kernel
        if start < KERNEL_PHYS_START {
            let _ = boot_info.memory_map.push(MemoryRegion::new(
                start,
                KERNEL_PHYS_START - start,
                MemoryKind::Usable,
            ));
        }
        // Kernel region itself (reserved)
        let kernel_start = start.max(KERNEL_PHYS_START);
        let kernel_end = end.min(KERNEL_PHYS_END);
        let _ = boot_info.memory_map.push(MemoryRegion::new(
            kernel_start,
            kernel_end - kernel_start,
            MemoryKind::Kernel,
        ));
        // Part after kernel
        if end > KERNEL_PHYS_END {
            let _ = boot_info.memory_map.push(MemoryRegion::new(
                KERNEL_PHYS_END,
                end - KERNEL_PHYS_END,
                MemoryKind::Usable,
            ));
        }
    }
}
