//! TEAM_422: Memory initialization for LevitateOS kernel binary.
//!
//! This module provides the bridge between boot info and the memory management
//! crate (los_mm). It initializes the physical frame allocator using the
//! memory map from the bootloader.

use crate::boot::{BootInfo, MemoryKind};
use los_hal::allocator::Page;
use los_mm::add_reserved;

/// Maximum number of RAM regions we can track.
const MAX_RAM_REGIONS: usize = 32;

/// Maximum number of reserved regions we can track.
const MAX_RESERVED_REGIONS: usize = 32;

/// TEAM_422: Initialize the physical memory allocator from boot info.
///
/// This function:
/// 1. Parses the memory map from boot info
/// 2. Identifies usable RAM regions and reserved regions
/// 3. Initializes the frame allocator with available memory
pub fn init(boot_info: &BootInfo) {
    // TEAM_316: Find minimum and maximum physical addresses for page array
    let mut phys_min = usize::MAX;
    let mut phys_max = 0usize;

    // Collect RAM and reserved regions
    let mut ram_regions: [Option<(usize, usize)>; MAX_RAM_REGIONS] = [None; MAX_RAM_REGIONS];
    let mut ram_count = 0usize;

    let mut reserved_regions: [Option<(usize, usize)>; MAX_RESERVED_REGIONS] =
        [None; MAX_RESERVED_REGIONS];
    let mut reserved_count = 0usize;

    // Parse memory map
    for region in boot_info.memory_map.iter() {
        let start = region.base;
        let end = region.end();

        match region.kind {
            MemoryKind::Usable => {
                // Track usable RAM
                if ram_count < MAX_RAM_REGIONS {
                    ram_regions[ram_count] = Some((start, end));
                    ram_count += 1;
                }

                // Update physical address bounds
                if start < phys_min {
                    phys_min = start;
                }
                if end > phys_max {
                    phys_max = end;
                }
            }
            MemoryKind::Kernel | MemoryKind::Bootloader | MemoryKind::Reserved => {
                // Track reserved regions to exclude from allocation
                add_reserved(&mut reserved_regions, &mut reserved_count, start, end);
            }
            _ => {
                // Other regions (ACPI, framebuffer, etc.) are also reserved
                add_reserved(&mut reserved_regions, &mut reserved_count, start, end);
            }
        }
    }

    if phys_min == usize::MAX || phys_max == 0 {
        log::error!("[MEM] No usable memory regions found!");
        return;
    }

    // Align to page boundaries
    phys_min &= !0xFFF;
    phys_max = (phys_max + 0xFFF) & !0xFFF;

    // Calculate size of page metadata array
    let total_pages = (phys_max - phys_min) / los_hal::mmu::PAGE_SIZE;
    let page_array_size = total_pages * core::mem::size_of::<Page>();
    let page_array_pages = (page_array_size + 0xFFF) / 0x1000;

    log::info!(
        "[MEM] Physical: 0x{:x} - 0x{:x} ({} pages, {} MB)",
        phys_min,
        phys_max,
        total_pages,
        (phys_max - phys_min) / (1024 * 1024)
    );

    // Find a usable region for the page array
    let mut page_array_base = None;
    for region in ram_regions.iter().flatten() {
        let region_pages = (region.1 - region.0) / 0x1000;
        if region_pages >= page_array_pages {
            page_array_base = Some(region.0);
            break;
        }
    }

    let Some(array_phys) = page_array_base else {
        log::error!("[MEM] Cannot find space for page metadata array");
        return;
    };

    // Reserve the page array region
    let array_end = array_phys + page_array_pages * 0x1000;
    add_reserved(
        &mut reserved_regions,
        &mut reserved_count,
        array_phys,
        array_end,
    );

    // Create page metadata array
    let array_va = los_hal::mmu::phys_to_virt(array_phys);
    // SAFETY: We've found a valid RAM region and reserved it. The array is
    // properly aligned and sized.
    let mem_map: &'static mut [Page] = unsafe {
        // Zero the array first
        core::ptr::write_bytes(array_va as *mut u8, 0, page_array_size);
        core::slice::from_raw_parts_mut(array_va as *mut Page, total_pages)
    };

    // Initialize the allocator
    // SAFETY: mem_map points to valid zeroed memory, phys_min is the correct
    // base, and RAM/reserved regions are properly identified.
    unsafe {
        los_mm::init_allocator(mem_map, phys_min, &ram_regions, &reserved_regions);
    }

    log::info!("[MEM] Frame allocator initialized");
}

// Re-export FRAME_ALLOCATOR for use in other modules
pub use los_mm::FRAME_ALLOCATOR;
