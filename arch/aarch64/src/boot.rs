use core::arch::global_asm;

global_asm!(include_str!("asm/boot.S"));

// =============================================================================
// TEAM_422: Boot data handling for AArch64
//
// Problem: Boot code runs at physical 0x40080000, but Rust code runs at
// higher-half 0xFFFF_8000... The adrp instruction has ±4GB range, so:
// - Boot assembly CAN'T reach higher-half symbols
// - Higher-half Rust code CAN'T reach physical-address symbols
//
// Solution: Two copies of boot data:
// 1. BOOT_*_PHYS: In .bss.boot at physical address, written by boot assembly
// 2. BOOT_*: Regular statics in higher-half, read by Rust code
//
// copy_boot_data() copies from physical to virtual using the identity mapping.
// =============================================================================

/// Physical-address copy of DTB address (written by boot.S)
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot")]
pub static mut BOOT_DTB_ADDR_PHYS: u64 = 0;

/// Physical-address copy of boot registers (written by boot.S)
#[unsafe(no_mangle)]
#[unsafe(link_section = ".bss.boot")]
pub static mut BOOT_REGS_PHYS: [u64; 4] = [0; 4];

/// Higher-half copy of DTB address (read by Rust code)
static mut BOOT_DTB_ADDR: u64 = 0;

/// Higher-half copy of boot registers (read by Rust code)
static mut BOOT_REGS: [u64; 4] = [0; 4];

/// Flag to track if boot data has been copied
static mut BOOT_DATA_COPIED: bool = false;

/// TEAM_422: Copy boot data from physical-address section to higher-half.
///
/// This must be called early in kernel initialization, after identity mapping
/// is set up but before any code tries to read BOOT_REGS or BOOT_DTB_ADDR.
///
/// # Safety
/// - Must be called exactly once during early boot
/// - Identity mapping for physical kernel region must be active
pub unsafe fn copy_boot_data() {
    // Get physical addresses of the boot data through linker symbols
    unsafe extern "C" {
        static BOOT_DTB_ADDR_PHYS: u64;
        static BOOT_REGS_PHYS: [u64; 4];
    }

    // Read from physical addresses (identity mapped)
    let dtb = core::ptr::read_volatile(core::ptr::addr_of!(BOOT_DTB_ADDR_PHYS));
    let regs = core::ptr::read_volatile(core::ptr::addr_of!(BOOT_REGS_PHYS));

    // Write to higher-half copies
    BOOT_DTB_ADDR = dtb;
    BOOT_REGS = regs;
    BOOT_DATA_COPIED = true;
}

use linked_list_allocator::LockedHeap;
#[global_allocator]
pub static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Initialize the kernel heap from linker-defined symbols.
pub fn init_heap() {
    unsafe extern "C" {
        static __heap_start: u8;
        static __heap_end: u8;
    }

    unsafe {
        let heap_start = &__heap_start as *const u8 as usize;
        let heap_end = &__heap_end as *const u8 as usize;
        let heap_size = heap_end - heap_start;
        ALLOCATOR.lock().init(heap_start as *mut u8, heap_size);
    }
    log::trace!("Heap initialized.");
}

/// Initialize MMU with fine-grained page tables.
pub fn init_mmu() {
    use los_hal::mmu;
    mmu::init();

    let root = unsafe {
        static mut ROOT_PT: mmu::PageTable = mmu::PageTable::new();
        &mut *core::ptr::addr_of_mut!(ROOT_PT)
    };

    let kernel_flags = mmu::PageFlags::KERNEL_DATA.difference(mmu::PageFlags::PXN);

    // Critical boot mappings
    {
        mmu::identity_map_range_optimized(
            root,
            mmu::KERNEL_PHYS_START,
            mmu::KERNEL_PHYS_END,
            kernel_flags,
        )
        .unwrap();
        mmu::map_range(
            root,
            mmu::KERNEL_VIRT_START + mmu::KERNEL_PHYS_START,
            mmu::KERNEL_PHYS_START,
            mmu::KERNEL_PHYS_END - mmu::KERNEL_PHYS_START,
            kernel_flags,
        )
        .unwrap();
        mmu::map_range(
            root,
            mmu::KERNEL_VIRT_START + 0x4000_0000,
            0x4000_0000,
            0x4000_0000,
            kernel_flags,
        )
        .unwrap();
        mmu::map_range(
            root,
            mmu::UART_VA,
            0x0900_0000,
            0x1000,
            mmu::PageFlags::DEVICE,
        )
        .unwrap();
        mmu::map_range(
            root,
            mmu::GIC_DIST_VA,
            0x0800_0000,
            0x20_0000,
            mmu::PageFlags::DEVICE,
        )
        .unwrap();
        mmu::map_range(
            root,
            mmu::VIRTIO_MMIO_VA,
            0x0a00_0000,
            0x10_0000,
            mmu::PageFlags::DEVICE,
        )
        .unwrap();
        mmu::map_range(
            root,
            mmu::ECAM_VA,
            mmu::ECAM_PA,
            0x10_0000,
            mmu::PageFlags::DEVICE,
        )
        .unwrap();
        mmu::map_range(
            root,
            mmu::PCI_MEM32_VA,
            mmu::PCI_MEM32_PA,
            mmu::PCI_MEM32_SIZE,
            mmu::PageFlags::DEVICE,
        )
        .unwrap();
        mmu::identity_map_range_optimized(root, 0x4000_0000, 0x5000_0000, kernel_flags).unwrap();
    }

    mmu::tlb_flush_all();
    let root_phys = mmu::virt_to_phys(root as *const _ as usize);
    unsafe {
        mmu::enable_mmu(root_phys, root_phys);
    }
    log::trace!("MMU re-initialized (Higher-Half + Identity).");
}

pub fn get_dtb_phys() -> Option<usize> {
    let addr = unsafe { BOOT_DTB_ADDR };
    if addr != 0 {
        log::trace!("DTB address from x0: 0x{:x}", addr);
        return Some(addr as usize);
    }
    let scan_start = 0x4000_0000usize;
    let scan_end = 0x4900_0000usize;
    for addr in (scan_start..scan_end).step_by(0x1000) {
        let magic = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if u32::from_be(magic) == 0xd00d_feed {
            log::trace!("Found DTB at 0x{:x}", addr);
            return Some(addr);
        }
    }
    None
}

// TEAM_422: Boot info initialization moved to levitate binary.
// The arch crate only provides primitives; kernel integration is in levitate.

pub fn print_boot_regs() {
    let regs = unsafe { BOOT_REGS };
    log::info!(
        "BOOT_REGS: x0={:x} x1={:x} x2={:x} x3={:x}",
        regs[0], regs[1], regs[2], regs[3]
    );
}
