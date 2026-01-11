//! TEAM_146: Kernel Entry Point
//!
//! This is the minimal kernel entry point. The actual work is split into:
//! - `boot.rs` - Architecture-specific boot code (rarely changes)
//! - `init.rs` - Device discovery and initialization (changes often)
//!
//! This separation improves upgradability by isolating stable boot code
//! from frequently-modified initialization logic.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::panic::PanicInfo;
use los_hal::println;

#[cfg(feature = "verbose")]
#[macro_export]
macro_rules! verbose {
    ($($arg:tt)*) => { los_hal::println!($($arg)*) };
}

#[cfg(not(feature = "verbose"))]
#[macro_export]
macro_rules! verbose {
    ($($arg:tt)*) => {};
}

// TEAM_422: External kernel subsystem crates
#[cfg(target_arch = "aarch64")]
pub use los_arch_aarch64 as arch;
#[cfg(target_arch = "x86_64")]
pub use los_arch_x86_64 as arch;

pub use los_sched as task;
pub use los_syscall as syscall;

// TEAM_422: Provide syscall_dispatch for arch crates
// This function is called from los_arch_x86_64::syscall and los_arch_aarch64::exceptions
#[unsafe(no_mangle)]
fn syscall_dispatch(frame: &mut crate::arch::SyscallFrame) {
    los_syscall::syscall_dispatch(frame);
}

// TEAM_422: AArch64 exception handlers
#[cfg(target_arch = "aarch64")]
mod aarch64_handlers {
    use crate::arch::SyscallFrame;

    /// Handle user-mode exceptions (page faults, etc.)
    #[unsafe(no_mangle)]
    pub extern "C" fn handle_user_exception(ec: u64, esr: u64, elr: u64, far: u64) -> ! {
        log::error!(
            "User exception: EC={:#x} ESR={:#x} ELR={:#x} FAR={:#x}",
            ec, esr, elr, far
        );
        crate::arch::cpu::halt();
    }

    /// Handle IRQ dispatch
    #[unsafe(no_mangle)]
    pub extern "C" fn handle_irq_dispatch(irq: u32) -> bool {
        // TODO: Implement proper IRQ handling
        log::trace!("IRQ {}", irq);
        false
    }

    /// Check and deliver signals before returning to userspace
    /// TEAM_422: Stub implementation - real signal delivery to be implemented
    #[unsafe(no_mangle)]
    pub extern "C" fn check_and_deliver_signals(_frame: &mut SyscallFrame) {
        // TODO(TEAM_422): Implement proper signal delivery
        // For now, this is a no-op placeholder
    }
}

// Local modules that remain in levitate
pub mod block;
pub mod boot; // TEAM_282: Boot abstraction layer
pub mod fs; // TEAM_422: Filesystem integration module
pub mod gpu;
pub mod init;
pub mod input;
pub mod loader;
pub mod logger;
pub mod memory; // TEAM_422: Memory initialization (wraps los_mm)
pub mod net;
pub mod process; // TEAM_422: Process spawning (spawn_from_elf)
pub mod terminal;
pub mod virtio;

/// TEAM_282: Unified kernel entry point accepting BootInfo.
///
/// This is the target signature for all boot paths. Currently called by
/// the legacy entry points after they parse boot info.
///
/// Note: The caller must call `boot::set_boot_info()` before calling this
/// to make boot info available globally.
pub fn kernel_main_unified(boot_info: &crate::boot::BootInfo) -> ! {
    // TEAM_305: Diagnostic 'R' for Rust Unified Entry (x86_64 only)
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Writing to serial port 0x3f8 is a standard debugging technique
    // in early x86_64 boot and is safe in this context.
    unsafe {
        core::arch::asm!("mov dx, 0x3f8", "mov al, 'R'", "out dx, al", out("ax") _, out("dx") _);
    }

    // TEAM_316: Initialize dynamic PHYS_OFFSET for Limine HHDM (Limine-only now)
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            core::arch::asm!("mov al, 'i'", "out dx, al", out("ax") _, out("dx") _);
        }
        if let Some(offset) = crate::boot::limine::hhdm_offset() {
            los_hal::mmu::set_phys_offset(offset as usize);
        }
    }

    // Stage 1: Early HAL - Console must be first for debug output
    // TEAM_316: Simplified - Limine only, no CR3 switch needed
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            core::arch::asm!("mov al, 'k'", "out dx, al", out("ax") _, out("dx") _);
        }
        los_hal::arch::init();  // TEAM_316: Simple init, Limine handles page tables
    }
    #[cfg(not(target_arch = "x86_64"))]
    los_hal::arch::init();

    crate::init::transition_to(crate::init::BootStage::EarlyHAL);
    los_hal::console::init();

    // TEAM_221: Initialize logger (Info level silences Debug/Trace)
    // TEAM_272: Enable Trace level in verbose builds to satisfy behavior tests
    #[cfg(feature = "verbose")]
    logger::init(log::LevelFilter::Trace);
    #[cfg(not(feature = "verbose"))]
    logger::init(log::LevelFilter::Info);

    // Initialize heap (required for alloc)
    crate::arch::init_heap();

    // Log boot protocol
    log::info!("[BOOT] Protocol: {:?}", boot_info.protocol);
    if !boot_info.memory_map.is_empty() {
        log::info!(
            "[BOOT] Memory: {} regions, {} MB usable",
            boot_info.memory_map.len(),
            boot_info.memory_map.total_usable() / (1024 * 1024)
        );
    }

    // Stage 2: Physical Memory Management
    crate::init::transition_to(crate::init::BootStage::MemoryMMU);

    // TEAM_316: Limine provides complete HHDM mapping, no PMO expansion needed
    crate::memory::init(boot_info);

    // TEAM_299: Initialize x86_64 CPU state (PCR, GS base)
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Initializing CPU-specific registers (GS base, etc.) is required
    // for correct kernel operation and is safe during early boot.
    unsafe {
        crate::arch::cpu::init();
    }

    // TEAM_409: Initialize AArch64 CPU state (PCR, TPIDR_EL1)
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Initializing CPU-specific registers (TPIDR_EL1) is required
    // for correct kernel operation and is safe during early boot.
    unsafe {
        crate::arch::cpu::init_pcr();
    }

    // TEAM_284: Initialize x86_64 syscalls after memory/heap
    #[cfg(target_arch = "x86_64")]
    // SAFETY: Initializing MSRs for syscall handling is a privileged but
    // necessary operation during kernel startup.
    unsafe {
        crate::arch::syscall::init();
    }

    // TEAM_262: Initialize bootstrap task immediately after heap/memory
    // TEAM_316: Use Box to heap-allocate TCB first to avoid stack overflow
    // during struct initialization (TCB is large with many fields)
    let bootstrap_box = alloc::boxed::Box::new(crate::task::TaskControlBlock::new_bootstrap());
    let bootstrap = alloc::sync::Arc::from(bootstrap_box);
    // SAFETY: Setting the initial task is required for the scheduler to function.
    // This is safe as it's the first task being set during boot.
    unsafe {
        crate::task::set_current_task(bootstrap);
    }

    // Hand off to init sequence (never returns)
    crate::init::run()
}

/// TEAM_422: x86_64 Limine entry point.
///
/// Called from boot.S after Limine puts us in long mode.
/// Parses Limine responses to construct BootInfo and calls kernel_main_unified.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main() -> ! {
    // Parse Limine responses to get BootInfo
    // Note: parse() is safe as it only reads from Limine-provided responses
    let boot_info = crate::boot::limine::parse();

    // Set boot info globally for other subsystems
    // SAFETY: Called once during early boot before any other access
    unsafe { crate::boot::set_boot_info(boot_info) };

    // Get reference to the stored boot info
    let boot_info =
        crate::boot::boot_info().expect("x86_64 must have BootInfo initialized from Limine");

    // Transition to unified main
    kernel_main_unified(boot_info)
}

/// TEAM_422: AArch64 entry point.
///
/// Called from los_arch_aarch64's boot.S after basic setup.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub extern "C" fn rust_main() -> ! {
    kmain()
}

/// TEAM_282: AArch64 main initialization.
#[cfg(target_arch = "aarch64")]
fn kmain() -> ! {
    // AArch64 requires DTB parsing to get BootInfo
    crate::arch::init_heap();

    // Parse DTB to get boot info
    let boot_info = if let Some(dtb_phys) = crate::arch::get_dtb_phys() {
        // SAFETY: dtb_phys is provided by the bootloader and is valid
        unsafe { crate::boot::dtb::parse(dtb_phys) }
    } else {
        crate::boot::BootInfo::empty()
    };

    // Set boot info globally for other subsystems
    // SAFETY: Called once during early boot before any other access
    unsafe { crate::boot::set_boot_info(boot_info) };

    // Get reference to the stored boot info
    let boot_info =
        crate::boot::boot_info().expect("AArch64 must have BootInfo initialized from DTB");

    // Transition to unified main
    kernel_main_unified(boot_info)
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("KERNEL PANIC: {}", info);
    crate::arch::cpu::halt();
}

/// TEAM_387: Custom allocation error handler with diagnostic info.
///
/// Reports heap state when allocation fails to help diagnose OOM issues.
#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    // Get heap stats from the allocator
    let (heap_used, heap_free) = {
        let allocator = crate::arch::ALLOCATOR.lock();
        (allocator.used(), allocator.free())
    };
    let heap_total = heap_used + heap_free;
    
    println!("\n[OOM] ALLOCATION FAILED");
    println!("  requested: {} bytes (align {})", layout.size(), layout.align());
    println!("  heap: {}/{} bytes used ({} free)",
        heap_used, heap_total, heap_free);
    
    // Diagnostic hints
    if layout.size() > heap_free {
        println!("  cause: insufficient free memory");
    } else {
        println!("  cause: likely fragmentation (enough free but not contiguous)");
    }
    
    if layout.size() > 1024 * 1024 {
        println!("  hint: large allocation ({}MB) - consider chunking",
            layout.size() / (1024 * 1024));
    }
    
    panic!("out of memory");
}
