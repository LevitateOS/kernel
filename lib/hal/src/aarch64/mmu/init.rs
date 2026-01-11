//! MMU initialization for AArch64.
//!
//! Contains init(), enable_mmu(), disable_mmu(), switch_ttbr0() and static page table pool.

use super::types::PageTable;

// ============================================================================
// MMU Initialization
// ============================================================================

/// Initialize MMU registers (MAIR, TCR). Does NOT enable MMU.
///
/// # TEAM_052: Stubbed Function
/// This function is a no-op because MAIR_EL1 and TCR_EL1 are configured
/// in the assembly bootstrap code (kernel/src/main.rs lines 148-165).
/// The assembly configuration matches the values that were previously defined here
/// (see commit 88c75b0 which removed the constants).
///
/// **Why this exists:** Called from kmain() for compatibility. Could be removed
/// if all initialization is moved to assembly permanently.
#[cfg(target_arch = "aarch64")]
pub fn init() {
    // MMU registers already configured by assembly bootstrap
    // See kernel/src/main.rs:148-165 for MAIR_EL1/TCR_EL1 setup
}

#[cfg(not(target_arch = "aarch64"))]
pub fn init() {
    // Stub for non-aarch64 builds (test builds on host)
}

/// Enable the MMU with both TTBR0 and TTBR1 root physical addresses.
///
/// # Safety
/// - `ttbr0_phys` and `ttbr1_phys` must point to valid page tables.
#[cfg(target_arch = "aarch64")]
pub unsafe fn enable_mmu(ttbr0_phys: usize, ttbr1_phys: usize) {
    // SAFETY: Caller guarantees ttbr0_phys and ttbr1_phys point to valid page tables.
    // The asm! blocks modify system registers - this is the core purpose of this function.
    unsafe {
        // Load TTBR0_EL1 and TTBR1_EL1
        core::arch::asm!(
            "msr ttbr0_el1, {}",
            "msr ttbr1_el1, {}",
            "isb",
            in(reg) ttbr0_phys,
            in(reg) ttbr1_phys,
            options(nostack)
        );

        // Read SCTLR_EL1
        let mut sctlr: u64;
        core::arch::asm!(
            "mrs {}, sctlr_el1",
            out(reg) sctlr,
            options(nostack)
        );

        // Set M bit (enable MMU)
        sctlr |= 1;

        // Write SCTLR_EL1
        core::arch::asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr,
            options(nostack)
        );
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn enable_mmu(_ttbr0_phys: usize, _ttbr1_phys: usize) {
    // Stub for non-aarch64 builds (test builds on host)
}

/// Disable the MMU.
#[cfg(target_arch = "aarch64")]
pub unsafe fn disable_mmu() {
    // SAFETY: Disabling MMU requires identity-mapped code to be executing.
    // Caller must ensure current PC is identity-mapped before calling.
    unsafe {
        let mut sctlr: u64;
        core::arch::asm!(
            "mrs {}, sctlr_el1",
            out(reg) sctlr,
            options(nostack)
        );

        sctlr &= !1; // Clear M bit

        core::arch::asm!(
            "msr sctlr_el1, {}",
            "isb",
            in(reg) sctlr,
            options(nostack)
        );
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn disable_mmu() {
    // Stub for non-aarch64 builds (test builds on host)
}

/// TEAM_073: Switch TTBR0_EL1 to a new user page table.
///
/// This is used during context switch to switch user address spaces.
/// TTBR1 (kernel mappings) is not affected.
///
/// # Safety
/// - `ttbr0_phys` must point to a valid page table
#[cfg(target_arch = "aarch64")]
pub unsafe fn switch_ttbr0(ttbr0_phys: usize) {
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {}",
            "isb",
            "tlbi vmalle1",  // Invalidate all TLB entries (all ASIDs)
            "dsb sy",
            "isb",
            in(reg) ttbr0_phys,
            options(nostack)
        );
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn switch_ttbr0(_ttbr0_phys: usize) {
    // Stub for non-aarch64 builds
}

// ============================================================================
// Static Page Table Pool (for early boot before heap is available)
// ============================================================================

/// Static pool of page tables for early boot.
/// TEAM_019: With 2MB block mappings, we need far fewer tables:
/// - 1 L0 + 1-2 L1 + 1-2 L2 = ~4 tables for blocks
/// - Plus a few L3 tables for unaligned boundaries
/// - 16 tables provides ample safety margin
pub(crate) static mut PT_POOL: [PageTable; 16] = [const { PageTable::new() }; 16];
pub(crate) static mut PT_POOL_NEXT: usize = 0;

/// Allocate a page table from the static pool.
/// Returns None if pool is exhausted.
pub(crate) fn alloc_page_table() -> Option<&'static mut PageTable> {
    // SAFETY: Single-threaded boot context, no concurrent access
    unsafe {
        let pool_ptr = core::ptr::addr_of_mut!(PT_POOL);
        let next_ptr = core::ptr::addr_of_mut!(PT_POOL_NEXT);
        let next = *next_ptr;
        let pool_len = (*pool_ptr).len();

        if next >= pool_len {
            return None;
        }

        let pt = &mut (*pool_ptr)[next];
        *next_ptr = next + 1;
        pt.zero();
        Some(pt)
    }
}
