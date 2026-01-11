//! MMU operations for AArch64.
//!
//! Contains virtual address indexing functions and TLB flush operations.

// ============================================================================
// Virtual Address Indexing
// Behaviors: [M7]-[M10] VA index extraction
// ============================================================================

/// [M7] Extract L0 index from virtual address (bits [47:39])
#[inline]
pub fn va_l0_index(va: usize) -> usize {
    (va >> 39) & 0x1FF // [M7]
}

/// [M8] Extract L1 index from virtual address (bits [38:30])
#[inline]
pub fn va_l1_index(va: usize) -> usize {
    (va >> 30) & 0x1FF // [M8]
}

/// [M9] Extract L2 index from virtual address (bits [29:21])
#[inline]
pub fn va_l2_index(va: usize) -> usize {
    (va >> 21) & 0x1FF // [M9]
}

/// [M10] Extract L3 index from virtual address (bits [20:12])
#[inline]
pub fn va_l3_index(va: usize) -> usize {
    (va >> 12) & 0x1FF // [M10]
}

// ============================================================================
// TLB Flush (from Theseus patterns)
// ============================================================================

/// Flush all TLB entries.
#[cfg(target_arch = "aarch64")]
pub fn tlb_flush_all() {
    use aarch64_cpu::asm::barrier;
    // SAFETY: TLB flush is always safe - it only invalidates cached translations.
    // The system will re-walk page tables on next access.
    // TEAM_132: Migrate barriers to aarch64-cpu, keep tlbi as raw asm (not in crate)
    unsafe {
        core::arch::asm!("tlbi vmalle1", options(nostack));
    }
    barrier::dsb(barrier::SY);
    barrier::isb(barrier::SY);
}

#[cfg(not(target_arch = "aarch64"))]
pub fn tlb_flush_all() {
    // Stub for non-aarch64 builds (test builds on host)
}

/// Flush TLB entry for a specific virtual address.
#[cfg(target_arch = "aarch64")]
pub fn tlb_flush_page(va: usize) {
    use aarch64_cpu::asm::barrier;
    // SAFETY: TLB flush for a single VA is always safe - invalidates one cached translation.
    // TEAM_132: Migrate barriers to aarch64-cpu
    unsafe {
        let value = va >> 12;
        core::arch::asm!("tlbi vae1, {}", in(reg) value, options(nostack));
    }
    barrier::dsb(barrier::SY);
    barrier::isb(barrier::SY);
}

#[cfg(not(target_arch = "aarch64"))]
pub fn tlb_flush_page(_va: usize) {
    // Stub for non-aarch64 builds (test builds on host)
}
