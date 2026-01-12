//! TEAM_422: User Address Space Layout Constants
//!
//! Defines the memory layout for user processes.

// TEAM_462: Import from central constants module
use los_hal::mmu::PAGE_SIZE;

/// User stack top (grows down from here)
/// Max user address for 48-bit VA with TTBR0
pub const STACK_TOP: usize = 0x0000_7FFF_FFFF_0000;

/// User stack size (2MB for Eyra/Linux compatibility)
/// TEAM_374: Eyra binaries need much larger stack than bare-metal userspace
pub const STACK_SIZE: usize = 2 * 1024 * 1024;

/// End of user address space (bit 47 clear = TTBR0)
pub const USER_SPACE_END: usize = 0x0000_8000_0000_0000;

/// TEAM_408: TLS area base address (below stack)
/// On AArch64, TPIDR_EL0 points to the TLS block
pub const TLS_BASE: usize = 0x0000_7FFF_FFFE_0000;

/// TEAM_408: TLS area size (one page is enough for basic TLS)
/// TEAM_462: Use PAGE_SIZE constant
pub const TLS_SIZE: usize = PAGE_SIZE;
