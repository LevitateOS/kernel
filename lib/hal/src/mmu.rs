// TEAM_260: Generic MMU delegation.
// Provides arch-agnostic access to MMU functions where possible.

#[cfg(target_arch = "x86_64")]
pub use crate::arch::mem::mmu::*;
#[cfg(target_arch = "aarch64")]
pub use crate::arch::mmu::*;
pub use crate::traits::PageAllocator;
