//! TEAM_422: Auxiliary Vector Types and Constants
//!
//! Defines the auxiliary vector (auxv) entries passed to user processes
//! during exec. These are part of the Linux ABI.

/// TEAM_217: Auxiliary Vector entry type.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuxEntry {
    pub a_type: usize,
    pub a_val: usize,
}

// Auxiliary vector type constants (from Linux ABI)
pub const AT_NULL: usize = 0;
pub const AT_PHDR: usize = 3;
pub const AT_PHENT: usize = 4;
pub const AT_PHNUM: usize = 5;
pub const AT_PAGESZ: usize = 6;
pub const AT_BASE: usize = 7;   // TEAM_354: Base address for PIE
pub const AT_ENTRY: usize = 9;  // TEAM_354: Entry point
pub const AT_HWCAP: usize = 16;
pub const AT_RANDOM: usize = 25;
