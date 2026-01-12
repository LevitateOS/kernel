//! TEAM_422: Auxiliary Vector Types and Constants
//!
//! Defines the auxiliary vector (auxv) entries passed to user processes
//! during exec. These are part of the Linux ABI.
//!
//! TEAM_464: AT_* constants match linux-raw-sys values exactly (verified from
//! linux-raw-sys 0.12.1 src/x86_64/auxvec.rs and src/aarch64/auxvec.rs).
//! These are Linux ABI constants that don't change.

// TEAM_464: AT_* auxiliary vector type constants (Linux ABI)
// Values are identical across architectures and match linux-raw-sys::auxvec
// (linux-raw-sys::auxvec not available for bare-metal kernel targets, so we
// define these locally with values verified from linux-raw-sys 0.12.1 source)
pub const AT_NULL: u32 = 0;
pub const AT_PHDR: u32 = 3;
pub const AT_PHENT: u32 = 4;
pub const AT_PHNUM: u32 = 5;
pub const AT_PAGESZ: u32 = 6;
pub const AT_BASE: u32 = 7;
pub const AT_ENTRY: u32 = 9;
pub const AT_HWCAP: u32 = 16;
pub const AT_RANDOM: u32 = 25;

/// TEAM_217: Auxiliary Vector entry type.
/// TEAM_464: Uses u64 for both fields to match the Linux ABI (unsigned long on 64-bit).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuxEntry {
    pub a_type: u64,
    pub a_val: u64,
}
