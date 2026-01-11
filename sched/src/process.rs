//! TEAM_073: User process spawning and management.
//!
//! This module provides the high-level interface for creating and
//! running user processes.
//!
//! TEAM_158: Behavior IDs [PROC1]-[PROC4] for traceability.
//!
//! TEAM_422: This module depends on the ELF loader which is in levitate.
//! It is conditionally compiled out of los_sched. The spawn functions
//! are re-exported from levitate::process instead.
//!
//! TODO(TEAM_422): Either:
//! 1. Extract the ELF loader to a separate los_loader crate
//! 2. Keep spawn_from_elf in levitate and remove this file from sched

// TEAM_422: This module is disabled in los_sched. The functionality lives in levitate.
// The code below is kept for reference but won't compile without the ELF loader dependency.

#[cfg(feature = "_spawn_from_elf")]
mod spawn_impl {
    use crate::fd_table::SharedFdTable;
    use crate::user::UserTask;
    use los_hal::mmu::MmuError;
    use los_mm::user as mm_user;

    // Note: These imports would require los_loader crate
    // use los_loader::elf::Elf;
    // use los_loader::elf::ElfError;

    use los_error::define_kernel_error;

    define_kernel_error! {
        /// TEAM_073: Error type for process spawning.
        pub enum SpawnError(0x03) {
            /// ELF parsing/loading failed
            Elf = 0x01 => "ELF loading failed",
            /// Page table creation failed
            PageTable(MmuError) = 0x02 => "Page table creation failed",
            /// Stack setup failed
            Stack(MmuError) = 0x03 => "Stack setup failed",
        }
    }
}

// TEAM_422: Re-export SpawnError stub for compatibility
use los_error::define_kernel_error;
use los_hal::mmu::MmuError;

define_kernel_error! {
    /// TEAM_073: Error type for process spawning.
    /// TEAM_422: Stub version without ELF dependency.
    pub enum SpawnError(0x03) {
        /// ELF parsing/loading failed
        Elf = 0x01 => "ELF loading failed",
        /// Page table creation failed
        PageTable(MmuError) = 0x02 => "Page table creation failed",
        /// Stack setup failed
        Stack(MmuError) = 0x03 => "Stack setup failed",
    }
}
