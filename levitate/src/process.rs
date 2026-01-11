//! TEAM_422: Process spawning for LevitateOS kernel binary.
//!
//! This module provides the spawn_from_elf function that ties together:
//! - ELF loading (from crate::loader)
//! - User page table creation (from los_mm)
//! - User stack setup (from los_mm)
//! - UserTask creation (from los_sched)

use crate::loader::elf::{Elf, ElfError};
use crate::task::fd_table::SharedFdTable;
use crate::task::user::UserTask;
use los_error::define_kernel_error;
use los_hal::mmu::MmuError;
use los_mm::user::{
    AT_BASE, AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM, AuxEntry, create_user_page_table,
    setup_stack_args, setup_user_stack, setup_user_tls,
};

/// Number of stack pages to allocate (512KB)
const USER_STACK_PAGES: usize = 128;

define_kernel_error! {
    /// TEAM_422: Error type for process spawning.
    pub enum SpawnError(0x03) {
        /// ELF parsing/loading failed
        Elf(ElfError) = 0x01 => "ELF loading failed",
        /// Page table creation failed
        PageTableAlloc = 0x02 => "Page table allocation failed",
        /// Stack setup failed
        Stack(MmuError) = 0x03 => "Stack setup failed",
        /// TLS setup failed
        Tls(MmuError) = 0x04 => "TLS setup failed",
    }
}

/// TEAM_422: Spawn a user process from ELF data.
///
/// This function:
/// 1. Parses the ELF binary
/// 2. Creates user page tables
/// 3. Loads ELF segments into user address space
/// 4. Sets up user stack with argc/argv/envp/auxv
/// 5. Sets up TLS area
/// 6. Returns a UserTask ready for scheduling
///
/// # Arguments
/// * `elf_data` - Raw ELF binary data
/// * `fd_table` - File descriptor table for the new process
///
/// # Returns
/// A `UserTask` on success, or `SpawnError` on failure.
pub fn spawn_from_elf(elf_data: &[u8], fd_table: SharedFdTable) -> Result<UserTask, SpawnError> {
    // 1. Parse ELF
    let elf = Elf::parse(elf_data).map_err(SpawnError::Elf)?;

    // 2. Create user page tables
    let ttbr0_phys = create_user_page_table().ok_or(SpawnError::PageTableAlloc)?;

    // 3. Load ELF segments
    let (entry_point, initial_brk) = elf.load(ttbr0_phys).map_err(SpawnError::Elf)?;

    // 4. Set up user stack
    // SAFETY: ttbr0_phys is a valid page table created above
    let stack_top =
        unsafe { setup_user_stack(ttbr0_phys, USER_STACK_PAGES) }.map_err(SpawnError::Stack)?;

    // 5. Build auxiliary vector for the runtime
    let auxv = [
        AuxEntry {
            a_type: AT_PHDR,
            a_val: elf.program_headers_vaddr(),
        },
        AuxEntry {
            a_type: AT_PHENT,
            a_val: 56, // sizeof(Elf64_Phdr)
        },
        AuxEntry {
            a_type: AT_PHNUM,
            a_val: elf.program_headers_count(),
        },
        AuxEntry {
            a_type: AT_ENTRY,
            a_val: entry_point,
        },
        AuxEntry {
            a_type: AT_BASE,
            a_val: elf.load_base(),
        },
    ];

    // 6. Set up stack arguments (for now, minimal args)
    let args: [&str; 1] = ["init"];
    let envs: [&str; 0] = [];
    let user_sp =
        setup_stack_args(ttbr0_phys, stack_top, &args, &envs, &auxv).map_err(SpawnError::Stack)?;

    // 7. Set up TLS area
    // SAFETY: ttbr0_phys is a valid page table
    let tls_base = unsafe { setup_user_tls(ttbr0_phys) }.map_err(SpawnError::Tls)?;

    // 8. Create UserTask
    let user_task = UserTask::new(
        entry_point,
        user_sp,
        ttbr0_phys,
        initial_brk,
        fd_table,
        tls_base,
    );

    log::info!(
        "[SPAWN] Created process PID={} entry=0x{:x} sp=0x{:x} brk=0x{:x}",
        user_task.pid.0,
        entry_point,
        user_sp,
        initial_brk
    );

    Ok(user_task)
}
