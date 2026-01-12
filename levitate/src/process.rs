//! TEAM_422: Process spawning for LevitateOS kernel binary.
//!
//! This module provides the spawn_from_elf function that ties together:
//! - ELF loading (from crate::loader)
//! - User page table creation (from los_mm)
//! - User stack setup (from los_mm)
//! - UserTask creation (from los_sched)
//!
//! TEAM_436: Added prepare_exec_image for execve support.

use crate::loader::elf::{Elf, ElfError};
use crate::task::fd_table::SharedFdTable;
use crate::task::user::UserTask;
use los_error::define_kernel_error;
use los_hal::mmu::{page_align_down, MmuError, PAGE_SIZE};
use los_mm::user::{
    AT_BASE, AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM, AuxEntry, create_user_page_table,
    setup_stack_args, setup_user_stack, setup_user_tls,
};
use los_mm::vma::{Vma, VmaFlags, VmaList};

/// TEAM_436: Prepared exec image ready to be applied to a task.
/// Contains all state needed to replace a process image.
/// TEAM_455: Added vmas field for fork() support after execve.
pub struct ExecImage {
    /// Physical address of new page table
    pub ttbr0: usize,
    /// Entry point address
    pub entry_point: usize,
    /// Initial stack pointer
    pub stack_pointer: usize,
    /// Initial program break (heap start)
    pub initial_brk: usize,
    /// TLS base address
    pub tls_base: usize,
    /// VMA list for the new address space
    pub vmas: VmaList,
}

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

    // 3. Load ELF segments (returns VMAs for fork support)
    let (entry_point, initial_brk, elf_vmas) = elf.load(ttbr0_phys).map_err(SpawnError::Elf)?;

    // 4. Set up user stack
    // SAFETY: ttbr0_phys is a valid page table created above
    let stack_top =
        unsafe { setup_user_stack(ttbr0_phys, USER_STACK_PAGES) }.map_err(SpawnError::Stack)?;

    // 5. Build auxiliary vector for the runtime
    // TEAM_464: Cast values to u64 to match AuxEntry field types
    // AT_* constants are u32 from linux-raw-sys, cast to u64 for AuxEntry
    let auxv = [
        AuxEntry {
            a_type: AT_PHDR as u64,
            a_val: elf.program_headers_vaddr() as u64,
        },
        AuxEntry {
            a_type: AT_PHENT as u64,
            a_val: 56, // sizeof(Elf64_Phdr)
        },
        AuxEntry {
            a_type: AT_PHNUM as u64,
            a_val: elf.program_headers_count() as u64,
        },
        AuxEntry {
            a_type: AT_ENTRY as u64,
            a_val: entry_point as u64,
        },
        AuxEntry {
            a_type: AT_BASE as u64,
            a_val: elf.load_base() as u64,
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

    // TEAM_455: Build complete VMA list for fork() support
    let mut vmas = elf_vmas;

    // Add stack VMA (stack grows down, so stack_top is the high address)
    let stack_size = USER_STACK_PAGES * PAGE_SIZE;
    let stack_bottom = stack_top - stack_size;
    let _ = vmas.insert(Vma::new(stack_bottom, stack_top, VmaFlags::READ | VmaFlags::WRITE));

    // Add TLS VMA (pages allocated by setup_user_tls at TLS_BASE_ADDR)
    // TLS_BASE_ADDR is 0x100000000000 (from los_mm::user)
    // TEAM_456: Increased from 3 to 8 pages - busybox needs TLS up to 0x100000004000+
    const TLS_PAGES: usize = 8;
    // TEAM_462: Use helper function for page alignment
    let tls_start = page_align_down(tls_base);
    let tls_end = tls_start + TLS_PAGES * PAGE_SIZE;
    let _ = vmas.insert(Vma::new(tls_start, tls_end, VmaFlags::READ | VmaFlags::WRITE));

    // 8. Create UserTask with VMA list
    let user_task = UserTask::new(
        entry_point,
        user_sp,
        ttbr0_phys,
        initial_brk,
        fd_table,
        tls_base,
        vmas,
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

/// TEAM_436: Prepare an exec image from ELF data with arguments.
/// TEAM_455: Now includes VMA list for fork() support after execve.
///
/// This function is used by execve to prepare a new process image
/// without creating a new task. The caller applies the image to
/// the current task.
///
/// # Arguments
/// * `elf_data` - Raw ELF binary data
/// * `argv` - Command line arguments
/// * `envp` - Environment variables
///
/// # Returns
/// An `ExecImage` containing the new address space state.
pub fn prepare_exec_image(
    elf_data: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<ExecImage, SpawnError> {
    // 1. Parse ELF
    let elf = Elf::parse(elf_data).map_err(SpawnError::Elf)?;

    // 2. Create new user page tables
    let ttbr0_phys = create_user_page_table().ok_or(SpawnError::PageTableAlloc)?;

    // 3. Load ELF segments into new address space (returns VMAs for fork support)
    let (entry_point, initial_brk, elf_vmas) = elf.load(ttbr0_phys).map_err(SpawnError::Elf)?;

    // 4. Set up user stack
    // SAFETY: ttbr0_phys is a valid page table created above
    let stack_top =
        unsafe { setup_user_stack(ttbr0_phys, USER_STACK_PAGES) }.map_err(SpawnError::Stack)?;

    // 5. Build auxiliary vector for the runtime
    // TEAM_464: Cast values to u64 to match AuxEntry field types
    // AT_* constants are u32 from linux-raw-sys, cast to u64 for AuxEntry
    let auxv = [
        AuxEntry {
            a_type: AT_PHDR as u64,
            a_val: elf.program_headers_vaddr() as u64,
        },
        AuxEntry {
            a_type: AT_PHENT as u64,
            a_val: 56, // sizeof(Elf64_Phdr)
        },
        AuxEntry {
            a_type: AT_PHNUM as u64,
            a_val: elf.program_headers_count() as u64,
        },
        AuxEntry {
            a_type: AT_ENTRY as u64,
            a_val: entry_point as u64,
        },
        AuxEntry {
            a_type: AT_BASE as u64,
            a_val: elf.load_base() as u64,
        },
    ];

    // 6. Set up stack with argv/envp/auxv
    let stack_pointer =
        setup_stack_args(ttbr0_phys, stack_top, argv, envp, &auxv).map_err(SpawnError::Stack)?;

    // 7. Set up TLS area
    // SAFETY: ttbr0_phys is a valid page table
    let tls_base = unsafe { setup_user_tls(ttbr0_phys) }.map_err(SpawnError::Tls)?;

    // TEAM_455: Build complete VMA list for fork() support
    let mut vmas = elf_vmas;

    // Add stack VMA
    let stack_size = USER_STACK_PAGES * PAGE_SIZE;
    let stack_bottom = stack_top - stack_size;
    let _ = vmas.insert(Vma::new(stack_bottom, stack_top, VmaFlags::READ | VmaFlags::WRITE));

    // Add TLS VMA
    // TEAM_456: Increased from 3 to 8 pages - busybox needs TLS up to 0x100000004000+
    const TLS_PAGES: usize = 8;
    // TEAM_462: Use helper function for page alignment
    let tls_start = page_align_down(tls_base);
    let tls_end = tls_start + TLS_PAGES * PAGE_SIZE;
    let _ = vmas.insert(Vma::new(tls_start, tls_end, VmaFlags::READ | VmaFlags::WRITE));

    log::trace!(
        "[EXEC] Prepared image: entry=0x{:x} sp=0x{:x} brk=0x{:x} tls=0x{:x}",
        entry_point,
        stack_pointer,
        initial_brk,
        tls_base
    );

    Ok(ExecImage {
        ttbr0: ttbr0_phys,
        entry_point,
        stack_pointer,
        initial_brk,
        tls_base,
        vmas,
    })
}
