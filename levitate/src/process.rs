//! TEAM_422: Process spawning for LevitateOS kernel binary.
//!
//! This module provides the spawn_from_elf function that ties together:
//! - ELF loading (from crate::loader)
//! - User page table creation (from los_mm)
//! - User stack setup (from los_mm)
//! - UserTask creation (from los_sched)
//!
//! TEAM_436: Added prepare_exec_image for execve support.
//! TEAM_470: Added PT_INTERP support for dynamic linking.

use alloc::vec::Vec;
use crate::loader::elf::{Elf, ElfError};
use crate::task::fd_table::SharedFdTable;
use crate::task::user::UserTask;
use los_error::define_kernel_error;
use los_hal::mmu::{MmuError, PAGE_SIZE, page_align_down};
use los_mm::user::{
    AT_BASE, AT_ENTRY, AT_PHDR, AT_PHENT, AT_PHNUM, AuxEntry, create_user_page_table,
    setup_stack_args, setup_user_stack, setup_user_tls,
};
use los_mm::vma::{Vma, VmaFlags, VmaList};

/// TEAM_470: Base address for loading the dynamic linker.
/// High address to avoid conflicts with the main program.
const INTERP_BASE: usize = 0x7f00_0000_0000;

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
        /// TEAM_470: Interpreter not found
        InterpreterNotFound = 0x05 => "Interpreter not found",
        /// TEAM_470: Interpreter is itself dynamic (must be static)
        InterpreterDynamic = 0x06 => "Interpreter is itself dynamic",
    }
}

/// TEAM_470: Resolve interpreter path from initramfs.
/// Returns the interpreter's ELF data.
fn resolve_interpreter(path: &str) -> Result<Vec<u8>, SpawnError> {
    use los_utils::cpio::CpioEntryType;

    let archive_lock = crate::fs::INITRAMFS.lock();
    let Some(sb) = archive_lock.as_ref() else {
        return Err(SpawnError::InterpreterNotFound);
    };

    // Strip leading slashes for initramfs lookup
    let path = path.trim_start_matches('/');

    // Find the interpreter in initramfs
    let entry = sb
        .archive
        .iter()
        .find(|e| e.name == path)
        .ok_or(SpawnError::InterpreterNotFound)?;

    // Follow symlinks if needed (simple single-level resolution)
    if entry.entry_type == CpioEntryType::Symlink {
        let target = core::str::from_utf8(entry.data)
            .map_err(|_| SpawnError::InterpreterNotFound)?;
        let target = target.trim_start_matches('/');

        let target_entry = sb
            .archive
            .iter()
            .find(|e| e.name == target)
            .ok_or(SpawnError::InterpreterNotFound)?;

        return Ok(target_entry.data.to_vec());
    }

    Ok(entry.data.to_vec())
}

/// TEAM_422: Spawn a user process from ELF data.
/// TEAM_470: Added PT_INTERP support for dynamic linking.
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

    // TEAM_470: Check for dynamic linking (PT_INTERP)
    let (entry_point, initial_brk, mut vmas, auxv) = if let Some(interp_path) = elf.find_interp() {
        // === DYNAMIC BINARY ===
        log::info!("[SPAWN] Dynamic binary, interpreter: {}", interp_path);

        // Load interpreter from initramfs
        let interp_data = resolve_interpreter(interp_path)?;
        let interp_elf = Elf::parse(&interp_data).map_err(SpawnError::Elf)?;

        // Verify interpreter is NOT itself dynamic (must be static)
        if interp_elf.find_interp().is_some() {
            log::error!("[SPAWN] Interpreter {} is itself dynamic!", interp_path);
            return Err(SpawnError::InterpreterDynamic);
        }

        // Load main program at its normal address
        let (main_entry, main_brk, main_vmas) = elf.load(ttbr0_phys).map_err(SpawnError::Elf)?;

        // Load interpreter at high fixed base
        let (interp_entry, _, interp_vmas) = interp_elf
            .load_at(ttbr0_phys, INTERP_BASE)
            .map_err(SpawnError::Elf)?;

        // Merge VMAs
        let mut all_vmas = main_vmas;
        for vma in interp_vmas.iter() {
            let _ = all_vmas.insert(vma.clone());
        }

        // Build auxv for dynamic linking
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
                a_val: main_entry as u64, // Main program's entry!
            },
            AuxEntry {
                a_type: AT_BASE as u64,
                a_val: INTERP_BASE as u64, // Interpreter's base!
            },
        ];

        log::info!(
            "[SPAWN] Dynamic: interp_entry=0x{:x} main_entry=0x{:x} AT_BASE=0x{:x}",
            interp_entry,
            main_entry,
            INTERP_BASE
        );

        (interp_entry, main_brk, all_vmas, auxv)
    } else {
        // === STATIC BINARY (unchanged behavior) ===
        let (entry_point, initial_brk, elf_vmas) = elf.load(ttbr0_phys).map_err(SpawnError::Elf)?;

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

        (entry_point, initial_brk, elf_vmas, auxv)
    };

    // 4. Set up user stack
    // SAFETY: ttbr0_phys is a valid page table created above
    let stack_top =
        unsafe { setup_user_stack(ttbr0_phys, USER_STACK_PAGES) }.map_err(SpawnError::Stack)?;

    // 5. Set up stack arguments (for now, minimal args)
    let args: [&str; 1] = ["init"];
    let envs: [&str; 0] = [];
    let user_sp =
        setup_stack_args(ttbr0_phys, stack_top, &args, &envs, &auxv).map_err(SpawnError::Stack)?;

    // 6. Set up TLS area
    // SAFETY: ttbr0_phys is a valid page table
    let tls_base = unsafe { setup_user_tls(ttbr0_phys) }.map_err(SpawnError::Tls)?;

    // Add stack VMA (stack grows down, so stack_top is the high address)
    let stack_size = USER_STACK_PAGES * PAGE_SIZE;
    let stack_bottom = stack_top - stack_size;
    let _ = vmas.insert(Vma::new(
        stack_bottom,
        stack_top,
        VmaFlags::READ | VmaFlags::WRITE,
    ));

    // Add TLS VMA (pages allocated by setup_user_tls at TLS_BASE_ADDR)
    // TLS_BASE_ADDR is 0x100000000000 (from los_mm::user)
    // TEAM_456: Increased from 3 to 8 pages - busybox needs TLS up to 0x100000004000+
    const TLS_PAGES: usize = 8;
    // TEAM_462: Use helper function for page alignment
    let tls_start = page_align_down(tls_base);
    let tls_end = tls_start + TLS_PAGES * PAGE_SIZE;
    let _ = vmas.insert(Vma::new(
        tls_start,
        tls_end,
        VmaFlags::READ | VmaFlags::WRITE,
    ));

    // 7. Create UserTask with VMA list
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
/// TEAM_470: Added PT_INTERP support for dynamic linking.
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

    // TEAM_470: Check for dynamic linking (PT_INTERP)
    let (entry_point, initial_brk, mut vmas, auxv) = if let Some(interp_path) = elf.find_interp() {
        // === DYNAMIC BINARY ===
        log::info!("[EXEC] Dynamic binary, interpreter: {}", interp_path);

        // Load interpreter from initramfs
        let interp_data = resolve_interpreter(interp_path)?;
        let interp_elf = Elf::parse(&interp_data).map_err(SpawnError::Elf)?;

        // Verify interpreter is NOT itself dynamic (must be static)
        if interp_elf.find_interp().is_some() {
            log::error!("[EXEC] Interpreter {} is itself dynamic!", interp_path);
            return Err(SpawnError::InterpreterDynamic);
        }

        // Load main program at its normal address
        let (main_entry, main_brk, main_vmas) = elf.load(ttbr0_phys).map_err(SpawnError::Elf)?;

        // Load interpreter at high fixed base
        let (interp_entry, _, interp_vmas) = interp_elf
            .load_at(ttbr0_phys, INTERP_BASE)
            .map_err(SpawnError::Elf)?;

        // Merge VMAs
        let mut all_vmas = main_vmas;
        for vma in interp_vmas.iter() {
            let _ = all_vmas.insert(vma.clone());
        }

        // Build auxv for dynamic linking
        // AT_PHDR/AT_PHNUM/AT_PHENT: main program's headers (interpreter reads these)
        // AT_ENTRY: main program's entry point (interpreter jumps here after setup)
        // AT_BASE: interpreter's load base (so interpreter knows where it is)
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
                a_val: main_entry as u64, // Main program's entry!
            },
            AuxEntry {
                a_type: AT_BASE as u64,
                a_val: INTERP_BASE as u64, // Interpreter's base!
            },
        ];

        log::info!(
            "[EXEC] Dynamic: interp_entry=0x{:x} main_entry=0x{:x} AT_BASE=0x{:x}",
            interp_entry,
            main_entry,
            INTERP_BASE
        );

        // Entry point is interpreter's entry, not main program's
        (interp_entry, main_brk, all_vmas, auxv)
    } else {
        // === STATIC BINARY (unchanged behavior) ===
        let (entry_point, initial_brk, elf_vmas) = elf.load(ttbr0_phys).map_err(SpawnError::Elf)?;

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

        (entry_point, initial_brk, elf_vmas, auxv)
    };

    // 4. Set up user stack
    // SAFETY: ttbr0_phys is a valid page table created above
    let stack_top =
        unsafe { setup_user_stack(ttbr0_phys, USER_STACK_PAGES) }.map_err(SpawnError::Stack)?;

    // 5. Set up stack with argv/envp/auxv
    let stack_pointer =
        setup_stack_args(ttbr0_phys, stack_top, argv, envp, &auxv).map_err(SpawnError::Stack)?;

    // 6. Set up TLS area
    // SAFETY: ttbr0_phys is a valid page table
    let tls_base = unsafe { setup_user_tls(ttbr0_phys) }.map_err(SpawnError::Tls)?;

    // Add stack VMA
    let stack_size = USER_STACK_PAGES * PAGE_SIZE;
    let stack_bottom = stack_top - stack_size;
    let _ = vmas.insert(Vma::new(
        stack_bottom,
        stack_top,
        VmaFlags::READ | VmaFlags::WRITE,
    ));

    // Add TLS VMA
    // TEAM_456: Increased from 3 to 8 pages - busybox needs TLS up to 0x100000004000+
    const TLS_PAGES: usize = 8;
    // TEAM_462: Use helper function for page alignment
    let tls_start = page_align_down(tls_base);
    let tls_end = tls_start + TLS_PAGES * PAGE_SIZE;
    let _ = vmas.insert(Vma::new(
        tls_start,
        tls_end,
        VmaFlags::READ | VmaFlags::WRITE,
    ));

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
