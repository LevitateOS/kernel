//! Process lifecycle syscalls.
//!
//! TEAM_073: Core process syscalls (exit, getpid, spawn).
//! TEAM_120: Process spawning from initramfs.
//! TEAM_186: Spawn with arguments.
//! TEAM_188: Waitpid implementation.
//! TEAM_414: Helper function extraction.
//! TEAM_417: Extracted from process.rs.

use crate::SyscallResult;
use los_mm::user as mm_user;
// TEAM_420: Direct linux_raw_sys imports, no shims
// TEAM_422: Removed ELOOP, ENOENT - not directly used after hook refactor
use linux_raw_sys::errno::{ECHILD, EFAULT, EINVAL, ENOSYS};
use los_hal::IrqSafeLock;

// ============================================================================
// TEAM_414: Process Syscall Helpers
// ============================================================================

/// TEAM_414: Maximum symlink depth when resolving executables.
#[allow(dead_code)]
const MAX_SYMLINK_DEPTH: usize = 8;

// TEAM_422: Hook types for kernel integration.
// The INITRAMFS and spawn_from_elf functions are implemented in the main kernel
// (levitate) and registered via these hooks at boot time.

use core::sync::atomic::{AtomicPtr, Ordering};

/// TEAM_422: Hook for resolving an executable from initramfs.
/// Function signature: fn(&str) -> Result<Vec<u8>, u32>
/// Set by levitate during init.
pub static RESOLVE_EXECUTABLE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// TEAM_422: Hook for spawning a process from ELF data.
/// Function signature: fn(&[u8], IrqSafeLock<FdTable>) -> Result<los_sched::user::UserTask, los_sched::process::SpawnError>
pub static SPAWN_FROM_ELF_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// TEAM_422: Hook for spawning a process from ELF data with arguments.
/// Function signature: fn(&[u8], &[&str], &[&str], IrqSafeLock<FdTable>) -> Result<los_sched::user::UserTask, los_sched::process::SpawnError>
pub static SPAWN_FROM_ELF_WITH_ARGS_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// TEAM_436: Hook for preparing an exec image (for execve).
/// Function signature: fn(&[u8], &[&str], &[&str]) -> Result<ExecImage, SpawnError>
/// Returns the prepared address space without creating a new task.
pub static PREPARE_EXEC_IMAGE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// TEAM_422: Resolve an executable path from initramfs (via hook).
fn resolve_initramfs_executable(path: &str) -> Result<alloc::vec::Vec<u8>, u32> {
    let hook_ptr = RESOLVE_EXECUTABLE_HOOK.load(Ordering::Acquire);
    if hook_ptr.is_null() {
        // Hook not set - kernel didn't register INITRAMFS resolver
        log::warn!("[PROCESS] resolve_initramfs_executable: hook not set");
        return Err(ENOSYS);
    }

    // SAFETY: We only store valid function pointers via registration during boot
    type ResolveHook = fn(&str) -> Result<alloc::vec::Vec<u8>, u32>;
    let hook: ResolveHook = unsafe { core::mem::transmute(hook_ptr) };
    hook(path)
}

/// TEAM_414: Clone the current task's FD table for a child process.
/// TEAM_443: Updated to return SharedFdTable (Arc<IrqSafeLock<FdTable>>) for CLONE_FILES support.
fn clone_fd_table_for_child() -> los_sched::fd_table::SharedFdTable {
    let task = los_sched::current_task();
    let flags = los_hal::interrupts::disable();
    let parent_fds = task.fd_table.lock().clone();
    los_hal::interrupts::restore(flags);
    alloc::sync::Arc::new(IrqSafeLock::new(parent_fds))
}

/// TEAM_414: Register a newly spawned process and add it to the scheduler.
fn register_spawned_process(new_task: los_sched::user::UserTask) -> i64 {
    let pid = new_task.pid.0 as i64;
    let parent_pid = los_sched::current_task().id.0;
    let child_pid = new_task.pid.0 as usize;
    let tcb: los_sched::TaskControlBlock = new_task.into();
    let task_arc = alloc::sync::Arc::new(tcb);
    los_sched::process_table::register_process(child_pid, parent_pid, task_arc.clone());
    los_sched::scheduler::SCHEDULER.add_task(task_arc);
    pid
}

/// TEAM_414: Write an exit status to a user-space pointer.
///
/// TEAM_446: Fixed to use correct Linux wait status encoding.
/// Linux encodes the status word as follows:
/// - Normal exit: (exit_code & 0xFF) << 8
/// - Killed by signal: signal_number & 0x7F
/// - Core dumped: signal_number | 0x80
///
/// This allows WIFEXITED/WEXITSTATUS macros to work correctly.
fn write_exit_status(ttbr0: usize, status_ptr: usize, exit_code: i32) -> Result<(), u32> {
    if status_ptr == 0 {
        return Ok(());
    }

    if mm_user::validate_user_buffer(ttbr0, status_ptr, 4, true).is_err() {
        return Err(EFAULT);
    }

    match mm_user::user_va_to_kernel_ptr(ttbr0, status_ptr) {
        Some(ptr) => {
            // SAFETY: validate_user_buffer confirmed address is writable
            //
            // TEAM_446: Encode exit status for Linux ABI compatibility.
            // For normal exit: bits 8-15 contain the exit code, bits 0-7 are zero.
            // This makes WIFEXITED(status) return true and WEXITSTATUS(status)
            // return the actual exit code.
            let encoded_status = (exit_code & 0xFF) << 8;
            unsafe {
                *(ptr as *mut i32) = encoded_status;
            }
            Ok(())
        }
        None => Err(EFAULT),
    }
}

// ============================================================================
// Process Lifecycle Syscalls
// ============================================================================

/// TEAM_073: sys_exit - Terminate the process.
pub fn sys_exit(code: i32) -> SyscallResult {
    log::trace!("[SYSCALL] exit({})", code);

    // TEAM_188: Wake waiters before exiting
    let task = los_sched::current_task();
    let pid = task.id.0;
    let waiters = los_sched::process_table::mark_exited(pid, code);
    for waiter in waiters {
        waiter.set_state(los_sched::TaskState::Ready);
        los_sched::scheduler::SCHEDULER.add_task(waiter);
    }

    // TEAM_333: Close all FDs immediately to unblock parents reading pipes
    task.fd_table.lock().close_all();

    los_sched::task_exit();
}

/// TEAM_073: sys_getpid - Get process ID.
pub fn sys_getpid() -> SyscallResult {
    Ok(los_sched::current_task().id.0 as i64)
}

/// TEAM_217: sys_getppid - Get parent process ID.
pub fn sys_getppid() -> SyscallResult {
    let current = los_sched::current_task();
    Ok(los_sched::process_table::PROCESS_TABLE
        .lock()
        .get(&current.id.0)
        .map(|e| e.parent_pid as i64)
        .unwrap_or(0))
}

/// TEAM_129: sys_yield - Voluntarily yield CPU to other tasks.
pub fn sys_yield() -> SyscallResult {
    los_sched::yield_now();
    Ok(0)
}

/// TEAM_350: sys_exit_group - Terminate all threads in the process.
///
/// Unlike sys_exit which only terminates the calling thread, exit_group
/// terminates all threads in the thread group (process).
///
/// For now, LevitateOS doesn't have multi-threaded processes with shared
/// resources, so this behaves the same as sys_exit.
pub fn sys_exit_group(status: i32) -> SyscallResult {
    log::trace!("[SYSCALL] exit_group({})", status);
    // TEAM_350: For now, same as exit since we don't track thread groups
    sys_exit(status)
}

/// TEAM_120: sys_spawn - Spawn a new process from initramfs.
/// TEAM_414: Refactored to use helper functions.
pub fn sys_spawn(path_ptr: usize, path_len: usize) -> SyscallResult {
    let path_len = path_len.min(256);
    let task = los_sched::current_task();

    // Read path from user space
    let mut path_buf = [0u8; 256];
    let path = crate::copy_user_string(task.ttbr0.load(Ordering::Acquire), path_ptr, path_len, &mut path_buf)?;

    log::trace!("[SYSCALL] spawn('{}')", path);

    // TEAM_414: Use helper to resolve executable with symlink following
    let elf_data = resolve_initramfs_executable(path)?;

    // TEAM_414: Use helper to clone FD table
    let new_fd_table = clone_fd_table_for_child();

    // TEAM_422: Use spawn hook instead of direct call
    let hook_ptr = SPAWN_FROM_ELF_HOOK.load(Ordering::Acquire);
    if hook_ptr.is_null() {
        log::warn!("[SYSCALL] spawn: spawn_from_elf hook not set");
        return Err(ENOSYS);
    }

    // TEAM_443: Use SharedFdTable (Arc<IrqSafeLock<FdTable>>) to match actual hook signature
    type SpawnHook = fn(
        &[u8],
        los_sched::fd_table::SharedFdTable,
    ) -> Result<los_sched::user::UserTask, los_sched::process::SpawnError>;
    let hook: SpawnHook = unsafe { core::mem::transmute(hook_ptr) };

    match hook(&elf_data, new_fd_table) {
        Ok(new_task) => Ok(register_spawned_process(new_task)),
        Err(e) => {
            log::debug!("[SYSCALL] spawn failed: {:?}", e);
            Ok(-1)
        }
    }
}

/// TEAM_120: sys_exec - Replace current process with one from initramfs.
/// TEAM_422: Uses hook mechanism for initramfs access.
/// TEAM_436: Now calls sys_execve with empty argv/envp for backwards compatibility.
pub fn sys_exec(path_ptr: usize, path_len: usize) -> SyscallResult {
    let path_len = path_len.min(256);
    let task = los_sched::current_task();

    // TEAM_226: Use safe copy through kernel pointers
    let mut path_buf = [0u8; 256];
    let path = crate::copy_user_string(task.ttbr0.load(Ordering::Acquire), path_ptr, path_len, &mut path_buf)?;

    log::trace!("[SYSCALL] exec('{}')", path);

    // TEAM_436: Delegate to execve_internal with minimal args
    let argv: [&str; 1] = [path];
    let envp: [&str; 0] = [];
    execve_internal(path, &argv, &envp, None)
}

// ============================================================================
// TEAM_436: execve Implementation
// ============================================================================

use crate::SyscallFrame;

/// TEAM_436: ExecImage mirrors the kernel's ExecImage struct.
/// Contains prepared address space for execve.
/// TEAM_455: Added vmas field for fork() support after execve.
pub struct ExecImage {
    pub ttbr0: usize,
    pub entry_point: usize,
    pub stack_pointer: usize,
    pub initial_brk: usize,
    pub tls_base: usize,
    pub vmas: los_mm::vma::VmaList,
}

/// TEAM_436: Maximum number of arguments for execve.
const MAX_EXECVE_ARGC: usize = 64;
/// TEAM_436: Maximum number of environment variables.
const MAX_EXECVE_ENVC: usize = 64;
/// TEAM_436: Maximum length of a single string.
const MAX_EXECVE_STRLEN: usize = 4096;

/// TEAM_436: sys_execve - Replace current process image (Linux ABI).
///
/// # Arguments
/// * `path_ptr` - Pointer to null-terminated path string
/// * `argv_ptr` - Pointer to null-terminated array of string pointers
/// * `envp_ptr` - Pointer to null-terminated array of string pointers (can be NULL)
/// * `frame` - Syscall frame to modify for new entry point
///
/// On success, this function does not return - execution continues at new entry point.
/// On failure, returns negative errno.
pub fn sys_execve(
    path_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
    frame: &mut SyscallFrame,
) -> SyscallResult {
    let task = los_sched::current_task();

    // 1. Read path (null-terminated C string)
    let path = read_user_cstring(task.ttbr0.load(Ordering::Acquire), path_ptr, MAX_EXECVE_STRLEN)?;
    log::trace!("[SYSCALL] execve('{}', argv={:#x}, envp={:#x})", path, argv_ptr, envp_ptr);

    // 2. Read argv array
    let argv_strings = read_user_string_array(task.ttbr0.load(Ordering::Acquire), argv_ptr, MAX_EXECVE_ARGC)?;
    let argv_refs: alloc::vec::Vec<&str> = argv_strings.iter().map(|s| s.as_str()).collect();

    // 3. Read envp array (can be NULL)
    let envp_strings = if envp_ptr != 0 {
        read_user_string_array(task.ttbr0.load(Ordering::Acquire), envp_ptr, MAX_EXECVE_ENVC)?
    } else {
        alloc::vec::Vec::new()
    };
    let envp_refs: alloc::vec::Vec<&str> = envp_strings.iter().map(|s| s.as_str()).collect();

    // 4. Call internal execve with frame
    execve_internal(&path, &argv_refs, &envp_refs, Some(frame))
}

/// TEAM_436: Internal execve implementation.
fn execve_internal(
    path: &str,
    argv: &[&str],
    envp: &[&str],
    frame: Option<&mut SyscallFrame>,
) -> SyscallResult {
    // 1. Resolve executable from initramfs
    let elf_data = resolve_initramfs_executable(path)?;

    // 2. Prepare exec image via hook
    let hook_ptr = PREPARE_EXEC_IMAGE_HOOK.load(Ordering::Acquire);
    if hook_ptr.is_null() {
        log::warn!("[SYSCALL] execve: prepare_exec_image hook not set");
        return Err(ENOSYS);
    }

    // Define the hook type matching the kernel's function signature
    type PrepareExecHook = fn(&[u8], &[&str], &[&str]) -> Result<ExecImage, los_sched::process::SpawnError>;
    let prepare_hook: PrepareExecHook = unsafe { core::mem::transmute(hook_ptr) };

    let exec_image = match prepare_hook(&elf_data, argv, envp) {
        Ok(img) => img,
        Err(e) => {
            log::warn!("[SYSCALL] execve: prepare_exec_image failed: {:?}", e);
            return Err(linux_raw_sys::errno::ENOEXEC);
        }
    };

    // 3. Get current task and apply the new image
    let task = los_sched::current_task();

    // TEAM_468: Close O_CLOEXEC file descriptors (implements POSIX close-on-exec)
    task.fd_table.lock().close_cloexec();

    // TEAM_468: Reset signal handlers to default on exec.
    // Per POSIX: SIG_IGN remains SIG_IGN, all other handlers become SIG_DFL.
    {
        const SIG_IGN: usize = 1;
        let mut handlers = task.signal_handlers.lock();
        for action in handlers.iter_mut() {
            if action.handler != SIG_IGN {
                *action = los_sched::SignalAction::default();
            }
        }
    }

    // 4. Update task state with new address space
    // Note: We can't directly modify task fields since they're behind Arc.
    // Instead, we update the syscall frame to jump to new code.

    // 5. Switch to new address space
    // SAFETY: We're replacing the current process's address space
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // Switch TTBR0 to new page table
        core::arch::asm!(
            "msr ttbr0_el1, {0}",
            "isb",
            "tlbi vmalle1",
            "dsb sy",
            "isb",
            in(reg) exec_image.ttbr0
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Switch CR3 to new page table
        core::arch::asm!("mov cr3, {}", in(reg) exec_image.ttbr0);
    }

    // TEAM_456: Critical fix - update task.ttbr0 so mmap uses the new page table!
    // Without this, find_free_mmap_region scans the OLD (forked) page table.
    task.ttbr0.store(exec_image.ttbr0, Ordering::Release);

    // 6. Update TLS register
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr tpidr_el0, {}", in(reg) exec_image.tls_base);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // TEAM_436: Set FS_BASE MSR directly for TLS
        // IA32_FS_BASE MSR = 0xC0000100
        let addr = exec_image.tls_base as u64;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0100u32,
            in("eax") (addr as u32),
            in("edx") ((addr >> 32) as u32),
            options(nostack, preserves_flags)
        );
    }

    // 7. Update heap state
    task.heap.lock().reset(exec_image.initial_brk);

    // TEAM_455: Update VMAs for fork() support after execve
    *task.vmas.lock() = exec_image.vmas;

    // 8. Set syscall frame to jump to new entry point
    if let Some(f) = frame {
        f.set_pc(exec_image.entry_point as u64);
        f.set_sp(exec_image.stack_pointer as u64);
        // Clear return value register (execve returns to new code, not caller)
        f.set_return(0);

        // TEAM_436: Zero general purpose registers for security (Linux behavior)
        #[cfg(target_arch = "aarch64")]
        {
            for i in 1..31 {
                f.regs[i] = 0;
            }
        }
        #[cfg(target_arch = "x86_64")]
        {
            f.rdi = 0;
            f.rsi = 0;
            f.rdx = 0;
            f.rcx = exec_image.entry_point as u64; // RCX is used for RIP on sysret
            f.r8 = 0;
            f.r9 = 0;
            f.r10 = 0;
            f.r11 = 0;
            // TEAM_456: Zero callee-saved registers too - musl's _start uses RBP
            // without initializing it, causing page faults if garbage remains
            f.rbx = 0;
            f.rbp = 0;
            f.r12 = 0;
            f.r13 = 0;
            f.r14 = 0;
            f.r15 = 0;
        }
    }

    log::trace!(
        "[EXECVE] Success: path='{}' entry=0x{:x} sp=0x{:x}",
        path,
        exec_image.entry_point,
        exec_image.stack_pointer
    );

    // execve never returns on success - the syscall return will jump to new code
    Ok(0)
}

/// TEAM_436: Read a null-terminated C string from user space.
fn read_user_cstring(ttbr0: usize, ptr: usize, max_len: usize) -> Result<alloc::string::String, u32> {
    use alloc::string::String;

    if ptr == 0 {
        return Err(EFAULT);
    }

    let mut result = String::new();
    for i in 0..max_len {
        let byte_ptr = ptr.checked_add(i).ok_or(EFAULT)?;
        let byte = match mm_user::user_va_to_kernel_ptr(ttbr0, byte_ptr) {
            Some(kptr) => unsafe { *(kptr as *const u8) },
            None => return Err(EFAULT),
        };
        if byte == 0 {
            break;
        }
        result.push(byte as char);
    }

    Ok(result)
}

/// TEAM_436: Read a null-terminated array of string pointers from user space.
fn read_user_string_array(
    ttbr0: usize,
    array_ptr: usize,
    max_count: usize,
) -> Result<alloc::vec::Vec<alloc::string::String>, u32> {
    use alloc::vec::Vec;

    if array_ptr == 0 {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    let ptr_size = core::mem::size_of::<usize>();

    for i in 0..max_count {
        let entry_ptr = array_ptr.checked_add(i * ptr_size).ok_or(EFAULT)?;

        // Read the string pointer
        let str_ptr: usize = match mm_user::user_va_to_kernel_ptr(ttbr0, entry_ptr) {
            Some(kptr) => unsafe { *(kptr as *const usize) },
            None => return Err(EFAULT),
        };

        // NULL terminates the array
        if str_ptr == 0 {
            break;
        }

        // Read the string
        let s = read_user_cstring(ttbr0, str_ptr, MAX_EXECVE_STRLEN)?;
        result.push(s);
    }

    Ok(result)
}

// ============================================================================
// TEAM_186: Spawn with Arguments
// ============================================================================

/// TEAM_186: Argv entry from userspace.
#[repr(C)]
#[derive(Copy, Clone)]
struct UserArgvEntry {
    ptr: usize,
    len: usize,
}

/// TEAM_186: Maximum number of arguments
const MAX_ARGC: usize = 16;
/// TEAM_186: Maximum length of a single argument
const MAX_ARG_LEN: usize = 256;

/// TEAM_186: sys_spawn_args - Spawn a new process with arguments.
/// TEAM_414: Refactored to use helper functions.
pub fn sys_spawn_args(
    path_ptr: usize,
    path_len: usize,
    argv_ptr: usize,
    argc: usize,
) -> SyscallResult {
    // 1. Validate argc
    if argc > MAX_ARGC {
        return Err(EINVAL);
    }

    // 2. Validate and read path
    let path_len = path_len.min(256);
    let task = los_sched::current_task();
    let mut path_buf = [0u8; 256];
    let path =
        crate::copy_user_string(task.ttbr0.load(Ordering::Acquire), path_ptr, path_len, &mut path_buf).map_err(|e| {
            log::debug!("[SYSCALL] spawn_args: Invalid path: errno={}", e);
            e
        })?;

    // 3. Validate and read argv entries
    let entry_size = core::mem::size_of::<UserArgvEntry>();
    let argv_size = match argc.checked_mul(entry_size) {
        Some(size) => size,
        None => return Err(EINVAL),
    };
    if argc > 0 && mm_user::validate_user_buffer(task.ttbr0.load(Ordering::Acquire), argv_ptr, argv_size, false).is_err() {
        return Err(EFAULT);
    }

    // 4. Parse each argument
    let mut args: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    for i in 0..argc {
        let offset = match i.checked_mul(entry_size) {
            Some(o) => o,
            None => return Err(EINVAL),
        };
        let entry_ptr = match argv_ptr.checked_add(offset) {
            Some(p) => p,
            None => return Err(EINVAL),
        };
        let entry = unsafe {
            let kernel_ptr = mm_user::user_va_to_kernel_ptr(task.ttbr0.load(Ordering::Acquire), entry_ptr);
            match kernel_ptr {
                Some(p) => *(p as *const UserArgvEntry),
                None => return Err(EFAULT),
            }
        };

        let arg_len = entry.len.min(MAX_ARG_LEN);
        let mut arg_buf = [0u8; MAX_ARG_LEN];
        let arg_str = crate::copy_user_string(task.ttbr0.load(Ordering::Acquire), entry.ptr, arg_len, &mut arg_buf)?;
        args.push(alloc::string::String::from(arg_str));
    }

    log::trace!("[SYSCALL] spawn_args('{}', argc={})", path, argc);
    for (i, arg) in args.iter().enumerate() {
        log::trace!("[SYSCALL]   argv[{}] = '{}'", i, arg);
    }

    // 5. TEAM_414: Use helper to resolve executable with symlink following
    let elf_data = resolve_initramfs_executable(path).map_err(|e| {
        log::debug!("[SYSCALL] spawn_args: resolve failed: errno={}", e);
        e
    })?;

    // 6. Convert args to &str slice
    let arg_refs: alloc::vec::Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    // 7. TEAM_414: Use helper to clone FD table
    let new_fd_table = clone_fd_table_for_child();

    // 8. TEAM_422: Use spawn hook instead of direct call
    let hook_ptr = SPAWN_FROM_ELF_WITH_ARGS_HOOK.load(Ordering::Acquire);
    if hook_ptr.is_null() {
        log::warn!("[SYSCALL] spawn_args: spawn_from_elf_with_args hook not set");
        return Err(ENOSYS);
    }

    // TEAM_443: Use SharedFdTable (Arc<IrqSafeLock<FdTable>>) to match actual hook signature
    type SpawnArgsHook = fn(
        &[u8],
        &[&str],
        &[&str],
        los_sched::fd_table::SharedFdTable,
    )
        -> Result<los_sched::user::UserTask, los_sched::process::SpawnError>;
    let hook: SpawnArgsHook = unsafe { core::mem::transmute(hook_ptr) };

    match hook(&elf_data, &arg_refs, &[], new_fd_table) {
        Ok(new_task) => Ok(register_spawned_process(new_task)),
        Err(e) => {
            log::debug!("[SYSCALL] spawn_args: spawn failed for '{}': {:?}", path, e);
            Ok(-1)
        }
    }
}

// ============================================================================
// TEAM_188: Waitpid
// ============================================================================

/// TEAM_188: sys_waitpid - Wait for a child process to exit.
/// TEAM_414: Refactored to use write_exit_status helper.
/// TEAM_453: Added support for pid=-1 (wait for any child) for BusyBox init.
/// TEAM_454: Fixed to properly block when waiting for any child.
/// TEAM_460: Added options parameter to support WNOHANG for command substitution.
pub fn sys_waitpid(pid: i32, status_ptr: usize, options: u32) -> SyscallResult {
    let current = los_sched::current_task();

    // TEAM_460: WNOHANG flag - return immediately if no child has exited
    const WNOHANG: u32 = 1;
    let nohang = (options & WNOHANG) != 0;

    // TEAM_453: Handle pid=-1 (wait for any child)
    // TEAM_454: Fixed to properly block instead of returning ECHILD
    if pid == -1 {
        // Try to find any exited child
        if let Some((child_pid, exit_code)) = los_sched::process_table::try_wait_any() {
            let _ = write_exit_status(current.ttbr0.load(Ordering::Acquire), status_ptr, exit_code);
            los_sched::process_table::reap_zombie(child_pid);
            return Ok(child_pid as i64);
        }

        // TEAM_460: If WNOHANG and no zombie, return 0 (no child exited yet)
        if nohang {
            return Ok(0);
        }

        // No exited children yet - block and wait
        los_sched::process_table::add_any_child_waiter(current.clone());
        current.set_state(los_sched::TaskState::Blocked);
        los_sched::scheduler::SCHEDULER.schedule();

        // Woken up - try again to find exited child
        if let Some((child_pid, exit_code)) = los_sched::process_table::try_wait_any() {
            let _ = write_exit_status(current.ttbr0.load(Ordering::Acquire), status_ptr, exit_code);
            los_sched::process_table::reap_zombie(child_pid);
            return Ok(child_pid as i64);
        }

        // Still no child? Should not happen, but return ECHILD for safety
        return Err(ECHILD);
    }

    if pid <= 0 {
        // pid=0 means wait for any child in same process group (not supported)
        // pid<-1 means wait for any child in process group |pid| (not supported)
        return Err(EINVAL);
    }

    let pid = pid as usize;

    // Check if child already exited
    if let Some(exit_code) = los_sched::process_table::try_wait(pid) {
        // TEAM_414: Use helper to write exit status (ignores errors for compat)
        let _ = write_exit_status(current.ttbr0.load(Ordering::Acquire), status_ptr, exit_code);
        los_sched::process_table::reap_zombie(pid);
        return Ok(pid as i64);
    }

    // TEAM_460: If WNOHANG and child not exited, return 0
    if nohang {
        return Ok(0);
    }

    // Child still running - block
    if los_sched::process_table::add_waiter(pid, current.clone()).is_err() {
        return Err(ECHILD);
    }

    // Block and schedule
    current.set_state(los_sched::TaskState::Blocked);
    los_sched::scheduler::SCHEDULER.schedule();

    // Woken up - child exited
    if let Some(exit_code) = los_sched::process_table::try_wait(pid) {
        let _ = write_exit_status(current.ttbr0.load(Ordering::Acquire), status_ptr, exit_code);
        los_sched::process_table::reap_zombie(pid);
        return Ok(pid as i64);
    }

    Err(ECHILD)
}

/// TEAM_220: sys_set_foreground - Set the foreground process for shell control.
pub fn sys_set_foreground(pid: usize) -> SyscallResult {
    *los_sched::FOREGROUND_PID.lock() = pid;
    Ok(0)
}

/// TEAM_244: sys_get_foreground - Get the foreground process PID.
pub fn sys_get_foreground() -> SyscallResult {
    Ok(*los_sched::FOREGROUND_PID.lock() as i64)
}
