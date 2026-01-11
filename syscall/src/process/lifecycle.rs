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
use los_sched::fd_table::FdTable;

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
fn clone_fd_table_for_child() -> IrqSafeLock<FdTable> {
    let task = los_sched::current_task();
    let flags = los_hal::interrupts::disable();
    let parent_fds = task.fd_table.lock().clone();
    los_hal::interrupts::restore(flags);
    IrqSafeLock::new(parent_fds)
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
            unsafe {
                *(ptr as *mut i32) = exit_code;
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
    let path = crate::copy_user_string(task.ttbr0, path_ptr, path_len, &mut path_buf)?;

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

    type SpawnHook = fn(
        &[u8],
        IrqSafeLock<FdTable>,
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
pub fn sys_exec(path_ptr: usize, path_len: usize) -> SyscallResult {
    let path_len = path_len.min(256);
    let task = los_sched::current_task();

    // TEAM_226: Use safe copy through kernel pointers
    let mut path_buf = [0u8; 256];
    let path = crate::copy_user_string(task.ttbr0, path_ptr, path_len, &mut path_buf)?;

    log::trace!("[SYSCALL] exec('{}')", path);

    // TEAM_422: Use hook to resolve executable from initramfs
    let _elf_data = resolve_initramfs_executable(path)?;

    log::warn!("[SYSCALL] exec is currently a stub");
    Err(ENOSYS)
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
        crate::copy_user_string(task.ttbr0, path_ptr, path_len, &mut path_buf).map_err(|e| {
            log::debug!("[SYSCALL] spawn_args: Invalid path: errno={}", e);
            e
        })?;

    // 3. Validate and read argv entries
    let entry_size = core::mem::size_of::<UserArgvEntry>();
    let argv_size = match argc.checked_mul(entry_size) {
        Some(size) => size,
        None => return Err(EINVAL),
    };
    if argc > 0 && mm_user::validate_user_buffer(task.ttbr0, argv_ptr, argv_size, false).is_err() {
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
            let kernel_ptr = mm_user::user_va_to_kernel_ptr(task.ttbr0, entry_ptr);
            match kernel_ptr {
                Some(p) => *(p as *const UserArgvEntry),
                None => return Err(EFAULT),
            }
        };

        let arg_len = entry.len.min(MAX_ARG_LEN);
        let mut arg_buf = [0u8; MAX_ARG_LEN];
        let arg_str = crate::copy_user_string(task.ttbr0, entry.ptr, arg_len, &mut arg_buf)?;
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

    type SpawnArgsHook = fn(
        &[u8],
        &[&str],
        &[&str],
        IrqSafeLock<FdTable>,
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
pub fn sys_waitpid(pid: i32, status_ptr: usize) -> SyscallResult {
    if pid <= 0 {
        // For now, only support specific PID
        return Err(EINVAL);
    }

    let pid = pid as usize;
    let current = los_sched::current_task();

    // Check if child already exited
    if let Some(exit_code) = los_sched::process_table::try_wait(pid) {
        // TEAM_414: Use helper to write exit status (ignores errors for compat)
        let _ = write_exit_status(current.ttbr0, status_ptr, exit_code);
        los_sched::process_table::reap_zombie(pid);
        return Ok(pid as i64);
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
        let _ = write_exit_status(current.ttbr0, status_ptr, exit_code);
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
