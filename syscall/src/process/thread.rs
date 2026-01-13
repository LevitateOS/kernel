//! Threading and process cloning syscalls.
//!
//! TEAM_228: Threading syscalls for std support.
//! TEAM_230: sys_clone implementation (threads).
//! TEAM_417: Extracted from process.rs.
//! TEAM_420: Uses linux_raw_sys directly, no shims.
//! TEAM_432: Added fork() support (full address space copy).

use crate::SyscallResult;
use core::sync::atomic::Ordering;
use los_mm::user as mm_user;
// TEAM_420: Direct imports from linux_raw_sys
use linux_raw_sys::errno::ENOMEM;
use linux_raw_sys::general::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_THREAD,
    CLONE_VM,
};

/// TEAM_230: sys_clone - Create a new thread or process.
/// TEAM_432: Now supports both threads (CLONE_VM) and fork (no CLONE_VM).
///
/// # Clone Modes
///
/// **Thread mode** (CLONE_VM | CLONE_THREAD set):
/// - Shares parent's address space
/// - Gets new stack pointer from `stack` parameter
/// - Gets TLS from `tls` parameter if CLONE_SETTLS
///
/// **Fork mode** (CLONE_VM not set):
/// - Gets complete copy of parent's address space
/// - Continues at same user stack (no new stack needed)
/// - Inherits file descriptors, heap, VMAs, cwd
///
/// # Arguments
/// * `flags` - Clone flags (u32 to match linux-raw-sys types)
/// * `stack` - New stack pointer for child (threads only)
/// * `parent_tid` - Address to write parent TID (if CLONE_PARENT_SETTID)
/// * `tls` - TLS pointer for child (if CLONE_SETTLS)
/// * `child_tid` - Address for child TID operations
/// * `tf` - Parent's syscall frame for register cloning
///
/// # Returns
/// Child PID/TID to parent, 0 to child, or negative errno.
pub fn sys_clone(
    flags: u32,
    stack: usize,
    parent_tid: usize,
    tls: usize,
    child_tid: usize,
    tf: &crate::SyscallFrame,
) -> SyscallResult {
    log::trace!(
        "[SYSCALL] clone(flags=0x{:x}, stack=0x{:x}, tls=0x{:x})",
        flags,
        stack,
        tls
    );

    // TEAM_432: Check if this is a thread-style or fork-style clone
    let is_thread = (flags & CLONE_VM != 0) && (flags & CLONE_THREAD != 0);

    if is_thread {
        // TEAM_230: Thread mode - share address space
        clone_thread(flags, stack, parent_tid, tls, child_tid, tf)
    } else {
        // TEAM_432: Fork mode - copy address space
        clone_fork(flags, parent_tid, child_tid, tf)
    }
}

/// TEAM_230: Create a new thread sharing the parent's address space.
fn clone_thread(
    flags: u32,
    stack: usize,
    parent_tid: usize,
    tls: usize,
    child_tid: usize,
    tf: &crate::SyscallFrame,
) -> SyscallResult {
    // TEAM_230: Get parent task info
    let parent = los_sched::current_task();
    // TEAM_456: Use .load() since ttbr0 is now AtomicUsize
    let parent_ttbr0 = parent.ttbr0.load(Ordering::Acquire);

    // TEAM_230: Determine TLS value
    let thread_tls = if flags & CLONE_SETTLS != 0 { tls } else { 0 };

    // TEAM_230: Determine clear_child_tid address
    let clear_tid = if flags & CLONE_CHILD_CLEARTID != 0 {
        child_tid
    } else {
        0
    };

    // TEAM_230: Create the thread
    // TEAM_443: Pass flags so create_thread can share fd_table when CLONE_FILES is set
    let child = match los_sched::thread::create_thread(
        parent_ttbr0,
        stack,
        thread_tls,
        clear_tid,
        flags,
        tf,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[SYSCALL] clone: create_thread failed: {:?}", e);
            return Err(ENOMEM);
        }
    };

    let child_tid_value = child.id.0;

    // TEAM_230: Handle CLONE_PARENT_SETTID - write child TID to parent's address
    if flags & CLONE_PARENT_SETTID != 0 && parent_tid != 0 {
        if let Some(ptr) = mm_user::user_va_to_kernel_ptr(parent_ttbr0, parent_tid) {
            // SAFETY: user_va_to_kernel_ptr verified the address is mapped
            // and belongs to this task's address space.
            unsafe {
                *(ptr as *mut i32) = child_tid_value as i32;
            }
        }
    }

    // TEAM_230: Handle CLONE_CHILD_SETTID - write child TID to child's address
    // Since CLONE_VM means shared address space, we can write it now
    if flags & CLONE_CHILD_SETTID != 0 && child_tid != 0 {
        if let Some(ptr) = mm_user::user_va_to_kernel_ptr(parent_ttbr0, child_tid) {
            // SAFETY: user_va_to_kernel_ptr verified the address is mapped.
            // Address is in shared address space (CLONE_VM).
            unsafe {
                *(ptr as *mut i32) = child_tid_value as i32;
            }
        }
    }

    // TEAM_230: Register in process table (as child of parent)
    let parent_pid = parent.id.0;
    los_sched::process_table::register_process(child_tid_value, parent_pid, child.clone());

    // TEAM_230: Add child to scheduler
    los_sched::scheduler::SCHEDULER.add_task(child);

    log::trace!(
        "[SYSCALL] clone: created thread TID={} for parent PID={}",
        child_tid_value,
        parent_pid
    );

    // TEAM_230: Return child TID to parent
    Ok(child_tid_value as i64)
}

/// TEAM_432: Create a new process by forking (full address space copy).
///
/// This implements fork() semantics:
/// - Child gets a complete copy of parent's address space
/// - Child inherits file descriptors (cloned, not shared)
/// - Child inherits heap, VMAs, working directory
/// - Returns child PID to parent, 0 to child
fn clone_fork(
    flags: u32,
    parent_tid: usize,
    child_tid: usize,
    tf: &crate::SyscallFrame,
) -> SyscallResult {
    log::trace!("[SYSCALL] clone: fork mode (no CLONE_VM)");

    // TEAM_432: Create the forked process
    let child = match los_sched::fork::create_fork(tf) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[SYSCALL] clone: create_fork failed: {:?}", e);
            return Err(ENOMEM);
        }
    };

    let child_pid = child.id.0;
    let parent = los_sched::current_task();
    let parent_pid = parent.id.0;

    // TEAM_432: Handle CLONE_PARENT_SETTID - write child PID to parent's address
    // TEAM_456: Use .load() since ttbr0 is now AtomicUsize
    if flags & CLONE_PARENT_SETTID != 0 && parent_tid != 0 {
        if let Some(ptr) =
            mm_user::user_va_to_kernel_ptr(parent.ttbr0.load(Ordering::Acquire), parent_tid)
        {
            // SAFETY: user_va_to_kernel_ptr verified the address is mapped.
            unsafe {
                *(ptr as *mut i32) = child_pid as i32;
            }
        }
    }

    // TEAM_432: Handle CLONE_CHILD_SETTID for fork - write to CHILD's address space
    // Unlike threads, fork creates a separate address space, so we need to use
    // the child's ttbr0 for this write.
    // TEAM_456: Use .load() since ttbr0 is now AtomicUsize
    if flags & CLONE_CHILD_SETTID != 0 && child_tid != 0 {
        if let Some(ptr) =
            mm_user::user_va_to_kernel_ptr(child.ttbr0.load(Ordering::Acquire), child_tid)
        {
            // SAFETY: user_va_to_kernel_ptr verified the address is mapped
            // in the child's address space.
            unsafe {
                *(ptr as *mut i32) = child_pid as i32;
            }
        }
    }

    // TEAM_432: Register child in process table
    los_sched::process_table::register_process(child_pid, parent_pid, child.clone());

    // TEAM_432: Add child to scheduler
    los_sched::scheduler::SCHEDULER.add_task(child);

    log::trace!(
        "[SYSCALL] clone: forked process PID={} from parent PID={}",
        child_pid,
        parent_pid
    );

    // TEAM_432: Return child PID to parent (child gets 0 via set_return in create_fork)
    Ok(child_pid as i64)
}

/// TEAM_460: sys_fork - Create a new process by forking.
///
/// This is the common implementation for both fork() and vfork() syscalls.
/// True vfork() should share address space until exec, but we use fork
/// semantics (full copy) which is safer and correct, just less efficient.
///
/// # Arguments
/// * `tf` - Parent's syscall frame for register cloning
///
/// # Returns
/// Child PID to parent, 0 to child, or negative errno.
pub fn sys_fork(tf: &crate::SyscallFrame) -> SyscallResult {
    const SIGCHLD: u32 = 17;
    // Fork semantics: no CLONE_VM, just SIGCHLD for child termination signal
    clone_fork(SIGCHLD, 0, 0, tf)
}

/// TEAM_228: sys_set_tid_address - Set pointer to thread ID.
///
/// # Arguments
/// * `tidptr` - Address to store TID, cleared on thread exit
///
/// # Returns
/// Current thread ID.
pub fn sys_set_tid_address(tidptr: usize) -> SyscallResult {
    let task = los_sched::current_task();

    // Store the address for clear-on-exit
    task.clear_child_tid
        .store(tidptr, core::sync::atomic::Ordering::Release);

    // Return current TID
    Ok(task.id.0 as i64)
}
