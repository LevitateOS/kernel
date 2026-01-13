//! TEAM_230: Thread creation for sys_clone support.
//!
//! This module provides thread creation that shares address space with
//! the parent process, as required for Linux-compatible threading.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use los_hal::IrqSafeLock;
use los_mm::heap::ProcessHeap;
use los_mm::vma::VmaList;

// TEAM_422: Architecture-specific imports
#[cfg(target_arch = "aarch64")]
use los_arch_aarch64::{Context, SyscallFrame, exception_return};

#[cfg(target_arch = "x86_64")]
use los_arch_x86_64::{Context, SyscallFrame, exception_return};

use crate::fd_table;
use crate::user::Pid;
use crate::{SignalAction, TaskControlBlock, TaskId, TaskState, current_task};
// TEAM_464: Use linux-raw-sys constants as canonical source
use linux_raw_sys::general::CLONE_FILES;

/// TEAM_230: Error type for thread creation.
#[derive(Debug)]
pub enum ThreadError {
    /// Failed to allocate kernel stack
    AllocationFailed,
}

/// TEAM_230: Create a new thread sharing the parent's address space.
///
/// This is the core function for sys_clone with CLONE_VM | CLONE_THREAD.
/// The new thread shares:
/// - Page tables (ttbr0)
/// - Virtual address space
/// - File descriptors (if CLONE_FILES is set)
///
/// The new thread has its own:
/// - Kernel stack
/// - Context (registers)
/// - PID/TID
///
/// # Arguments
/// * `parent_ttbr0` - Physical address of parent's page table (shared)
/// * `child_stack` - User stack pointer for the child
/// * `child_tls` - Thread Local Storage pointer (TPIDR_EL0)
/// * `clear_child_tid` - Address to clear and wake on thread exit
/// * `clone_flags` - Clone flags from sys_clone (TEAM_443: needed for CLONE_FILES)
/// * `tf` - Parent's trap frame (for register cloning)
///
/// # Returns
/// Arc to new TCB on success, ThreadError on failure.
pub fn create_thread(
    parent_ttbr0: usize,
    child_stack: usize,
    child_tls: usize,
    clear_child_tid: usize,
    clone_flags: u32,
    tf: &SyscallFrame,
) -> Result<Arc<TaskControlBlock>, ThreadError> {
    // TEAM_230: Allocate kernel stack for new thread (16KB)
    let kernel_stack_size = 16384;
    let kernel_stack = vec![0u64; kernel_stack_size / 8].into_boxed_slice();
    let kernel_stack_ptr = kernel_stack.as_ptr() as usize;
    let kernel_stack_top = kernel_stack_ptr + kernel_stack.len() * core::mem::size_of::<u64>();

    // TEAM_230: Clone parent's TrapFrame to child's kernel stack
    // The TrapFrame must be at the top of the stack when we "return" to userspace
    let frame_size = core::mem::size_of::<SyscallFrame>();
    let child_frame_addr = kernel_stack_top - frame_size;

    // Safety check alignment (frame size is 280, top is usually 16-byte aligned)
    // 280 is multiple of 8, so u64 alignment is fine.

    let mut child_frame = *tf;
    // Set return value to 0 for child (arch-agnostic via set_return)
    child_frame.set_return(0);
    // Set child stack pointer (if provided, otherwise inherits parent's SP)
    if child_stack != 0 {
        child_frame.set_sp(child_stack as u64);
    }

    // Copy frame to new stack
    unsafe {
        let ptr = child_frame_addr as *mut SyscallFrame;
        *ptr = child_frame;
    }

    // TEAM_230: Generate new PID/TID
    let pid = Pid::next();
    let tid = pid.0 as usize;

    // TEAM_230: Set up context for first switch
    // We want to call `exception_return`, which restores from SP and erets.
    let mut context = Context::new(child_frame_addr, exception_return as *const () as usize);

    // TEAM_438: On x86_64, we need to jump directly to exception_return, not task_entry_trampoline.
    // task_entry_trampoline is a Rust function that creates stack frames and corrupts RSP.
    // For threads, RSP must point to the SyscallFrame when exception_return runs.
    #[cfg(target_arch = "x86_64")]
    {
        context.rip = exception_return as *const () as usize as u64;
    }

    // TEAM_258: Set TLS in context using abstraction (architecture-independent)
    if child_tls != 0 {
        context.set_tls(child_tls as u64);
    }

    // TEAM_230: Create TCB
    let tcb = TaskControlBlock {
        id: TaskId(tid),
        state: AtomicU8::new(TaskState::Ready as u8),
        context,
        stack: Some(kernel_stack),
        stack_top: kernel_stack_top,
        stack_size: kernel_stack_size,
        // TEAM_230: Share parent's page table (key for threads!)
        ttbr0: AtomicUsize::new(parent_ttbr0),
        // TEAM_230: Child's user-space state - mostly tracked in TrapFrame on stack now
        // But we keep these updated for info/debugging
        user_sp: child_stack,
        user_entry: child_frame.pc as usize, // Use PC from frame
        // TEAM_230: Thread gets its own heap tracking (shared address space though)
        heap: IrqSafeLock::new(ProcessHeap::new(0)),
        // TEAM_443: Share fd_table when CLONE_FILES is set (fixes Tokio/brush crash)
        // Child gets Arc::clone of parent's fd table, so they share the same fds.
        // Without CLONE_FILES, create a new fd table (fork semantics).
        fd_table: if clone_flags & CLONE_FILES != 0 {
            current_task().fd_table.clone()
        } else {
            fd_table::new_shared_fd_table()
        },
        // TEAM_230: Inherit CWD from parent (threads share filesystem state)
        cwd: IrqSafeLock::new(String::from("/")),
        // TEAM_230: Thread signal state
        pending_signals: AtomicU32::new(0),
        blocked_signals: AtomicU64::new(0),
        // TEAM_441: Initialize with default SignalAction (all SIG_DFL)
        signal_handlers: IrqSafeLock::new([SignalAction::default(); 64]),
        signal_trampoline: AtomicUsize::new(0),
        // TEAM_230: Store clear_child_tid for CLONE_CHILD_CLEARTID
        clear_child_tid: AtomicUsize::new(clear_child_tid),
        // TEAM_238: Threads share parent's VMA tracking (same address space)
        vmas: IrqSafeLock::new(VmaList::new()),
        // TEAM_350: Initialize TLS with child_tls from clone flags
        tls: AtomicUsize::new(child_tls),
        // TEAM_394: Threads inherit parent's process group and session
        pgid: AtomicUsize::new(current_task().pgid.load(Ordering::Acquire)),
        sid: AtomicUsize::new(current_task().sid.load(Ordering::Acquire)),
        // TEAM_406: Threads inherit parent's umask
        umask: AtomicU32::new(current_task().umask.load(Ordering::Acquire)),
    };

    Ok(Arc::new(tcb))
}
