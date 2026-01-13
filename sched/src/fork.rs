//! TEAM_432: Process forking for fork() syscall support.
//!
//! This module provides process forking that creates a full copy of the
//! parent's address space, as required for fork() semantics.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use los_hal::IrqSafeLock;

// TEAM_432: Architecture-specific imports
#[cfg(target_arch = "aarch64")]
use los_arch_aarch64::{Context, SyscallFrame, exception_return};

#[cfg(target_arch = "x86_64")]
use los_arch_x86_64::{Context, SyscallFrame, exception_return};

use crate::user::Pid;
use crate::{TaskControlBlock, TaskId, TaskState, current_task};

/// TEAM_432: Error type for fork creation.
#[derive(Debug)]
pub enum ForkError {
    /// Failed to allocate memory (kernel stack or page table)
    AllocationFailed,
    /// Failed to copy address space
    AddressSpaceCopyFailed,
}

/// TEAM_432: Create a new process by forking the current one.
///
/// This is the core function for fork()/clone() without CLONE_VM.
/// The new process has:
/// - A complete copy of the parent's address space (all mapped pages)
/// - Cloned file descriptor table
/// - Cloned heap state
/// - Cloned VMA list
/// - Same user stack pointer (continues execution at same point)
///
/// The new process has its own:
/// - Kernel stack
/// - Context (registers, with return value set to 0)
/// - PID
/// - Page tables (copy of parent's, but separate physical pages)
///
/// # Arguments
/// * `tf` - Parent's syscall frame (for register cloning)
///
/// # Returns
/// Arc to new TCB on success, ForkError on failure.
pub fn create_fork(tf: &SyscallFrame) -> Result<Arc<TaskControlBlock>, ForkError> {
    let parent = current_task();

    log::trace!("[FORK] Creating fork of PID={}", parent.id.0);

    // TEAM_454: Debug - log parent frame values to diagnose fork issues
    #[cfg(target_arch = "x86_64")]
    log::trace!(
        "[FORK] Parent frame: rcx=0x{:x}, rsp=0x{:x}, rax=0x{:x}",
        tf.rcx,
        tf.rsp,
        tf.rax
    );
    #[cfg(target_arch = "aarch64")]
    log::trace!("[FORK] Parent frame: pc=0x{:x}, sp=0x{:x}", tf.pc, tf.sp);

    // 1. Clone VMA list from parent (needed for address space copy)
    let parent_vmas = (*parent.vmas.lock()).clone();

    // 2. Copy the entire address space (creates new page table with copied pages)
    // TEAM_456: Use .load() since ttbr0 is now AtomicUsize
    let child_ttbr0 =
        los_mm::user::copy_user_address_space(parent.ttbr0.load(Ordering::Acquire), &parent_vmas)
            .ok_or(ForkError::AddressSpaceCopyFailed)?;

    log::trace!(
        "[FORK] Copied address space, child_ttbr0=0x{:x}",
        child_ttbr0
    );

    // 3. Allocate kernel stack for the child (16KB, same as threads)
    let kernel_stack_size = 16384;
    let kernel_stack = vec![0u64; kernel_stack_size / 8].into_boxed_slice();
    let kernel_stack_ptr = kernel_stack.as_ptr() as usize;
    let kernel_stack_top = kernel_stack_ptr + kernel_stack.len() * core::mem::size_of::<u64>();

    // 4. Clone parent's SyscallFrame to child's kernel stack
    // The frame must be at the top of the stack for exception_return
    let frame_size = core::mem::size_of::<SyscallFrame>();
    let child_frame_addr = kernel_stack_top - frame_size;

    let mut child_frame = *tf;
    // Set return value to 0 for child (fork returns 0 to child)
    child_frame.set_return(0);
    // Child keeps same SP as parent (unlike threads which get a new stack)

    // Copy frame to child's kernel stack
    // SAFETY: child_frame_addr is within the just-allocated kernel stack
    unsafe {
        let ptr = child_frame_addr as *mut SyscallFrame;
        *ptr = child_frame;
    }

    // TEAM_454: Debug - verify child frame was written correctly
    #[cfg(target_arch = "x86_64")]
    log::trace!(
        "[FORK] Child frame at 0x{:x}: rcx=0x{:x}, rsp=0x{:x}",
        child_frame_addr,
        child_frame.rcx,
        child_frame.rsp
    );
    #[cfg(target_arch = "aarch64")]
    log::trace!(
        "[FORK] Child frame at 0x{:x}: pc=0x{:x}, sp=0x{:x}",
        child_frame_addr,
        child_frame.pc,
        child_frame.sp
    );
    // TEAM_454: Read back the frame to verify it was written correctly
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ptr = child_frame_addr as *const SyscallFrame;
        let readback = &*ptr;
        log::trace!(
            "[FORK] Frame readback: rcx=0x{:x}, rsp=0x{:x}, rax=0x{:x}",
            readback.rcx,
            readback.rsp,
            readback.rax
        );
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let ptr = child_frame_addr as *const SyscallFrame;
        let readback = &*ptr;
        log::trace!(
            "[FORK] Frame readback: pc=0x{:x}, sp=0x{:x}",
            readback.pc,
            readback.sp
        );
    }

    // 5. Generate new PID for child
    let pid = Pid::next();
    let tid = pid.0 as usize;

    log::trace!("[FORK] Child PID={}", tid);

    // 6. Set up context for first switch
    // We want exception_return to restore from the SyscallFrame we just set up
    let mut context = Context::new(child_frame_addr, exception_return as *const () as usize);

    // TEAM_454: Debug - verify Context.sp is set correctly
    #[cfg(target_arch = "x86_64")]
    log::trace!(
        "[FORK] Context setup: rsp=0x{:x}, rip=0x{:x}, rbx=0x{:x}",
        context.rsp,
        context.rip,
        context.rbx
    );
    #[cfg(target_arch = "aarch64")]
    log::trace!(
        "[FORK] Context setup: sp=0x{:x}, lr=0x{:x}",
        context.sp,
        context.lr
    );

    // Copy TLS from parent (child inherits TLS pointer)
    let parent_tls = parent.tls.load(Ordering::Acquire);
    if parent_tls != 0 {
        context.set_tls(parent_tls as u64);
    }

    // 7. Clone other parent state
    let child_heap = (*parent.heap.lock()).clone();
    let child_fds = (*parent.fd_table.lock()).clone();
    let child_cwd = (*parent.cwd.lock()).clone();
    let child_signal_handlers = (*parent.signal_handlers.lock()).clone();
    let parent_pgid = parent.pgid.load(Ordering::Acquire);
    let parent_sid = parent.sid.load(Ordering::Acquire);
    let parent_umask = parent.umask.load(Ordering::Acquire);
    let parent_trampoline = parent.signal_trampoline.load(Ordering::Acquire);

    // 8. Create the child TCB with cloned state
    let tcb = TaskControlBlock {
        id: TaskId(tid),
        state: AtomicU8::new(TaskState::Ready as u8),
        context,
        stack: Some(kernel_stack),
        stack_top: kernel_stack_top,
        stack_size: kernel_stack_size,
        // TEAM_432: Child gets its OWN page table (copy of parent's)
        // TEAM_456: Use AtomicUsize for ttbr0 to allow execve to update it
        ttbr0: AtomicUsize::new(child_ttbr0),
        // User state - child continues at same point as parent
        user_sp: tf.sp as usize,
        user_entry: tf.pc as usize,
        // TEAM_432: Clone parent's heap state
        heap: IrqSafeLock::new(child_heap),
        // TEAM_432: Clone parent's file descriptor table
        // TEAM_443: Fork creates a NEW fd table (not shared), wrapped in Arc
        fd_table: Arc::new(IrqSafeLock::new(child_fds)),
        // TEAM_432: Clone parent's VMA list
        vmas: IrqSafeLock::new(parent_vmas),
        // TEAM_432: Clone parent's working directory
        cwd: IrqSafeLock::new(child_cwd),
        // Signal state - cloned from parent
        pending_signals: AtomicU32::new(0), // Child starts with no pending signals
        blocked_signals: AtomicU64::new(parent.blocked_signals.load(Ordering::Acquire)),
        signal_handlers: IrqSafeLock::new(child_signal_handlers),
        signal_trampoline: AtomicUsize::new(parent_trampoline),
        // No clear-on-exit TID for forked processes
        clear_child_tid: AtomicUsize::new(0),
        // TLS inherited from parent
        tls: AtomicUsize::new(parent_tls),
        // Process group and session inherited from parent
        pgid: AtomicUsize::new(parent_pgid),
        sid: AtomicUsize::new(parent_sid),
        // Umask inherited from parent
        umask: AtomicU32::new(parent_umask),
        // TEAM_472: Initialize with full quantum for preemptive scheduling
        ticks_remaining: AtomicU32::new(crate::QUANTUM_TICKS),
        total_ticks: AtomicU64::new(0),
    };

    log::trace!(
        "[FORK] Created child TCB: PID={}, ttbr0=0x{:x}, entry=0x{:x}",
        tid,
        child_ttbr0,
        tf.pc
    );

    let arc_tcb = Arc::new(tcb);

    // TEAM_454: Refresh kernel mappings AFTER all kernel allocations.
    // The child's page table was created before kernel stack allocation and
    // Arc<TCB> allocation, so it may be missing new kernel heap mappings.
    // Re-copy PML4 entries to ensure the child can access all kernel memory.
    los_mm::user::refresh_kernel_mappings(child_ttbr0);

    Ok(arc_tcb)
}
