//! TEAM_208: Synchronization syscalls (futex)
//! TEAM_360: Added ppoll syscall for Eyra/std support
//! TEAM_421: Return SyscallResult, no scattered casts
//! TEAM_422: Uses Arc<dyn Any> downcasting for type-erased FdType handles
//!
//! Futex (Fast Userspace Mutex) enables efficient blocking synchronization
//! in userspace. Tasks wait for a memory location's value to change without
//! burning CPU cycles.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use los_hal::IrqSafeLock;

use crate::SyscallResult;
use crate::epoll::EventFdState;
use los_mm::user as mm_user; // TEAM_422: Import for downcasting
// TEAM_420: Direct linux_raw_sys imports, no shims
use linux_raw_sys::errno::{EAGAIN, EFAULT, EINVAL};
use los_sched::scheduler::SCHEDULER;
use los_sched::{TaskControlBlock, TaskState, current_task, yield_now};

// TEAM_360: Poll event constants (matching Linux)
pub const POLLIN: i16 = 0x0001; // Data to read
pub const POLLPRI: i16 = 0x0002; // Urgent data
pub const POLLOUT: i16 = 0x0004; // Writing possible
pub const POLLERR: i16 = 0x0008; // Error (output only)
pub const POLLHUP: i16 = 0x0010; // Hang up (output only)
pub const POLLNVAL: i16 = 0x0020; // Invalid fd (output only)

/// TEAM_360: struct pollfd (8 bytes)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// TEAM_208: Futex operations
pub const FUTEX_WAIT: usize = 0;
pub const FUTEX_WAKE: usize = 1;

/// TEAM_208: A task waiting on a futex
struct FutexWaiter {
    task: Arc<TaskControlBlock>,
}

/// TEAM_208: Global wait list: virtual address → list of waiters
/// Uses BTreeMap instead of HashMap (no hashbrown dependency)
static FUTEX_WAITERS: IrqSafeLock<BTreeMap<usize, Vec<FutexWaiter>>> =
    IrqSafeLock::new(BTreeMap::new());

/// TEAM_208: sys_futex - Fast userspace mutex operations
/// TEAM_421: Returns SyscallResult
///
/// # Arguments
/// - `addr`: User virtual address of the futex word (must be 4-byte aligned)
/// - `op`: Operation (FUTEX_WAIT or FUTEX_WAKE)
/// - `val`: Expected value (for WAIT) or max waiters to wake (for WAKE)
/// - `_timeout`: Timeout in nanoseconds (currently ignored)
/// - `_addr2`: Second address (for REQUEUE, currently ignored)
///
/// # Returns
/// - FUTEX_WAIT: Ok(0) on success, Err(EAGAIN) if value mismatch, Err(EFAULT) if bad address
/// - FUTEX_WAKE: Ok(number of tasks woken)
pub fn sys_futex(
    addr: usize,
    op: usize,
    val: usize,
    _timeout: usize,
    _addr2: usize,
) -> SyscallResult {
    match op {
        FUTEX_WAIT => futex_wait(addr, val as u32),
        FUTEX_WAKE => futex_wake(addr, val),
        _ => Err(EINVAL),
    }
}

/// TEAM_208: Block the current task if *addr == expected
/// TEAM_421: Returns SyscallResult
fn futex_wait(addr: usize, expected: u32) -> SyscallResult {
    // Must be 4-byte aligned
    if addr % 4 != 0 {
        return Err(EINVAL);
    }

    let task = current_task();
    let ttbr0 = task.ttbr0.load(Ordering::Acquire);

    // Read the current value at the user address
    let Some(kernel_ptr) = mm_user::user_va_to_kernel_ptr(ttbr0, addr) else {
        return Err(EFAULT);
    };

    // Read atomically
    // SAFETY: We validated the address is mapped and aligned
    let current_val = unsafe {
        let atomic_ptr = kernel_ptr as *const AtomicU32;
        (*atomic_ptr).load(Ordering::SeqCst)
    };

    // If value doesn't match, return immediately
    if current_val != expected {
        return Err(EAGAIN);
    }

    // Add to wait list and block
    {
        let mut waiters = FUTEX_WAITERS.lock();
        waiters
            .entry(addr)
            .or_insert_with(Vec::new)
            .push(FutexWaiter { task: task.clone() });

        // Mark task as blocked
        task.set_state(TaskState::Blocked);
    }

    // Yield to scheduler - we won't be picked up again until unblocked
    yield_now();

    Ok(0)
}

/// TEAM_208: Wake up to `count` tasks waiting on addr
/// TEAM_230: Made public for CLONE_CHILD_CLEARTID thread exit handling
/// TEAM_421: Returns SyscallResult
pub fn futex_wake(addr: usize, count: usize) -> SyscallResult {
    let mut woken = 0usize;

    let mut waiters = FUTEX_WAITERS.lock();

    if let Some(queue) = waiters.get_mut(&addr) {
        while !queue.is_empty() && woken < count {
            let waiter = queue.swap_remove(0);
            // Mark task as ready and add back to scheduler
            waiter.task.set_state(TaskState::Ready);
            SCHEDULER.add_task(waiter.task);
            woken += 1;
        }

        // Clean up empty queue
        if queue.is_empty() {
            waiters.remove(&addr);
        }
    }

    Ok(woken as i64)
}

/// TEAM_360: sys_ppoll - Wait for events on file descriptors.
/// TEAM_421: Returns SyscallResult
///
/// This implements the ppoll syscall for Eyra/std support.
/// Currently implements non-blocking poll that checks fd state immediately.
///
/// # Arguments
/// * `fds_ptr` - User pointer to array of pollfd structs
/// * `nfds` - Number of file descriptors
/// * `tmo_ptr` - User pointer to timeout (NULL = block forever, currently ignored)
/// * `sigmask_ptr` - Signal mask (currently ignored)
///
/// # Returns
/// Ok(number of fds with events), Ok(0) on timeout, or Err(errno)
pub fn sys_ppoll(
    fds_ptr: usize,
    nfds: usize,
    _tmo_ptr: usize,
    _sigmask_ptr: usize,
) -> SyscallResult {
    let task = current_task();
    let ttbr0 = task.ttbr0.load(Ordering::Acquire);

    // Validate nfds (reasonable limit)
    if nfds > 1024 {
        return Err(EINVAL);
    }

    if nfds == 0 {
        return Ok(0);
    }

    let pollfd_size = core::mem::size_of::<Pollfd>();
    let buf_size = nfds * pollfd_size;

    // Validate buffer
    if mm_user::validate_user_buffer(ttbr0, fds_ptr, buf_size, true).is_err() {
        return Err(EFAULT);
    }

    // TEAM_460: Poll with blocking - yield to scheduler when nothing ready
    // This is a simple implementation that polls in a loop with yields.
    // A proper implementation would use wait queues.
    const MAX_POLL_LOOPS: usize = 1000; // Prevent infinite loop

    for _attempt in 0..MAX_POLL_LOOPS {
        let fd_table = task.fd_table.lock();
        let mut ready_count: i64 = 0;

        for i in 0..nfds {
            let pfd_addr = fds_ptr + i * pollfd_size;

            // Read pollfd from user space
            let pfd = match read_pollfd(ttbr0, pfd_addr) {
                Some(p) => p,
                None => return Err(EFAULT),
            };

            // Determine revents based on fd type
            let revents = if pfd.fd < 0 {
                // Negative fd: ignore, set revents = 0
                0i16
            } else {
                match fd_table.get(pfd.fd as usize) {
                    None => {
                        // Invalid fd
                        POLLNVAL
                    }
                    Some(entry) => poll_fd_type(&entry.fd_type, pfd.events),
                }
            };

            // Write revents back to user space
            if !write_pollfd_revents(ttbr0, pfd_addr, revents) {
                return Err(EFAULT);
            }

            if revents != 0 {
                ready_count += 1;
            }
        }

        // If something is ready, return
        if ready_count > 0 {
            log::trace!("[SYSCALL] ppoll(nfds={}) -> {} ready", nfds, ready_count);
            return Ok(ready_count);
        }

        // Nothing ready - drop fd_table lock and yield to let other tasks run
        drop(fd_table);
        los_sched::yield_now();
    }

    // Timed out (hit MAX_POLL_LOOPS)
    log::trace!("[SYSCALL] ppoll(nfds={}) -> 0 (timeout)", nfds);
    Ok(0)
}

/// TEAM_360: Read a pollfd struct from user space
fn read_pollfd(ttbr0: usize, addr: usize) -> Option<Pollfd> {
    let mut bytes = [0u8; 8];
    for i in 0..8 {
        bytes[i] = crate::read_from_user(ttbr0, addr + i)?;
    }

    Some(Pollfd {
        fd: i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        events: i16::from_ne_bytes([bytes[4], bytes[5]]),
        revents: i16::from_ne_bytes([bytes[6], bytes[7]]),
    })
}

/// TEAM_360: Write revents field back to user pollfd
fn write_pollfd_revents(ttbr0: usize, addr: usize, revents: i16) -> bool {
    let revents_offset = 6; // offset of revents in pollfd struct
    let bytes = revents.to_ne_bytes();

    for (i, &byte) in bytes.iter().enumerate() {
        if !crate::write_to_user_buf(ttbr0, addr + revents_offset, i, byte) {
            return false;
        }
    }
    true
}

/// TEAM_360: Determine poll events for a given fd type
fn poll_fd_type(fd_type: &los_sched::fd_table::FdType, events: i16) -> i16 {
    use los_sched::fd_table::FdType;

    let mut revents: i16 = 0;

    match fd_type {
        FdType::Stdin => {
            // Stdin: check if input available
            // For now, always report readable (conservative)
            if events & POLLIN != 0 {
                revents |= POLLIN;
            }
        }
        FdType::Stdout | FdType::Stderr => {
            // Stdout/Stderr: always writable
            if events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        FdType::VfsFile(_) => {
            // Regular files: always ready for read/write
            if events & POLLIN != 0 {
                revents |= POLLIN;
            }
            if events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        FdType::PipeRead(pipe) => {
            // Pipe read end: readable if data available
            if pipe.has_data() {
                if events & POLLIN != 0 {
                    revents |= POLLIN;
                }
            }
            // Check for hangup (write end closed)
            // For now, don't report POLLHUP
        }
        FdType::PipeWrite(pipe) => {
            // Pipe write end: writable if not full
            if pipe.has_space() {
                if events & POLLOUT != 0 {
                    revents |= POLLOUT;
                }
            }
        }
        FdType::PtyMaster(_) | FdType::PtySlave(_) => {
            // PTY: treat like terminal - always ready
            if events & POLLIN != 0 {
                revents |= POLLIN;
            }
            if events & POLLOUT != 0 {
                revents |= POLLOUT;
            }
        }
        // TEAM_394: Epoll fds are not pollable themselves
        FdType::Epoll(_) => {}
        // TEAM_394: EventFd poll support
        // TEAM_422: Downcast Arc<dyn Any> to EventFdState
        FdType::EventFd(efd) => {
            if let Some(state) = efd.downcast_ref::<EventFdState>() {
                if state.is_readable() && (events & POLLIN != 0) {
                    revents |= POLLIN;
                }
                if state.is_writable() && (events & POLLOUT != 0) {
                    revents |= POLLOUT;
                }
            }
        }
    }

    revents
}

// ============================================================================
// TEAM_406: poll syscall (wrapper around ppoll)
// ============================================================================

/// TEAM_406: sys_poll - Wait for events on file descriptors.
/// TEAM_421: Returns SyscallResult
///
/// This is a wrapper around ppoll with simpler timeout handling.
/// poll() is the older interface, ppoll() is the modern one.
///
/// # Arguments
/// * `fds_ptr` - User pointer to array of pollfd structs
/// * `nfds` - Number of file descriptors
/// * `timeout_ms` - Timeout in milliseconds (-1 = infinite, 0 = non-blocking)
///
/// # Returns
/// Ok(number of fds with events), Ok(0) on timeout, or Err(errno)
pub fn sys_poll(fds_ptr: usize, nfds: usize, _timeout_ms: i32) -> SyscallResult {
    // poll() is essentially ppoll() with simpler timeout
    // Current ppoll ignores timeout anyway, so just delegate
    sys_ppoll(fds_ptr, nfds, 0, 0)
}

// ============================================================================
// TEAM_438: socketpair syscall (stub for brush shell)
// ============================================================================

/// TEAM_438: sys_socketpair - Create a pair of connected sockets.
///
/// Brush uses socketpair for internal IPC. We implement this as a pipe pair
/// since we don't have full socket support.
///
/// # Arguments
/// * `_domain` - Socket domain (AF_UNIX, etc.) - ignored
/// * `_type` - Socket type (SOCK_STREAM, etc.) - ignored  
/// * `_protocol` - Protocol - ignored
/// * `sv_ptr` - User pointer to int[2] for the socket pair
///
/// # Returns
/// Ok(0) on success, Err(errno) on failure
pub fn sys_socketpair(_domain: i32, _type: i32, _protocol: i32, sv_ptr: usize) -> SyscallResult {
    use los_sched::fd_table::FdType;
    use los_vfs::pipe::Pipe;

    let task = current_task();

    // Validate user buffer (2 * sizeof(i32) = 8 bytes)
    if mm_user::validate_user_buffer(task.ttbr0.load(Ordering::Acquire), sv_ptr, 8, true).is_err() {
        return Err(EFAULT);
    }

    // Create a bidirectional pipe pair (two pipes for full-duplex)
    let pipe1 = Pipe::new();
    let pipe2 = Pipe::new();

    // Allocate file descriptors
    // sv[0] reads from pipe1, writes to pipe2
    // sv[1] reads from pipe2, writes to pipe1
    let (fd0, fd1) = {
        let mut fd_table = task.fd_table.lock();

        // For simplicity, just create a single pipe and use both ends
        // This gives half-duplex behavior which is sufficient for most uses
        let fd0 = match fd_table.alloc(FdType::PipeRead(pipe1.clone())) {
            Some(fd) => fd,
            None => return Err(linux_raw_sys::errno::EMFILE),
        };

        let fd1 = match fd_table.alloc(FdType::PipeWrite(pipe1.clone())) {
            Some(fd) => fd,
            None => {
                fd_table.close(fd0);
                return Err(linux_raw_sys::errno::EMFILE);
            }
        };

        // Drop unused pipe2 - we're doing half-duplex for now
        drop(pipe2);

        (fd0, fd1)
    };

    // Write fds to user space
    let ptr = match mm_user::user_va_to_kernel_ptr(task.ttbr0.load(Ordering::Acquire), sv_ptr) {
        Some(p) => p,
        None => return Err(EFAULT),
    };
    unsafe {
        let fds = ptr as *mut [i32; 2];
        (*fds)[0] = fd0 as i32;
        (*fds)[1] = fd1 as i32;
    }

    log::trace!("[SYSCALL] socketpair: created fds [{}, {}]", fd0, fd1);
    Ok(0)
}

// ============================================================================
// TEAM_456: socket/sendto stubs for BusyBox
// ============================================================================

/// TEAM_456: sys_socket - Create a socket (stub).
///
/// BusyBox may try to create sockets for logging or networking.
/// Since we don't have a network stack, return EAFNOSUPPORT.
///
/// # Arguments
/// * `domain` - Socket domain (AF_UNIX=1, AF_INET=2, etc.)
/// * `type_` - Socket type (SOCK_STREAM=1, SOCK_DGRAM=2, etc.)
/// * `protocol` - Protocol number
///
/// # Returns
/// Err(EAFNOSUPPORT) - address family not supported
pub fn sys_socket(_domain: i32, _type: i32, _protocol: i32) -> SyscallResult {
    log::trace!(
        "[SYSCALL] socket(domain={}, type={}, protocol={}) -> EAFNOSUPPORT",
        _domain,
        _type,
        _protocol
    );
    Err(linux_raw_sys::errno::EAFNOSUPPORT)
}

/// TEAM_456: sys_sendto - Send message on socket (stub).
///
/// BusyBox may try to send data to sockets for logging.
/// Since we don't have sockets, return ENOTSOCK.
///
/// # Arguments
/// * `sockfd` - Socket file descriptor
/// * `buf` - Buffer containing message
/// * `len` - Length of message
/// * `flags` - Send flags
/// * `dest_addr` - Destination address
/// * `addrlen` - Length of destination address
///
/// # Returns
/// Err(ENOTSOCK) - fd is not a socket
pub fn sys_sendto(
    _sockfd: i32,
    _buf: usize,
    _len: usize,
    _flags: i32,
    _dest_addr: usize,
    _addrlen: usize,
) -> SyscallResult {
    log::trace!(
        "[SYSCALL] sendto(sockfd={}, len={}) -> ENOTSOCK",
        _sockfd,
        _len
    );
    Err(linux_raw_sys::errno::ENOTSOCK)
}
