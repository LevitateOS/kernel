//! TEAM_394: Epoll and eventfd syscalls for tokio/async support.
//!
//! Implements epoll_create1, epoll_ctl, epoll_wait, and eventfd2 syscalls
//! required by tokio async runtime for brush shell support.
//! TEAM_420: Uses linux_raw_sys directly, no shims
//! TEAM_421: Return SyscallResult, no scattered casts
//! TEAM_422: Uses Arc<dyn Any> downcasting for type-erased FdType handles

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};
use los_hal::IrqSafeLock;

use crate::SyscallResult;
use los_mm::user as mm_user;
use los_sched::fd_table::FdType;
use los_sched::{current_task, yield_now};

// TEAM_420: Direct imports from linux-raw-sys, no shims
use linux_raw_sys::errno::{EAGAIN, EBADF, EEXIST, EFAULT, EINVAL, EMFILE, ENOENT};
use linux_raw_sys::general::{
    EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL,
    EPOLL_CTL_MOD, EPOLLERR, EPOLLIN, EPOLLOUT,
};

/// TEAM_394: struct epoll_event (12 bytes on Linux, but we use 16 for alignment)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64, // User data (typically the fd)
}

/// TEAM_394: Internal representation of a registered fd in an epoll instance.
#[derive(Debug, Clone)]
struct EpollRegistration {
    fd: i32,
    events: u32,
    data: u64,
}

/// TEAM_394: Epoll instance state.
pub struct EpollInstance {
    /// Map of registered fds to their event settings
    registrations: BTreeMap<i32, EpollRegistration>,
}

impl EpollInstance {
    pub fn new() -> Self {
        Self {
            registrations: BTreeMap::new(),
        }
    }

    /// Add or modify a file descriptor registration
    /// TEAM_420: op is u32 to match linux-raw-sys types
    /// TEAM_421: Returns Result<(), u32> for SyscallResult compatibility
    pub fn ctl(&mut self, op: u32, fd: i32, event: &EpollEvent) -> Result<(), u32> {
        match op {
            EPOLL_CTL_ADD => {
                if self.registrations.contains_key(&fd) {
                    return Err(EEXIST);
                }
                self.registrations.insert(
                    fd,
                    EpollRegistration {
                        fd,
                        events: event.events,
                        data: event.data,
                    },
                );
                Ok(())
            }
            EPOLL_CTL_MOD => {
                if let Some(reg) = self.registrations.get_mut(&fd) {
                    reg.events = event.events;
                    reg.data = event.data;
                    Ok(())
                } else {
                    Err(ENOENT)
                }
            }
            EPOLL_CTL_DEL => {
                if self.registrations.remove(&fd).is_some() {
                    Ok(())
                } else {
                    Err(ENOENT)
                }
            }
            _ => Err(EINVAL),
        }
    }

    /// Poll for ready events
    pub fn wait(&self, max_events: usize) -> Vec<EpollEvent> {
        let task = current_task();
        let fd_table = task.fd_table.lock();
        let mut ready = Vec::new();

        for reg in self.registrations.values() {
            if ready.len() >= max_events {
                break;
            }

            // Check if this fd has events
            if let Some(entry) = fd_table.get(reg.fd as usize) {
                let revents = poll_fd_for_epoll(&entry.fd_type, reg.events);
                if revents != 0 {
                    ready.push(EpollEvent {
                        events: revents,
                        data: reg.data,
                    });
                }
            } else {
                // fd closed - report error
                ready.push(EpollEvent {
                    events: EPOLLERR,
                    data: reg.data,
                });
            }
        }

        ready
    }
}

/// TEAM_394: EventFd state.
pub struct EventFdState {
    counter: AtomicU64,
    flags: u32,
}

impl EventFdState {
    pub fn new(initval: u32, flags: u32) -> Self {
        Self {
            counter: AtomicU64::new(initval as u64),
            flags,
        }
    }

    /// Read from eventfd: returns counter value (blocks if zero and blocking mode)
    /// TEAM_421: Returns Result<u64, u32> for SyscallResult compatibility
    pub fn read(&self) -> Result<u64, u32> {
        loop {
            let val = self.counter.load(Ordering::SeqCst);
            if val == 0 {
                if self.flags & EFD_NONBLOCK != 0 {
                    return Err(EAGAIN);
                }
                // Block until counter > 0
                yield_now();
                continue;
            }

            // For semaphore mode, decrement by 1; otherwise reset to 0
            let new_val = if self.flags & EFD_SEMAPHORE != 0 {
                val - 1
            } else {
                0
            };

            if self
                .counter
                .compare_exchange(val, new_val, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(if self.flags & EFD_SEMAPHORE != 0 {
                    1
                } else {
                    val
                });
            }
        }
    }

    /// Write to eventfd: adds to counter
    /// TEAM_421: Returns Result<(), u32> for SyscallResult compatibility
    pub fn write(&self, val: u64) -> Result<(), u32> {
        if val == u64::MAX {
            return Err(EINVAL);
        }

        loop {
            let current = self.counter.load(Ordering::SeqCst);
            let new_val = current.saturating_add(val);

            // Check for overflow (would exceed u64::MAX - 1)
            if new_val == u64::MAX {
                if self.flags & EFD_NONBLOCK != 0 {
                    return Err(EAGAIN);
                }
                yield_now();
                continue;
            }

            if self
                .counter
                .compare_exchange(current, new_val, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Check if readable (counter > 0)
    pub fn is_readable(&self) -> bool {
        self.counter.load(Ordering::SeqCst) > 0
    }

    /// Check if writable (counter < u64::MAX - 1)
    pub fn is_writable(&self) -> bool {
        self.counter.load(Ordering::SeqCst) < u64::MAX - 1
    }
}

// TEAM_422: Type aliases for wrapped instances stored in FdType
/// Wrapped EpollInstance stored in FdType::Epoll
pub type EpollWrapped = IrqSafeLock<EpollInstance>;
/// Wrapped EventFdState stored in FdType::EventFd
pub type EventFdWrapped = EventFdState;

// TEAM_422: Downcasting helpers for Arc<dyn Any> -> concrete types

/// Downcast an EpollRef to the underlying EpollWrapped
fn downcast_epoll(any: &Arc<dyn Any + Send + Sync>) -> Option<&EpollWrapped> {
    any.downcast_ref::<EpollWrapped>()
}

/// Downcast an EventFdRef to the underlying EventFdState
fn downcast_eventfd(any: &Arc<dyn Any + Send + Sync>) -> Option<&EventFdState> {
    any.downcast_ref::<EventFdState>()
}

/// TEAM_394: Convert poll events to epoll events for an fd type
fn poll_fd_for_epoll(fd_type: &FdType, wanted: u32) -> u32 {
    use los_sched::fd_table::FdType;

    let mut revents: u32 = 0;

    match fd_type {
        FdType::Stdin => {
            if wanted & EPOLLIN != 0 {
                revents |= EPOLLIN;
            }
        }
        FdType::Stdout | FdType::Stderr => {
            if wanted & EPOLLOUT != 0 {
                revents |= EPOLLOUT;
            }
        }
        FdType::VfsFile(_) => {
            if wanted & EPOLLIN != 0 {
                revents |= EPOLLIN;
            }
            if wanted & EPOLLOUT != 0 {
                revents |= EPOLLOUT;
            }
        }
        FdType::PipeRead(pipe) => {
            if pipe.has_data() && (wanted & EPOLLIN != 0) {
                revents |= EPOLLIN;
            }
        }
        FdType::PipeWrite(pipe) => {
            if pipe.has_space() && (wanted & EPOLLOUT != 0) {
                revents |= EPOLLOUT;
            }
        }
        FdType::PtyMaster(_) | FdType::PtySlave(_) => {
            if wanted & EPOLLIN != 0 {
                revents |= EPOLLIN;
            }
            if wanted & EPOLLOUT != 0 {
                revents |= EPOLLOUT;
            }
        }
        FdType::Epoll(_) => {
            // Epoll fds are not pollable themselves
        }
        FdType::EventFd(efd) => {
            // TEAM_422: Downcast Arc<dyn Any> to EventFdState
            if let Some(state) = downcast_eventfd(efd) {
                if state.is_readable() && (wanted & EPOLLIN != 0) {
                    revents |= EPOLLIN;
                }
                if state.is_writable() && (wanted & EPOLLOUT != 0) {
                    revents |= EPOLLOUT;
                }
            }
        }
    }

    revents
}

/// TEAM_394: sys_epoll_create1 - Create an epoll instance.
/// TEAM_421: Returns SyscallResult
///
/// # Arguments
/// * `flags` - EPOLL_CLOEXEC or 0
///
/// # Returns
/// * Ok(file descriptor) on success, or Err(errno)
pub fn sys_epoll_create1(flags: i32) -> SyscallResult {
    // Validate flags
    // TEAM_420: EPOLL_CLOEXEC is u32 from linux-raw-sys
    if flags != 0 && flags as u32 != EPOLL_CLOEXEC {
        return Err(EINVAL);
    }

    let task = current_task();
    let epoll = Arc::new(IrqSafeLock::new(EpollInstance::new()));

    let mut fd_table = task.fd_table.lock();
    match fd_table.alloc(FdType::Epoll(epoll)) {
        Some(fd) => {
            log::trace!("[SYSCALL] epoll_create1({}) -> fd={}", flags, fd);
            Ok(fd as i64)
        }
        None => Err(EMFILE),
    }
}

/// TEAM_394: sys_epoll_ctl - Control an epoll instance.
/// TEAM_420: op is u32 to match linux-raw-sys types
/// TEAM_421: Returns SyscallResult
///
/// # Arguments
/// * `epfd` - Epoll file descriptor
/// * `op` - Operation (EPOLL_CTL_ADD, EPOLL_CTL_MOD, EPOLL_CTL_DEL)
/// * `fd` - Target file descriptor
/// * `event_ptr` - User pointer to epoll_event struct
///
/// # Returns
/// * Ok(0) on success, Err(errno)
pub fn sys_epoll_ctl(epfd: i32, op: u32, fd: i32, event_ptr: usize) -> SyscallResult {
    let task = current_task();
    let ttbr0 = task.ttbr0;

    // Read event from user space (not needed for DEL)
    let event = if op != EPOLL_CTL_DEL {
        match read_epoll_event(ttbr0, event_ptr) {
            Some(e) => e,
            None => return Err(EFAULT),
        }
    } else {
        EpollEvent::default()
    };

    let fd_table = task.fd_table.lock();

    // Get the epoll instance
    let epoll = match fd_table.get(epfd as usize) {
        Some(entry) => match &entry.fd_type {
            FdType::Epoll(e) => e.clone(),
            _ => return Err(EINVAL),
        },
        None => return Err(EBADF),
    };

    // Verify target fd exists (except for DEL which may be on a closed fd)
    if op != EPOLL_CTL_DEL && fd_table.get(fd as usize).is_none() {
        return Err(EBADF);
    }

    drop(fd_table); // Release fd_table before locking epoll

    // TEAM_422: Downcast Arc<dyn Any> to EpollWrapped
    let epoll_wrapped = match downcast_epoll(&epoll) {
        Some(e) => e,
        None => return Err(EINVAL),
    };
    let mut epoll_guard = epoll_wrapped.lock();
    match epoll_guard.ctl(op, fd, &event) {
        Ok(()) => {
            log::trace!(
                "[SYSCALL] epoll_ctl(epfd={}, op={}, fd={}) -> 0",
                epfd,
                op,
                fd
            );
            Ok(0)
        }
        Err(e) => Err(e),
    }
}

/// TEAM_394: sys_epoll_wait - Wait for events on an epoll instance.
/// TEAM_421: Returns SyscallResult
///
/// # Arguments
/// * `epfd` - Epoll file descriptor
/// * `events_ptr` - User pointer to array of epoll_event structs
/// * `maxevents` - Maximum number of events to return
/// * `timeout` - Timeout in milliseconds (-1 = block forever, 0 = non-blocking)
///
/// # Returns
/// * Ok(number of ready fds), or Err(errno)
pub fn sys_epoll_wait(epfd: i32, events_ptr: usize, maxevents: i32, timeout: i32) -> SyscallResult {
    if maxevents <= 0 {
        return Err(EINVAL);
    }

    let task = current_task();
    let ttbr0 = task.ttbr0;

    // Validate output buffer
    let event_size = core::mem::size_of::<EpollEvent>();
    let buf_size = maxevents as usize * event_size;
    if mm_user::validate_user_buffer(ttbr0, events_ptr, buf_size, true).is_err() {
        return Err(EFAULT);
    }

    // Get the epoll instance
    let epoll = {
        let fd_table = task.fd_table.lock();
        match fd_table.get(epfd as usize) {
            Some(entry) => match &entry.fd_type {
                FdType::Epoll(e) => e.clone(),
                _ => return Err(EINVAL),
            },
            None => return Err(EBADF),
        }
    };

    #[cfg(target_arch = "x86_64")]
    let freq = los_arch_x86_64::time::read_timer_frequency();
    #[cfg(target_arch = "aarch64")]
    let freq = los_arch_aarch64::time::read_timer_frequency();

    #[cfg(target_arch = "x86_64")]
    let start_time = los_arch_x86_64::time::read_timer_counter();
    #[cfg(target_arch = "aarch64")]
    let start_time = los_arch_aarch64::time::read_timer_counter();
    let timeout_ticks = if timeout < 0 {
        u64::MAX // Block forever
    } else if timeout == 0 {
        0 // Non-blocking
    } else if freq > 0 {
        // Convert ms to timer ticks
        (timeout as u64) * freq / 1000
    } else {
        // Fallback: use yield count as rough timing
        (timeout as u64) * 100
    };

    // TEAM_422: Downcast Arc<dyn Any> to EpollWrapped
    let epoll_wrapped = match downcast_epoll(&epoll) {
        Some(e) => e,
        None => return Err(EINVAL),
    };

    loop {
        let epoll_guard = epoll_wrapped.lock();
        let ready = epoll_guard.wait(maxevents as usize);
        drop(epoll_guard);

        if !ready.is_empty() {
            // Write events to user space
            for (i, event) in ready.iter().enumerate() {
                if !write_epoll_event(ttbr0, events_ptr + i * event_size, event) {
                    return Err(EFAULT);
                }
            }

            log::trace!(
                "[SYSCALL] epoll_wait(epfd={}, maxevents={}) -> {}",
                epfd,
                maxevents,
                ready.len()
            );
            return Ok(ready.len() as i64);
        }

        // Check timeout
        if timeout == 0 {
            return Ok(0); // Non-blocking, no events
        }

        #[cfg(target_arch = "x86_64")]
        let elapsed = los_arch_x86_64::time::read_timer_counter().saturating_sub(start_time);
        #[cfg(target_arch = "aarch64")]
        let elapsed = los_arch_aarch64::time::read_timer_counter().saturating_sub(start_time);
        if elapsed >= timeout_ticks {
            return Ok(0); // Timeout
        }

        // Yield and try again
        yield_now();
    }
}

/// TEAM_394: sys_eventfd2 - Create an eventfd.
/// TEAM_421: Returns SyscallResult
///
/// # Arguments
/// * `initval` - Initial counter value
/// * `flags` - EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE
///
/// # Returns
/// * Ok(file descriptor) on success, or Err(errno)
pub fn sys_eventfd2(initval: u32, flags: u32) -> SyscallResult {
    // Validate flags
    let valid_flags = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
    if flags & !valid_flags != 0 {
        return Err(EINVAL);
    }

    let task = current_task();
    let eventfd = Arc::new(EventFdState::new(initval, flags));

    let mut fd_table = task.fd_table.lock();
    match fd_table.alloc(FdType::EventFd(eventfd)) {
        Some(fd) => {
            log::trace!(
                "[SYSCALL] eventfd2(initval={}, flags={:#x}) -> fd={}",
                initval,
                flags,
                fd
            );
            Ok(fd as i64)
        }
        None => Err(EMFILE),
    }
}

/// TEAM_394: Read an epoll_event from user space
fn read_epoll_event(ttbr0: usize, addr: usize) -> Option<EpollEvent> {
    // epoll_event is 12 bytes on Linux (events: u32, data: u64)
    // We read 12 bytes
    let mut bytes = [0u8; 12];
    for i in 0..12 {
        bytes[i] = crate::read_from_user(ttbr0, addr + i)?;
    }

    Some(EpollEvent {
        events: u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        data: u64::from_ne_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]),
    })
}

/// TEAM_394: Write an epoll_event to user space
fn write_epoll_event(ttbr0: usize, addr: usize, event: &EpollEvent) -> bool {
    let events_bytes = event.events.to_ne_bytes();
    let data_bytes = event.data.to_ne_bytes();

    for (i, &byte) in events_bytes.iter().enumerate() {
        if !crate::write_to_user_buf(ttbr0, addr, i, byte) {
            return false;
        }
    }

    for (i, &byte) in data_bytes.iter().enumerate() {
        if !crate::write_to_user_buf(ttbr0, addr, 4 + i, byte) {
            return false;
        }
    }

    true
}
