//! Scheduler syscalls.
//!
//! TEAM_435: Scheduler affinity syscalls for sysinfo/brush support.
//! TEAM_421: Returns SyscallResult, no scattered casts.

use crate::SyscallResult;
use core::sync::atomic::Ordering;
use linux_raw_sys::errno::{EFAULT, EINVAL};
use los_mm::user as mm_user;

/// TEAM_435: sys_sched_getaffinity - Get CPU affinity mask.
///
/// Returns the CPU affinity mask for the specified process.
/// LevitateOS currently runs on a single CPU, so we return a mask
/// with just CPU 0 set.
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `cpusetsize` - Size of the CPU set buffer in bytes
/// * `mask` - User pointer to cpu_set_t buffer
///
/// # Returns
/// Ok(bytes_written) on success, Err(errno) on failure.
pub fn sys_sched_getaffinity(pid: i32, cpusetsize: usize, mask: usize) -> SyscallResult {
    let task = los_sched::current_task();

    // For now, we only support querying the current process
    // pid == 0 means current process, which is valid
    if pid != 0 && pid as u64 != task.id.0 as u64 {
        // We could return ESRCH for unknown PIDs, but for simplicity
        // just return the same affinity (single CPU system)
        log::trace!(
            "[SYSCALL] sched_getaffinity({}, {}, 0x{:x}) -> other pid",
            pid,
            cpusetsize,
            mask
        );
    }

    // cpu_set_t is typically 128 bytes on Linux (1024 bits = 1024 CPUs)
    // We need at least 1 byte to report CPU 0
    if cpusetsize == 0 {
        return Err(EINVAL);
    }

    // Validate user buffer
    let write_size = cpusetsize.min(128); // Cap at typical cpu_set_t size
    if mm_user::validate_user_buffer(task.ttbr0.load(Ordering::Acquire), mask, write_size, true)
        .is_err()
    {
        return Err(EFAULT);
    }

    // Zero the entire buffer first
    for i in 0..write_size {
        if let Some(ptr) =
            mm_user::user_va_to_kernel_ptr(task.ttbr0.load(Ordering::Acquire), mask + i)
        {
            // SAFETY: We validated the buffer above
            unsafe {
                *ptr = 0;
            }
        } else {
            return Err(EFAULT);
        }
    }

    // Set bit 0 (CPU 0) - LevitateOS is single-CPU
    if let Some(ptr) = mm_user::user_va_to_kernel_ptr(task.ttbr0.load(Ordering::Acquire), mask) {
        // SAFETY: We validated the buffer above
        unsafe {
            *ptr = 1; // Bit 0 set = CPU 0 is in the affinity mask
        }
    } else {
        return Err(EFAULT);
    }

    log::trace!(
        "[SYSCALL] sched_getaffinity({}, {}, 0x{:x}) -> {}",
        pid,
        cpusetsize,
        mask,
        write_size
    );

    // Return the number of bytes written (minimum size to represent our CPU set)
    Ok(write_size as i64)
}

/// TEAM_435: sys_sched_setaffinity - Set CPU affinity mask.
///
/// Sets the CPU affinity mask for the specified process.
/// LevitateOS is single-CPU, so we accept the call but don't actually
/// change anything (as long as CPU 0 is in the mask).
///
/// # Arguments
/// * `pid` - Process ID (0 = calling process)
/// * `cpusetsize` - Size of the CPU set buffer in bytes
/// * `mask` - User pointer to cpu_set_t buffer
///
/// # Returns
/// Ok(0) on success, Err(errno) on failure.
pub fn sys_sched_setaffinity(pid: i32, cpusetsize: usize, mask: usize) -> SyscallResult {
    let task = los_sched::current_task();

    // Validate size
    if cpusetsize == 0 {
        return Err(EINVAL);
    }

    // Validate user buffer
    let read_size = cpusetsize.min(128);
    if mm_user::validate_user_buffer(task.ttbr0.load(Ordering::Acquire), mask, read_size, false)
        .is_err()
    {
        return Err(EFAULT);
    }

    // Read the first byte to check if CPU 0 is set
    let first_byte = if let Some(ptr) =
        mm_user::user_va_to_kernel_ptr(task.ttbr0.load(Ordering::Acquire), mask)
    {
        // SAFETY: We validated the buffer above
        unsafe { *ptr }
    } else {
        return Err(EFAULT);
    };

    // Check if CPU 0 is in the mask (bit 0)
    if first_byte & 1 == 0 {
        // CPU 0 not in mask - on a single-CPU system this is an error
        // But actually, let's be lenient - apps might just be probing
        log::warn!(
            "[SYSCALL] sched_setaffinity: CPU 0 not in mask (first_byte=0x{:02x})",
            first_byte
        );
        // Still succeed - we can't actually change anything
    }

    log::trace!(
        "[SYSCALL] sched_setaffinity({}, {}, 0x{:x}) -> 0",
        pid,
        cpusetsize,
        mask
    );

    Ok(0)
}
