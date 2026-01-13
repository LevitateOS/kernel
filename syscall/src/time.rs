use core::sync::atomic::Ordering;
// TEAM_413: Use new syscall helpers
// TEAM_418: Import time types from SSOT
// TEAM_420: Direct linux_raw_sys imports, no shims
// TEAM_421: Return SyscallResult, no scattered casts
// TEAM_430: Fixed nanosleep to read timespec from user memory
use crate::{SyscallResult, Timespec, Timeval, read_struct_from_user, write_struct_to_user};
use linux_raw_sys::errno::{EFAULT, EINVAL};

/// TEAM_198: Get uptime in seconds (for tmpfs timestamps).
pub fn uptime_seconds() -> u64 {
    let freq = read_timer_frequency();
    if freq == 0 {
        return 0;
    }
    read_timer_counter() / freq
}

/// TEAM_170: Read the ARM generic timer counter.
#[inline]
#[cfg(target_arch = "x86_64")]
fn read_timer_counter() -> u64 {
    los_arch_x86_64::time::read_timer_counter()
}

/// TEAM_170: Read the ARM generic timer counter.
#[inline]
#[cfg(target_arch = "aarch64")]
fn read_timer_counter() -> u64 {
    los_arch_aarch64::time::read_timer_counter()
}

/// TEAM_170: Read the ARM generic timer frequency.
#[inline]
#[cfg(target_arch = "x86_64")]
fn read_timer_frequency() -> u64 {
    los_arch_x86_64::time::read_timer_frequency()
}

/// TEAM_170: Read the ARM generic timer frequency.
#[inline]
#[cfg(target_arch = "aarch64")]
fn read_timer_frequency() -> u64 {
    los_arch_aarch64::time::read_timer_frequency()
}

/// TEAM_170: sys_nanosleep - Sleep for specified duration.
/// TEAM_421: Returns SyscallResult
/// TEAM_430: Fixed to read timespec from user memory (Linux ABI)
///
/// # Arguments
/// * `req_ptr` - User pointer to timespec struct specifying sleep duration
/// * `rem_ptr` - User pointer to store remaining time (if interrupted), can be NULL
///
/// # Returns
/// Ok(0) on success, Err(errno) on failure
pub fn sys_nanosleep(req_ptr: usize, _rem_ptr: usize) -> SyscallResult {
    // TEAM_430: Read timespec from user memory
    if req_ptr == 0 {
        return Err(EFAULT);
    }

    let task = los_sched::current_task();
    let req: Timespec = read_struct_from_user(task.ttbr0.load(Ordering::Acquire), req_ptr)?;

    log::debug!(
        "[SYSCALL] nanosleep: tv_sec={}, tv_nsec={}",
        req.tv_sec,
        req.tv_nsec
    );

    // Validate timespec
    if req.tv_nsec < 0 || req.tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }

    let seconds = req.tv_sec as u64;
    let nanoseconds = req.tv_nsec as u64;

    // TEAM_186: Normalize nanoseconds if > 1e9
    let extra_secs = nanoseconds / 1_000_000_000;
    let norm_nanos = nanoseconds % 1_000_000_000;
    let total_secs = seconds.saturating_add(extra_secs);

    let freq = read_timer_frequency();
    if freq == 0 {
        // TEAM_186: Use saturating arithmetic for fallback path
        let millis = total_secs
            .saturating_mul(1000)
            .saturating_add(norm_nanos / 1_000_000);
        for _ in 0..(millis.min(u64::MAX as u64) as usize).min(1_000_000) {
            los_sched::yield_now();
        }
        return Ok(0);
    }

    let start = read_timer_counter();

    // TEAM_186: Calculate ticks with overflow protection
    // ticks = seconds * freq + (nanoseconds * freq) / 1e9
    // Split calculation to avoid overflow
    let ticks_from_secs = total_secs.saturating_mul(freq);
    let ticks_from_nanos = (norm_nanos as u128 * freq as u128 / 1_000_000_000) as u64;
    let ticks_to_wait = ticks_from_secs.saturating_add(ticks_from_nanos);

    let target = start.saturating_add(ticks_to_wait);

    while read_timer_counter() < target {
        los_sched::yield_now();
    }

    // TODO: If interrupted, write remaining time to rem_ptr

    Ok(0)
}

/// TEAM_350: sys_clock_getres - Get clock resolution.
/// TEAM_421: Returns SyscallResult
///
/// Returns the resolution (precision) of the specified clock.
/// For CLOCK_MONOTONIC and CLOCK_REALTIME, we report 1 nanosecond.
/// TEAM_413: Updated to use write_struct_to_user helper.
pub fn sys_clock_getres(clockid: i32, res_buf: usize) -> SyscallResult {
    // clockid: 0 = CLOCK_REALTIME, 1 = CLOCK_MONOTONIC
    if clockid != 0 && clockid != 1 {
        return Err(EINVAL);
    }

    // If res_buf is NULL, just return success (allowed by POSIX)
    if res_buf == 0 {
        return Ok(0);
    }

    let task = los_sched::current_task();

    // TEAM_350: Report 1 nanosecond resolution
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: 1,
    };

    // TEAM_413: Use write_struct_to_user helper
    write_struct_to_user(task.ttbr0.load(Ordering::Acquire), res_buf, &ts)?;
    Ok(0)
}

/// TEAM_409: sys_gettimeofday - Get time of day (legacy interface).
/// TEAM_421: Returns SyscallResult
///
/// Returns the current time as seconds and microseconds since epoch.
/// This is the legacy POSIX interface; clock_gettime is preferred.
/// TEAM_413: Updated to use write_struct_to_user helper.
///
/// # Arguments
/// * `tv` - User pointer to timeval struct {tv_sec: i64, tv_usec: i64}
/// * `tz` - User pointer to timezone struct (ignored, can be NULL)
///
/// # Returns
/// Ok(0) on success, Err(errno) on failure.
pub fn sys_gettimeofday(tv: usize, _tz: usize) -> SyscallResult {
    // TEAM_418: Use Timeval from SSOT (syscall/types.rs)
    // If tv is NULL, just return success (allowed by POSIX)
    if tv == 0 {
        return Ok(0);
    }

    let task = los_sched::current_task();
    let freq = read_timer_frequency();
    let counter = read_timer_counter();

    let timeval = if freq > 0 {
        let seconds = counter / freq;
        let remainder = counter % freq;
        // Convert remainder to microseconds
        let microseconds = (remainder * 1_000_000) / freq;
        Timeval {
            tv_sec: seconds as i64,
            tv_usec: microseconds as i64,
        }
    } else {
        Timeval {
            tv_sec: 0,
            tv_usec: 0,
        }
    };

    // TEAM_413: Use write_struct_to_user helper
    write_struct_to_user(task.ttbr0.load(Ordering::Acquire), tv, &timeval)?;
    Ok(0)
}

/// TEAM_430: sys_clock_nanosleep - High-resolution sleep with clock specification.
/// TEAM_421: Returns SyscallResult
///
/// This is the syscall used by rustix/Eyra for std::thread::sleep.
///
/// # Arguments
/// * `clockid` - Clock to use (CLOCK_REALTIME=0, CLOCK_MONOTONIC=1)
/// * `flags` - 0 = relative time, TIMER_ABSTIME(1) = absolute time
/// * `req_ptr` - User pointer to timespec struct specifying sleep duration
/// * `rem_ptr` - User pointer to store remaining time (if interrupted), can be NULL
///
/// # Returns
/// Ok(0) on success, Err(errno) on failure
pub fn sys_clock_nanosleep(
    clockid: i32,
    flags: i32,
    req_ptr: usize,
    _rem_ptr: usize,
) -> SyscallResult {
    // Validate clockid (we only support CLOCK_REALTIME and CLOCK_MONOTONIC)
    if clockid != 0 && clockid != 1 {
        return Err(EINVAL);
    }

    // TEAM_430: Read timespec from user memory
    if req_ptr == 0 {
        return Err(EFAULT);
    }

    let task = los_sched::current_task();
    let req: Timespec = read_struct_from_user(task.ttbr0.load(Ordering::Acquire), req_ptr)?;

    log::debug!(
        "[SYSCALL] clock_nanosleep: clockid={}, flags={}, tv_sec={}, tv_nsec={}",
        clockid,
        flags,
        req.tv_sec,
        req.tv_nsec
    );

    // Validate timespec
    if req.tv_nsec < 0 || req.tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }

    let freq = read_timer_frequency();

    // Handle TIMER_ABSTIME flag (flags == 1)
    if flags == 1 {
        // Absolute time - sleep until the specified time
        if freq == 0 {
            // Can't do absolute timing without a timer
            return Ok(0);
        }

        // Convert requested absolute time to ticks
        let req_secs = req.tv_sec as u64;
        let req_nanos = req.tv_nsec as u64;
        let target_ticks = req_secs
            .saturating_mul(freq)
            .saturating_add((req_nanos as u128 * freq as u128 / 1_000_000_000) as u64);

        // Sleep until we reach or pass the target time
        while read_timer_counter() < target_ticks {
            los_sched::yield_now();
        }

        return Ok(0);
    }

    // Relative time (flags == 0) - same logic as nanosleep
    let seconds = req.tv_sec as u64;
    let nanoseconds = req.tv_nsec as u64;

    // Normalize nanoseconds if > 1e9 (shouldn't happen due to validation, but be safe)
    let extra_secs = nanoseconds / 1_000_000_000;
    let norm_nanos = nanoseconds % 1_000_000_000;
    let total_secs = seconds.saturating_add(extra_secs);

    if freq == 0 {
        // Fallback path without timer
        let millis = total_secs
            .saturating_mul(1000)
            .saturating_add(norm_nanos / 1_000_000);
        for _ in 0..(millis.min(u64::MAX) as usize).min(1_000_000) {
            los_sched::yield_now();
        }
        return Ok(0);
    }

    let start = read_timer_counter();

    // Calculate ticks with overflow protection
    let ticks_from_secs = total_secs.saturating_mul(freq);
    let ticks_from_nanos = (norm_nanos as u128 * freq as u128 / 1_000_000_000) as u64;
    let ticks_to_wait = ticks_from_secs.saturating_add(ticks_from_nanos);

    let target = start.saturating_add(ticks_to_wait);

    while read_timer_counter() < target {
        los_sched::yield_now();
    }

    // TODO: If interrupted, write remaining time to rem_ptr

    Ok(0)
}

/// TEAM_170: sys_clock_gettime - Get current monotonic time.
/// TEAM_360: Fixed to accept clockid as first argument (Linux ABI).
/// TEAM_413: Updated to use write_struct_to_user helper.
/// TEAM_421: Returns SyscallResult
///
/// # Arguments
/// * `clockid` - Clock to query (CLOCK_REALTIME=0, CLOCK_MONOTONIC=1, etc.)
/// * `timespec_buf` - User pointer to store result
pub fn sys_clock_gettime(clockid: i32, timespec_buf: usize) -> SyscallResult {
    // TEAM_360: We ignore clockid and always return monotonic time
    let _ = clockid;
    let task = los_sched::current_task();
    let freq = read_timer_frequency();
    let counter = read_timer_counter();

    let ts = if freq > 0 {
        let seconds = counter / freq;
        let remainder = counter % freq;
        let nanoseconds = (remainder * 1_000_000_000) / freq;
        Timespec {
            tv_sec: seconds as i64,
            tv_nsec: nanoseconds as i64,
        }
    } else {
        Timespec::default()
    };

    // TEAM_413: Use write_struct_to_user helper
    write_struct_to_user(task.ttbr0.load(Ordering::Acquire), timespec_buf, &ts)?;
    Ok(0)
}
