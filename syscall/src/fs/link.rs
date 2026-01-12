use core::sync::atomic::Ordering;
use los_mm::user as mm_user;
use los_vfs::dispatch::*;
use los_vfs::error::VfsError;
// TEAM_420: Direct linux_raw_sys imports, no shims
// TEAM_421: Import SyscallResult
use crate::{SyscallResult, read_user_cstring, write_to_user_buf};
use linux_raw_sys::errno::{EBADF, EEXIST, EFAULT, EINVAL, EIO, ENOENT, ENOTDIR};
// TEAM_464: Import UTIME_* constants from linux-raw-sys (canonical source, u32)
use linux_raw_sys::general::{AT_FDCWD, UTIME_NOW, UTIME_OMIT};

/// TEAM_345: sys_utimensat - Linux ABI compatible.
/// TEAM_421: Updated to return SyscallResult.
/// Signature: utimensat(dirfd, pathname, times, flags)
///
/// TEAM_198: Original implementation.
pub fn sys_utimensat(dirfd: i32, pathname: usize, times: usize, _flags: u32) -> SyscallResult {
    let task = los_sched::current_task();

    // TEAM_418: Use PATH_MAX from SSOT
    let mut path_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let path_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), pathname, &mut path_buf)?;

    // TEAM_345: Handle dirfd
    if dirfd != AT_FDCWD && !path_str.starts_with('/') {
        log::warn!("[SYSCALL] utimensat: dirfd {} not yet supported", dirfd);
        return Err(EBADF);
    }

    // Get current time
    let now = crate::time::uptime_seconds();

    // Determine new atime and mtime
    let (atime, mtime) = if times == 0 {
        (Some(now), Some(now))
    } else {
        // struct timespec { u64 tv_sec; u64 tv_nsec; }
        let mut times_data = [0u64; 4]; // [atime_sec, atime_nsec, mtime_sec, mtime_nsec]
        for i in 0..4 {
            let mut val = 0u64;
            for j in 0..8 {
                if let Some(ptr) = mm_user::user_va_to_kernel_ptr(task.ttbr0.load(Ordering::Acquire), times + i * 8 + j) {
                    val |= (unsafe { *ptr } as u64) << (j * 8);
                } else {
                    return Err(EFAULT);
                }
            }
            times_data[i] = val;
        }

        // TEAM_464: Cast our u64 values to u32 for comparison with linux-raw-sys constants
        // (linux-raw-sys uses u32 for UTIME_NOW/UTIME_OMIT)
        let atime = if times_data[1] as u32 == UTIME_OMIT {
            None
        } else if times_data[1] as u32 == UTIME_NOW {
            Some(now)
        } else {
            Some(times_data[0])
        };
        let mtime = if times_data[3] as u32 == UTIME_OMIT {
            None
        } else if times_data[3] as u32 == UTIME_NOW {
            Some(now)
        } else {
            Some(times_data[2])
        };
        (atime, mtime)
    };

    vfs_utimes(path_str, atime, mtime)
        .map(|_| Ok(0))
        .unwrap_or_else(|e| Err(e.to_errno()))
}

/// TEAM_345: sys_linkat - Linux ABI compatible.
/// TEAM_421: Updated to return SyscallResult.
/// Signature: linkat(olddirfd, oldpath, newdirfd, newpath, flags)
pub fn sys_linkat(
    olddirfd: i32,
    oldpath: usize,
    newdirfd: i32,
    newpath: usize,
    _flags: u32,
) -> SyscallResult {
    let task = los_sched::current_task();

    // TEAM_418: Use PATH_MAX from SSOT
    let mut old_path_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let old_path_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), oldpath, &mut old_path_buf)?;

    // TEAM_418: Use PATH_MAX from SSOT
    let mut new_path_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let new_path_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), newpath, &mut new_path_buf)?;

    // TEAM_345: Handle dirfd
    if (olddirfd != AT_FDCWD && !old_path_str.starts_with('/'))
        || (newdirfd != AT_FDCWD && !new_path_str.starts_with('/'))
    {
        log::warn!("[SYSCALL] linkat: dirfd not yet supported");
        return Err(EBADF);
    }

    match vfs_link(old_path_str, new_path_str) {
        Ok(()) => Ok(0),
        Err(e) => Err(e.to_errno()),
    }
}

/// TEAM_345: sys_symlinkat - Linux ABI compatible.
/// TEAM_421: Updated to return SyscallResult.
/// TEAM_466: Fixed to resolve relative paths against CWD.
/// Signature: symlinkat(target, newdirfd, linkpath)
pub fn sys_symlinkat(target: usize, newdirfd: i32, linkpath: usize) -> SyscallResult {
    let task = los_sched::current_task();

    // TEAM_418: Use PATH_MAX from SSOT
    let mut target_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let target_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), target, &mut target_buf)?;

    // TEAM_418: Use PATH_MAX from SSOT
    let mut linkpath_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let linkpath_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), linkpath, &mut linkpath_buf)?;

    // TEAM_466: Resolve relative paths against CWD for AT_FDCWD
    let resolved_linkpath = if newdirfd == AT_FDCWD && !linkpath_str.starts_with('/') {
        let cwd = task.cwd.lock();
        let base = cwd.trim_end_matches('/');
        if base.is_empty() {
            alloc::format!("/{}", linkpath_str)
        } else {
            alloc::format!("{}/{}", base, linkpath_str)
        }
    } else if !linkpath_str.starts_with('/') && newdirfd != AT_FDCWD {
        log::warn!("[SYSCALL] symlinkat: dirfd {} not yet supported", newdirfd);
        return Err(EBADF);
    } else {
        alloc::string::String::from(linkpath_str)
    };

    match vfs_symlink(target_str, &resolved_linkpath) {
        Ok(()) => Ok(0),
        Err(VfsError::AlreadyExists) => Err(EEXIST),
        Err(VfsError::NotFound) => Err(ENOENT),
        Err(VfsError::NotADirectory) => Err(ENOTDIR),
        Err(_) => Err(EINVAL),
    }
}

/// TEAM_345: sys_readlinkat - Linux ABI compatible.
/// TEAM_421: Updated to return SyscallResult.
/// Signature: readlinkat(dirfd, pathname, buf, bufsiz)
pub fn sys_readlinkat(dirfd: i32, pathname: usize, buf: usize, bufsiz: usize) -> SyscallResult {
    let task = los_sched::current_task();

    // TEAM_418: Use PATH_MAX from SSOT
    let mut path_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let path_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), pathname, &mut path_buf)?;

    // TEAM_345: Handle dirfd
    if dirfd != AT_FDCWD && !path_str.starts_with('/') {
        log::warn!("[SYSCALL] readlinkat: dirfd {} not yet supported", dirfd);
        return Err(EBADF);
    }

    let buf_len = bufsiz;

    match vfs_readlink(path_str) {
        Ok(target) => {
            let n = target.len().min(buf_len);
            let target_bytes = target.as_bytes();
            for i in 0..n {
                if !write_to_user_buf(task.ttbr0.load(Ordering::Acquire), buf, i, target_bytes[i]) {
                    return Err(EFAULT);
                }
            }
            Ok(n as i64)
        }
        Err(VfsError::NotFound) => Err(ENOENT),
        Err(_) => Err(EIO),
    }
}
