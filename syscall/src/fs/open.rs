extern crate alloc;

use core::sync::atomic::Ordering;
use los_vfs::dispatch::*;
use los_vfs::error::VfsError;
use los_vfs::file::OpenFlags;
// TEAM_420: Direct linux_raw_sys imports, no shims
// TEAM_421: Import SyscallResult
use crate::{SyscallResult, read_user_cstring};
use linux_raw_sys::errno::{EACCES, EBADF, EEXIST, EINVAL, EIO, EMFILE, ENOENT, ENOMEM, ENOTDIR};
use linux_raw_sys::general::AT_FDCWD;
use los_sched::fd_table::FdType;

/// TEAM_345: sys_openat - Linux ABI compatible.
/// TEAM_421: Updated to return SyscallResult.
/// TEAM_430: Apply umask to mode when creating files.
/// TEAM_466: Fixed to resolve relative paths against CWD.
/// Signature: openat(dirfd, pathname, flags, mode)
///
/// TEAM_168: Original implementation.
/// TEAM_176: Updated to support opening directories for getdents.
/// TEAM_194: Updated to support tmpfs at /tmp with O_CREAT and O_TRUNC.
pub fn sys_openat(dirfd: i32, pathname: usize, flags: u32, mode: u32) -> SyscallResult {
    use core::sync::atomic::Ordering;
    let task = los_sched::current_task();

    // TEAM_345: Read null-terminated pathname (Linux ABI)
    let mut path_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let path_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), pathname, &mut path_buf)?;

    // TEAM_466: Resolve relative paths against CWD for AT_FDCWD
    let resolved_path = if dirfd == AT_FDCWD && !path_str.starts_with('/') {
        let cwd = task.cwd.lock();
        let base = cwd.trim_end_matches('/');
        if base.is_empty() {
            alloc::format!("/{}", path_str)
        } else {
            alloc::format!("{}/{}", base, path_str)
        }
    } else if !path_str.starts_with('/') && dirfd != AT_FDCWD {
        // TEAM_345: Handle dirfd (non-AT_FDCWD with relative path not yet supported)
        log::warn!(
            "[SYSCALL] openat: dirfd {} not yet supported for relative paths",
            dirfd
        );
        return Err(EBADF);
    } else {
        alloc::string::String::from(path_str)
    };

    // TEAM_247: Handle PTY devices
    if path_str == "/dev/ptmx" {
        if let Some(pair) = los_fs_tty::pty::allocate_pty() {
            let mut fd_table = task.fd_table.lock();
            match fd_table.alloc(FdType::PtyMaster(pair)) {
                Some(fd) => return Ok(fd as i64),
                None => return Err(EMFILE),
            }
        }
        return Err(ENOMEM);
    }

    if path_str.starts_with("/dev/pts/") {
        if let Ok(id) = path_str[9..].parse::<usize>() {
            if let Some(pair) = los_fs_tty::pty::get_pty(id) {
                let mut fd_table = task.fd_table.lock();
                match fd_table.alloc(FdType::PtySlave(pair)) {
                    Some(fd) => return Ok(fd as i64),
                    None => return Err(EMFILE),
                }
            }
        }
        return Err(ENOENT);
    }

    // TEAM_205: All paths now go through generic vfs_open
    // TEAM_430: Apply umask when creating files (mode & ~umask)
    // TEAM_466: Use resolved_path which includes CWD resolution
    let vfs_flags = OpenFlags::new(flags);
    let umask = task.umask.load(Ordering::Acquire);
    let effective_mode = mode & !umask;
    match vfs_open(&resolved_path, vfs_flags, effective_mode) {
        Ok(file) => {
            let mut fd_table = task.fd_table.lock();
            // TEAM_468: Pass cloexec flag from O_CLOEXEC
            let cloexec = vfs_flags.is_cloexec();
            match fd_table.alloc_cloexec(FdType::VfsFile(file), cloexec) {
                Some(fd) => Ok(fd as i64),
                None => Err(EMFILE),
            }
        }
        Err(VfsError::NotFound) => Err(ENOENT),
        Err(VfsError::AlreadyExists) => Err(EEXIST),
        Err(VfsError::NotADirectory) => Err(ENOTDIR),
        Err(VfsError::IsADirectory) => {
            Err(EIO) // Should not normally happen if vfs_open succeeded
        }
        Err(_) => Err(EIO),
    }
}

/// TEAM_168: sys_close - Close a file descriptor.
/// TEAM_421: Updated to return SyscallResult.
/// TEAM_467: Allow closing fd 0/1/2 - BusyBox uniq closes stdin to reopen file at fd 0.
pub fn sys_close(fd: usize) -> SyscallResult {
    let task = los_sched::current_task();
    let mut fd_table = task.fd_table.lock();

    // TEAM_467: Remove check for fd < 3. Programs like BusyBox uniq close stdin (fd 0)
    // and reopen a file to reuse the fd slot. This is a valid POSIX pattern.

    if fd_table.close(fd) {
        Ok(0)
    } else {
        Err(EBADF)
    }
}

// ============================================================================
// TEAM_350: faccessat - Check file accessibility
// ============================================================================

/// TEAM_350: sys_faccessat - Check file accessibility.
/// TEAM_421: Updated to return SyscallResult.
///
/// Checks whether the calling process can access the file pathname.
/// For LevitateOS (single-user, root), we only check file existence.
///
/// # Arguments
/// * `dirfd` - Directory file descriptor (AT_FDCWD for cwd)
/// * `pathname` - Path to check
/// * `mode` - Access mode (0=F_OK, 4=R_OK, 2=W_OK, 1=X_OK from linux-raw-sys)
/// * `flags` - Flags (AT_SYMLINK_NOFOLLOW, etc.)
///
/// # Returns
/// Ok(0) if access is permitted, Err(errno) otherwise.
#[allow(unused_variables)]
pub fn sys_faccessat(dirfd: i32, pathname: usize, mode: i32, flags: i32) -> SyscallResult {
    use los_vfs::dispatch::vfs_access;

    let task = los_sched::current_task();

    // TEAM_418: Use PATH_MAX from SSOT
    let mut path_buf = [0u8; linux_raw_sys::general::PATH_MAX as usize];
    let path_str = read_user_cstring(task.ttbr0.load(Ordering::Acquire), pathname, &mut path_buf)?;

    log::trace!(
        "[SYSCALL] faccessat(dirfd={}, path='{}', mode=0x{:x}, flags=0x{:x})",
        dirfd,
        path_str,
        mode,
        flags
    );

    // Handle dirfd (AT_FDCWD means use cwd)
    if dirfd != AT_FDCWD && !path_str.starts_with('/') {
        log::warn!(
            "[SYSCALL] faccessat: dirfd {} not yet supported for relative paths",
            dirfd
        );
        return Err(EBADF);
    }

    // TEAM_350: For single-user OS, we only check existence
    // R_OK, W_OK, X_OK always succeed if file exists (we're root)
    match vfs_access(path_str, mode as u32) {
        Ok(_) => Ok(0), // File exists, access granted
        Err(los_vfs::error::VfsError::NotFound) => Err(ENOENT),
        Err(los_vfs::error::VfsError::NotADirectory) => Err(ENOTDIR),
        Err(e) => {
            // TEAM_459: Log unexpected errors to help debug
            log::warn!("[SYSCALL] faccessat '{}' failed with: {:?}", path_str, e);
            Err(EACCES)
        }
    }
}
