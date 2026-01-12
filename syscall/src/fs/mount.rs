use core::sync::atomic::Ordering;
// TEAM_206: Mount syscalls
// TEAM_421: Returns SyscallResult, no scattered casts

use crate::SyscallResult;
use core::convert::TryFrom;
use linux_raw_sys::errno::{EACCES, EBUSY, EFAULT, EINVAL, ENOENT};

// TEAM_206: Mount a filesystem
/// TEAM_421: Returns SyscallResult
pub fn sys_mount(
    source_ptr: usize,
    target_ptr: usize,
    fstype_ptr: usize,
    flags: usize,
    _data_ptr: usize,
) -> SyscallResult {
    let task = los_sched::current_task();
    let ttbr0 = task.ttbr0.load(Ordering::Acquire);

    // Read source string
    let source = match crate::sys::read_user_string(ttbr0, source_ptr, 256) {
        Ok(s) => s,
        Err(_) => return Err(EFAULT),
    };

    // Read target string
    let target = match crate::sys::read_user_string(ttbr0, target_ptr, 256) {
        Ok(s) => s,
        Err(_) => return Err(EFAULT),
    };

    // Read fstype string
    let fstype_str = match crate::sys::read_user_string(ttbr0, fstype_ptr, 64) {
        Ok(s) => s,
        Err(_) => return Err(EFAULT),
    };

    // Convert fstype
    let fstype = match los_vfs::mount::FsType::try_from(fstype_str.as_str()) {
        Ok(t) => t,
        Err(_) => return Err(EINVAL),
    };

    // Convert flags (simplified)
    let mount_flags = if (flags & 1) != 0 {
        los_vfs::mount::MountFlags::readonly()
    } else {
        los_vfs::mount::MountFlags::new()
    };

    match los_vfs::mount::mount(
        los_vfs::path::Path::new(&target),
        fstype,
        mount_flags,
        &source,
    ) {
        Ok(_) => Ok(0),
        Err(e) => match e {
            los_vfs::mount::MountError::AlreadyMounted => Err(EBUSY),
            los_vfs::mount::MountError::NotMounted => Err(EINVAL),
            los_vfs::mount::MountError::InvalidMountpoint => Err(ENOENT),
            los_vfs::mount::MountError::UnsupportedFsType => Err(EINVAL),
            los_vfs::mount::MountError::PermissionDenied => Err(EACCES),
        },
    }
}

// TEAM_206: Unmount a filesystem
/// TEAM_421: Returns SyscallResult
pub fn sys_umount(target_ptr: usize, _flags: usize) -> SyscallResult {
    let task = los_sched::current_task();
    let ttbr0 = task.ttbr0.load(Ordering::Acquire);

    // Read target string
    let target = match crate::sys::read_user_string(ttbr0, target_ptr, 256) {
        Ok(s) => s,
        Err(_) => return Err(EFAULT),
    };

    match los_vfs::mount::umount(los_vfs::path::Path::new(&target)) {
        Ok(_) => Ok(0),
        Err(_) => Err(EINVAL),
    }
}
