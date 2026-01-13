use core::sync::atomic::Ordering;
// TEAM_206: Mount syscalls
// TEAM_421: Returns SyscallResult, no scattered casts
// TEAM_469: Added procfs and sysfs support with dentry mounting

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use crate::SyscallResult;
use core::convert::TryFrom;
use linux_raw_sys::errno::{EACCES, EBUSY, EFAULT, EINVAL, ENOENT};
use los_vfs::dentry::Dentry;
use los_vfs::mount::FsType;
use los_vfs::superblock::Superblock;

// TEAM_206: Mount a filesystem
/// TEAM_421: Returns SyscallResult
/// TEAM_469: Now actually mounts filesystems via dentry, not just tracking
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
    let fstype = match FsType::try_from(fstype_str.as_str()) {
        Ok(t) => t,
        Err(_) => return Err(EINVAL),
    };

    // Convert flags (simplified)
    let mount_flags = if (flags & 1) != 0 {
        los_vfs::mount::MountFlags::readonly()
    } else {
        los_vfs::mount::MountFlags::new()
    };

    // TEAM_469: Create the appropriate superblock for the filesystem type
    let superblock: Arc<dyn Superblock + Send + Sync> = match fstype {
        FsType::Tmpfs => los_fs_tmpfs::create_superblock(),
        FsType::Procfs => los_fs_procfs::create_superblock(),
        FsType::Sysfs => los_fs_sysfs::create_superblock(),
        // Other filesystems don't support dynamic mounting yet
        _ => return Err(EINVAL),
    };

    // TEAM_469: Get the target dentry and mount the filesystem
    let mount_result = mount_at_dentry(&target, superblock);

    if mount_result.is_err() {
        return Err(ENOENT);
    }

    // Also record in mount table for tracking
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

/// TEAM_469: Mount a filesystem at a dentry path
fn mount_at_dentry(target: &str, superblock: Arc<dyn Superblock + Send + Sync>) -> Result<(), ()> {
    // Get root dentry
    let root = los_vfs::dcache().root().ok_or(())?;

    // Normalize target path
    let target = target.trim_start_matches('/');
    if target.is_empty() {
        // Mounting at root - not supported this way
        return Err(());
    }

    // Find or create parent dentry
    let parts: alloc::vec::Vec<&str> = target.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return Err(());
    }

    let mut current = root;

    // Walk to parent, creating dentries if needed
    for (i, part) in parts.iter().enumerate() {
        if i == parts.len() - 1 {
            // This is the final component - create/get mount point dentry
            let mount_dentry = current.lookup_child(part).unwrap_or_else(|| {
                let d = Arc::new(Dentry::new(
                    String::from(*part),
                    Some(Arc::downgrade(&current)),
                    None, // No inode - mount will provide it
                ));
                current.add_child(Arc::clone(&d));
                d
            });

            // Mount the filesystem at this dentry
            mount_dentry.mount(superblock);
            return Ok(());
        } else {
            // Intermediate component - look it up
            current = match current.lookup_child(part) {
                Some(d) => d,
                None => {
                    // Try to look up in filesystem
                    let inode = current.get_inode().ok_or(())?;
                    let child_inode = inode.lookup(part).map_err(|_| ())?;
                    let d = Arc::new(Dentry::new(
                        String::from(*part),
                        Some(Arc::downgrade(&current)),
                        Some(child_inode),
                    ));
                    current.add_child(Arc::clone(&d));
                    d
                }
            };
        }
    }

    Err(())
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
