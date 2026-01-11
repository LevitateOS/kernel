//! TEAM_422: Filesystem integration module for LevitateOS kernel binary.
//!
//! This module re-exports and organizes the various filesystem crates:
//! - `vfs` - Core VFS primitives (inode, dentry, file, etc.)
//! - `initramfs` - CPIO-based initramfs filesystem
//! - `tmpfs` - In-memory writable filesystem
//! - `mount` - Mount table management (from VFS)
//!
//! It also provides kernel-specific filesystem state like the INITRAMFS global.

extern crate alloc;

use alloc::sync::Arc;
use los_utils::Mutex;

// Re-export VFS as submodule
pub use los_vfs as vfs;

// Re-export initramfs
pub use los_fs_initramfs as initramfs;

// Re-export tmpfs
pub use los_fs_tmpfs as tmpfs;

// Re-export mount directly from VFS
pub use los_vfs::mount;

// Re-export common VFS types at fs level for convenience
pub use los_vfs::{
    Dentry, DentryCache, File, FileRef, Inode, InodeRef, OpenFlags, Pipe, PipeRef, Superblock,
    SuperblockRef, VfsError, VfsResult, dcache,
};

/// TEAM_120: Global initramfs superblock for syscall access.
///
/// This is set during boot in init.rs after parsing the initramfs.
pub static INITRAMFS: Mutex<Option<Arc<initramfs::InitramfsSuperblock>>> = Mutex::new(None);

/// TEAM_422: Initialize disk filesystem (ext4/FAT32).
///
/// This attempts to mount the disk image if a block device is available.
/// Returns Ok(()) if successful or if no disk is present.
/// Returns Err with message if mounting fails.
pub fn init() -> Result<(), &'static str> {
    // TEAM_422: Disk filesystem initialization is handled by block::init_disk_fs()
    // which is called from virtio.rs after block device detection.
    // This function is a placeholder for compatibility with existing init.rs code.
    log::debug!("[FS] Filesystem subsystem ready");
    Ok(())
}
