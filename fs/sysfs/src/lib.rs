//! TEAM_469: Sysfs - System Filesystem Stub
//!
//! A minimal stub implementation of sysfs that mounts successfully
//! but provides only empty directory structures.
//! Full sysfs implementation can be added later when device enumeration is needed.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use linux_raw_sys::general::S_IFDIR;
use los_hal::IrqSafeLock;
use los_utils::Mutex;
use los_vfs::error::{VfsError, VfsResult};
use los_vfs::inode::Inode;
use los_vfs::ops::{DirEntry, InodeOps};
use los_vfs::superblock::Superblock;

// ============================================================================
// Entry Types
// ============================================================================

/// TEAM_469: Sysfs entry type
#[derive(Clone, Debug)]
pub enum SysfsEntry {
    /// Root /sys/ directory
    Root,
    /// /sys/class/ directory
    Class,
    /// /sys/devices/ directory
    Devices,
}

impl SysfsEntry {
    /// Get mode for this entry
    pub fn mode(&self) -> u32 {
        S_IFDIR | 0o555
    }
}

// ============================================================================
// Superblock
// ============================================================================

/// TEAM_469: Sysfs superblock (minimal stub)
pub struct SysfsSuperblock {
    next_ino: AtomicU64,
    vfs_root: IrqSafeLock<Option<Arc<Inode>>>,
}

impl SysfsSuperblock {
    pub fn new() -> Self {
        Self {
            next_ino: AtomicU64::new(2),
            vfs_root: IrqSafeLock::new(None),
        }
    }
}

impl Default for SysfsSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

impl Superblock for SysfsSuperblock {
    fn root(&self) -> Arc<Inode> {
        let mut root = self.vfs_root.lock();
        if let Some(ref r) = *root {
            return Arc::clone(r);
        }

        // Get weak reference to ourselves
        let sb_weak = {
            let sb_lock = SYSFS_SUPERBLOCK.lock();
            sb_lock
                .as_ref()
                .map(Arc::downgrade)
                .unwrap_or_else(|| Arc::downgrade(&Arc::new(SysfsSuperblock::new())))
        };

        let inode = Arc::new(Inode {
            ino: 1,
            dev: 0,
            mode: AtomicU32::new(S_IFDIR | 0o555),
            nlink: AtomicU32::new(2),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            rdev: 0,
            size: AtomicU64::new(0),
            atime: AtomicU64::new(0),
            mtime: AtomicU64::new(0),
            ctime: AtomicU64::new(0),
            blksize: 4096,
            private: Box::new(SysfsEntry::Root),
            ops: &SYSFS_DIR_OPS,
            sb: sb_weak,
        });

        *root = Some(Arc::clone(&inode));
        inode
    }

    fn statfs(&self) -> VfsResult<los_vfs::StatFs> {
        Ok(los_vfs::StatFs {
            f_type: 0x62656572, // SYSFS_MAGIC
            f_bsize: 4096,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: 0,
        })
    }

    fn fs_type(&self) -> &'static str {
        "sysfs"
    }

    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Global Superblock
// ============================================================================

/// Global sysfs superblock
pub static SYSFS_SUPERBLOCK: Mutex<Option<Arc<SysfsSuperblock>>> = Mutex::new(None);

/// Create a sysfs superblock
pub fn create_superblock() -> Arc<dyn Superblock + Send + Sync> {
    let mut sb = SYSFS_SUPERBLOCK.lock();
    if sb.is_none() {
        *sb = Some(Arc::new(SysfsSuperblock::new()));
    }
    Arc::clone(sb.as_ref().unwrap()) as Arc<dyn Superblock + Send + Sync>
}

// ============================================================================
// Directory Operations
// ============================================================================

/// TEAM_469: Sysfs directory operations (minimal stub)
pub struct SysfsDirOps;

static SYSFS_DIR_OPS: SysfsDirOps = SysfsDirOps;

impl InodeOps for SysfsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> VfsResult<Arc<Inode>> {
        let entry = inode
            .private
            .downcast_ref::<SysfsEntry>()
            .ok_or(VfsError::IoError)?;

        match entry {
            SysfsEntry::Root => match name {
                "class" => create_inode(SysfsEntry::Class),
                "devices" => create_inode(SysfsEntry::Devices),
                _ => Err(VfsError::NotFound),
            },
            // Subdirectories are empty for now
            SysfsEntry::Class | SysfsEntry::Devices => Err(VfsError::NotFound),
        }
    }

    fn readdir(&self, inode: &Inode, offset: usize) -> VfsResult<Option<DirEntry>> {
        let entry = inode
            .private
            .downcast_ref::<SysfsEntry>()
            .ok_or(VfsError::IoError)?;

        match entry {
            SysfsEntry::Root => {
                let entries = [("class", 2u64), ("devices", 3u64)];
                if offset >= entries.len() {
                    return Ok(None);
                }
                let (name, ino) = entries[offset];
                Ok(Some(DirEntry {
                    name: String::from(name),
                    ino,
                    file_type: S_IFDIR,
                }))
            }
            // Subdirectories are empty
            SysfsEntry::Class | SysfsEntry::Devices => Ok(None),
        }
    }
}

/// Create an inode for a sysfs entry
fn create_inode(entry: SysfsEntry) -> VfsResult<Arc<Inode>> {
    let sb_lock = SYSFS_SUPERBLOCK.lock();
    let sb = sb_lock.as_ref().ok_or(VfsError::IoError)?;
    let ino = sb.alloc_ino();
    let sb_weak = Arc::downgrade(sb);
    drop(sb_lock);

    Ok(Arc::new(Inode {
        ino,
        dev: 0,
        mode: AtomicU32::new(entry.mode()),
        nlink: AtomicU32::new(2),
        uid: AtomicU32::new(0),
        gid: AtomicU32::new(0),
        rdev: 0,
        size: AtomicU64::new(0),
        atime: AtomicU64::new(0),
        mtime: AtomicU64::new(0),
        ctime: AtomicU64::new(0),
        blksize: 4096,
        private: Box::new(entry),
        ops: &SYSFS_DIR_OPS,
        sb: sb_weak,
    }))
}
