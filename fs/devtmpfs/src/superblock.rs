//! TEAM_431: Devtmpfs Superblock
//!
//! Implements the Superblock trait for the device filesystem.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU64, Ordering};
use los_utils::Mutex;

use los_vfs::error::VfsResult;
use los_vfs::inode::Inode;
use los_vfs::mode;
use los_vfs::ops::InodeOps;
use los_vfs::superblock::{StatFs, Superblock};

use crate::device_ops::DEVTMPFS_CHARDEV_OPS;
use crate::dir_ops::DEVTMPFS_DIR_OPS;
use crate::node::{DevtmpfsNode, DevtmpfsNodeType};
use crate::uptime_seconds;

/// TEAM_431: The devtmpfs filesystem state
pub struct Devtmpfs {
    /// Root directory node
    pub(crate) root: Arc<Mutex<DevtmpfsNode>>,
    /// Next inode number
    pub(crate) next_ino: AtomicU64,
    /// VFS root inode (cached)
    pub(crate) vfs_root: Mutex<Option<Arc<Inode>>>,
}

impl Devtmpfs {
    /// Create a new devtmpfs instance
    pub fn new() -> Self {
        let now = uptime_seconds();
        Self {
            root: Arc::new(Mutex::new(DevtmpfsNode::new_root(1, now))),
            next_ino: AtomicU64::new(2),
            vfs_root: Mutex::new(None),
        }
    }

    /// Allocate a new inode number
    pub(crate) fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::SeqCst)
    }

    /// Create a character device in the root directory
    pub fn create_device(&self, name: &str, rdev: u64) {
        let now = uptime_seconds();
        let ino = self.alloc_ino();
        let device_node = Arc::new(Mutex::new(DevtmpfsNode::new_char_device(
            ino,
            rdev,
            Arc::downgrade(&self.root),
            now,
        )));

        let mut root = self.root.lock();
        root.add_child(String::from(name), device_node);
    }

    /// Create a directory in the root directory
    pub fn create_directory(&self, name: &str) {
        let now = uptime_seconds();
        let ino = self.alloc_ino();
        let dir_node = Arc::new(Mutex::new(DevtmpfsNode::new_directory(
            ino,
            Arc::downgrade(&self.root),
            now,
        )));

        let mut root = self.root.lock();
        root.add_child(String::from(name), dir_node);
        root.nlink += 1; // Parent gets extra link from child's ".."
    }

    /// Convert a DevtmpfsNode to a VFS Inode
    pub fn make_inode(
        &self,
        node: Arc<Mutex<DevtmpfsNode>>,
        sb: Weak<dyn Superblock>,
    ) -> Arc<Inode> {
        let node_locked = node.lock();
        let ino = node_locked.ino;
        let node_type = node_locked.node_type;
        // TEAM_431: rdev is stored in DevtmpfsNode and accessed via private data
        // (inode.rdev is a plain u64 that can't be modified after creation)
        let atime = node_locked.atime;
        let mtime = node_locked.mtime;
        let ctime = node_locked.ctime;
        drop(node_locked);

        let (file_mode, ops): (u32, &'static dyn InodeOps) = match node_type {
            DevtmpfsNodeType::Directory => (mode::S_IFDIR | 0o755, &DEVTMPFS_DIR_OPS),
            DevtmpfsNodeType::CharDevice => (mode::S_IFCHR | 0o666, &DEVTMPFS_CHARDEV_OPS),
        };

        let inode = Arc::new(Inode::new(ino, 0, file_mode, ops, sb, Box::new(node)));

        inode.atime.store(atime, Ordering::Relaxed);
        inode.mtime.store(mtime, Ordering::Relaxed);
        inode.ctime.store(ctime, Ordering::Relaxed);

        inode
    }
}

impl Superblock for Devtmpfs {
    fn root(&self) -> Arc<Inode> {
        let root_cache = self.vfs_root.lock();
        if let Some(ref root) = *root_cache {
            return Arc::clone(root);
        }
        panic!("Devtmpfs::root called before vfs_root was initialized");
    }

    fn statfs(&self) -> VfsResult<StatFs> {
        Ok(StatFs {
            f_type: 0x1373, // devtmpfs magic
            f_bsize: 4096,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 1024,
            f_ffree: 1024,
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: 0,
        })
    }

    fn fs_type(&self) -> &'static str {
        "devtmpfs"
    }

    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::SeqCst)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

impl Default for Devtmpfs {
    fn default() -> Self {
        Self::new()
    }
}
