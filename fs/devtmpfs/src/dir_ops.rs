//! TEAM_431: Devtmpfs Directory Operations
//!
//! Implements lookup and readdir for device filesystem directories.

extern crate alloc;

use alloc::string::ToString;
use alloc::sync::Arc;
use los_utils::Mutex;

use los_vfs::error::{VfsError, VfsResult};
use los_vfs::inode::Inode;
use los_vfs::mode;
use los_vfs::ops::{DirEntry, InodeOps};

use crate::node::{DevtmpfsNode, DevtmpfsNodeType};
use crate::DEVTMPFS;

/// TEAM_431: Devtmpfs Directory Operations
pub struct DevtmpfsDirOps;

impl InodeOps for DevtmpfsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> VfsResult<Arc<Inode>> {
        let node = inode
            .private::<Arc<Mutex<DevtmpfsNode>>>()
            .ok_or(VfsError::IoError)?;

        let node_inner = node.lock();
        if node_inner.node_type != DevtmpfsNodeType::Directory {
            return Err(VfsError::NotADirectory);
        }

        // Look up child by name
        if let Some(child) = node_inner.lookup_child(name) {
            let sb = inode.sb.upgrade().ok_or(VfsError::IoError)?;
            let devtmpfs_lock = DEVTMPFS.lock();
            let devtmpfs = devtmpfs_lock.as_ref().ok_or(VfsError::IoError)?;
            return Ok(devtmpfs.make_inode(child, Arc::downgrade(&sb)));
        }

        Err(VfsError::NotFound)
    }

    fn readdir(&self, inode: &Inode, offset: usize) -> VfsResult<Option<DirEntry>> {
        let node = inode
            .private::<Arc<Mutex<DevtmpfsNode>>>()
            .ok_or(VfsError::IoError)?;

        let node_inner = node.lock();
        if node_inner.node_type != DevtmpfsNodeType::Directory {
            return Err(VfsError::NotADirectory);
        }

        // offsets 0 and 1 are . and ..
        if offset == 0 {
            return Ok(Some(DirEntry {
                ino: node_inner.ino,
                name: ".".to_string(),
                file_type: mode::S_IFDIR,
            }));
        }
        if offset == 1 {
            let parent_ino = if let Some(p) = node_inner.parent.upgrade() {
                p.lock().ino
            } else {
                node_inner.ino // root's parent is itself
            };
            return Ok(Some(DirEntry {
                ino: parent_ino,
                name: "..".to_string(),
                file_type: mode::S_IFDIR,
            }));
        }

        // Index 2+ are actual children
        let child_idx = offset - 2;
        if child_idx < node_inner.children.len() {
            let entry = &node_inner.children[child_idx];
            let child_node = entry.node.lock();
            let file_type = match child_node.node_type {
                DevtmpfsNodeType::Directory => mode::S_IFDIR,
                DevtmpfsNodeType::CharDevice => mode::S_IFCHR,
            };
            let de = DirEntry {
                ino: child_node.ino,
                name: entry.name.clone(),
                file_type: mode::file_type(file_type),
            };
            Ok(Some(de))
        } else {
            Ok(None)
        }
    }
}

/// Static instance for use in inodes
pub static DEVTMPFS_DIR_OPS: DevtmpfsDirOps = DevtmpfsDirOps;
