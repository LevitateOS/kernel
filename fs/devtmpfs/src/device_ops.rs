//! TEAM_431: Character device InodeOps implementation
//!
//! Dispatches read/write operations to the device registry based on major:minor.

extern crate alloc;

use alloc::sync::Arc;
use los_utils::Mutex;
use los_vfs::inode::Inode;
use los_vfs::ops::InodeOps;
use los_vfs::{VfsError, VfsResult};

use crate::devices::lookup_char_device;
use crate::node::DevtmpfsNode;

/// InodeOps implementation for character devices
///
/// Dispatches operations to the device registry based on inode's rdev
pub struct DevtmpfsCharDevOps;

impl DevtmpfsCharDevOps {
    /// TEAM_431: Get rdev from the DevtmpfsNode stored in inode private data
    fn get_rdev(inode: &Inode) -> VfsResult<u64> {
        let node = inode
            .private::<Arc<Mutex<DevtmpfsNode>>>()
            .ok_or(VfsError::IoError)?;
        Ok(node.lock().rdev)
    }
}

impl InodeOps for DevtmpfsCharDevOps {
    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let rdev = Self::get_rdev(inode)?;
        let ops = lookup_char_device(rdev).ok_or(VfsError::NoData)?;
        ops.read(offset, buf)
    }

    fn write(&self, inode: &Inode, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let rdev = Self::get_rdev(inode)?;
        let ops = lookup_char_device(rdev).ok_or(VfsError::NoData)?;
        ops.write(offset, buf)
    }

    fn truncate(&self, _inode: &Inode, _size: u64) -> VfsResult<()> {
        // Truncate is a no-op for devices
        Ok(())
    }
}

/// Static instance for use in inodes
pub static DEVTMPFS_CHARDEV_OPS: DevtmpfsCharDevOps = DevtmpfsCharDevOps;
