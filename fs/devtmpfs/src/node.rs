//! TEAM_431: devtmpfs node types
//!
//! Defines the node structure for device filesystem entries.

extern crate alloc;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use los_utils::Mutex;

/// Node type in devtmpfs
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DevtmpfsNodeType {
    /// Directory containing device files
    Directory,
    /// Character device (e.g., /dev/null)
    CharDevice,
}

/// Directory entry in devtmpfs
pub struct DevtmpfsDirEntry {
    pub name: String,
    pub node: Arc<Mutex<DevtmpfsNode>>,
}

/// A node in the devtmpfs tree
pub struct DevtmpfsNode {
    /// Inode number (unique within filesystem)
    pub ino: u64,
    /// Node type
    pub node_type: DevtmpfsNodeType,
    /// Device number (major:minor) for device nodes
    pub rdev: u64,
    /// Children (for directories only)
    pub children: Vec<DevtmpfsDirEntry>,
    /// Access time (seconds since boot)
    pub atime: u64,
    /// Modification time (seconds since boot)
    pub mtime: u64,
    /// Change time (seconds since boot)
    pub ctime: u64,
    /// Parent directory (weak ref to avoid cycles)
    pub parent: Weak<Mutex<DevtmpfsNode>>,
    /// Hard link count
    pub nlink: u32,
}

impl DevtmpfsNode {
    /// Create a new root directory node
    pub fn new_root(ino: u64, now: u64) -> Self {
        Self {
            ino,
            node_type: DevtmpfsNodeType::Directory,
            rdev: 0,
            children: Vec::new(),
            atime: now,
            mtime: now,
            ctime: now,
            parent: Weak::new(),
            nlink: 2, // . and parent
        }
    }

    /// Create a new directory node
    pub fn new_directory(ino: u64, parent: Weak<Mutex<DevtmpfsNode>>, now: u64) -> Self {
        Self {
            ino,
            node_type: DevtmpfsNodeType::Directory,
            rdev: 0,
            children: Vec::new(),
            atime: now,
            mtime: now,
            ctime: now,
            parent,
            nlink: 2,
        }
    }

    /// Create a new character device node
    pub fn new_char_device(
        ino: u64,
        rdev: u64,
        parent: Weak<Mutex<DevtmpfsNode>>,
        now: u64,
    ) -> Self {
        Self {
            ino,
            node_type: DevtmpfsNodeType::CharDevice,
            rdev,
            children: Vec::new(),
            atime: now,
            mtime: now,
            ctime: now,
            parent,
            nlink: 1,
        }
    }

    /// Look up a child by name
    pub fn lookup_child(&self, name: &str) -> Option<Arc<Mutex<DevtmpfsNode>>> {
        self.children
            .iter()
            .find(|e| e.name == name)
            .map(|e| Arc::clone(&e.node))
    }

    /// Add a child to this directory
    pub fn add_child(&mut self, name: String, node: Arc<Mutex<DevtmpfsNode>>) {
        self.children.push(DevtmpfsDirEntry { name, node });
    }
}
