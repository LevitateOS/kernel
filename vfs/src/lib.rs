#![no_std]
//! TEAM_202: Virtual Filesystem (VFS) Core
//!
//! This module provides the core VFS abstractions that allow the kernel
//! to work with any filesystem through a unified interface.
#![allow(unused_imports)]
//!
//! ## Architecture
//!
//! ```text
//! +------------------+
//! |   System Calls   |
//! +------------------+
//!          |
//!          v
//! +------------------+
//! |   VFS Dispatch   |  vfs_open, vfs_read, vfs_write, etc.
//! +------------------+
//!          |
//!          v
//! +------------------+
//! |  Dentry Cache    |  Path → Inode resolution
//! +------------------+
//!          |
//!          v
//! +------------------+
//! |     Inode        |  In-memory file/dir representation
//! +------------------+
//!          |
//!          v
//! +------------------+
//! |   InodeOps       |  Filesystem-specific operations
//! +------------------+
//! ```

pub mod dentry;
pub mod dispatch;
pub mod error;
pub mod file;
pub mod inode;
pub mod mode;
pub mod mount; // TEAM_422: Export mount module for los_syscall
pub mod ops;
pub mod path; // TEAM_422: Export path module for los_syscall
pub mod pipe; // TEAM_422: Export pipe module for los_sched::fd_table
pub mod superblock;

// Re-export main types at module level for convenience
pub use dentry::{Dentry, DentryCache, DentryRef, dcache};
pub use error::{VfsError, VfsResult};
pub use file::{File, FileRef, OpenFlags};
pub use inode::{Inode, InodeRef, WeakInodeRef};
pub use ops::{DirEntry, FileOps, InodeOps, PollEvents, SeekWhence, SetAttr};
pub use pipe::{Pipe, PipeRef}; // TEAM_422: Export pipe types
pub use superblock::{StatFs, Superblock, SuperblockRef};

// Re-export dispatch functions
pub use dispatch::{
    vfs_access, vfs_fstat, vfs_mkdir, vfs_open, vfs_read, vfs_readdir, vfs_readlink, vfs_rename,
    vfs_rmdir, vfs_seek, vfs_stat, vfs_symlink, vfs_truncate, vfs_unlink, vfs_write,
};
