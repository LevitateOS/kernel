//! Shared kernel types for LevitateOS
//!
//! TEAM_422: This crate contains types shared across multiple kernel subsystems.
//! Types here must be architecture-agnostic or properly handle arch differences.

#![no_std]

use bitflags::bitflags;

// ============================================================================
// File Mode Constants
// ============================================================================

/// File type mask
pub const S_IFMT: u32 = 0o170000;
/// Regular file
pub const S_IFREG: u32 = 0o100000;
/// Directory
pub const S_IFDIR: u32 = 0o040000;
/// Character device
pub const S_IFCHR: u32 = 0o020000;
/// Block device
pub const S_IFBLK: u32 = 0o060000;
/// FIFO (named pipe)
pub const S_IFIFO: u32 = 0o010000;
/// Symbolic link
pub const S_IFLNK: u32 = 0o120000;
/// Socket
pub const S_IFSOCK: u32 = 0o140000;

/// Set-user-ID on execution
pub const S_ISUID: u32 = 0o4000;
/// Set-group-ID on execution
pub const S_ISGID: u32 = 0o2000;
/// Sticky bit
pub const S_ISVTX: u32 = 0o1000;

/// Owner read permission
pub const S_IRUSR: u32 = 0o0400;
/// Owner write permission
pub const S_IWUSR: u32 = 0o0200;
/// Owner execute permission
pub const S_IXUSR: u32 = 0o0100;
/// Group read permission
pub const S_IRGRP: u32 = 0o0040;
/// Group write permission
pub const S_IWGRP: u32 = 0o0020;
/// Group execute permission
pub const S_IXGRP: u32 = 0o0010;
/// Others read permission
pub const S_IROTH: u32 = 0o0004;
/// Others write permission
pub const S_IWOTH: u32 = 0o0002;
/// Others execute permission
pub const S_IXOTH: u32 = 0o0001;

// ============================================================================
// Stat Structure
// ============================================================================

/// File status structure (Linux ABI compatible)
///
/// Must be exactly 128 bytes on both architectures.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    /// Device ID containing file
    pub st_dev: u64,
    /// Inode number
    pub st_ino: u64,
    /// File type and permissions
    pub st_mode: u32,
    /// Number of hard links
    pub st_nlink: u32,
    /// Owner user ID
    pub st_uid: u32,
    /// Owner group ID
    pub st_gid: u32,
    /// Device ID (if special file)
    pub st_rdev: u64,
    /// Padding
    __pad1: u64,
    /// File size in bytes
    pub st_size: i64,
    /// Block size for filesystem I/O
    pub st_blksize: i32,
    /// Padding
    __pad2: i32,
    /// Number of 512-byte blocks allocated
    pub st_blocks: i64,
    /// Access time (seconds)
    pub st_atime: i64,
    /// Access time (nanoseconds)
    pub st_atime_nsec: u64,
    /// Modification time (seconds)
    pub st_mtime: i64,
    /// Modification time (nanoseconds)
    pub st_mtime_nsec: u64,
    /// Status change time (seconds)
    pub st_ctime: i64,
    /// Status change time (nanoseconds)
    pub st_ctime_nsec: u64,
    /// Unused
    __unused: [u32; 2],
}

impl Stat {
    /// Create Stat for a character/block device
    pub fn new_device(mode: u32, rdev: u64) -> Self {
        Self {
            st_mode: mode,
            st_nlink: 1,
            st_rdev: rdev,
            ..Default::default()
        }
    }

    /// Create Stat for a regular file
    pub fn new_file(mode: u32, size: i64, ino: u64) -> Self {
        Self {
            st_mode: S_IFREG | mode,
            st_nlink: 1,
            st_size: size,
            st_ino: ino,
            st_blksize: 4096,
            st_blocks: (size + 511) / 512,
            ..Default::default()
        }
    }

    /// Create Stat for a directory
    pub fn new_dir(mode: u32, ino: u64) -> Self {
        Self {
            st_mode: S_IFDIR | mode,
            st_nlink: 2,
            st_ino: ino,
            st_blksize: 4096,
            ..Default::default()
        }
    }

    /// Create Stat for a symbolic link
    pub fn new_symlink(mode: u32, size: i64, ino: u64) -> Self {
        Self {
            st_mode: S_IFLNK | mode,
            st_nlink: 1,
            st_size: size,
            st_ino: ino,
            st_blksize: 4096,
            ..Default::default()
        }
    }

    /// Create Stat for a pipe (FIFO)
    pub fn new_pipe(blksize: i32) -> Self {
        Self {
            st_mode: S_IFIFO | 0o600,
            st_nlink: 1,
            st_blksize: blksize,
            ..Default::default()
        }
    }

    /// Create Stat from inode data (used by VFS)
    #[allow(clippy::too_many_arguments)]
    pub fn from_inode_data(
        dev: u64,
        ino: u64,
        mode: u32,
        nlink: u32,
        uid: u32,
        gid: u32,
        rdev: u64,
        size: i64,
        blksize: i32,
        blocks: i64,
        atime: i64,
        mtime: i64,
        ctime: i64,
    ) -> Self {
        Self {
            st_dev: dev,
            st_ino: ino,
            st_mode: mode,
            st_nlink: nlink,
            st_uid: uid,
            st_gid: gid,
            st_rdev: rdev,
            st_size: size,
            st_blksize: blksize,
            st_blocks: blocks,
            st_atime: atime,
            st_atime_nsec: 0,
            st_mtime: mtime,
            st_mtime_nsec: 0,
            st_ctime: ctime,
            st_ctime_nsec: 0,
            ..Default::default()
        }
    }
}

// ============================================================================
// Time Types
// ============================================================================

/// Time value with microsecond precision
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// Time value with nanosecond precision
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

// ============================================================================
// Open Flags
// ============================================================================

bitflags! {
    /// File open flags (Linux ABI)
    #[derive(Clone, Copy, Debug, Default)]
    pub struct OpenFlags: u32 {
        const O_RDONLY = 0;
        const O_WRONLY = 1;
        const O_RDWR = 2;
        const O_CREAT = 0o100;
        const O_EXCL = 0o200;
        const O_NOCTTY = 0o400;
        const O_TRUNC = 0o1000;
        const O_APPEND = 0o2000;
        const O_NONBLOCK = 0o4000;
        const O_DIRECTORY = 0o200000;
        const O_CLOEXEC = 0o2000000;
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Filesystem error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    PermissionDenied,
    NotDirectory,
    IsDirectory,
    AlreadyExists,
    NotEmpty,
    InvalidPath,
    TooManyLinks,
    NoSpace,
    IoError,
    ReadOnly,
    InvalidArgument,
    NotSupported,
}

/// Block device error type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    IoError,
    OutOfBounds,
    NotReady,
    InvalidOperation,
}
