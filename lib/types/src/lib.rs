//! Shared kernel types for LevitateOS
//!
//! TEAM_422: This crate contains types shared across multiple kernel subsystems.
//! Types here must be architecture-agnostic or properly handle arch differences.
//!
//! TEAM_464: Use linux-raw-sys constants as canonical source.

#![no_std]

use bitflags::bitflags;

// ============================================================================
// File Mode Constants
// ============================================================================
// TEAM_464: Re-export S_* constants from linux-raw-sys as canonical source

pub use linux_raw_sys::general::{
    // File type mask and types
    S_IFMT, S_IFREG, S_IFDIR, S_IFCHR, S_IFBLK, S_IFIFO, S_IFLNK, S_IFSOCK,
    // Special bits
    S_ISUID, S_ISGID, S_ISVTX,
    // Owner permissions
    S_IRUSR, S_IWUSR, S_IXUSR,
    // Group permissions
    S_IRGRP, S_IWGRP, S_IXGRP,
    // Others permissions
    S_IROTH, S_IWOTH, S_IXOTH,
};

// ============================================================================
// Stat Structure - Architecture Specific
// ============================================================================
//
// TEAM_446: Linux has different stat struct layouts per architecture!
// - aarch64 uses asm-generic layout (128 bytes)
// - x86_64 has its own layout (144 bytes) with st_nlink BEFORE st_mode
//
// References:
// - https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/stat.h
// - https://github.com/torvalds/linux/blob/master/arch/x86/include/uapi/asm/stat.h

#[cfg(target_arch = "aarch64")]
mod stat_impl {
    use super::*;

    /// File status structure (Linux AArch64 ABI - asm-generic layout)
    ///
    /// TEAM_446: This is the correct 128-byte layout for aarch64.
    /// Uses asm-generic/stat.h structure.
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

    // Compile-time size check
    const _: () = assert!(core::mem::size_of::<Stat>() == 128);

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
        /// Note: blksize is i64 for API consistency across architectures
        pub fn new_pipe(blksize: i64) -> Self {
            Self {
                st_mode: S_IFIFO | 0o600,
                st_nlink: 1,
                st_blksize: blksize as i32,
                ..Default::default()
            }
        }

        /// Create Stat from inode data (used by VFS)
        /// Note: blksize is i64 for API consistency across architectures
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
            blksize: i64,
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
                st_blksize: blksize as i32,
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
}

#[cfg(target_arch = "x86_64")]
mod stat_impl {
    use super::*;

    /// File status structure (Linux x86_64 ABI)
    ///
    /// TEAM_446: This is the correct 144-byte layout for x86_64.
    /// Key differences from aarch64:
    /// - st_nlink comes BEFORE st_mode and is 8 bytes (not 4)
    /// - st_blksize and st_blocks are 8 bytes (not 4)
    /// - Total size is 144 bytes (not 128)
    ///
    /// Reference: arch/x86/include/uapi/asm/stat.h
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Stat {
        /// Device ID containing file
        pub st_dev: u64,
        /// Inode number
        pub st_ino: u64,
        /// Number of hard links (NOTE: before st_mode on x86_64!)
        pub st_nlink: u64,
        /// File type and permissions
        pub st_mode: u32,
        /// Owner user ID
        pub st_uid: u32,
        /// Owner group ID
        pub st_gid: u32,
        /// Padding
        __pad0: u32,
        /// Device ID (if special file)
        pub st_rdev: u64,
        /// File size in bytes
        pub st_size: i64,
        /// Block size for filesystem I/O
        pub st_blksize: i64,
        /// Number of 512-byte blocks allocated
        pub st_blocks: i64,
        /// Access time (seconds)
        pub st_atime: u64,
        /// Access time (nanoseconds)
        pub st_atime_nsec: u64,
        /// Modification time (seconds)
        pub st_mtime: u64,
        /// Modification time (nanoseconds)
        pub st_mtime_nsec: u64,
        /// Status change time (seconds)
        pub st_ctime: u64,
        /// Status change time (nanoseconds)
        pub st_ctime_nsec: u64,
        /// Unused
        __unused: [i64; 3],
    }

    // Compile-time size check
    const _: () = assert!(core::mem::size_of::<Stat>() == 144);

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
        pub fn new_pipe(blksize: i64) -> Self {
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
            blksize: i64,
            blocks: i64,
            atime: i64,
            mtime: i64,
            ctime: i64,
        ) -> Self {
            Self {
                st_dev: dev,
                st_ino: ino,
                st_nlink: nlink as u64,
                st_mode: mode,
                st_uid: uid,
                st_gid: gid,
                st_rdev: rdev,
                st_size: size,
                st_blksize: blksize,
                st_blocks: blocks,
                st_atime: atime as u64,
                st_atime_nsec: 0,
                st_mtime: mtime as u64,
                st_mtime_nsec: 0,
                st_ctime: ctime as u64,
                st_ctime_nsec: 0,
                ..Default::default()
            }
        }
    }
}

// Re-export the architecture-specific Stat
#[cfg(target_arch = "aarch64")]
pub use stat_impl::Stat;

#[cfg(target_arch = "x86_64")]
pub use stat_impl::Stat;

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
