#![no_std]
//! TEAM_431: devtmpfs — Device filesystem for LevitateOS.
//!
//! Provides device files at `/dev` for Unix compatibility:
//! - `/dev/null` (1:3) - Data sink, reads return EOF
//! - `/dev/zero` (1:5) - Reads return zeros
//! - `/dev/full` (1:7) - Writes return ENOSPC
//! - `/dev/urandom` (1:9) - Reads return random bytes
//!
//! Module structure:
//! - `node.rs` - DevtmpfsNode types
//! - `superblock.rs` - Devtmpfs struct, Superblock impl
//! - `device_ops.rs` - InodeOps for character devices
//! - `dir_ops.rs` - InodeOps for directories
//! - `devices/` - Individual device implementations

extern crate alloc;

use alloc::sync::Arc;
use los_utils::Mutex;

use los_vfs::superblock::Superblock;

// Submodules
mod device_ops;
mod dir_ops;
pub mod devices;
pub mod node;
mod superblock;

// Re-exports for public API
pub use superblock::Devtmpfs;

/// TEAM_431: Global devtmpfs instance
pub static DEVTMPFS: Mutex<Option<Arc<Devtmpfs>>> = Mutex::new(None);

/// TEAM_431: Initialize the devtmpfs with standard device nodes
pub fn init() {
    use devices::devno::{MEM_MAJOR, NULL_MINOR, ZERO_MINOR, FULL_MINOR, URANDOM_MINOR, TTY_MAJOR, CONSOLE_MINOR};
    use devices::makedev;

    // Register built-in device drivers
    devices::register_builtin_devices();

    // Create filesystem instance
    let devtmpfs = Arc::new(Devtmpfs::new());

    // Create device nodes
    devtmpfs.create_device("null", makedev(MEM_MAJOR, NULL_MINOR));
    devtmpfs.create_device("zero", makedev(MEM_MAJOR, ZERO_MINOR));
    devtmpfs.create_device("full", makedev(MEM_MAJOR, FULL_MINOR));
    devtmpfs.create_device("urandom", makedev(MEM_MAJOR, URANDOM_MINOR));
    // TEAM_453: Console device for BusyBox init
    devtmpfs.create_device("console", makedev(TTY_MAJOR, CONSOLE_MINOR));

    // Create /dev/pts directory for future PTY support
    devtmpfs.create_directory("pts");

    // Initialize VFS root inode
    let root_inode = devtmpfs.make_inode(
        Arc::clone(&devtmpfs.root),
        Arc::downgrade(&(Arc::clone(&devtmpfs) as Arc<dyn Superblock>)),
    );
    *devtmpfs.vfs_root.lock() = Some(root_inode);

    *DEVTMPFS.lock() = Some(devtmpfs);

    log::info!("[DEVTMPFS] Initialized with null, zero, full, urandom, console devices");
}

/// TEAM_431: Get uptime in seconds for timestamps (cross-platform).
#[cfg(target_arch = "aarch64")]
pub(crate) fn uptime_seconds() -> u64 {
    los_hal::timer::uptime_seconds()
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn uptime_seconds() -> u64 {
    // TEAM_431: x86_64 timestamp placeholder
    // Device files don't really need accurate timestamps
    0
}
