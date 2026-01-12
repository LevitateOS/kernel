//! TEAM_168: File Descriptor Table for LevitateOS.
//!
//! Per-process file descriptor management for syscalls.
//! Supports stdin/stdout/stderr (fd 0/1/2), initramfs files, and tmpfs files.
//!
//! TEAM_422: This module was extracted from the monolithic kernel.
//! Some types (EpollInstance, EventFdState, PtyPair) are defined externally
//! to avoid circular dependencies.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use los_hal::IrqSafeLock;

/// TEAM_168: Maximum number of open file descriptors per process.
pub const MAX_FDS: usize = 64;

// TEAM_422: Import types from los_vfs
use los_vfs::{FileRef, PipeRef};

// TEAM_422: Opaque wrapper types for epoll/eventfd/pty to break circular deps.
// These are Arc<dyn Any + Send + Sync> which can be downcast by the syscall layer.
// This allows fd_table to not depend on los_syscall or los_fs_tty directly.

/// TEAM_422: Opaque handle for Epoll instance (actual type in los_syscall::epoll)
pub type EpollRef = Arc<dyn Any + Send + Sync>;
/// TEAM_422: Opaque handle for EventFd state (actual type in los_syscall::epoll)
pub type EventFdRef = Arc<dyn Any + Send + Sync>;
/// TEAM_422: Opaque handle for PTY pair (actual type in los_fs_tty::pty)
pub type PtyRef = Arc<dyn Any + Send + Sync>;

/// TEAM_168: Type of file descriptor entry.
/// TEAM_194: Removed Copy derive to support Arc<> for tmpfs nodes.
/// TEAM_195: Removed Debug derive since Mutex<TmpfsNode> doesn't implement Debug.
/// TEAM_203: Added VfsFile variant and removed legacy Tmpfs variants.
/// TEAM_233: Added PipeRead and PipeWrite variants for pipe support.
/// TEAM_422: PTY, Epoll, EventFd now use opaque handles to break circular deps.
pub enum FdType {
    /// Standard input (keyboard)
    Stdin,
    /// Standard output (console)
    Stdout,
    /// Standard error (console)
    Stderr,
    /// TEAM_203: Generic VFS file (used for tmpfs, FAT32, etc.)
    VfsFile(FileRef),
    /// TEAM_233: Read end of a pipe
    PipeRead(PipeRef),
    /// TEAM_233: Write end of a pipe
    PipeWrite(PipeRef),
    /// TEAM_247: PTY Master side (opaque handle - downcast in syscall layer)
    PtyMaster(PtyRef),
    /// TEAM_247: PTY Slave side (opaque handle - downcast in syscall layer)
    PtySlave(PtyRef),
    /// TEAM_394: Epoll instance (opaque handle - downcast in syscall layer)
    Epoll(EpollRef),
    /// TEAM_394: EventFd for inter-thread signaling (opaque handle)
    EventFd(EventFdRef),
}

impl Clone for FdType {
    fn clone(&self) -> Self {
        match self {
            FdType::Stdin => FdType::Stdin,
            FdType::Stdout => FdType::Stdout,
            FdType::Stderr => FdType::Stderr,
            FdType::VfsFile(f) => FdType::VfsFile(f.clone()),
            FdType::PipeRead(p) => {
                p.inc_read();
                FdType::PipeRead(p.clone())
            }
            FdType::PipeWrite(p) => {
                p.inc_write();
                FdType::PipeWrite(p.clone())
            }
            FdType::PtyMaster(p) => FdType::PtyMaster(p.clone()),
            FdType::PtySlave(p) => FdType::PtySlave(p.clone()),
            FdType::Epoll(e) => FdType::Epoll(e.clone()),
            FdType::EventFd(e) => FdType::EventFd(e.clone()),
        }
    }
}

impl Drop for FdType {
    fn drop(&mut self) {
        match self {
            FdType::PipeRead(p) => p.close_read(),
            FdType::PipeWrite(p) => p.close_write(),
            _ => {}
        }
    }
}

/// TEAM_168: A single file descriptor entry.
/// TEAM_194: Removed Copy derive since FdType no longer implements Copy.
/// TEAM_195: Removed Debug derive since FdType no longer implements Debug.
#[derive(Clone)]
pub struct FdEntry {
    /// Type and state of this fd
    pub fd_type: FdType,
    /// Reference count (for future dup() support)
    #[allow(dead_code)]
    pub refcount: usize,
}

impl FdEntry {
    /// TEAM_168: Create a new fd entry.
    pub fn new(fd_type: FdType) -> Self {
        Self {
            fd_type,
            refcount: 1,
        }
    }
}

/// TEAM_168: Per-process file descriptor table.
/// TEAM_195: Removed Debug derive since FdEntry no longer implements Debug.
#[derive(Clone)]
pub struct FdTable {
    /// Sparse array of file descriptors (None = unused slot)
    entries: Vec<Option<FdEntry>>,
}

impl FdTable {
    /// TEAM_168: Create a new fd table with stdin/stdout/stderr pre-populated.
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(MAX_FDS);

        // Pre-populate fd 0 (stdin), 1 (stdout), 2 (stderr)
        entries.push(Some(FdEntry::new(FdType::Stdin))); // fd 0
        entries.push(Some(FdEntry::new(FdType::Stdout))); // fd 1
        entries.push(Some(FdEntry::new(FdType::Stderr))); // fd 2

        Self { entries }
    }

    /// TEAM_168: Allocate a new file descriptor (lowest available per Q2 decision).
    ///
    /// Returns the fd number on success, or None if table is full.
    pub fn alloc(&mut self, fd_type: FdType) -> Option<usize> {
        // Q2 decision: Always use lowest available (POSIX behavior)
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(FdEntry::new(fd_type));
                return Some(i);
            }
        }

        // No free slot in existing entries, try to extend
        if self.entries.len() < MAX_FDS {
            let fd = self.entries.len();
            self.entries.push(Some(FdEntry::new(fd_type)));
            return Some(fd);
        }

        None // Table full
    }

    /// TEAM_168: Get a file descriptor entry by number.
    pub fn get(&self, fd: usize) -> Option<&FdEntry> {
        self.entries.get(fd).and_then(|e| e.as_ref())
    }

    /// TEAM_168: Get a mutable file descriptor entry by number.
    #[allow(dead_code)]
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FdEntry> {
        self.entries.get_mut(fd).and_then(|e| e.as_mut())
    }

    /// TEAM_168: Close a file descriptor.
    /// TEAM_240: Now properly closes pipe read/write ends.
    ///
    /// Returns true if fd was valid and closed, false otherwise.
    pub fn close(&mut self, fd: usize) -> bool {
        if let Some(slot) = self.entries.get_mut(fd) {
            if slot.take().is_some() {
                // Entry dropped -> FdType dropped -> refcount decremented
                return true;
            }
        }
        false
    }

    /// TEAM_333: Close all file descriptors (for process exit).
    pub fn close_all(&mut self) {
        for slot in self.entries.iter_mut() {
            slot.take(); // Drops entry -> decrements refcounts
        }
    }

    /// TEAM_168: Check if a file descriptor is valid.
    #[allow(dead_code)]
    pub fn is_valid(&self, fd: usize) -> bool {
        self.get(fd).is_some()
    }

    /// TEAM_233: Duplicate a file descriptor to the lowest available slot.
    ///
    /// Returns the new fd number on success, or None if oldfd is invalid or table is full.
    pub fn dup(&mut self, oldfd: usize) -> Option<usize> {
        // Get the FdType from oldfd
        let fd_type = self.get(oldfd)?.fd_type.clone();
        // Allocate a new fd with the same type
        self.alloc(fd_type)
    }

    /// TEAM_233: Duplicate a file descriptor to a specific slot.
    ///
    /// If newfd is already open, it is closed first.
    /// Returns newfd on success, or None if oldfd is invalid.
    pub fn dup_to(&mut self, oldfd: usize, newfd: usize) -> Option<usize> {
        if oldfd == newfd {
            return None; // dup3 returns EINVAL for this
        }
        if newfd >= MAX_FDS {
            return None;
        }

        // Get the FdType from oldfd
        let fd_type = self.get(oldfd)?.fd_type.clone();

        // Ensure entries vector is large enough
        while self.entries.len() <= newfd {
            self.entries.push(None);
        }

        // TEAM_240: Close newfd if open (will trigger Drop and cleanup)
        let _ = self.entries[newfd].take();

        // Set newfd to point to same fd_type
        self.entries[newfd] = Some(FdEntry::new(fd_type));
        Some(newfd)
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

/// TEAM_168: Thread-safe wrapper for FdTable.
/// TEAM_443: Now uses Arc to enable fd table sharing for CLONE_FILES.
/// When clone() is called with CLONE_FILES, parent and child share the same
/// Arc, giving them a shared view of file descriptors.
pub type SharedFdTable = Arc<IrqSafeLock<FdTable>>;

/// TEAM_168: Create a new shared fd table.
/// TEAM_443: Wraps in Arc for CLONE_FILES sharing support.
pub fn new_shared_fd_table() -> SharedFdTable {
    Arc::new(IrqSafeLock::new(FdTable::new()))
}

/// TEAM_453: Create a shared fd table with stdin/stdout/stderr pre-opened.
/// This is required for BusyBox init which expects fd 0,1,2 to be valid.
pub fn new_shared_fd_table_with_stdio() -> SharedFdTable {
    let mut table = FdTable::new();
    // Allocate fd 0 = stdin
    table.alloc(FdType::Stdin);
    // Allocate fd 1 = stdout
    table.alloc(FdType::Stdout);
    // Allocate fd 2 = stderr
    table.alloc(FdType::Stderr);
    Arc::new(IrqSafeLock::new(table))
}
