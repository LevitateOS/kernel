//! TEAM_168: File Descriptor Table for LevitateOS.
//!
//! Per-process file descriptor management for syscalls.
//! Supports stdin/stdout/stderr (fd 0/1/2), initramfs files, and tmpfs files.
//!
//! TEAM_422: This module was extracted from the monolithic kernel.
//! Some types (EpollInstance, EventFdState, PtyPair) are defined externally
//! to avoid circular dependencies.
//!
//! TEAM_459: Refactored with bitmap-based allocation for O(1) free slot lookup.
//! Increased MAX_FDS from 64 to 1024.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use los_hal::IrqSafeLock;

/// TEAM_459: Maximum number of open file descriptors per process.
/// Increased from 64 to 1024 (Linux default soft limit).
pub const MAX_FDS: usize = 1024;

/// TEAM_459: Number of u64 words needed for the bitmap (1024 / 64 = 16).
const BITMAP_WORDS: usize = MAX_FDS / 64;

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
/// TEAM_459: Added bitmap for O(1) allocation, next_free hint.
#[derive(Clone)]
pub struct FdTable {
    /// Sparse array of file descriptors (None = unused slot)
    entries: Vec<Option<FdEntry>>,
    /// TEAM_459: Bitmap tracking used FDs (bit set = FD in use)
    bitmap: [u64; BITMAP_WORDS],
    /// TEAM_459: Hint for next free FD (may be stale, but speeds up common case)
    next_free: usize,
}

impl FdTable {
    /// TEAM_168: Create a new fd table with stdin/stdout/stderr pre-populated.
    /// TEAM_459: Now initializes bitmap with bits 0,1,2 set.
    pub fn new() -> Self {
        let mut entries = Vec::with_capacity(16); // Start small, grow as needed

        // Pre-populate fd 0 (stdin), 1 (stdout), 2 (stderr)
        entries.push(Some(FdEntry::new(FdType::Stdin))); // fd 0
        entries.push(Some(FdEntry::new(FdType::Stdout))); // fd 1
        entries.push(Some(FdEntry::new(FdType::Stderr))); // fd 2

        // TEAM_459: Initialize bitmap with fd 0,1,2 marked as used
        let mut bitmap = [0u64; BITMAP_WORDS];
        bitmap[0] = 0b111; // Bits 0, 1, 2 set

        Self {
            entries,
            bitmap,
            next_free: 3, // First free FD after stdio
        }
    }

    /// TEAM_459: Set a bit in the bitmap (mark FD as used).
    #[inline]
    fn bitmap_set(&mut self, fd: usize) {
        let word = fd / 64;
        let bit = fd % 64;
        self.bitmap[word] |= 1u64 << bit;
    }

    /// TEAM_459: Clear a bit in the bitmap (mark FD as free).
    #[inline]
    fn bitmap_clear(&mut self, fd: usize) {
        let word = fd / 64;
        let bit = fd % 64;
        self.bitmap[word] &= !(1u64 << bit);
    }

    /// TEAM_459: Check if a bit is set in the bitmap.
    #[inline]
    fn bitmap_is_set(&self, fd: usize) -> bool {
        let word = fd / 64;
        let bit = fd % 64;
        (self.bitmap[word] & (1u64 << bit)) != 0
    }

    /// TEAM_459: Find the lowest free FD using bitmap.
    /// Returns None if all FDs are in use.
    fn find_lowest_free(&self) -> Option<usize> {
        for (word_idx, &word) in self.bitmap.iter().enumerate() {
            if word != u64::MAX {
                // This word has at least one free bit
                let bit_idx = (!word).trailing_zeros() as usize;
                let fd = word_idx * 64 + bit_idx;
                if fd < MAX_FDS {
                    return Some(fd);
                }
            }
        }
        None
    }

    /// TEAM_168: Allocate a new file descriptor (lowest available per Q2 decision).
    /// TEAM_459: Rewritten to use bitmap for O(1) amortized allocation.
    ///
    /// Returns the fd number on success, or None if table is full.
    pub fn alloc(&mut self, fd_type: FdType) -> Option<usize> {
        // TEAM_459: Fast path - check next_free hint first
        let fd = if self.next_free < MAX_FDS && !self.bitmap_is_set(self.next_free) {
            self.next_free
        } else {
            // Slow path - find lowest free via bitmap scan
            self.find_lowest_free()?
        };

        // Ensure entries vector is large enough
        while self.entries.len() <= fd {
            self.entries.push(None);
        }

        // Mark FD as used in bitmap and store entry
        self.bitmap_set(fd);
        self.entries[fd] = Some(FdEntry::new(fd_type));

        // Update next_free hint (scan forward from allocated FD)
        self.next_free = fd + 1;
        while self.next_free < MAX_FDS && self.bitmap_is_set(self.next_free) {
            self.next_free += 1;
        }

        Some(fd)
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
    /// TEAM_459: Now clears bitmap and updates next_free hint.
    ///
    /// Returns true if fd was valid and closed, false otherwise.
    pub fn close(&mut self, fd: usize) -> bool {
        if fd >= MAX_FDS {
            return false;
        }
        if let Some(slot) = self.entries.get_mut(fd) {
            if slot.take().is_some() {
                // Entry dropped -> FdType dropped -> refcount decremented
                // TEAM_459: Clear bitmap and update hint
                self.bitmap_clear(fd);
                if fd < self.next_free {
                    self.next_free = fd;
                }
                return true;
            }
        }
        false
    }

    /// TEAM_333: Close all file descriptors (for process exit).
    /// TEAM_459: Now resets bitmap and next_free hint.
    pub fn close_all(&mut self) {
        for slot in self.entries.iter_mut() {
            slot.take(); // Drops entry -> decrements refcounts
        }
        // TEAM_459: Reset bitmap
        self.bitmap = [0u64; BITMAP_WORDS];
        self.next_free = 0;
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
    /// TEAM_459: Now updates bitmap when closing/opening FDs.
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
        // TEAM_459: Clear bitmap if newfd was in use
        if self.entries[newfd].take().is_some() {
            self.bitmap_clear(newfd);
        }

        // Set newfd to point to same fd_type
        self.bitmap_set(newfd);
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
/// TEAM_459: Simplified - FdTable::new() already sets up stdio at fd 0,1,2.
pub fn new_shared_fd_table_with_stdio() -> SharedFdTable {
    // FdTable::new() already allocates stdin/stdout/stderr at fd 0,1,2
    Arc::new(IrqSafeLock::new(FdTable::new()))
}
