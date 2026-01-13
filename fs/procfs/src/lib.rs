//! TEAM_469: Procfs - Process Filesystem Implementation
//!
//! A pseudo-filesystem that exposes kernel state to userspace.
//! Provides /proc/[pid]/ directories for process info and system-wide files.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use linux_raw_sys::general::{S_IFDIR, S_IFLNK, S_IFREG};
use los_hal::IrqSafeLock;
use los_vfs::error::{VfsError, VfsResult};
use los_vfs::inode::Inode;
use los_vfs::ops::{DirEntry, FileOps, InodeOps};
use los_vfs::superblock::Superblock;

// ============================================================================
// Entry Types
// ============================================================================

/// TEAM_469: What a procfs inode represents
#[derive(Clone, Debug)]
pub enum ProcfsEntry {
    /// Root /proc/ directory
    Root,
    /// /proc/[pid]/ directory
    ProcessDir { pid: u32 },
    /// /proc/[pid]/stat file
    ProcessStat { pid: u32 },
    /// /proc/[pid]/status file
    ProcessStatus { pid: u32 },
    /// /proc/[pid]/cmdline file
    ProcessCmdline { pid: u32 },
    /// /proc/[pid]/maps file
    ProcessMaps { pid: u32 },
    /// /proc/[pid]/exe symlink
    ProcessExe { pid: u32 },
    /// /proc/[pid]/cwd symlink
    ProcessCwd { pid: u32 },
    /// /proc/[pid]/fd/ directory
    ProcessFdDir { pid: u32 },
    /// /proc/[pid]/fd/[fd] symlink
    ProcessFd { pid: u32, fd: u32 },
    /// /proc/self symlink
    SelfLink,
    /// /proc/meminfo file
    Meminfo,
    /// /proc/uptime file
    Uptime,
}

impl ProcfsEntry {
    /// Get the file mode for this entry type
    pub fn mode(&self) -> u32 {
        match self {
            Self::Root | Self::ProcessDir { .. } | Self::ProcessFdDir { .. } => S_IFDIR | 0o555,
            Self::ProcessStat { .. }
            | Self::ProcessStatus { .. }
            | Self::ProcessCmdline { .. }
            | Self::ProcessMaps { .. }
            | Self::Meminfo
            | Self::Uptime => S_IFREG | 0o444,
            Self::ProcessExe { .. }
            | Self::ProcessCwd { .. }
            | Self::ProcessFd { .. }
            | Self::SelfLink => S_IFLNK | 0o777,
        }
    }

    /// Check if this entry is a directory
    pub fn is_dir(&self) -> bool {
        matches!(
            self,
            Self::Root | Self::ProcessDir { .. } | Self::ProcessFdDir { .. }
        )
    }

    /// Check if this entry is a symlink
    pub fn is_symlink(&self) -> bool {
        matches!(
            self,
            Self::ProcessExe { .. }
                | Self::ProcessCwd { .. }
                | Self::ProcessFd { .. }
                | Self::SelfLink
        )
    }
}

// ============================================================================
// Superblock
// ============================================================================

/// TEAM_469: Procfs superblock
pub struct ProcfsSuperblock {
    /// Next inode number
    next_ino: AtomicU64,
    /// Cached VFS root inode
    vfs_root: IrqSafeLock<Option<Arc<Inode>>>,
}

impl ProcfsSuperblock {
    /// Create a new procfs superblock
    pub fn new() -> Self {
        Self {
            next_ino: AtomicU64::new(2), // 1 is root
            vfs_root: IrqSafeLock::new(None),
        }
    }

    /// Allocate a new inode number
    pub fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for ProcfsSuperblock {
    fn default() -> Self {
        Self::new()
    }
}

impl Superblock for ProcfsSuperblock {
    fn root(&self) -> Arc<Inode> {
        let mut root = self.vfs_root.lock();
        if let Some(ref r) = *root {
            return Arc::clone(r);
        }

        // Get weak reference to ourselves
        let sb_weak = {
            let sb_lock = PROCFS_SUPERBLOCK.lock();
            sb_lock.as_ref().map(Arc::downgrade).unwrap_or_else(|| {
                // Fallback: create a dummy weak (shouldn't happen)
                Arc::downgrade(&Arc::new(ProcfsSuperblock::new()))
            })
        };

        // Create root inode
        let inode = Arc::new(Inode {
            ino: 1,
            dev: 0,
            mode: AtomicU32::new(S_IFDIR | 0o555),
            nlink: AtomicU32::new(2),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            rdev: 0,
            size: AtomicU64::new(0),
            atime: AtomicU64::new(0),
            mtime: AtomicU64::new(0),
            ctime: AtomicU64::new(0),
            blksize: 4096,
            private: Box::new(ProcfsEntry::Root),
            ops: &PROCFS_DIR_OPS,
            sb: sb_weak,
        });

        *root = Some(Arc::clone(&inode));
        inode
    }

    fn statfs(&self) -> VfsResult<los_vfs::StatFs> {
        Ok(los_vfs::StatFs {
            f_type: 0x9fa0, // PROC_SUPER_MAGIC
            f_bsize: 4096,
            f_blocks: 0,
            f_bfree: 0,
            f_bavail: 0,
            f_files: 0,
            f_ffree: 0,
            f_namelen: 255,
            f_frsize: 4096,
            f_flags: 0,
        })
    }

    fn fs_type(&self) -> &'static str {
        "proc"
    }

    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ============================================================================
// Global Superblock
// ============================================================================

use los_utils::Mutex;

/// Global procfs superblock (singleton - only one /proc)
/// Initialized on first mount via create_superblock()
pub static PROCFS_SUPERBLOCK: Mutex<Option<Arc<ProcfsSuperblock>>> = Mutex::new(None);

/// Create a procfs superblock (returns the global singleton)
pub fn create_superblock() -> Arc<dyn Superblock + Send + Sync> {
    let mut sb = PROCFS_SUPERBLOCK.lock();
    if sb.is_none() {
        *sb = Some(Arc::new(ProcfsSuperblock::new()));
    }
    Arc::clone(sb.as_ref().unwrap()) as Arc<dyn Superblock + Send + Sync>
}

// ============================================================================
// Directory Operations
// ============================================================================

/// TEAM_469: Directory operations for procfs
pub struct ProcfsDirOps;

static PROCFS_DIR_OPS: ProcfsDirOps = ProcfsDirOps;

impl InodeOps for ProcfsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> VfsResult<Arc<Inode>> {
        let entry = inode
            .private
            .downcast_ref::<ProcfsEntry>()
            .ok_or(VfsError::IoError)?;

        match entry {
            ProcfsEntry::Root => lookup_root(name),
            ProcfsEntry::ProcessDir { pid } => lookup_process_dir(*pid, name),
            ProcfsEntry::ProcessFdDir { pid } => lookup_fd_dir(*pid, name),
            _ => Err(VfsError::NotADirectory),
        }
    }

    fn readdir(&self, inode: &Inode, offset: usize) -> VfsResult<Option<DirEntry>> {
        let entry = inode
            .private
            .downcast_ref::<ProcfsEntry>()
            .ok_or(VfsError::IoError)?;

        match entry {
            ProcfsEntry::Root => readdir_root(offset),
            ProcfsEntry::ProcessDir { pid } => readdir_process_dir(*pid, offset),
            ProcfsEntry::ProcessFdDir { pid } => readdir_fd_dir(*pid, offset),
            _ => Err(VfsError::NotADirectory),
        }
    }
}

/// Look up an entry in /proc/
fn lookup_root(name: &str) -> VfsResult<Arc<Inode>> {
    // Check for "self" symlink
    if name == "self" {
        return create_inode(ProcfsEntry::SelfLink);
    }

    // Check for system files
    match name {
        "meminfo" => return create_inode(ProcfsEntry::Meminfo),
        "uptime" => return create_inode(ProcfsEntry::Uptime),
        _ => {}
    }

    // Check for PID directory
    if let Ok(pid) = name.parse::<u32>() {
        // Verify process exists
        if process_exists(pid) {
            return create_inode(ProcfsEntry::ProcessDir { pid });
        }
    }

    Err(VfsError::NotFound)
}

/// Look up an entry in /proc/[pid]/
fn lookup_process_dir(pid: u32, name: &str) -> VfsResult<Arc<Inode>> {
    // Verify process still exists
    if !process_exists(pid) {
        return Err(VfsError::NotFound);
    }

    match name {
        "stat" => create_inode(ProcfsEntry::ProcessStat { pid }),
        "status" => create_inode(ProcfsEntry::ProcessStatus { pid }),
        "cmdline" => create_inode(ProcfsEntry::ProcessCmdline { pid }),
        "maps" => create_inode(ProcfsEntry::ProcessMaps { pid }),
        "exe" => create_inode(ProcfsEntry::ProcessExe { pid }),
        "cwd" => create_inode(ProcfsEntry::ProcessCwd { pid }),
        "fd" => create_inode(ProcfsEntry::ProcessFdDir { pid }),
        _ => Err(VfsError::NotFound),
    }
}

/// Look up an entry in /proc/[pid]/fd/
fn lookup_fd_dir(pid: u32, name: &str) -> VfsResult<Arc<Inode>> {
    if !process_exists(pid) {
        return Err(VfsError::NotFound);
    }

    if let Ok(fd) = name.parse::<u32>() {
        // TODO: Verify fd exists for this process
        return create_inode(ProcfsEntry::ProcessFd { pid, fd });
    }

    Err(VfsError::NotFound)
}

/// Read /proc/ directory
fn readdir_root(offset: usize) -> VfsResult<Option<DirEntry>> {
    // Static entries
    let static_entries = ["self", "meminfo", "uptime"];

    // Check if offset is within static entries
    if offset < static_entries.len() {
        let name = static_entries[offset];
        return Ok(Some(DirEntry {
            name: String::from(name),
            ino: (offset + 2) as u64,
            file_type: if name == "self" { S_IFLNK } else { S_IFREG },
        }));
    }

    // Check process directories
    let pids = get_all_pids();
    let pid_offset = offset - static_entries.len();
    if pid_offset < pids.len() {
        let pid = pids[pid_offset];
        return Ok(Some(DirEntry {
            name: pid.to_string(),
            ino: (offset + 100) as u64,
            file_type: S_IFDIR,
        }));
    }

    // No more entries
    Ok(None)
}

/// Read /proc/[pid]/ directory
fn readdir_process_dir(pid: u32, offset: usize) -> VfsResult<Option<DirEntry>> {
    if !process_exists(pid) {
        return Err(VfsError::NotFound);
    }

    let entries_list = [
        ("stat", S_IFREG),
        ("status", S_IFREG),
        ("cmdline", S_IFREG),
        ("maps", S_IFREG),
        ("exe", S_IFLNK),
        ("cwd", S_IFLNK),
        ("fd", S_IFDIR),
    ];

    if offset < entries_list.len() {
        let (name, ftype) = entries_list[offset];
        return Ok(Some(DirEntry {
            name: String::from(name),
            ino: (offset + 1000) as u64,
            file_type: ftype,
        }));
    }

    Ok(None)
}

/// Read /proc/[pid]/fd/ directory
fn readdir_fd_dir(pid: u32, offset: usize) -> VfsResult<Option<DirEntry>> {
    if !process_exists(pid) {
        return Err(VfsError::NotFound);
    }

    let fds = get_process_fds(pid);

    if offset < fds.len() {
        let fd = fds[offset];
        return Ok(Some(DirEntry {
            name: fd.to_string(),
            ino: (fd as u64) + 10000,
            file_type: S_IFLNK,
        }));
    }

    Ok(None)
}

// ============================================================================
// File Operations
// ============================================================================

/// TEAM_469: File operations for procfs regular files
pub struct ProcfsFileOps;

static PROCFS_FILE_OPS: ProcfsFileOps = ProcfsFileOps;

impl InodeOps for ProcfsFileOps {
    fn read(&self, inode: &Inode, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let entry = inode
            .private
            .downcast_ref::<ProcfsEntry>()
            .ok_or(VfsError::IoError)?;

        let content = match entry {
            ProcfsEntry::ProcessStat { pid } => generate_stat(*pid)?,
            ProcfsEntry::ProcessStatus { pid } => generate_status(*pid)?,
            ProcfsEntry::ProcessCmdline { pid } => generate_cmdline(*pid)?,
            ProcfsEntry::ProcessMaps { pid } => generate_maps(*pid)?,
            ProcfsEntry::Meminfo => generate_meminfo(),
            ProcfsEntry::Uptime => generate_uptime(),
            _ => return Err(VfsError::NotSupported),
        };

        let offset = offset as usize;
        if offset >= content.len() {
            return Ok(0);
        }

        let to_copy = core::cmp::min(buf.len(), content.len() - offset);
        buf[..to_copy].copy_from_slice(&content.as_bytes()[offset..offset + to_copy]);

        Ok(to_copy)
    }
}

impl FileOps for ProcfsFileOps {
    fn read(&self, file: &los_vfs::file::File, buf: &mut [u8]) -> VfsResult<usize> {
        let offset = file.offset.load(Ordering::Acquire);
        let n = <Self as InodeOps>::read(self, &file.inode, offset, buf)?;
        file.offset.fetch_add(n as u64, Ordering::Release);
        Ok(n)
    }

    fn write(&self, _file: &los_vfs::file::File, _buf: &[u8]) -> VfsResult<usize> {
        // procfs files are read-only
        Err(VfsError::NotSupported)
    }
}

// ============================================================================
// Symlink Operations
// ============================================================================

/// TEAM_469: Symlink operations for procfs
pub struct ProcfsSymlinkOps;

static PROCFS_SYMLINK_OPS: ProcfsSymlinkOps = ProcfsSymlinkOps;

impl InodeOps for ProcfsSymlinkOps {
    fn readlink(&self, inode: &Inode) -> VfsResult<String> {
        let entry = inode
            .private
            .downcast_ref::<ProcfsEntry>()
            .ok_or(VfsError::IoError)?;

        match entry {
            ProcfsEntry::SelfLink => {
                let pid = los_sched::current_task().id.0;
                Ok(pid.to_string())
            }
            ProcfsEntry::ProcessExe { pid: _ } => {
                // TODO: Return actual exe path when TCB stores it
                Ok(String::from("[unknown]"))
            }
            ProcfsEntry::ProcessCwd { pid } => {
                if let Some(task) = get_task(*pid) {
                    let cwd = task.cwd.lock().clone();
                    Ok(cwd)
                } else {
                    Err(VfsError::NotFound)
                }
            }
            ProcfsEntry::ProcessFd { pid: _, fd: _ } => {
                // TODO: Return actual file path
                Ok(String::from("[unknown]"))
            }
            _ => Err(VfsError::NotSupported),
        }
    }
}

// ============================================================================
// Content Generators
// ============================================================================

/// Generate /proc/[pid]/stat content
fn generate_stat(pid: u32) -> VfsResult<String> {
    let task = get_task(pid).ok_or(VfsError::NotFound)?;

    // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ...
    // We implement a subset of fields
    let state = 'R'; // Running (simplified)
    let ppid = 1; // TODO: Get actual parent PID
    let pgrp = task.pgid.load(Ordering::Relaxed);
    let session = task.sid.load(Ordering::Relaxed);

    Ok(alloc::format!(
        "{} (task{}) {} {} {} {} 0 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0\n",
        pid,
        pid,
        state,
        ppid,
        pgrp,
        session
    ))
}

/// Generate /proc/[pid]/status content
fn generate_status(pid: u32) -> VfsResult<String> {
    let task = get_task(pid).ok_or(VfsError::NotFound)?;

    let mut s = String::new();
    s.push_str(&alloc::format!("Name:\ttask{}\n", pid));
    s.push_str(&alloc::format!("Pid:\t{}\n", pid));
    s.push_str("PPid:\t1\n");
    s.push_str("State:\tR (running)\n");
    // Single-user OS - all processes run as root
    s.push_str("Uid:\t0\t0\t0\t0\n");
    s.push_str("Gid:\t0\t0\t0\t0\n");

    // Memory info from VMAs
    let vmas = task.vmas.lock();
    let vm_size: usize = vmas.iter().map(|vma| vma.end - vma.start).sum();
    s.push_str(&alloc::format!("VmSize:\t{} kB\n", vm_size / 1024));

    Ok(s)
}

/// Generate /proc/[pid]/cmdline content
fn generate_cmdline(_pid: u32) -> VfsResult<String> {
    // TODO: Return actual cmdline when TCB stores it
    Ok(String::new())
}

/// Generate /proc/[pid]/maps content
fn generate_maps(pid: u32) -> VfsResult<String> {
    let task = get_task(pid).ok_or(VfsError::NotFound)?;

    let mut s = String::new();
    let vmas = task.vmas.lock();

    for vma in vmas.iter() {
        // Format: address perms offset dev inode pathname
        let perms = alloc::format!(
            "{}{}{}p",
            if vma.flags.contains(los_mm::vma::VmaFlags::READ) {
                'r'
            } else {
                '-'
            },
            if vma.flags.contains(los_mm::vma::VmaFlags::WRITE) {
                'w'
            } else {
                '-'
            },
            if vma.flags.contains(los_mm::vma::VmaFlags::EXEC) {
                'x'
            } else {
                '-'
            },
        );

        s.push_str(&alloc::format!(
            "{:08x}-{:08x} {} 00000000 00:00 0\n",
            vma.start,
            vma.end,
            perms
        ));
    }

    Ok(s)
}

/// Generate /proc/meminfo content
fn generate_meminfo() -> String {
    // TODO: Get actual memory stats from frame allocator when API is available
    // For now, return placeholder values
    let total_kb = 512 * 1024; // 512 MB placeholder
    let free_kb = 256 * 1024; // 256 MB placeholder

    alloc::format!(
        "MemTotal:       {} kB\nMemFree:        {} kB\nBuffers:        0 kB\nCached:         0 kB\n",
        total_kb,
        free_kb
    )
}

/// Generate /proc/uptime content
fn generate_uptime() -> String {
    // TODO: Get actual uptime when timer API is available
    // For now, return a placeholder
    alloc::format!("0.00 0.00\n")
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create an inode for a procfs entry
fn create_inode(entry: ProcfsEntry) -> VfsResult<Arc<Inode>> {
    let mode = entry.mode();
    let ops: &'static dyn InodeOps = if entry.is_dir() {
        &PROCFS_DIR_OPS
    } else if entry.is_symlink() {
        &PROCFS_SYMLINK_OPS
    } else {
        &PROCFS_FILE_OPS
    };

    // Get the superblock and allocate an inode number
    let sb_lock = PROCFS_SUPERBLOCK.lock();
    let sb = sb_lock.as_ref().ok_or(VfsError::IoError)?;
    let ino = sb.alloc_ino();
    let sb_weak = Arc::downgrade(sb);
    drop(sb_lock);

    Ok(Arc::new(Inode {
        ino,
        dev: 0,
        mode: AtomicU32::new(mode),
        nlink: AtomicU32::new(1),
        uid: AtomicU32::new(0),
        gid: AtomicU32::new(0),
        rdev: 0,
        size: AtomicU64::new(0),
        atime: AtomicU64::new(0),
        mtime: AtomicU64::new(0),
        ctime: AtomicU64::new(0),
        blksize: 4096,
        private: Box::new(entry),
        ops,
        sb: sb_weak,
    }))
}

/// Check if a process exists
fn process_exists(pid: u32) -> bool {
    let table = los_sched::process_table::PROCESS_TABLE.lock();
    table.get(&(pid as usize)).is_some()
}

/// Get task by PID
fn get_task(pid: u32) -> Option<Arc<los_sched::TaskControlBlock>> {
    let table = los_sched::process_table::PROCESS_TABLE.lock();
    table
        .get(&(pid as usize))
        .and_then(|entry| entry.task.clone())
}

/// Get all process IDs
fn get_all_pids() -> Vec<u32> {
    let table = los_sched::process_table::PROCESS_TABLE.lock();
    table.keys().map(|&pid| pid as u32).collect()
}

/// Get open file descriptors for a process
fn get_process_fds(pid: u32) -> Vec<u32> {
    if let Some(task) = get_task(pid) {
        let fd_table = task.fd_table.lock();
        let mut fds = Vec::new();
        // Check standard fds (0, 1, 2) which are always present
        for fd in 0..3 {
            if fd_table.get(fd).is_some() {
                fds.push(fd as u32);
            }
        }
        // Check a reasonable range of additional fds
        for fd in 3..64 {
            if fd_table.get(fd).is_some() {
                fds.push(fd as u32);
            }
        }
        fds
    } else {
        Vec::new()
    }
}
