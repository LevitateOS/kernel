//! TEAM_461: Kernel configuration constants
//!
//! Centralizes hardcoded values that were previously scattered across modules.
//! This prevents mismatches and makes tuning easier.
//!
//! Future: Could be moved to a separate crate for wider visibility,
//! or made runtime-configurable via /proc/sys.

/// Default screen resolution (fallback when GPU detection fails)
pub mod display {
    /// Default screen width in pixels
    pub const FALLBACK_WIDTH: u32 = 1280;
    /// Default screen height in pixels
    pub const FALLBACK_HEIGHT: u32 = 800;
}

/// Tmpfs limits
/// TEAM_461: These should eventually be dynamic (percentage of RAM)
pub mod tmpfs {
    /// Maximum size of a single file (16 MB)
    pub const MAX_FILE_SIZE: usize = 16 * 1024 * 1024;
    /// Maximum total tmpfs usage (64 MB)
    pub const MAX_TOTAL_SIZE: usize = 64 * 1024 * 1024;
}

/// Process limits
pub mod process {
    /// Maximum file descriptors per process (Linux default soft limit)
    /// Note: This is also defined in los_sched::fd_table as MAX_FDS
    pub const MAX_FDS: usize = 1024;
    /// Maximum processes system-wide
    pub const MAX_PROCESSES: usize = 4096;
    /// Maximum VMAs per process
    pub const MAX_VMAS: usize = 65535;
}

/// Scheduler settings
pub mod scheduler {
    /// Default time slice in milliseconds
    pub const DEFAULT_TIMESLICE_MS: u64 = 10;
}
