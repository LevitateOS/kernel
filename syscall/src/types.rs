//! Common syscall type definitions (SSOT).
//!
//! TEAM_418: Consolidated from scattered definitions across the codebase.
//! TEAM_423: Re-export canonical types from los_types to avoid duplication.

// ============================================================================
// Time Types - Re-exported from los_types
// ============================================================================

pub use los_types::{Timespec, Timeval};
