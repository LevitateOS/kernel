//! TEAM_462: Memory-related constants and utilities
//!
//! This module provides centralized memory constants to prevent
//! duplicate definitions across the kernel.

pub mod constants;

// Re-export commonly used items at module level
pub use constants::{
    is_page_aligned, page_align_down, page_align_up, pages_needed, PAGE_MASK, PAGE_SHIFT,
    PAGE_SIZE,
};
