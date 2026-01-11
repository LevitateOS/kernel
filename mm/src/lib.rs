//! # los_mm - Memory Management
//!
//! TEAM_422: Kernel memory management crate.
//!
//! This crate provides:
//! - Physical frame allocation (buddy allocator)
//! - Kernel heap management
//! - Virtual memory area (VMA) tracking
//! - User address space handling
//!
//! ## Usage
//!
//! ```rust,ignore
//! use los_mm::{FRAME_ALLOCATOR, alloc_frame, free_frame};
//! use los_mm::user::{AddressSpace, map_user_page};
//! ```

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

// TEAM_422: Placeholder - will be populated during migration
// Currently re-exporting from kernel's memory module
