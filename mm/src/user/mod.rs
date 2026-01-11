//! TEAM_422: User Address Space Management for LevitateOS.
//!
//! This module provides:
//! - Per-process TTBR0 page table creation
//! - User memory mapping functions
//! - Address space layout for user processes
//!
//! TEAM_415: Refactored with StackWriter and auxv submodule.
//! TEAM_422: Split into submodules for maintainability.

// Submodules
pub mod auxv;
pub mod layout;
mod mapping;
mod page_table;
mod stack;

// Re-export public API
pub use auxv::{
    AT_BASE, AT_ENTRY, AT_HWCAP, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_RANDOM,
    AuxEntry,
};
pub use mapping::{
    alloc_and_map_heap_page, alloc_and_map_user_range, alloc_zero_map_page, map_user_page,
    map_user_range, user_va_to_kernel_ptr, validate_user_buffer,
};
pub use page_table::{create_user_page_table, destroy_user_page_table};
pub use stack::{setup_stack_args, setup_user_stack, setup_user_tls};
