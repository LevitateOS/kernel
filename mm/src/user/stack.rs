//! TEAM_422: User Stack Setup
//!
//! Handles user stack allocation and argument/environment setup
//! according to Linux ABI.

use alloc::vec::Vec;

use los_hal::mmu::{MmuError, PAGE_SIZE, PageFlags};

use super::auxv::{AT_HWCAP, AT_NULL, AT_PAGESZ, AT_RANDOM, AuxEntry};
use super::layout;
use super::mapping::{alloc_zero_map_page, user_va_to_kernel_ptr};

/// TEAM_415: Helper struct for writing to user stack during process setup.
///
/// Encapsulates the common pattern of writing bytes, usizes, and strings
/// to a user stack through page table translation.
pub(super) struct StackWriter {
    ttbr0_phys: usize,
    sp: usize,
}

impl StackWriter {
    /// Create a new StackWriter starting at the given stack pointer.
    pub fn new(ttbr0_phys: usize, stack_top: usize) -> Self {
        Self {
            ttbr0_phys,
            sp: stack_top,
        }
    }

    /// Get the current stack pointer.
    pub fn sp(&self) -> usize {
        self.sp
    }

    /// Write raw bytes to the stack (growing downward).
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), MmuError> {
        self.sp -= bytes.len();
        for (i, &byte) in bytes.iter().enumerate() {
            let ptr = user_va_to_kernel_ptr(self.ttbr0_phys, self.sp + i)
                .ok_or(MmuError::InvalidVirtualAddress)?;
            // SAFETY: ptr is valid from user_va_to_kernel_ptr
            unsafe {
                *ptr = byte;
            }
        }
        Ok(())
    }

    /// Write a usize to the stack (growing downward).
    pub fn write_usize(&mut self, val: usize) -> Result<(), MmuError> {
        self.sp -= core::mem::size_of::<usize>();
        let ptr = user_va_to_kernel_ptr(self.ttbr0_phys, self.sp)
            .ok_or(MmuError::InvalidVirtualAddress)?;
        // SAFETY: ptr is valid and aligned for usize write
        unsafe {
            *(ptr as *mut usize) = val;
        }
        Ok(())
    }

    /// Write a null-terminated string to the stack.
    /// Returns the user-space pointer to the string.
    pub fn write_string(&mut self, s: &str) -> Result<usize, MmuError> {
        let len = s.len() + 1; // Include null terminator
        self.sp -= len;
        self.sp &= !7; // Align to 8 bytes
        let str_ptr = self.sp;

        for (i, byte) in s.bytes().enumerate() {
            let ptr = user_va_to_kernel_ptr(self.ttbr0_phys, str_ptr + i)
                .ok_or(MmuError::InvalidVirtualAddress)?;
            // SAFETY: ptr is valid from user_va_to_kernel_ptr
            unsafe {
                *ptr = byte;
            }
        }
        // Null terminator
        let ptr = user_va_to_kernel_ptr(self.ttbr0_phys, str_ptr + s.len())
            .ok_or(MmuError::InvalidVirtualAddress)?;
        // SAFETY: ptr is valid from user_va_to_kernel_ptr
        unsafe {
            *ptr = 0;
        }

        Ok(str_ptr)
    }

    /// Align the stack pointer to 16 bytes, with optional extra padding.
    pub fn align16(&mut self, extra_padding: bool) {
        self.sp &= !15;
        if extra_padding {
            self.sp -= 8;
        }
    }
}

/// TEAM_073: Allocate and map user stack pages.
///
/// Allocates physical pages for the user stack and maps them at the
/// standard stack location.
///
/// # Arguments
/// * `ttbr0_phys` - Physical address of user L0 page table
/// * `stack_pages` - Number of stack pages (e.g., 16 for 64KB)
///
/// # Returns
/// Initial stack pointer (top of stack) on success.
/// TEAM_415: Refactored to use alloc_zero_map_page helper.
pub unsafe fn setup_user_stack(ttbr0_phys: usize, stack_pages: usize) -> Result<usize, MmuError> {
    let stack_size = stack_pages * PAGE_SIZE;
    let stack_bottom = layout::STACK_TOP - stack_size;

    for i in 0..stack_pages {
        let page_va = stack_bottom + i * PAGE_SIZE;
        alloc_zero_map_page(ttbr0_phys, page_va, PageFlags::USER_STACK)?;
    }

    Ok(layout::STACK_TOP)
}

/// TEAM_408: Allocate and map TLS area for user process.
/// TEAM_415: Refactored to use alloc_zero_map_page helper.
///
/// On AArch64, TPIDR_EL0 points to this area. Userspace runtimes like
/// Origin/Eyra expect a valid TLS pointer on entry.
pub unsafe fn setup_user_tls(ttbr0_phys: usize) -> Result<usize, MmuError> {
    alloc_zero_map_page(ttbr0_phys, layout::TLS_BASE, PageFlags::USER_DATA)?;
    log::debug!("[TLS] TEAM_408: Allocated TLS at 0x{:x}", layout::TLS_BASE);
    Ok(layout::TLS_BASE)
}

/// TEAM_169: Set up user stack with argc/argv/envp/auxv.
/// TEAM_415: Refactored to use StackWriter.
///
/// Per Phase 2 Q5 decision: Stack-based argument passing (Linux ABI compatible).
///
/// Stack layout (grows downward):
/// ```text
/// High addresses
///   +---------------+
///   | random data   |  <- 16 bytes for AT_RANDOM
///   | env strings   |  <- Environment variable strings
///   | arg strings   |  <- Argument strings
///   | AT_NULL       |  <- auxv terminator
///   | auxv[n]       |  <- Auxiliary vector entries
///   | ...           |
///   | auxv[0]       |
///   | NULL          |  <- envp terminator
///   | envp[n-1]     |  <- Environment pointers
///   | ...           |
///   | envp[0]       |
///   | NULL          |  <- argv terminator
///   | argv[argc-1]  |  <- Argument pointers
///   | ...           |
///   | argv[0]       |
///   | argc          |  <- SP points here
///   +---------------+
/// Low addresses
/// ```
pub fn setup_stack_args(
    ttbr0_phys: usize,
    stack_top: usize,
    args: &[&str],
    envs: &[&str],
    auxv: &[AuxEntry],
) -> Result<usize, MmuError> {
    let mut sw = StackWriter::new(ttbr0_phys, stack_top);

    // 0. Write random data for AT_RANDOM
    let mut random_bytes = [0u8; 16];
    for i in 0..16 {
        random_bytes[i] = (i * 7) as u8; // TODO: Use actual entropy
    }
    sw.write_bytes(&random_bytes)?;
    let random_ptr = sw.sp();

    // 1. Write all strings to stack (env first, then args)
    let mut env_ptrs = Vec::new();
    for env in envs.iter().rev() {
        env_ptrs.push(sw.write_string(env)?);
    }
    env_ptrs.reverse();

    let mut arg_ptrs = Vec::new();
    for arg in args.iter().rev() {
        arg_ptrs.push(sw.write_string(arg)?);
    }
    arg_ptrs.reverse();

    // TEAM_363: Calculate total size for 16-byte alignment (x86-64 ABI requirement)
    let auxv_entries = auxv.len() + 4; // AT_PAGESZ, AT_HWCAP, AT_RANDOM, AT_NULL
    let total_array_size = auxv_entries * 16 + (envs.len() + 1) * 8 + (args.len() + 1) * 8 + 8;
    sw.align16(total_array_size % 16 != 0);

    // 2. Write Auxiliary Vector (auxv) with mandatory entries
    let mut final_auxv = Vec::from(auxv);
    final_auxv.push(AuxEntry {
        a_type: AT_PAGESZ,
        a_val: PAGE_SIZE,
    });
    final_auxv.push(AuxEntry {
        a_type: AT_HWCAP,
        a_val: 0,
    }); // TODO: Pass actual HWCAP
    final_auxv.push(AuxEntry {
        a_type: AT_RANDOM,
        a_val: random_ptr,
    });
    final_auxv.push(AuxEntry {
        a_type: AT_NULL,
        a_val: 0,
    });

    for entry in final_auxv.iter().rev() {
        sw.write_usize(entry.a_val)?;
        sw.write_usize(entry.a_type)?;
    }

    // 3. Write envp[] array (NULL terminated)
    sw.write_usize(0)?;
    for ptr in env_ptrs.iter().rev() {
        sw.write_usize(*ptr)?;
    }

    // 4. Write argv[] array (NULL terminated)
    sw.write_usize(0)?;
    for ptr in arg_ptrs.iter().rev() {
        sw.write_usize(*ptr)?;
    }

    // 5. Write argc
    sw.write_usize(args.len())?;

    debug_assert!(
        sw.sp() % 16 == 0,
        "Stack not 16-byte aligned: sp=0x{:x}",
        sw.sp()
    );
    Ok(sw.sp())
}
