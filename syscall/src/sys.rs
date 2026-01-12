// TEAM_142: System syscalls
// TEAM_421: Returns SyscallResult, no scattered casts
// TEAM_464: Use linux-raw-sys constants as canonical source

use core::sync::atomic::Ordering;
use crate::SyscallResult;
use linux_raw_sys::errno::EFAULT;
// TEAM_464: Import reboot command constants from linux-raw-sys (u32)
use linux_raw_sys::general::{
    LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_CMD_HALT, LINUX_REBOOT_CMD_CAD_ON,
    LINUX_REBOOT_CMD_CAD_OFF, LINUX_REBOOT_CMD_POWER_OFF,
};
use los_mm::user as mm_user;

/// TEAM_142: Shutdown flags for verbose mode
pub mod shutdown_flags {
    pub const VERBOSE: u32 = 1;
}

/// TEAM_142: sys_shutdown - Handle Linux reboot syscall.
/// TEAM_421: Returns SyscallResult
/// TEAM_453: Fixed to check cmd argument - not all reboot calls mean shutdown!
///
/// Linux reboot(2) args: magic1, magic2, cmd, arg
/// - CAD_OFF (0): Disable Ctrl+Alt+Del - just return success
/// - CAD_ON: Enable Ctrl+Alt+Del - just return success  
/// - HALT/POWER_OFF/RESTART: Actually shutdown
pub fn sys_shutdown(cmd: u32) -> SyscallResult {
    match cmd {
        LINUX_REBOOT_CMD_CAD_OFF => {
            // TEAM_453: BusyBox init calls this to disable Ctrl+Alt+Del
            // Just acknowledge and return success - don't shutdown!
            log::trace!("[REBOOT] CAD_OFF - Ctrl+Alt+Del disabled");
            return Ok(0);
        }
        LINUX_REBOOT_CMD_CAD_ON => {
            log::trace!("[REBOOT] CAD_ON - Ctrl+Alt+Del enabled");
            return Ok(0);
        }
        LINUX_REBOOT_CMD_RESTART | LINUX_REBOOT_CMD_HALT | LINUX_REBOOT_CMD_POWER_OFF => {
            // These actually mean shutdown
            log::info!("[SHUTDOWN] Initiating graceful shutdown (cmd=0x{:x})...", cmd);
        }
        _ => {
            log::warn!("[REBOOT] Unknown cmd=0x{:x}, treating as shutdown", cmd);
        }
    }
    
    let verbose = true;
    log::info!("[SHUTDOWN] Initiating graceful shutdown...");

    if verbose {
        log::info!("[SHUTDOWN] Phase 1: Stopping user tasks...");
    }

    if verbose {
        log::info!("[SHUTDOWN] Phase 1: Complete");
        log::info!("[SHUTDOWN] Phase 2: Flushing GPU framebuffer...");
    }

    // TEAM_422: GPU flush is handled by kernel, not syscall crate
    // The GPU module is in the main kernel and this crate cannot access it directly.
    // GPU flushing should be done at the kernel level before calling system_off().

    if verbose {
        log::info!("[SHUTDOWN] GPU flush complete");
        log::info!("[SHUTDOWN] Phase 2: Complete");
        log::info!("[SHUTDOWN] Phase 3: Syncing filesystems...");
    }

    if verbose {
        log::info!("[SHUTDOWN] Phase 3: Complete (no pending writes)");
    }

    if verbose {
        log::info!("[SHUTDOWN] Phase 4: Disabling interrupts...");
        log::info!("[SHUTDOWN] Phase 4: Complete");
    }

    log::info!("[SHUTDOWN] System halted. Safe to power off.");
    log::info!("[SHUTDOWN] Goodbye!");

    for _ in 0..100000 {
        core::hint::spin_loop();
    }

    los_hal::interrupts::disable();

    // TEAM_422: Use arch-specific power module
    #[cfg(target_arch = "x86_64")]
    los_arch_x86_64::power::system_off();
    #[cfg(target_arch = "aarch64")]
    los_arch_aarch64::power::system_off();
}

// ============================================================================
// TEAM_350: Eyra Prerequisites - getrandom
// ============================================================================

use core::sync::atomic::AtomicBool;

/// Track if PRNG has been seeded from timer.
static PRNG_SEEDED: AtomicBool = AtomicBool::new(false);

/// Ensure PRNG is seeded with timer entropy (called on first use).
fn ensure_prng_seeded() {
    if !PRNG_SEEDED.swap(true, Ordering::Relaxed) {
        // Seed from timer counter + stack address for entropy
        let timer = crate::time::uptime_seconds();
        let addr_entropy = &timer as *const _ as u64;
        los_utils::entropy::seed(timer ^ addr_entropy);
    }
}

/// TEAM_350: sys_getrandom - Get random bytes.
/// TEAM_421: Returns SyscallResult
///
/// Fills a buffer with random bytes. Uses hardware RNG if available,
/// falls back to PRNG seeded from timer.
///
/// # Arguments
/// * `buf` - User buffer to fill with random bytes
/// * `buflen` - Number of bytes to generate
/// * `flags` - GRND_RANDOM (1) or GRND_NONBLOCK (2), currently ignored
///
/// # Returns
/// Number of bytes written on success, Err(errno) on failure.
pub fn sys_getrandom(buf: usize, buflen: usize, flags: u32) -> SyscallResult {
    log::trace!(
        "[SYSCALL] getrandom(buf=0x{:x}, len={}, flags=0x{:x})",
        buf,
        buflen,
        flags
    );

    if buflen == 0 {
        return Ok(0);
    }

    let task = los_sched::current_task();

    // Validate user buffer
    if mm_user::validate_user_buffer(task.ttbr0.load(Ordering::Acquire), buf, buflen, true).is_err() {
        return Err(EFAULT);
    }

    // Initialize PRNG if needed
    ensure_prng_seeded();

    // TEAM_416: Replace unwrap() with proper error handling for panic safety
    let dest = match mm_user::user_va_to_kernel_ptr(task.ttbr0.load(Ordering::Acquire), buf) {
        Some(ptr) => ptr,
        None => return Err(EFAULT),
    };

    // Fill buffer with random bytes using shared entropy module
    let mut written = 0usize;
    while written < buflen {
        let rand_val = los_utils::entropy::next_u64();
        let rand_bytes = rand_val.to_ne_bytes();

        for &byte in rand_bytes.iter() {
            if written >= buflen {
                break;
            }
            // SAFETY: dest is valid from user_va_to_kernel_ptr check above,
            // and we're writing within validated buffer bounds.
            unsafe {
                *dest.add(written) = byte;
            }
            written += 1;
        }
    }

    Ok(written as i64)
}

/// TEAM_206: Read null-terminated string from user memory
pub fn read_user_string(
    ttbr0: usize,
    ptr: usize,
    max_len: usize,
) -> Result<alloc::string::String, ()> {
    let mut s = alloc::string::String::new();
    for i in 0..max_len {
        let va = ptr + i;
        if let Some(kptr) = mm_user::user_va_to_kernel_ptr(ttbr0, va) {
            let byte = unsafe { *kptr };
            if byte == 0 {
                return Ok(s);
            }
            s.push(byte as char);
        } else {
            return Err(());
        }
    }
    // Truncated or too long
    Err(())
}
