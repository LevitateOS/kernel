//! TEAM_222: x86_64 time support
//! TEAM_430: Implemented RDTSC-based timing for nanosleep/clock_gettime

use core::sync::atomic::{AtomicU64, Ordering};

/// Cached TSC frequency (detected once at boot)
static TSC_FREQUENCY: AtomicU64 = AtomicU64::new(0);

/// Read the TSC (Time Stamp Counter)
#[inline]
pub fn read_timer_counter() -> u64 {
    // SAFETY: RDTSC is available on all modern x86_64 CPUs
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem, preserves_flags)
        );
        ((hi as u64) << 32) | (lo as u64)
    }
}

/// Get the TSC frequency in Hz
///
/// Uses CPUID leaf 0x15 (Time Stamp Counter and Nominal Core Crystal Clock)
/// if available, otherwise estimates by measuring against PIT.
pub fn read_timer_frequency() -> u64 {
    let cached = TSC_FREQUENCY.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }

    // Try CPUID leaf 0x15 first (Intel Skylake+, AMD Zen+)
    let freq = detect_tsc_frequency_cpuid()
        .unwrap_or_else(|| detect_tsc_frequency_pit());

    TSC_FREQUENCY.store(freq, Ordering::Relaxed);
    freq
}

/// Detect TSC frequency using CPUID leaf 0x15
fn detect_tsc_frequency_cpuid() -> Option<u64> {
    // Check if CPUID leaf 0x15 is available
    let max_leaf = cpuid(0).eax;
    if max_leaf < 0x15 {
        return None;
    }

    let result = cpuid(0x15);
    let denominator = result.eax as u64; // TSC/core crystal clock ratio denominator
    let numerator = result.ebx as u64;   // TSC/core crystal clock ratio numerator
    let crystal_freq = result.ecx as u64; // Core crystal clock frequency in Hz

    if denominator == 0 || numerator == 0 {
        return None;
    }

    if crystal_freq != 0 {
        // TSC frequency = crystal_freq * numerator / denominator
        Some((crystal_freq * numerator) / denominator)
    } else {
        // Crystal frequency not reported - common on older Intel CPUs
        // Try to get nominal frequency from leaf 0x16
        let max_leaf = cpuid(0).eax;
        if max_leaf >= 0x16 {
            let freq_info = cpuid(0x16);
            let base_mhz = freq_info.eax as u64;
            if base_mhz != 0 {
                return Some(base_mhz * 1_000_000);
            }
        }
        None
    }
}

/// Detect TSC frequency by calibrating against PIT (fallback method)
/// Uses PIT channel 2 for measurement
fn detect_tsc_frequency_pit() -> u64 {
    const PIT_FREQUENCY: u64 = 1_193_182; // PIT oscillator frequency
    const CALIBRATION_MS: u64 = 10; // Calibrate for 10ms
    const PIT_COUNT: u16 = ((PIT_FREQUENCY * CALIBRATION_MS) / 1000) as u16;

    // Configure PIT channel 2 for one-shot mode
    // SAFETY: Writing to PIT I/O ports is safe
    unsafe {
        // Disable speaker (bit 0) and gate (bit 1)
        let control = inb(0x61);
        outb(0x61, control & !0x03);

        // Configure channel 2: mode 0 (interrupt on terminal count), binary
        outb(0x43, 0xB0); // Channel 2, lobyte/hibyte, mode 0, binary

        // Load count
        outb(0x42, (PIT_COUNT & 0xFF) as u8);
        outb(0x42, ((PIT_COUNT >> 8) & 0xFF) as u8);

        // Enable gate to start counting
        let control = inb(0x61);
        outb(0x61, control | 0x01);

        // Read start TSC
        let start_tsc = read_timer_counter();

        // Wait for PIT to count down (bit 5 of port 0x61 goes high)
        while (inb(0x61) & 0x20) == 0 {
            core::hint::spin_loop();
        }

        // Read end TSC
        let end_tsc = read_timer_counter();

        // Disable gate
        let control = inb(0x61);
        outb(0x61, control & !0x01);

        // Calculate frequency: ticks * 1000 / ms
        let ticks = end_tsc.saturating_sub(start_tsc);
        (ticks * 1000) / CALIBRATION_MS
    }
}

/// CPUID result
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    #[allow(dead_code)]
    edx: u32,
}

/// Execute CPUID instruction
fn cpuid(leaf: u32) -> CpuidResult {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;

    // SAFETY: CPUID is available on all x86_64 CPUs
    // Note: We must save/restore rbx because LLVM uses it internally
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            in("eax") leaf,
            in("ecx") 0u32,
            ebx_out = out(reg) ebx,
            lateout("eax") eax,
            lateout("ecx") ecx,
            lateout("edx") edx,
            options(preserves_flags)
        );
    }

    CpuidResult { eax, ebx, ecx, edx }
}

/// Read from I/O port
#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nostack, nomem, preserves_flags)
        );
    }
    value
}

/// Write to I/O port
#[inline]
unsafe fn outb(port: u16, value: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nostack, nomem, preserves_flags)
        );
    }
}
