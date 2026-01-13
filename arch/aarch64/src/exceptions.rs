use core::arch::global_asm;

global_asm!(include_str!("asm/exceptions.S"));

// TEAM_422: Extern functions provided by levitate for kernel integration
unsafe extern "Rust" {
    fn syscall_dispatch(frame: &mut super::SyscallFrame);
    fn handle_user_exception(ec: u64, esr: u64, elr: u64, far: u64) -> !;
}

/// TEAM_073: Handle synchronous exception from lower EL (userspace).
///
/// This dispatches SVC (syscall) exceptions to the syscall handler,
/// and handles other exceptions (faults, etc.) by killing the process.
#[unsafe(no_mangle)]
pub extern "C" fn handle_sync_lower_el(frame: *mut super::SyscallFrame) {
    // Read ESR to determine exception type
    use aarch64_cpu::registers::{ESR_EL1, Readable};
    let esr: u64 = ESR_EL1.get();

    if super::is_svc_exception(esr) {
        // SVC exception - this is a syscall
        let frame = unsafe { &mut *frame };
        unsafe { syscall_dispatch(frame) };

        // TEAM_216: Check for signals before returning to EL0
        check_signals(frame);
    } else {
        // Other exception from user mode - delegate to kernel
        use aarch64_cpu::registers::{ELR_EL1, FAR_EL1, Readable as _};
        let elr: u64 = ELR_EL1.get();
        let far: u64 = FAR_EL1.get();
        let ec = super::esr_exception_class(esr);

        // TEAM_422: Delegate to kernel-provided handler
        unsafe { handle_user_exception(ec, esr, elr, far) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_sync_exception(esr: u64, elr: u64) {
    // raw prints to avoid core::fmt
    use core::fmt::Write;
    let _ = los_hal::arch::console::WRITER
        .lock()
        .write_str("\n*** KERNEL EXCEPTION: Synchronous ***\n");
    let _ = los_hal::arch::console::WRITER.lock().write_str("ESR: ");
    los_hal::arch::console::print_hex(esr);
    let _ = los_hal::arch::console::WRITER.lock().write_str("\nELR: ");
    los_hal::arch::console::print_hex(elr);
    let _ = los_hal::arch::console::WRITER.lock().write_str("\n");
}

// TEAM_422: Additional extern functions for IRQ and signal handling
// TEAM_472: Added check_preemption_hook for preemptive scheduling
unsafe extern "Rust" {
    fn handle_irq_dispatch(irq: u32) -> bool;
    fn check_and_deliver_signals(frame: &mut super::SyscallFrame);
    fn check_preemption_hook(frame: &mut super::SyscallFrame);
}

/// Handle IRQs.
#[unsafe(no_mangle)]
pub extern "C" fn handle_irq(frame: *mut super::SyscallFrame) {
    use los_hal::aarch64::gic;
    let gic_api = gic::active_api();
    let irq = gic_api.acknowledge();

    if gic::Gic::is_spurious(irq) {
        return;
    }

    // TEAM_422: Delegate IRQ dispatch to kernel
    if !unsafe { handle_irq_dispatch(irq) } {
        log::warn!("Unhandled IRQ: {}", irq);
    }

    gic_api.end_interrupt(irq);

    // TEAM_216: If IRQ came from userspace, check for signals and preemption
    if !frame.is_null() {
        let frame = unsafe { &mut *frame };
        check_signals(frame);
        // TEAM_472: Check if preemption is needed after handling IRQ
        check_preemption(frame);
    }
}

/// TEAM_216: Check for pending unmasked signals and deliver them.
/// TEAM_422: Delegates to kernel-provided signal handler.
pub fn check_signals(frame: &mut super::SyscallFrame) {
    unsafe { check_and_deliver_signals(frame) };
}

/// TEAM_472: Check if preemption is needed before returning to userspace.
/// Called after IRQ handling when returning to user mode.
/// Delegates to kernel-provided check_preemption_hook.
pub fn check_preemption(frame: &mut super::SyscallFrame) {
    unsafe { check_preemption_hook(frame) };
}

pub fn init() {
    unsafe extern "C" {
        static vectors: u8;
    }
    use aarch64_cpu::registers::{VBAR_EL1, Writeable};
    let vectors_ptr = unsafe { &vectors as *const u8 as u64 };
    VBAR_EL1.set(vectors_ptr);
}
