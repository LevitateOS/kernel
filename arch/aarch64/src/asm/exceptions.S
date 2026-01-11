// TEAM_422: AArch64 exception vector table
// Aligned to 2048 bytes (0x800) as required by ARM architecture.

.section .text.vectors
.align 11  // 2^11 = 2048 byte alignment

.global vectors
vectors:
    // Current EL with SP_EL0
    .align 7
    b sync_current_sp0      // 0x000 - Synchronous
    .align 7
    b irq_current_sp0       // 0x080 - IRQ
    .align 7
    b fiq_current_sp0       // 0x100 - FIQ
    .align 7
    b serror_current_sp0    // 0x180 - SError

    // Current EL with SP_ELx
    .align 7
    b sync_current_spx      // 0x200 - Synchronous
    .align 7
    b irq_current_spx       // 0x280 - IRQ
    .align 7
    b fiq_current_spx       // 0x300 - FIQ
    .align 7
    b serror_current_spx    // 0x380 - SError

    // Lower EL using AArch64
    .align 7
    b sync_lower_el         // 0x400 - Synchronous
    .align 7
    b irq_lower_el          // 0x480 - IRQ
    .align 7
    b fiq_lower_el          // 0x500 - FIQ
    .align 7
    b serror_lower_el       // 0x580 - SError

    // Lower EL using AArch32
    .align 7
    b sync_lower_el32       // 0x600 - Synchronous
    .align 7
    b irq_lower_el32        // 0x680 - IRQ
    .align 7
    b fiq_lower_el32        // 0x700 - FIQ
    .align 7
    b serror_lower_el32     // 0x780 - SError

// Save SyscallFrame macro
.macro save_frame
    sub sp, sp, #280        // SyscallFrame size (31*8 + 4*8)
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    mrs x0, sp_el0
    str x0, [sp, #248]      // sp
    mrs x0, elr_el1
    str x0, [sp, #256]      // pc
    mrs x0, spsr_el1
    str x0, [sp, #264]      // pstate
    mrs x0, ttbr0_el1
    str x0, [sp, #272]      // ttbr0
.endm

// Restore SyscallFrame macro
.macro restore_frame
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    ldr x17, [sp, #248]
    msr sp_el0, x17
    ldr x17, [sp, #256]
    msr elr_el1, x17
    ldr x17, [sp, #264]
    msr spsr_el1, x17
    add sp, sp, #280
.endm

// Exception handlers
sync_current_sp0:
sync_current_spx:
    mrs x0, esr_el1
    mrs x1, elr_el1
    bl handle_sync_exception
    eret

irq_current_sp0:
irq_current_spx:
    save_frame
    mov x0, #0              // No frame for kernel IRQ
    bl handle_irq
    restore_frame
    eret

fiq_current_sp0:
fiq_current_spx:
serror_current_sp0:
serror_current_spx:
    b .                     // Hang on unhandled exception

// Lower EL handlers (userspace)
sync_lower_el:
    save_frame
    mov x0, sp              // Pass SyscallFrame pointer
    bl handle_sync_lower_el
    restore_frame
    eret

irq_lower_el:
    save_frame
    mov x0, sp              // Pass SyscallFrame pointer
    bl handle_irq
    restore_frame
    eret

fiq_lower_el:
serror_lower_el:
sync_lower_el32:
irq_lower_el32:
fiq_lower_el32:
serror_lower_el32:
    b .                     // Hang on unhandled
