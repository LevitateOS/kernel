// TEAM_422: AArch64 boot assembly stub
// This file provides the early boot entry point for the kernel.
// The actual implementation should set up the initial stack and call the Rust entry point.

// BOOT_REGS and BOOT_DTB_ADDR are defined in Rust (boot.rs)
.extern BOOT_REGS
.extern BOOT_DTB_ADDR

.section .text.boot
.global _start

_start:
    // Preserve boot registers (x0-x3)
    adrp x4, BOOT_REGS
    add x4, x4, :lo12:BOOT_REGS
    stp x0, x1, [x4]
    stp x2, x3, [x4, #16]

    // Store DTB address
    adrp x4, BOOT_DTB_ADDR
    add x4, x4, :lo12:BOOT_DTB_ADDR
    str x0, [x4]

    // Set up stack
    ldr x4, =__stack_end
    mov sp, x4

    // Clear BSS
    ldr x4, =__bss_start
    ldr x5, =__bss_end
1:  cmp x4, x5
    b.ge 2f
    str xzr, [x4], #8
    b 1b
2:
    // Jump to Rust entry
    bl rust_main

    // If Rust returns, halt
3:  wfe
    b 3b
