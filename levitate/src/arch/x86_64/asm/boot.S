// TEAM_422: x86_64 Limine boot entry point
// Limine puts us in 64-bit long mode with paging enabled.
// We just need to set up our stack and call the Rust entry point.

.intel_syntax noprefix

.section .text.boot
.global _start
.extern kernel_main

_start:
    // Clear direction flag for string operations
    cld

    // Set up the stack (stack grows down, so we use the end)
    lea rsp, [rip + __stack_end]

    // Clear BSS section
    lea rdi, [rip + __bss_start]
    lea rcx, [rip + __bss_end]
    sub rcx, rdi
    shr rcx, 3           // Divide by 8 (qwords)
    xor eax, eax
    rep stosq

    // Call the Rust kernel_main
    // Limine doesn't pass arguments in registers like DTB boot
    xor edi, edi         // arg0 = 0
    xor esi, esi         // arg1 = 0
    call kernel_main

    // If kernel_main returns, halt
.Lhalt:
    cli
    hlt
    jmp .Lhalt

// Stack (16KB, 16-byte aligned)
.section .bss
.align 16
__stack_start:
    .space 16384
.global __stack_end
__stack_end:

// BSS markers (defined by linker script, but provide defaults)
.weak __bss_start
.weak __bss_end
