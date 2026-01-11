// TEAM_422: x86_64 GDT (Global Descriptor Table)
// Limine already sets up a GDT, but we define our own for kernel control.

.section .rodata
.align 16

// GDT entries (each is 8 bytes)
.global gdt64
gdt64:
    .quad 0                     // 0x00: Null descriptor
    .quad 0x00AF9A000000FFFF    // 0x08: Kernel Code (64-bit, ring 0)
    .quad 0x00AF92000000FFFF    // 0x10: Kernel Data (64-bit, ring 0)
    .quad 0x00AFFA000000FFFF    // 0x18: User Data (64-bit, ring 3)
    .quad 0x00AFF2000000FFFF    // 0x20: User Code (64-bit, ring 3)
gdt64_end:

// GDT pointer structure
.global gdt64_ptr
gdt64_ptr:
    .word gdt64_end - gdt64 - 1 // Limit
    .quad gdt64                  // Base address

// Segment selectors
.global GDT_KERNEL_CODE
.equ GDT_KERNEL_CODE, 0x08
.global GDT_KERNEL_DATA
.equ GDT_KERNEL_DATA, 0x10
.global GDT_USER_DATA
.equ GDT_USER_DATA, 0x1B        // 0x18 | 3
.global GDT_USER_CODE
.equ GDT_USER_CODE, 0x23        // 0x20 | 3
