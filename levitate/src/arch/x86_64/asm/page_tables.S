// TEAM_422: x86_64 Page Tables
// Limine already sets up paging, but we may want our own tables later.
// This file provides stubs/placeholders for future use.

.section .bss
.align 4096

// Page table storage for kernel use (if needed)
// Each table is 4KB (512 entries * 8 bytes)
.global boot_pml4
boot_pml4:
    .space 4096

.global boot_pdpt
boot_pdpt:
    .space 4096

.global boot_pd
boot_pd:
    .space 4096

.global boot_pt
boot_pt:
    .space 4096
