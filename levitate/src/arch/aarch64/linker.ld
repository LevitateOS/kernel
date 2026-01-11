/* TEAM_422: AArch64 Linker Script for LevitateOS
 *
 * Memory Layout (QEMU virt):
 * - Physical: 0x40080000 (QEMU virt kernel load address)
 * - Virtual:  0xFFFF800000000000 (higher-half)
 */

ENTRY(_start)

SECTIONS
{
    /* Physical Load Address */
    . = 0x40080000;
    _kernel_phys_start = .;
    __executable_start = .;

    /* Boot code that runs before MMU or in identity map */
    .text.head : {
        KEEP(*(.text.head))
        KEEP(*(.text.boot))
    }

    /* Boot-time data accessible from physical address space.
     * BOOT_REGS and BOOT_DTB_ADDR must be here because boot code uses
     * adrp which has ±4GB range - can't reach higher-half from 0x40080000.
     */
    .data.boot : {
        *(.data.boot)
        *(.data.boot.*)
    }

    .bss.boot (NOLOAD) : {
        __bss_boot_start = .;
        *(.bss.boot)
        *(.bss.boot.*)
        . = ALIGN(16);
        __bss_boot_end = .;
    }

    /* Early page tables for boot MMU setup (must be 4KB aligned)
     * These are used by boot.S before jumping to higher-half Rust code.
     * Layout:
     * - __boot_l0_ttbr1: L0 for TTBR1 (higher-half)
     * - __boot_l0_ttbr0: L0 for TTBR0 (identity map)
     * - __boot_l1_high:  L1 for higher-half mapping
     * - __boot_l1_low:   L1 for identity mapping
     */
    . = ALIGN(4096);
    __boot_page_tables_start = .;
    .boot_page_tables (NOLOAD) : {
        __boot_l0_ttbr1 = .;
        . = . + 4096;
        __boot_l0_ttbr0 = .;
        . = . + 4096;
        __boot_l1_high = .;
        . = . + 4096;
        __boot_l1_low = .;
        . = . + 4096;
    }
    __boot_page_tables_end = .;

    /* Higher-Half Virtual Address Base */
    _kernel_virt_base = 0xFFFF800000000000;
    . += _kernel_virt_base;
    _kernel_virt_start = .;

    .text : AT(ADDR(.text) - _kernel_virt_base) {
        . = ALIGN(0x800);
        __vectors_start = .;
        *(.text.vectors)
        *(.text*)
    }

    .rodata : AT(ADDR(.rodata) - _kernel_virt_base) {
        *(.rodata*)
    }

    .data : AT(ADDR(.data) - _kernel_virt_base) {
        *(.data*)
    }

    .bss : AT(ADDR(.bss) - _kernel_virt_base) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    /* Stack (64KB) - grows downward */
    . = ALIGN(16);
    __stack_start = .;
    . = . + 0x10000;
    __stack_end = .;
    stack_top = .;

    /* Heap (128MB) */
    . = ALIGN(16);
    __heap_start = .;
    . = _kernel_virt_base + 0x41F00000;
    __heap_end = .;
    _kernel_end = .;

    _kernel_size = . - _kernel_virt_base - 0x40080000;

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.note*)
    }
}
