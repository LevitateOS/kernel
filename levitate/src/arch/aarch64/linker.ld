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
