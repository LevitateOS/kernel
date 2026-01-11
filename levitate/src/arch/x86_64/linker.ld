/* TEAM_422: x86_64 Linker Script for Limine Boot
 *
 * Limine loads the kernel at the virtual address specified in .requests.
 * The kernel runs in long mode from the start, with paging already enabled.
 */

ENTRY(_start)

PHDRS
{
    text      PT_LOAD FLAGS(5); /* R-X */
    rodata    PT_LOAD FLAGS(4); /* R-- */
    data      PT_LOAD FLAGS(6); /* RW- */
}

SECTIONS
{
    /* Higher-Half Virtual Address Base for x86_64 */
    _kernel_virt_base = 0xFFFFFFFF80000000;
    . = _kernel_virt_base;

    _kernel_virt_start = .;

    /* Boot text section - entry point first */
    .text ALIGN(4K) : {
        __text_start = .;
        KEEP(*(.text.boot))
        *(.text*)
        __text_end = .;
    } :text

    .rodata ALIGN(4K) : {
        __rodata_start = .;
        *(.rodata*)
        __rodata_end = .;
    } :rodata

    /* Limine requests section - must be writable for responses */
    .requests ALIGN(4K) : {
        KEEP(*(.requests))
    } :data

    .data ALIGN(4K) : {
        __data_start = .;
        *(.data*)
        __data_end = .;
    } :data

    .bss ALIGN(4K) : {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } :data

    /* Kernel stack defined in boot.S */

    /* Kernel heap - must be part of a segment to be mapped by Limine */
    /* TEAM_387: 128MB heap for coreutils support */
    .heap ALIGN(4K) : {
        __heap_start = .;
        . = . + 0x8000000; /* 128MB */
        __heap_end = .;
        BYTE(0) /* Force section to have size */
    } :data

    _kernel_end = .;

    /* Symbols for compatibility */
    __kernel_start = _kernel_virt_start;
    _kernel_size = _kernel_end - _kernel_virt_start;

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.note*)
    }
}
