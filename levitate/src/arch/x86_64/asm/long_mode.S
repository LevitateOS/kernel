// TEAM_422: x86_64 Long Mode Utilities
// Limine already puts us in long mode. These are utility functions.

.intel_syntax noprefix

.section .text

// Reload segment registers after GDT change
.global reload_segments
reload_segments:
    // Load new GDT
    lgdt [rip + gdt64_ptr]

    // Reload CS via far return
    push 0x08               // Kernel code segment
    lea rax, [rip + .Lreload_cs]
    push rax
    retfq

.Lreload_cs:
    // Reload data segments
    mov ax, 0x10            // Kernel data segment
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    ret

// Load TSS (Task State Segment)
.global load_tss
load_tss:
    // rdi = TSS selector (e.g., 0x28 for 6th GDT entry)
    ltr di
    ret

// Invalidate TLB entry
.global invlpg
invlpg:
    // rdi = virtual address to invalidate
    invlpg [rdi]
    ret

// Flush entire TLB by reloading CR3
.global flush_tlb
flush_tlb:
    mov rax, cr3
    mov cr3, rax
    ret
