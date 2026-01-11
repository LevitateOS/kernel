// TEAM_422: AArch64 boot assembly with early MMU setup
// TEAM_427: Investigation of boot failures - see .teams/TEAM_427_aarch64_boot_investigation.md
//           Status: Partial fix - kernel prints boot messages but crashes during memory::init()
//           with L0 translation fault at FAR 0xffff800040082000
//
// Boot sequence:
// 1. Save boot registers (x0-x3) from bootloader
// 2. Disable interrupts
// 3. Zero boot BSS (includes page tables)
// 4. Set up early page tables with identity + higher-half mapping
// 5. Configure and enable MMU
// 6. Jump to higher-half rust_main
//
// Memory model (QEMU virt):
// - Physical kernel load: 0x40080000
// - Virtual kernel base:  0xFFFF_8000_0000_0000 (higher-half)
// - Identity map needed:  0x0000_0000 - 0x8000_0000 (low 2GB for devices/RAM)
// - Higher-half map:      Physical RAM mapped at VA = PA + 0xFFFF_8000_0000_0000

// External symbols from linker script (at physical addresses)
.extern __bss_boot_start
.extern __bss_boot_end
.extern __boot_page_tables_start
.extern __boot_page_tables_end
.extern __boot_l0_ttbr1
.extern __boot_l0_ttbr0
.extern __boot_l1_high
.extern __boot_l1_low
.extern __stack_end

// Boot data symbols at physical address (in .bss.boot section)
.extern BOOT_REGS_PHYS
.extern BOOT_DTB_ADDR_PHYS

// Rust entry point (at higher-half virtual address)
.extern rust_main

// Constants
.equ KERNEL_VIRT_BASE, 0xFFFF800000000000

// Page table descriptor flags
// These must be values that work with AArch64 immediate encoding
.equ PT_VALID,     0x1            // Valid entry
.equ PT_TABLE,     0x2            // Table descriptor
.equ PT_AF,        0x400          // Access flag (bit 10)
.equ PT_SH_INNER,  0x300          // Inner shareable (bits 9:8 = 11)
.equ PT_ATTR_IDX0, 0x0            // MAIR index 0 = normal memory (bits 4:2)
.equ PT_ATTR_IDX1, 0x4            // MAIR index 1 = device memory (bits 4:2)

// Combined flags - use mov + orr sequence to build these
// BLOCK_NORMAL = Valid + Block + AF + Inner-Share + AttrIdx0 = 0x701
// BLOCK_DEVICE = Valid + Block + AF + AttrIdx1 = 0x405
// TABLE = Valid + Table = 0x3
.equ BLOCK_NORMAL_FLAGS, 0x701
.equ BLOCK_DEVICE_FLAGS, 0x405
.equ TABLE_FLAGS, 0x3

.section .text.boot, "ax"
.global _start

_start:
    // Disable interrupts
    msr daifset, #0xf

    // TEAM_427: Enable FP/SIMD (required for Rust code) FIRST
    // Use x9 as a scratch register to preserve x0-x3 boot registers
    // Set CPACR_EL1.FPEN to 0b11 (bits 21:20) to enable EL1/EL0 access
    mov x9, #(3 << 20)
    msr cpacr_el1, x9
    isb

    // Save boot registers to physical-address symbols
    // x0 = DTB address (on QEMU virt), x1-x3 = bootloader-specific
    adrp x4, BOOT_REGS_PHYS
    add x4, x4, :lo12:BOOT_REGS_PHYS
    stp x0, x1, [x4]
    stp x2, x3, [x4, #16]

    adrp x4, BOOT_DTB_ADDR_PHYS
    add x4, x4, :lo12:BOOT_DTB_ADDR_PHYS
    str x0, [x4]

    // Set up early stack (at physical address, before MMU)
    ldr x4, =__stack_end
    // Convert from virtual to physical (subtract virt base)
    // __stack_end is after the virt base jump, so it's a virtual address
    // But wait - at this point we're using the linker symbol directly
    // and the literal pool is at physical address, containing the virtual address.
    // We need to calculate the physical address.
    // TEAM_427: Build 0xFFFF_8000_0000_0000 correctly
    // movz sets bits 63:48 to 0xFFFF, movk sets bits 47:32 to 0x8000
    movz x5, #0xFFFF, lsl #48  // x5 = 0xFFFF_0000_0000_0000
    movk x5, #0x8000, lsl #32  // x5 = 0xFFFF_8000_0000_0000
    sub x4, x4, x5              // Convert VA to PA
    mov sp, x4

    // Zero boot BSS and page tables (at physical addresses)
    adrp x4, __bss_boot_start
    add x4, x4, :lo12:__bss_boot_start
    adrp x5, __boot_page_tables_end
    add x5, x5, :lo12:__boot_page_tables_end
.Lzero_boot_bss:
    cmp x4, x5
    b.ge .Lzero_done
    str xzr, [x4], #8
    b .Lzero_boot_bss
.Lzero_done:

    // === Set up early page tables ===
    // We need:
    // - Identity map: VA 0-2GB -> PA 0-2GB (for continued execution after MMU on)
    // - Higher-half map: VA 0xFFFF_8000_0000_0000+ -> PA 0+ (for kernel)
    //
    // Using 1GB blocks in L1 for simplicity.
    // Each TTBR needs: L0 table -> L1 table (with 1GB block descriptors)

    // Get page table addresses (all at physical addresses)
    adrp x10, __boot_l0_ttbr1
    add x10, x10, :lo12:__boot_l0_ttbr1   // x10 = L0 for TTBR1 (higher-half)
    adrp x11, __boot_l0_ttbr0
    add x11, x11, :lo12:__boot_l0_ttbr0   // x11 = L0 for TTBR0 (identity)
    adrp x12, __boot_l1_high
    add x12, x12, :lo12:__boot_l1_high    // x12 = L1 for higher-half
    adrp x13, __boot_l1_low
    add x13, x13, :lo12:__boot_l1_low     // x13 = L1 for identity

    // === TTBR1 (higher-half) page tables ===
    // L0[256] -> L1_high (index 256 covers VA 0xFFFF_8000_0000_0000)
    // L0 index for 0xFFFF_8000_0000_0000 = bits[47:39] = 256
    mov x3, x12                 // L1_high physical address
    orr x3, x3, #TABLE_FLAGS    // Add table descriptor flags
    str x3, [x10, #(256 * 8)]   // L0_ttbr1[256] = L1_high table

    // L1_high[0] = 0x0000_0000 (1GB block) - first 1GB (devices)
    mov x3, #BLOCK_DEVICE_FLAGS
    str x3, [x12, #(0 * 8)]

    // L1_high[1] = 0x4000_0000 (1GB block) - second 1GB (kernel RAM)
    mov x3, #0x40000000
    mov x4, #BLOCK_NORMAL_FLAGS
    orr x3, x3, x4
    str x3, [x12, #(1 * 8)]

    // === TTBR0 (identity map) page tables ===
    // L0[0] -> L1_low (index 0 covers VA 0x0000_0000_0000_0000)
    mov x3, x13                 // L1_low physical address
    orr x3, x3, #TABLE_FLAGS    // Add table descriptor flags
    str x3, [x11, #(0 * 8)]     // L0_ttbr0[0] = L1_low table

    // L1_low[0] = 0x0000_0000 (1GB device block) - devices
    mov x3, #BLOCK_DEVICE_FLAGS
    str x3, [x13, #(0 * 8)]

    // L1_low[1] = 0x4000_0000 (1GB normal block) - RAM (kernel runs here initially)
    mov x3, #0x40000000
    mov x4, #BLOCK_NORMAL_FLAGS
    orr x3, x3, x4
    str x3, [x13, #(1 * 8)]

    // === Configure MMU ===

    // MAIR_EL1: Memory Attribute Indirection Register
    // Index 0: Normal memory (write-back, write-allocate) = 0xFF
    // Index 1: Device-nGnRnE memory = 0x00
    // Index 2-7: unused (0)
    mov x3, #0xFF               // Index 0: Normal memory
    msr mair_el1, x3

    // TCR_EL1: Translation Control Register
    // Configure 4KB granule, 48-bit VA for both TTBR0 and TTBR1
    //
    // Bit layout:
    // [5:0]   T0SZ = 16 (48-bit VA for TTBR0)
    // [7:6]   reserved
    // [9:8]   IRGN0 = 1 (write-back write-allocate)
    // [11:10] ORGN0 = 1 (write-back write-allocate)
    // [13:12] SH0 = 3 (inner shareable)
    // [15:14] TG0 = 0 (4KB granule)
    // [21:16] T1SZ = 16 (48-bit VA for TTBR1)
    // [23:22] A1, EPD1 = 0
    // [25:24] IRGN1 = 1
    // [27:26] ORGN1 = 1
    // [29:28] SH1 = 3
    // [31:30] TG1 = 2 (4KB granule)
    // [34:32] IPS = 5 (48-bit PA)
    //
    // Value: 0x5_B5103510
    // T0SZ=16, IRGN0=1, ORGN0=1, SH0=3, TG0=0,
    // T1SZ=16, IRGN1=1, ORGN1=1, SH1=3, TG1=2, IPS=5
    ldr x3, =0x5B5103510
    msr tcr_el1, x3

    // Load TTBR0_EL1 (identity map) - x11 still holds __boot_l0_ttbr0
    msr ttbr0_el1, x11

    // Load TTBR1_EL1 (higher-half map) - x10 still holds __boot_l0_ttbr1
    msr ttbr1_el1, x10

    // TEAM_428: Ensure page table writes are visible to MMU
    // CRITICAL FIX: Must clean+invalidate the ENTIRE page table region,
    // not just the entries we wrote. The zeroing loop may have left
    // stale data in the cache that could corrupt the MMU's view.
    //
    // Page tables span 16KB (4 x 4KB tables) from __boot_l0_ttbr1 to
    // __boot_page_tables_end. That's 256 cache lines (64 bytes each).
    dsb sy

    // Clean and invalidate entire page table region (16KB)
    // x10 = __boot_l0_ttbr1 (start of page tables)
    mov x3, x10                 // Start address
    mov x4, #256                // 256 cache lines = 16KB
.Lflush_pt_cache:
    dc civac, x3                // Clean+invalidate cache line at x3
    add x3, x3, #64             // Next cache line (64 bytes)
    subs x4, x4, #1             // Decrement counter
    b.ne .Lflush_pt_cache       // Loop until done
    dsb sy
    isb

    // Invalidate TLB before enabling MMU
    tlbi vmalle1
    dsb sy
    isb

    // Enable MMU via SCTLR_EL1
    mrs x3, sctlr_el1
    orr x3, x3, #(1 << 0)       // M: Enable MMU
    orr x3, x3, #(1 << 2)       // C: Enable data cache
    orr x3, x3, #(1 << 12)      // I: Enable instruction cache
    msr sctlr_el1, x3

    dsb sy
    isb

    // TEAM_427: Set up exception vectors BEFORE jumping to Rust
    // This ensures any early exceptions are properly caught
    .extern vectors
    ldr x4, =vectors
    msr vbar_el1, x4
    isb

    // === Jump to higher-half Rust entry point ===
    // Now that MMU is on, we can use virtual addresses
    ldr x4, =rust_main
    br x4

    // Should never reach here
.Lhalt:
    wfe
    b .Lhalt
