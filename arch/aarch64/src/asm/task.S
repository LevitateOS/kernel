// TEAM_422: AArch64 context switch and task entry trampoline

.section .text

// cpu_switch_to(old: *mut Context, new: *const Context)
// Context layout (offsets in bytes):
//   x19-x28: 0-80
//   x29 (fp): 80
//   x30 (lr): 88
//   sp: 96
//   tpidr_el0: 104
//   fpu_state: 112 (512 bytes for v0-v31 + 8 bytes for fpcr/fpsr)
.global cpu_switch_to
cpu_switch_to:
    // Save callee-saved registers to old context
    stp x19, x20, [x0, #0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    mov x9, sp
    str x9, [x0, #96]
    mrs x9, tpidr_el0
    str x9, [x0, #104]

    // Save FPU state
    add x9, x0, #112
    stp q0, q1, [x9, #0]
    stp q2, q3, [x9, #32]
    stp q4, q5, [x9, #64]
    stp q6, q7, [x9, #96]
    stp q8, q9, [x9, #128]
    stp q10, q11, [x9, #160]
    stp q12, q13, [x9, #192]
    stp q14, q15, [x9, #224]
    stp q16, q17, [x9, #256]
    stp q18, q19, [x9, #288]
    stp q20, q21, [x9, #320]
    stp q22, q23, [x9, #352]
    stp q24, q25, [x9, #384]
    stp q26, q27, [x9, #416]
    stp q28, q29, [x9, #448]
    stp q30, q31, [x9, #480]
    mrs x10, fpcr
    mrs x11, fpsr
    // Can't use stp with offset 512, use add + str instead
    add x12, x9, #512
    str w10, [x12]
    str w11, [x12, #4]

    // Restore callee-saved registers from new context
    ldp x19, x20, [x1, #0]
    ldp x21, x22, [x1, #16]
    ldp x23, x24, [x1, #32]
    ldp x25, x26, [x1, #48]
    ldp x27, x28, [x1, #64]
    ldp x29, x30, [x1, #80]
    ldr x9, [x1, #96]
    mov sp, x9
    ldr x9, [x1, #104]
    msr tpidr_el0, x9

    // Restore FPU state
    add x9, x1, #112
    ldp q0, q1, [x9, #0]
    ldp q2, q3, [x9, #32]
    ldp q4, q5, [x9, #64]
    ldp q6, q7, [x9, #96]
    ldp q8, q9, [x9, #128]
    ldp q10, q11, [x9, #160]
    ldp q12, q13, [x9, #192]
    ldp q14, q15, [x9, #224]
    ldp q16, q17, [x9, #256]
    ldp q18, q19, [x9, #288]
    ldp q20, q21, [x9, #320]
    ldp q22, q23, [x9, #352]
    ldp q24, q25, [x9, #384]
    ldp q26, q27, [x9, #416]
    ldp q28, q29, [x9, #448]
    ldp q30, q31, [x9, #480]
    // Can't use ldp with offset 512, use add + ldr instead
    add x12, x9, #512
    ldr w10, [x12]
    ldr w11, [x12, #4]
    msr fpcr, x10
    msr fpsr, x11

    ret

// TEAM_422: Extern function provided by levitate for task exit
.extern task_exit

// task_entry_trampoline
// Called after context switch to a new task.
// Entry wrapper address is in x19 (restored from context).
.global task_entry_trampoline
task_entry_trampoline:
    mov x0, x19             // Pass entry wrapper as argument
    blr x19                 // Call entry wrapper

    // If entry wrapper returns, exit task (provided by levitate)
    bl task_exit
    b .                     // Should not reach here
