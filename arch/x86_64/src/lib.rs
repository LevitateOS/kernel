#![no_std]
//! TEAM_162: x86_64 Architecture Stub
//! TEAM_258: Added complete Linux x86_64 syscall numbers and termios constants
//!
//! This module provides stubs for x86_64 to verify the architecture abstraction.

pub mod boot;
pub mod cpu;
pub mod exceptions;
pub mod power;
pub mod syscall;
pub mod task;
pub mod time;

// Re-export Context and other items from task
pub use self::boot::*;
pub use self::exceptions::*;
pub use self::task::*;

pub const ELF_MACHINE: u16 = 62; // EM_X86_64

/// TEAM_293: GDT segment selectors
pub const GDT_KERNEL_CODE: u16 = 0x08;
pub const GDT_KERNEL_DATA: u16 = 0x10;
pub const GDT_USER_DATA: u16 = 0x18 | 3; // 0x1B - Ring 3
pub const GDT_USER_CODE: u16 = 0x20 | 3; // 0x23 - Ring 3

/// TEAM_258: Linux x86_64 compatible syscall numbers
/// Reference: https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
/// NOTE: Using names expected by syscall dispatcher (some differ from Linux canonical names)
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    // === Standard Linux x86_64 syscalls ===
    Read = 0,
    Write = 1,
    Close = 3,
    Fstat = 5,
    Poll = 7,  // TEAM_406: I/O multiplexing
    Lseek = 8, // TEAM_404: File positioning
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Sbrk = 12, // x86: brk=12
    SigAction = 13,
    SigProcMask = 14,
    SigReturn = 15,
    Ioctl = 16,
    Pread64 = 17,  // TEAM_404: Positioned read
    Pwrite64 = 18, // TEAM_404: Positioned write
    Readv = 19,
    Writev = 20,
    Yield = 24, // x86: sched_yield=24
    Dup = 32,
    Dup2 = 33, // TEAM_404: Legacy dup
    Pause = 34,
    Nanosleep = 35,
    GetPid = 39, // x86: getpid=39
    Clone = 56,
    Exec = 59, // x86: execve=59
    Exit = 60,
    Waitpid = 61, // x86: wait4=61
    Kill = 62,
    Uname = 63,        // TEAM_406: System identification
    Chmod = 90,        // TEAM_406: Change file permissions
    Fchmod = 91,       // TEAM_406: Change permissions by fd
    Chown = 92,        // TEAM_406: Change file owner
    Fchown = 93,       // TEAM_406: Change owner by fd
    Umask = 95,        // TEAM_406: File creation mask
    Gettimeofday = 96, // TEAM_409: Legacy time syscall
    Getrusage = 98,    // TEAM_409: Resource usage
    Truncate = 76,     // TEAM_409: Truncate file by path
    Ftruncate = 77,    // TEAM_404: Truncate file by fd
    Getdents = 78,
    Getcwd = 79,
    Chdir = 80,    // TEAM_404: Change directory
    Fchdir = 81,   // TEAM_404: Change directory by fd
    GetPpid = 110, // x86: getppid=110
    Mount = 165,
    Umount = 166,
    Shutdown = 169, // x86: reboot=169
    Futex = 202,
    SetTidAddress = 218,
    ClockGettime = 228,
    Openat = 257,
    Mkdirat = 258,
    Unlinkat = 263,
    Renameat = 264,
    Linkat = 265,
    Symlinkat = 266,
    Readlinkat = 267,
    Utimensat = 280,
    Dup3 = 292,
    Pipe2 = 293,
    // TEAM_350: Eyra prerequisites
    Gettid = 186,
    ExitGroup = 231,
    Getuid = 102,
    Geteuid = 107,
    Getgid = 104,
    Getegid = 108,
    ClockGetres = 229,
    Madvise = 28,
    Getrandom = 318,
    ArchPrctl = 158,
    Faccessat = 269,
    // TEAM_358: Extended file stat
    Statx = 332,
    // TEAM_360: Eyra syscalls
    Ppoll = 271,
    Tkill = 200,
    PkeyAlloc = 330,
    PkeyMprotect = 329, // TEAM_409: Fixed from 302
    Sigaltstack = 131,
    // TEAM_394: Epoll syscalls for tokio/brush support
    EpollCreate1 = 291,
    EpollCtl = 233,
    EpollWait = 232,
    Eventfd2 = 290,
    // TEAM_394: Process group syscalls for brush job control
    Setpgid = 109,
    Getpgid = 121,
    Getpgrp = 111,
    Setsid = 112,
    // TEAM_394: fcntl for brush (F_SETPIPE_SZ, etc.)
    Fcntl = 72,
    // TEAM_409: Additional syscalls for coreutils
    Fstatat = 262,   // newfstatat - stat relative to dirfd
    Prlimit64 = 302, // get/set resource limits

    // === Custom LevitateOS syscalls ===
    Spawn = 1000,
    SpawnArgs = 1001,
    SetForeground = 1002,
    GetForeground = 1003,
    Isatty = 1010,
}

impl SyscallNumber {
    pub fn from_u64(n: u64) -> Option<Self> {
        match n {
            0 => Some(Self::Read),
            1 => Some(Self::Write),
            3 => Some(Self::Close),
            5 => Some(Self::Fstat),
            7 => Some(Self::Poll),  // TEAM_406
            8 => Some(Self::Lseek), // TEAM_404
            9 => Some(Self::Mmap),
            10 => Some(Self::Mprotect),
            11 => Some(Self::Munmap),
            12 => Some(Self::Sbrk),
            13 => Some(Self::SigAction),
            14 => Some(Self::SigProcMask),
            15 => Some(Self::SigReturn),
            16 => Some(Self::Ioctl),
            17 => Some(Self::Pread64),  // TEAM_404
            18 => Some(Self::Pwrite64), // TEAM_404
            19 => Some(Self::Readv),
            20 => Some(Self::Writev),
            24 => Some(Self::Yield),
            32 => Some(Self::Dup),
            33 => Some(Self::Dup2), // TEAM_404
            34 => Some(Self::Pause),
            35 => Some(Self::Nanosleep),
            39 => Some(Self::GetPid),
            56 => Some(Self::Clone),
            59 => Some(Self::Exec),
            60 => Some(Self::Exit),
            61 => Some(Self::Waitpid),
            62 => Some(Self::Kill),
            63 => Some(Self::Uname),        // TEAM_406
            90 => Some(Self::Chmod),        // TEAM_406
            91 => Some(Self::Fchmod),       // TEAM_406
            92 => Some(Self::Chown),        // TEAM_406
            93 => Some(Self::Fchown),       // TEAM_406
            95 => Some(Self::Umask),        // TEAM_406
            96 => Some(Self::Gettimeofday), // TEAM_409
            98 => Some(Self::Getrusage),    // TEAM_409
            76 => Some(Self::Truncate),     // TEAM_409
            77 => Some(Self::Ftruncate),    // TEAM_404
            78 => Some(Self::Getdents),
            79 => Some(Self::Getcwd),
            80 => Some(Self::Chdir),  // TEAM_404
            81 => Some(Self::Fchdir), // TEAM_404
            110 => Some(Self::GetPpid),
            165 => Some(Self::Mount),
            166 => Some(Self::Umount),
            169 => Some(Self::Shutdown),
            202 => Some(Self::Futex),
            218 => Some(Self::SetTidAddress),
            228 => Some(Self::ClockGettime),
            257 => Some(Self::Openat),
            258 => Some(Self::Mkdirat),
            263 => Some(Self::Unlinkat),
            264 => Some(Self::Renameat),
            265 => Some(Self::Linkat),
            266 => Some(Self::Symlinkat),
            267 => Some(Self::Readlinkat),
            280 => Some(Self::Utimensat),
            292 => Some(Self::Dup3),
            22 => Some(Self::Pipe2), // TEAM_404: Old pipe() syscall → Pipe2
            293 => Some(Self::Pipe2),
            // TEAM_350: Eyra prerequisites
            186 => Some(Self::Gettid),
            231 => Some(Self::ExitGroup),
            102 => Some(Self::Getuid),
            107 => Some(Self::Geteuid),
            104 => Some(Self::Getgid),
            108 => Some(Self::Getegid),
            229 => Some(Self::ClockGetres),
            28 => Some(Self::Madvise),
            318 => Some(Self::Getrandom),
            158 => Some(Self::ArchPrctl),
            269 => Some(Self::Faccessat),
            332 => Some(Self::Statx),
            // TEAM_360: Eyra syscalls
            271 => Some(Self::Ppoll),
            200 => Some(Self::Tkill),
            330 => Some(Self::PkeyAlloc),
            329 => Some(Self::PkeyMprotect), // TEAM_409: Fixed - was incorrectly 302
            302 => Some(Self::Prlimit64),
            131 => Some(Self::Sigaltstack),
            // TEAM_394: Epoll syscalls
            291 => Some(Self::EpollCreate1),
            233 => Some(Self::EpollCtl),
            232 => Some(Self::EpollWait),
            290 => Some(Self::Eventfd2),
            // TEAM_394: Process group syscalls
            109 => Some(Self::Setpgid),
            121 => Some(Self::Getpgid),
            111 => Some(Self::Getpgrp),
            112 => Some(Self::Setsid),
            72 => Some(Self::Fcntl),
            // TEAM_409: Additional syscalls for coreutils
            262 => Some(Self::Fstatat),
            // Custom LevitateOS
            1000 => Some(Self::Spawn),
            1001 => Some(Self::SpawnArgs),
            1002 => Some(Self::SetForeground),
            1003 => Some(Self::GetForeground),
            1010 => Some(Self::Isatty),
            _ => None,
        }
    }
}

// TEAM_423: Use canonical Stat from los_types (removed duplicate definition)
pub use los_types::Stat;

#[inline]
pub fn is_svc_exception(_esr: u64) -> bool {
    false
}

// TEAM_418: Re-export Timespec from los_types
pub use los_types::Timespec;

/// TEAM_247: Number of control characters in termios.
pub const NCCS: usize = 32;

/// x86_64 Termios (matches Linux glibc layout)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

impl Termios {
    pub const INITIAL_TERMIOS: Termios = Termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0u8; NCCS],
        c_ispeed: 0,
        c_ospeed: 0,
    };
}

// TEAM_258: Local mode flags (c_lflag) - same as AArch64
pub const ISIG: u32 = 0x01;
pub const ICANON: u32 = 0x02;
pub const ECHO: u32 = 0x08;
pub const ECHOE: u32 = 0x10;
pub const ECHOK: u32 = 0x20;
pub const ECHONL: u32 = 0x40;
pub const NOFLSH: u32 = 0x80;
pub const TOSTOP: u32 = 0x100;
pub const IEXTEN: u32 = 0x8000;

// Output mode flags (c_oflag)
pub const OPOST: u32 = 0x01;
pub const ONLCR: u32 = 0x04;

// Special characters (c_cc index)
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;

// ioctl requests - same as AArch64
pub const TCGETS: u64 = 0x5401;
pub const TCSETS: u64 = 0x5402;
pub const TCSETSW: u64 = 0x5403;
pub const TCSETSF: u64 = 0x5404;

pub const TIOCGPTN: u64 = 0x80045430;
pub const TIOCSPTLCK: u64 = 0x40045431;
pub const TIOCGWINSZ: u64 = 0x5413;
pub const TIOCSWINSZ: u64 = 0x5414;

// TEAM_277: x86_64 SyscallFrame - matches layout pushed by syscall_entry
// TEAM_297 BREADCRUMB: DEAD_END - SyscallFrame layout mismatch.
// Checked against assembly push order, layout matches exactly.
// Registers are preserved correctly. Do not reinvestigate unless struct/asm changes.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SyscallFrame {
    // These must be at the start so that regs[i] works correctly for syscall args
    // Order matches how we push/pop in assembly (index 0 is first field in bytes)
    pub rax: u64,    // 0: syscall number / return value
    pub rdi: u64,    // 1: arg0
    pub rsi: u64,    // 2: arg1
    pub rdx: u64,    // 3: arg2
    pub r10: u64,    // 4: arg3
    pub r8: u64,     // 5: arg4
    pub r9: u64,     // 6: arg5
    pub rcx: u64,    // 7: user pc (return address)
    pub r11: u64,    // 8: user rflags
    pub rbx: u64,    // 9
    pub rbp: u64,    // 10
    pub r12: u64,    // 11
    pub r13: u64,    // 12
    pub r14: u64,    // 13
    pub r15: u64,    // 14
    pub rsp: u64,    // 15: user stack
    pub ttbr0: u64,  // 16: CR3 placeholder
    pub pc: u64,     // 17: user pc (alias for rcx push in assembly)
    pub sp: u64,     // 18: user sp (alias for rsp push in assembly)
    pub pstate: u64, // 19: user rflags (alias for r11 push in assembly)

    /// Padding to ensure SyscallFrame is 16-byte aligned (total size 52 * 8 = 416 bytes)
    pub _padding: u64,

    // Total regs size for compatibility
    pub regs: [u64; 31],
}

impl SyscallFrame {
    pub fn syscall_number(&self) -> u64 {
        self.rax
    }
    pub fn arg0(&self) -> u64 {
        self.rdi
    }
    pub fn arg1(&self) -> u64 {
        self.rsi
    }
    pub fn arg2(&self) -> u64 {
        self.rdx
    }
    pub fn arg3(&self) -> u64 {
        self.r10
    }
    pub fn arg4(&self) -> u64 {
        self.r8
    }
    pub fn arg5(&self) -> u64 {
        self.r9
    }

    // TEAM_296: pc/sp aliases for arch-agnostic code
    pub fn pc(&self) -> u64 {
        self.rcx
    }
    pub fn set_pc(&mut self, val: u64) {
        self.rcx = val;
    }
    pub fn sp(&self) -> u64 {
        self.rsp
    }
    pub fn set_sp(&mut self, val: u64) {
        self.rsp = val;
    }

    pub fn set_return(&mut self, value: i64) {
        // TEAM_356: Removed trace! here - fires for every syscall, floods logs
        self.rax = value as u64;
    }
    pub fn arg6(&self) -> u64 {
        // x86_64 only supports 6 args (rdi, rsi, rdx, r10, r8, r9)
        0
    }
}

pub unsafe fn switch_mmu_config(config_phys: usize) {
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) config_phys);
    }
}

// TEAM_258: Stub for exception_return (not used on x86_64, but needed for shared code)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exception_return() {
    // Stub - x86_64 uses different return mechanism (sysret/iret)
    unimplemented!("x86_64 exception_return");
}

// TEAM_422: Kernel integration is handled by the levitate binary, not this crate.
// The kernel_main entry point and boot sequence are in levitate/src/main.rs.
