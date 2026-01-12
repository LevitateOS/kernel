#![no_std]

// TEAM_422: External crate imports for modular kernel
// These external crates provide modular kernel functionality:
// - los_mm: Memory management (user page tables, validation)
// - los_sched: Task scheduling (current_task, yield_now, TaskControlBlock)
// - los_vfs: Virtual filesystem operations

extern crate alloc;

pub mod epoll;
pub mod fs;
pub mod helpers; // TEAM_413: Syscall helper abstractions
pub mod mm;
pub mod process;
pub mod signal;
pub mod sync;
pub mod sys;
pub mod time;
pub mod types; // TEAM_418: SSOT for common syscall types (Timeval, Timespec)

// TEAM_413: Re-export commonly used helpers
// TEAM_415: Added ioctl helpers
pub use helpers::{
    SyscallResultExt, UserPtr, UserSlice, get_fd, get_vfs_file, ioctl_get_termios, ioctl_read_i32,
    ioctl_read_termios, ioctl_read_u32, ioctl_write_i32, ioctl_write_u32, is_valid_fd,
    read_struct_from_user, read_user_path, resolve_at_path, write_struct_to_user,
};

// TEAM_422: Architecture-specific imports
#[cfg(target_arch = "aarch64")]
pub use los_arch_aarch64::{SyscallFrame, SyscallNumber, is_svc_exception};
#[cfg(target_arch = "x86_64")]
pub use los_arch_x86_64::{SyscallFrame, SyscallNumber, is_svc_exception};

// TEAM_422: Use los_types::Stat as the canonical Stat type (same layout on all archs)
pub use los_types::Stat;
// TEAM_418: Re-export time types from SSOT module
pub use types::{Timespec, Timeval};

// TEAM_420: No shims - use linux_raw_sys directly at callsites
// TEAM_421: Syscall result type - single conversion point for errors

/// TEAM_421: Syscall result type
///
/// - Ok(i64): Success value (fd, count, address, etc.)
/// - Err(u32): Error code from linux_raw_sys::errno (positive, raw)
///
/// The dispatcher converts Err(e) to -(e as i64) for Linux ABI.
/// This eliminates scattered `-(ERRNO as i64)` casts throughout syscall code.
pub type SyscallResult = Result<i64, u32>;

/// TEAM_459: Verify task.ttbr0 matches actual CR3/TTBR0 register (GOTCHA #37).
///
/// This catches bugs where someone switched page tables without updating task.ttbr0,
/// which would cause mmap to scan the wrong page table (see TEAM_456).
///
/// Only compiled in debug builds to avoid runtime overhead in release.
#[cfg(debug_assertions)]
fn verify_ttbr0_consistency() {
    use core::sync::atomic::Ordering;

    let task = los_sched::current_task();
    let stored_ttbr0 = task.ttbr0.load(Ordering::Acquire);

    // Skip check for kernel-only tasks (ttbr0 == 0)
    if stored_ttbr0 == 0 {
        return;
    }

    #[cfg(target_arch = "x86_64")]
    let actual_ttbr0: usize = {
        let cr3: usize;
        // SAFETY: Reading CR3 is safe and doesn't modify state
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)) };
        cr3
    };

    #[cfg(target_arch = "aarch64")]
    let actual_ttbr0: usize = {
        let ttbr0: usize;
        // SAFETY: Reading TTBR0_EL1 is safe and doesn't modify state
        unsafe { core::arch::asm!("mrs {}, ttbr0_el1", out(reg) ttbr0, options(nomem, nostack)) };
        ttbr0
    };

    debug_assert_eq!(
        stored_ttbr0, actual_ttbr0,
        "GOTCHA #37: task.ttbr0 (0x{:x}) doesn't match actual CR3/TTBR0 (0x{:x})! \
         Did you forget to update task.ttbr0 after switching page tables? \
         See TEAM_456 for context.",
        stored_ttbr0, actual_ttbr0
    );
}

pub fn syscall_dispatch(frame: &mut SyscallFrame) {
    // TEAM_459: Debug assertion to catch ttbr0/CR3 desync bugs (see GOTCHA #37)
    // If this fires, someone switched page tables without updating task.ttbr0
    #[cfg(debug_assertions)]
    verify_ttbr0_consistency();

    let nr = frame.syscall_number();

    // TEAM_456: Debug logging for all syscalls
    log::trace!(
        "[SYSCALL] PID={} nr={} args=[0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]",
        los_sched::current_task().id.0,
        nr,
        frame.arg0(),
        frame.arg1(),
        frame.arg2(),
        frame.arg3()
    );

    let result = match SyscallNumber::from_u64(nr) {
        Some(SyscallNumber::Read) => fs::sys_read(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        Some(SyscallNumber::Write) => fs::sys_write(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        Some(SyscallNumber::Exit) => process::sys_exit(frame.arg0() as i32),
        Some(SyscallNumber::GetPid) => process::sys_getpid(),
        Some(SyscallNumber::Sbrk) => mm::sys_sbrk(frame.arg0() as isize),
        Some(SyscallNumber::Spawn) => {
            process::sys_spawn(frame.arg0() as usize, frame.arg1() as usize)
        }
        // TEAM_436: execve now passes frame for PC/SP modification
        Some(SyscallNumber::Exec) => process::sys_execve(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame,
        ),
        Some(SyscallNumber::Yield) => process::sys_yield(),
        // TEAM_453: Linux reboot(magic1, magic2, cmd, arg) - pass cmd (arg2)
        Some(SyscallNumber::Shutdown) => sys::sys_shutdown(frame.arg2() as u32),
        // TEAM_444: Legacy open() - translates to openat(AT_FDCWD, ...)
        // TEAM_446: x86_64 only - aarch64 doesn't have open() syscall
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Open) => fs::sys_openat(
            -100, // AT_FDCWD
            frame.arg0() as usize,
            frame.arg1() as u32,
            frame.arg2() as u32,
        ),
        // TEAM_345: Linux ABI - openat(dirfd, pathname, flags, mode)
        Some(SyscallNumber::Openat) => fs::sys_openat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as u32,
            frame.arg3() as u32,
        ),
        Some(SyscallNumber::Close) => fs::sys_close(frame.arg0() as usize),
        // TEAM_459: Legacy stat() - translates to fstatat(AT_FDCWD, ...)
        // Note: aarch64 doesn't have legacy stat syscall, only fstatat
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Stat) => fs::sys_fstatat(
            -100, // AT_FDCWD
            frame.arg0() as usize,
            frame.arg1() as usize,
            0,
        ),
        Some(SyscallNumber::Fstat) => fs::sys_fstat(frame.arg0() as usize, frame.arg1() as usize),
        // TEAM_459: lstat() - stat without following symlinks
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Lstat) => fs::sys_lstat(frame.arg0() as usize, frame.arg1() as usize),
        // TEAM_404: File positioning and descriptor syscalls
        Some(SyscallNumber::Lseek) => fs::sys_lseek(
            frame.arg0() as usize,
            frame.arg1() as i64,
            frame.arg2() as i32,
        ),
        Some(SyscallNumber::Pread64) => fs::sys_pread64(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as i64,
        ),
        Some(SyscallNumber::Pwrite64) => fs::sys_pwrite64(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as i64,
        ),
        Some(SyscallNumber::Dup2) => fs::sys_dup2(frame.arg0() as usize, frame.arg1() as usize),
        Some(SyscallNumber::Ftruncate) => {
            fs::sys_ftruncate(frame.arg0() as usize, frame.arg1() as i64)
        }
        Some(SyscallNumber::Chdir) => fs::sys_chdir(frame.arg0() as usize),
        Some(SyscallNumber::Fchdir) => fs::sys_fchdir(frame.arg0() as usize),
        // TEAM_430: nanosleep takes pointers to timespec structs
        Some(SyscallNumber::Nanosleep) => {
            time::sys_nanosleep(frame.arg0() as usize, frame.arg1() as usize)
        }
        // TEAM_409: Legacy time syscall
        Some(SyscallNumber::Gettimeofday) => {
            time::sys_gettimeofday(frame.arg0() as usize, frame.arg1() as usize)
        }
        Some(SyscallNumber::ClockGettime) => {
            time::sys_clock_gettime(frame.arg0() as i32, frame.arg1() as usize)
        }
        // TEAM_176: Directory listing syscall
        Some(SyscallNumber::Getdents) => fs::sys_getdents(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        // TEAM_459: getdents64 - same implementation, already uses Dirent64 format
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Getdents64) => fs::sys_getdents(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        // TEAM_186: Spawn process with arguments
        Some(SyscallNumber::SpawnArgs) => process::sys_spawn_args(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        // TEAM_188: Wait for child process
        Some(SyscallNumber::Waitpid) => {
            process::sys_waitpid(frame.arg0() as i32, frame.arg1() as usize)
        }
        Some(SyscallNumber::Getcwd) => fs::sys_getcwd(frame.arg0() as usize, frame.arg1() as usize),
        // TEAM_345: Linux ABI - mkdirat(dirfd, pathname, mode)
        Some(SyscallNumber::Mkdirat) => fs::sys_mkdirat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as u32,
        ),
        // TEAM_345: Linux ABI - unlinkat(dirfd, pathname, flags)
        Some(SyscallNumber::Unlinkat) => fs::sys_unlinkat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as u32,
        ),
        // TEAM_345: Linux ABI - renameat(olddirfd, oldpath, newdirfd, newpath)
        Some(SyscallNumber::Renameat) => fs::sys_renameat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as i32,
            frame.arg3() as usize,
        ),
        // TEAM_345: Linux ABI - utimensat(dirfd, pathname, times, flags)
        Some(SyscallNumber::Utimensat) => fs::sys_utimensat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as u32,
        ),
        // TEAM_345: Linux ABI - symlinkat(target, newdirfd, linkpath)
        Some(SyscallNumber::Symlinkat) => fs::sys_symlinkat(
            frame.arg0() as usize,
            frame.arg1() as i32,
            frame.arg2() as usize,
        ),
        // TEAM_345: Linux ABI - readlinkat(dirfd, pathname, buf, bufsiz)
        Some(SyscallNumber::Readlinkat) => fs::sys_readlinkat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        // TEAM_206: Mount/Umount
        Some(SyscallNumber::Mount) => fs::sys_mount(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as usize,
            frame.arg4() as usize,
        ),
        Some(SyscallNumber::Umount) => fs::sys_umount(frame.arg0() as usize, frame.arg1() as usize),
        // TEAM_208: Futex syscall
        Some(SyscallNumber::Futex) => {
            let addr = frame.arg0() as usize;
            let op = frame.arg1() as usize;
            let val = frame.arg2() as usize;
            let timeout = frame.arg3() as usize;
            let addr2 = frame.arg4() as usize;
            sync::sys_futex(addr, op, val, timeout, addr2)
        }
        Some(SyscallNumber::GetPpid) => process::sys_getppid(),
        Some(SyscallNumber::Writev) => fs::sys_writev(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        Some(SyscallNumber::Readv) => fs::sys_readv(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        // TEAM_345: Linux ABI - linkat(olddirfd, oldpath, newdirfd, newpath, flags)
        Some(SyscallNumber::Linkat) => fs::sys_linkat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as i32,
            frame.arg3() as usize,
            frame.arg4() as u32,
        ),
        // TEAM_216: Signal Handling syscalls
        Some(SyscallNumber::Kill) => signal::sys_kill(frame.arg0() as i32, frame.arg1() as i32),
        // TEAM_406: System identification and permissions
        Some(SyscallNumber::Uname) => process::sys_uname(frame.arg0() as usize),
        Some(SyscallNumber::Umask) => process::sys_umask(frame.arg0() as u32),
        Some(SyscallNumber::Chmod) => fs::sys_chmod(frame.arg0() as usize, frame.arg1() as u32),
        Some(SyscallNumber::Fchmod) => fs::sys_fchmod(frame.arg0() as usize, frame.arg1() as u32),
        // TEAM_450: fchmodat - chmod relative to directory fd
        Some(SyscallNumber::Fchmodat) => fs::sys_fchmodat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as u32,
            frame.arg3() as i32,
        ),
        Some(SyscallNumber::Chown) => fs::sys_chown(
            frame.arg0() as usize,
            frame.arg1() as u32,
            frame.arg2() as u32,
        ),
        Some(SyscallNumber::Fchown) => fs::sys_fchown(
            frame.arg0() as usize,
            frame.arg1() as u32,
            frame.arg2() as u32,
        ),
        // TEAM_450: fchownat - chown relative to directory fd
        Some(SyscallNumber::Fchownat) => fs::sys_fchownat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as u32,
            frame.arg3() as u32,
            frame.arg4() as i32,
        ),
        Some(SyscallNumber::Pause) => signal::sys_pause(),
        // TEAM_441: rt_sigaction takes 4 args: sig, act, oldact, sigsetsize
        Some(SyscallNumber::SigAction) => signal::sys_sigaction(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        Some(SyscallNumber::SigReturn) => signal::sys_sigreturn(frame),
        Some(SyscallNumber::SigProcMask) => signal::sys_sigprocmask(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        Some(SyscallNumber::SetForeground) => process::sys_set_foreground(frame.arg0() as usize),
        Some(SyscallNumber::GetForeground) => process::sys_get_foreground(),
        Some(SyscallNumber::Isatty) => fs::sys_isatty(frame.arg0() as i32),
        // TEAM_228: Memory management syscalls
        Some(SyscallNumber::Mmap) => mm::sys_mmap(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as u32,
            frame.arg3() as u32,
            frame.arg4() as i32,
            frame.arg5() as usize,
        ),
        Some(SyscallNumber::Munmap) => mm::sys_munmap(frame.arg0() as usize, frame.arg1() as usize),
        Some(SyscallNumber::Mprotect) => mm::sys_mprotect(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as u32,
        ),
        // TEAM_228: Threading syscalls
        // TEAM_420: flags is u32 to match linux-raw-sys types
        // TEAM_442: Architecture-specific clone argument order:
        //   x86_64:  flags, stack, parent_tid, child_tid, tls
        //   aarch64: flags, stack, parent_tid, tls, child_tid
        // Our sys_clone signature matches aarch64 order.
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Clone) => process::sys_clone(
            frame.arg0() as u32,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg4() as usize, // tls is arg4 on x86_64
            frame.arg3() as usize, // child_tid is arg3 on x86_64
            frame,
        ),
        #[cfg(target_arch = "aarch64")]
        Some(SyscallNumber::Clone) => process::sys_clone(
            frame.arg0() as u32,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as usize, // tls is arg3 on aarch64
            frame.arg4() as usize, // child_tid is arg4 on aarch64
            frame,
        ),
        Some(SyscallNumber::SetTidAddress) => process::sys_set_tid_address(frame.arg0() as usize),
        // TEAM_453: vfork - BusyBox init uses this to spawn ash shell
        // True vfork shares address space (CLONE_VM), but that requires blocking
        // the parent until child execs. For now, use fork semantics (full copy)
        // which is safer and works correctly even if less efficient.
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Vfork) => {
            const SIGCHLD: u32 = 17;
            // Fork semantics: no CLONE_VM, just SIGCHLD for child termination signal
            process::sys_clone(SIGCHLD, 0, 0, 0, 0, frame)
        }
        // TEAM_233: Pipe and dup syscalls
        Some(SyscallNumber::Dup) => fs::sys_dup(frame.arg0() as usize),
        Some(SyscallNumber::Dup3) => fs::sys_dup3(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as u32,
        ),
        Some(SyscallNumber::Pipe2) => fs::sys_pipe2(frame.arg0() as usize, frame.arg1() as u32),
        Some(SyscallNumber::Ioctl) => fs::sys_ioctl(
            frame.arg0() as usize,
            frame.arg1() as u64,
            frame.arg2() as usize,
        ),
        // TEAM_350: Eyra prerequisites
        Some(SyscallNumber::Gettid) => process::sys_gettid(),
        Some(SyscallNumber::ExitGroup) => process::sys_exit_group(frame.arg0() as i32),
        Some(SyscallNumber::Getuid) => process::sys_getuid(),
        Some(SyscallNumber::Geteuid) => process::sys_geteuid(),
        Some(SyscallNumber::Getgid) => process::sys_getgid(),
        Some(SyscallNumber::Getegid) => process::sys_getegid(),
        // TEAM_450: User/group identity syscalls for BusyBox
        Some(SyscallNumber::Setuid) => process::sys_setuid(frame.arg0() as u32),
        Some(SyscallNumber::Setgid) => process::sys_setgid(frame.arg0() as u32),
        Some(SyscallNumber::Setreuid) => {
            process::sys_setreuid(frame.arg0() as u32, frame.arg1() as u32)
        }
        Some(SyscallNumber::Setregid) => {
            process::sys_setregid(frame.arg0() as u32, frame.arg1() as u32)
        }
        Some(SyscallNumber::Setresuid) => {
            process::sys_setresuid(frame.arg0() as u32, frame.arg1() as u32, frame.arg2() as u32)
        }
        Some(SyscallNumber::Getresuid) => process::sys_getresuid(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        Some(SyscallNumber::Setresgid) => {
            process::sys_setresgid(frame.arg0() as u32, frame.arg1() as u32, frame.arg2() as u32)
        }
        Some(SyscallNumber::Getresgid) => process::sys_getresgid(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        Some(SyscallNumber::ClockGetres) => {
            time::sys_clock_getres(frame.arg0() as i32, frame.arg1() as usize)
        }
        // TEAM_430: clock_nanosleep - used by rustix/Eyra for thread::sleep
        Some(SyscallNumber::ClockNanosleep) => time::sys_clock_nanosleep(
            frame.arg0() as i32,
            frame.arg1() as i32,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        Some(SyscallNumber::Madvise) => mm::sys_madvise(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as i32,
        ),
        Some(SyscallNumber::Getrandom) => sys::sys_getrandom(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as u32,
        ),
        // TEAM_350: x86_64-only arch_prctl (aarch64 uses TPIDR_EL0 directly)
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::ArchPrctl) => {
            process::sys_arch_prctl(frame.arg0() as i32, frame.arg1() as usize)
        }
        Some(SyscallNumber::Faccessat) => fs::sys_faccessat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as i32,
            frame.arg3() as i32,
        ),
        // TEAM_456: Legacy access() - translates to faccessat(AT_FDCWD, ...)
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Access) => fs::sys_faccessat(
            -100, // AT_FDCWD
            frame.arg0() as usize,
            frame.arg1() as i32,
            0, // flags = 0 for access()
        ),
        // TEAM_358: Extended file stat
        Some(SyscallNumber::Statx) => fs::sys_statx(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as i32,
            frame.arg3() as u32,
            frame.arg4() as usize,
        ),
        // TEAM_360/406: Poll syscalls
        Some(SyscallNumber::Poll) => sync::sys_poll(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as i32,
        ),
        Some(SyscallNumber::Ppoll) => sync::sys_ppoll(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        Some(SyscallNumber::Tkill) => signal::sys_tkill(frame.arg0() as i32, frame.arg1() as i32),
        // TEAM_456: rt_sigtimedwait for BusyBox init signal handling
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::RtSigtimedwait) => signal::sys_rt_sigtimedwait(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        Some(SyscallNumber::PkeyAlloc) => {
            mm::sys_pkey_alloc(frame.arg0() as u32, frame.arg1() as u32)
        }
        Some(SyscallNumber::PkeyMprotect) => mm::sys_pkey_mprotect(
            frame.arg0() as usize,
            frame.arg1() as usize,
            frame.arg2() as u32,
            frame.arg3() as i32,
        ),
        Some(SyscallNumber::Sigaltstack) => {
            signal::sys_sigaltstack(frame.arg0() as usize, frame.arg1() as usize)
        }
        // TEAM_394: Epoll syscalls for tokio/brush support
        Some(SyscallNumber::EpollCreate1) => epoll::sys_epoll_create1(frame.arg0() as i32),
        // TEAM_420: op is u32 to match linux-raw-sys types
        Some(SyscallNumber::EpollCtl) => epoll::sys_epoll_ctl(
            frame.arg0() as i32,
            frame.arg1() as u32,
            frame.arg2() as i32,
            frame.arg3() as usize,
        ),
        Some(SyscallNumber::EpollWait) => epoll::sys_epoll_wait(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as i32,
            frame.arg3() as i32,
        ),
        Some(SyscallNumber::Eventfd2) => {
            epoll::sys_eventfd2(frame.arg0() as u32, frame.arg1() as u32)
        }
        // TEAM_394: Process group syscalls for brush job control
        Some(SyscallNumber::Setpgid) => {
            process::sys_setpgid(frame.arg0() as i32, frame.arg1() as i32)
        }
        Some(SyscallNumber::Getpgid) => process::sys_getpgid(frame.arg0() as i32),
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Getpgrp) => process::sys_getpgrp(),
        Some(SyscallNumber::Setsid) => process::sys_setsid(),
        // TEAM_438: Socket syscalls for brush - stub returns pipe pair
        // TEAM_446: x86_64 only - aarch64 doesn't have socketpair syscall number
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Socketpair) => sync::sys_socketpair(
            frame.arg0() as i32,
            frame.arg1() as i32,
            frame.arg2() as i32,
            frame.arg3() as usize,
        ),
        // TEAM_456: Socket stubs for BusyBox (no network stack yet)
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Socket) => sync::sys_socket(
            frame.arg0() as i32,
            frame.arg1() as i32,
            frame.arg2() as i32,
        ),
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Sendto) => sync::sys_sendto(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as i32,
            frame.arg4() as usize,
            frame.arg5() as usize,
        ),
        Some(SyscallNumber::Fcntl) => fs::sys_fcntl(
            frame.arg0() as i32,
            frame.arg1() as i32,
            frame.arg2() as usize,
        ),
        // TEAM_409: fstatat and prlimit64 for coreutils
        Some(SyscallNumber::Fstatat) => fs::sys_fstatat(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
            frame.arg3() as i32,
        ),
        Some(SyscallNumber::Prlimit64) => process::sys_prlimit64(
            frame.arg0() as i32,
            frame.arg1() as u32,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        // TEAM_409: getrusage - resource usage statistics
        Some(SyscallNumber::Getrusage) => {
            process::sys_getrusage(frame.arg0() as i32, frame.arg1() as usize)
        }
        // TEAM_409: truncate - truncate file by path
        Some(SyscallNumber::Truncate) => {
            fs::sys_truncate(frame.arg0() as usize, frame.arg1() as i64)
        }
        // TEAM_459: sendfile - copy data between file descriptors
        #[cfg(target_arch = "x86_64")]
        Some(SyscallNumber::Sendfile) => fs::sys_sendfile(
            frame.arg0() as i32,
            frame.arg1() as i32,
            frame.arg2() as usize,
            frame.arg3() as usize,
        ),
        // TEAM_435: Scheduler affinity syscalls for sysinfo/brush
        Some(SyscallNumber::SchedGetaffinity) => process::sys_sched_getaffinity(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        Some(SyscallNumber::SchedSetaffinity) => process::sys_sched_setaffinity(
            frame.arg0() as i32,
            frame.arg1() as usize,
            frame.arg2() as usize,
        ),
        None => {
            log::warn!("[SYSCALL] Unknown syscall number: {}", nr);
            Err(linux_raw_sys::errno::ENOSYS)
        }
    };

    // TEAM_421: Single conversion point - Linux ABI boundary
    let abi_result = match &result {
        Ok(v) => *v,
        Err(e) => -(*e as i64),
    };

    frame.set_return(abi_result);
}

/// TEAM_446: Made public for use by levitate crate
pub fn write_to_user_buf(
    ttbr0: usize,
    user_buf_base: usize,
    offset: usize,
    byte: u8,
) -> bool {
    let user_va = user_buf_base + offset;
    if let Some(kernel_ptr) = los_mm::user::user_va_to_kernel_ptr(ttbr0, user_va) {
        // SAFETY: user_va_to_kernel_ptr ensures the address is mapped and valid.
        unsafe {
            *kernel_ptr = byte;
        }
        true
    } else {
        false
    }
}

pub(crate) fn read_from_user(ttbr0: usize, user_va: usize) -> Option<u8> {
    if let Some(kernel_ptr) = los_mm::user::user_va_to_kernel_ptr(ttbr0, user_va) {
        // SAFETY: user_va_to_kernel_ptr ensures the address is mapped and valid.
        Some(unsafe { *kernel_ptr })
    } else {
        None
    }
}

/// TEAM_226: Copy a string from user space into a kernel buffer.
/// TEAM_421: Returns u32 errno directly (no cast needed)
///
/// Validates the user buffer and copies bytes through kernel-accessible pointers.
/// This is the safe pattern for reading user memory from syscalls.
///
/// # Arguments
/// * `ttbr0` - User page table physical address
/// * `user_ptr` - User virtual address of string
/// * `len` - Length of string to copy
/// * `buf` - Kernel buffer to copy into
///
/// # Returns
/// * `Ok(&str)` - Valid UTF-8 string slice from buffer
/// * `Err(errno)` - EFAULT if copy fails, EINVAL if not valid UTF-8
pub fn copy_user_string<'a>(
    ttbr0: usize,
    user_ptr: usize,
    len: usize,
    buf: &'a mut [u8],
) -> Result<&'a str, u32> {
    use linux_raw_sys::errno::{EFAULT, EINVAL};
    let len = len.min(buf.len());
    if los_mm::user::validate_user_buffer(ttbr0, user_ptr, len, false).is_err() {
        return Err(EFAULT);
    }
    for i in 0..len {
        if let Some(ptr) = los_mm::user::user_va_to_kernel_ptr(ttbr0, user_ptr + i) {
            // SAFETY: user_va_to_kernel_ptr ensures the address is mapped and valid.
            buf[i] = unsafe { *ptr };
        } else {
            return Err(EFAULT);
        }
    }
    core::str::from_utf8(&buf[..len]).map_err(|_| EINVAL)
}

/// TEAM_345: Read a null-terminated C string from user space into a kernel buffer.
/// TEAM_421: Returns u32 errno directly (no cast needed)
///
/// This is the Linux ABI-compatible version that scans for null terminator.
/// Used for syscalls that accept `const char *pathname` arguments.
///
/// # Arguments
/// * `ttbr0` - User page table physical address
/// * `user_ptr` - User virtual address of null-terminated string
/// * `buf` - Kernel buffer to copy into (max path length)
///
/// # Returns
/// * `Ok(&str)` - Valid UTF-8 string slice from buffer (without null terminator)
/// * `Err(errno)` - EFAULT if copy fails, EINVAL if not valid UTF-8, ENAMETOOLONG if no null found
pub fn read_user_cstring<'a>(
    ttbr0: usize,
    user_ptr: usize,
    buf: &'a mut [u8],
) -> Result<&'a str, u32> {
    use linux_raw_sys::errno::{EFAULT, EINVAL, ENAMETOOLONG};
    for i in 0..buf.len() {
        match los_mm::user::user_va_to_kernel_ptr(ttbr0, user_ptr + i) {
            Some(ptr) => {
                // SAFETY: user_va_to_kernel_ptr ensures the address is mapped and valid.
                let byte = unsafe { *ptr };
                if byte == 0 {
                    // Found null terminator - return the string up to this point
                    return core::str::from_utf8(&buf[..i]).map_err(|_| EINVAL);
                }
                buf[i] = byte;
            }
            None => return Err(EFAULT),
        }
    }
    // Buffer full without finding null terminator
    Err(ENAMETOOLONG)
}
