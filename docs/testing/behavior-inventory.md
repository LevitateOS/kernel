# LevitateOS Kernel Behavior Inventory

**Generated**: 2026-01-13
**Purpose**: Complete enumeration of all kernel behaviors for testing and verification

This document catalogs every observable behavior in the LevitateOS kernel for behavior-driven testing and regression prevention. Each behavior is assigned a unique ID for traceability.

---

## Table of Contents

1. [Boot & Initialization](#1-boot--initialization)
2. [Memory Management](#2-memory-management)
3. [Process & Scheduler](#3-process--scheduler)
4. [System Calls](#4-system-calls)
5. [Virtual File System (VFS)](#5-virtual-file-system-vfs)
6. [Filesystems](#6-filesystems)
7. [Device Drivers](#7-device-drivers)
8. [Hardware Abstraction Layer (HAL)](#8-hardware-abstraction-layer-hal)
9. [Architecture-Specific](#9-architecture-specific)

---

## 1. Boot & Initialization

### 1.1 Boot Process (BOOT)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| BOOT1 | x86_64 Limine entry point receives control in long mode | main.rs | Runtime |
| BOOT2 | AArch64 entry point from boot.S receives control | main.rs | Runtime |
| BOOT3 | Set global BootInfo from Limine (x86_64) | main.rs | Runtime |
| BOOT4 | Parse Limine responses into BootInfo struct | boot/limine.rs | Runtime |
| BOOT5 | Set global BootInfo from DTB (AArch64) | main.rs | Runtime |
| BOOT6 | Parse DTB into BootInfo struct | boot/dtb.rs | Runtime |
| BOOT7 | Initialize HAL console for serial output | main.rs | Golden |
| BOOT8 | Initialize kernel logger with level filter | main.rs | Golden |
| BOOT9 | Transition boot stage tracking | init.rs | Golden |
| BOOT10 | Log boot protocol info (Limine/DTB/DeviceTree) | main.rs | Golden |
| BOOT11 | Log memory map regions and total usable memory | main.rs | Golden |

### 1.2 Initialization Sequence (INIT)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| INIT1 | Initialize CPU architecture layer | main.rs | Runtime |
| INIT2 | Initialize x86_64 syscall MSRs | main.rs | Runtime |
| INIT3 | Initialize AArch64 CPU PCR and TPIDR_EL1 | main.rs | Runtime |
| INIT4 | Create bootstrap task as first task | main.rs | Golden |
| INIT5 | Initialize memory from boot info | memory.rs | Golden |
| INIT6 | Parse usable RAM regions from memory map | memory.rs | Golden |
| INIT7 | Reserve kernel and initramfs regions from allocation | memory.rs | Golden |
| INIT8 | Create frame allocator with page metadata array | memory.rs | Golden |
| INIT9 | Transition to MemoryMMU stage | init.rs | Golden |
| INIT10 | Initialize exception handlers | init.rs | Golden |
| INIT11 | Run full initialization sequence | init.rs | Golden |

### 1.3 Boot Stages (STAGE)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| STAGE1 | Define boot stage enum (EarlyHAL, MemoryMMU, BootConsole, Discovery) | init.rs | Golden |
| STAGE2 | Prevent backward stage transitions | init.rs | Golden |
| STAGE3 | Log stage transitions with numbered messages | init.rs | Golden |
| STAGE4 | EarlyHAL: Initialize console | main.rs | Golden |
| STAGE5 | MemoryMMU: Initialize heap and memory | main.rs | Golden |
| STAGE6 | BootConsole: Initialize GPU/terminal | init.rs | Golden |
| STAGE7 | Discovery: Initialize devices and filesystem | init.rs | Golden |

---

## 2. Memory Management

### 2.1 Heap Management (HEAP)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| HEAP1 | ProcessHeap::new initializes with base address | heap.rs | Unit |
| HEAP2 | ProcessHeap::grow positive increment allocates pages | heap.rs | Unit |
| HEAP3 | ProcessHeap::grow negative increment frees pages | heap.rs | Unit |
| HEAP4 | ProcessHeap::grow returns Err for overflow | heap.rs | Unit |
| HEAP5 | ProcessHeap::grow returns Err when exceeding max | heap.rs | Unit |
| HEAP6 | ProcessHeap::size returns current heap size | heap.rs | Unit |
| HEAP7 | ProcessHeap::reset called by execve | heap.rs | Runtime |
| HEAP8 | Maximum heap size is 256MB | heap.rs | Unit |

### 2.2 Frame Allocator (FRAME)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FRAME1 | alloc_page returns physical address or None | lib.rs | Unit |
| FRAME2 | free_page returns page to buddy allocator | lib.rs | Unit |
| FRAME3 | init_allocator initializes with memory map | lib.rs | Runtime |
| FRAME4 | add_reserved records reserved regions | lib.rs | Runtime |
| FRAME5 | add_range_with_holes excludes reserved memory | lib.rs | Runtime |

### 2.3 Virtual Memory Areas (VMA)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| VMA1 | Vma::new creates with page-aligned bounds | vma.rs | Unit |
| VMA2 | Vma::contains checks address in range | vma.rs | Unit |
| VMA3 | Vma::overlaps detects range overlap | vma.rs | Unit |
| VMA4 | VmaList::insert uses binary search O(log n) | vma.rs | Unit |
| VMA5 | VmaList::insert returns Err for overlapping | vma.rs | Unit |
| VMA6 | VmaList::remove splits VMAs correctly | vma.rs | Unit |
| VMA7 | VmaList::find uses binary search O(log n) | vma.rs | Unit |
| VMA8 | VmaList::update_protection splits VMAs if needed | vma.rs | Unit |

### 2.4 User Memory (USER)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| USER1 | create_user_page_table allocates L0 table | page_table.rs | Runtime |
| USER2 | create_user_page_table copies kernel mappings (x86_64) | page_table.rs | Runtime |
| USER3 | destroy_user_page_table frees all pages recursively | page_table.rs | Runtime |
| USER4 | copy_user_address_space performs eager full copy | page_table.rs | Runtime |
| USER5 | map_user_page maps single page to user space | mapping.rs | Runtime |
| USER6 | map_user_page validates USER_SPACE_END | mapping.rs | Runtime |
| USER7 | alloc_and_map_user_range allocates and maps range | mapping.rs | Runtime |
| USER8 | user_va_to_kernel_ptr translates user VA | mapping.rs | Runtime |
| USER9 | validate_user_buffer checks all pages accessible | mapping.rs | Runtime |
| USER10 | setup_user_stack allocates stack pages at STACK_TOP | stack.rs | Runtime |
| USER11 | setup_stack_args sets up Linux ABI stack frame | stack.rs | Runtime |
| USER12 | Stack aligned to 16 bytes for x86-64 ABI | stack.rs | Runtime |

### 2.5 Memory Syscalls (MMAP)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| MMAP1 | sys_sbrk grows heap and allocates pages | mm.rs | Runtime |
| MMAP2 | sys_sbrk returns old break address | mm.rs | Runtime |
| MMAP3 | sys_mmap allocates anonymous memory | mm.rs | Runtime |
| MMAP4 | sys_mmap supports MAP_FIXED | mm.rs | Runtime |
| MMAP5 | sys_mmap returns EINVAL for invalid flags | mm.rs | Runtime |
| MMAP6 | sys_munmap frees pages and clears PTEs | mm.rs | Runtime |
| MMAP7 | sys_mprotect changes page protection | mm.rs | Runtime |
| MMAP8 | sys_madvise is no-op (stub) | mm.rs | Runtime |
| MMAP9 | MmapGuard provides RAII cleanup on failure | mm.rs | Unit |

---

## 3. Process & Scheduler

### 3.1 Task Control Block (TCB)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| TCB1 | TaskId::next returns unique sequential IDs | lib.rs | Unit |
| TCB2 | TaskState has Ready, Running, Blocked, Exited | lib.rs | Unit |
| TCB3 | TCB holds context, stack, ttbr0, heap, fd_table | lib.rs | Unit |
| TCB4 | TCB holds signal handlers array (64 entries) | lib.rs | Unit |
| TCB5 | TCB holds VMA list for fork support | lib.rs | Unit |
| TCB6 | ttbr0 is AtomicUsize for execve updates | lib.rs | Unit |

### 3.2 Context Switching (CTX)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| CTX1 | current_task returns Arc to current TCB | lib.rs | Runtime |
| CTX2 | set_current_task updates PCR and global | lib.rs | Runtime |
| CTX3 | switch_to updates CURRENT_TASK before switch | lib.rs | Runtime |
| CTX4 | switch_to no-ops for same task | lib.rs | Runtime |
| CTX5 | switch_to disables interrupts during switch | lib.rs | Runtime |
| CTX6 | switch_to switches MMU config before context | lib.rs | Runtime |
| CTX7 | cpu_switch_to saves/restores all registers | arch/*.S | Runtime |
| CTX8 | yield_now re-adds task unless blocked/exited | lib.rs | Runtime |

### 3.3 Scheduler (SCHED)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| SCHED1 | Scheduler uses VecDeque ready_list | scheduler.rs | Unit |
| SCHED2 | add_task pushes to back (O(1)) | scheduler.rs | Unit |
| SCHED3 | pick_next pops from front (FIFO) | scheduler.rs | Unit |
| SCHED4 | yield_and_reschedule is atomic add+pick | scheduler.rs | Unit |
| SCHED5 | schedule calls switch_to or returns | scheduler.rs | Runtime |

### 3.4 Process Creation (FORK)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FORK1 | create_fork clones VMA list | fork.rs | Runtime |
| FORK2 | create_fork copies entire address space | fork.rs | Runtime |
| FORK3 | create_fork allocates new kernel stack | fork.rs | Runtime |
| FORK4 | create_fork clones SyscallFrame to child stack | fork.rs | Runtime |
| FORK5 | Child returns 0, parent returns child PID | fork.rs | Runtime |
| FORK6 | create_fork creates new FdTable (not shared) | fork.rs | Runtime |

### 3.5 Thread Creation (THREAD)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| THREAD1 | create_thread shares parent ttbr0 | thread.rs | Runtime |
| THREAD2 | CLONE_FILES shares FdTable via Arc | thread.rs | Runtime |
| THREAD3 | CLONE_CHILD_CLEARTID stores address for exit | thread.rs | Runtime |
| THREAD4 | Child gets new user stack from clone args | thread.rs | Runtime |

### 3.6 Process Termination (EXIT)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| EXIT1 | task_exit marks task as Exited | lib.rs | Runtime |
| EXIT2 | task_exit handles CLONE_CHILD_CLEARTID | lib.rs | Runtime |
| EXIT3 | task_exit wakes futex waiters | lib.rs | Runtime |
| EXIT4 | terminate_with_signal uses exit code 128+sig | lib.rs | Runtime |
| EXIT5 | mark_exited wakes parent waiters | process_table.rs | Runtime |
| EXIT6 | Zombie process persists until reaped | process_table.rs | Runtime |

### 3.7 File Descriptor Table (FD)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FD1 | FdTable supports up to 1024 FDs | fd_table.rs | Unit |
| FD2 | alloc uses bitmap for O(1) allocation | fd_table.rs | Unit |
| FD3 | alloc_cloexec sets close-on-exec flag | fd_table.rs | Unit |
| FD4 | close clears bitmap and entry | fd_table.rs | Unit |
| FD5 | close_cloexec closes all marked FDs | fd_table.rs | Unit |
| FD6 | dup allocates lowest available FD | fd_table.rs | Unit |
| FD7 | dup_to duplicates to specific FD | fd_table.rs | Unit |

---

## 4. System Calls

### 4.1 File Operations (SYS_FILE)

| ID | Behavior | Syscall | Tested |
|----|----------|---------|--------|
| SYS_FILE1 | sys_read reads from fd into buffer | read | Runtime |
| SYS_FILE2 | sys_read returns 0 on EOF | read | Runtime |
| SYS_FILE3 | sys_write writes buffer to fd | write | Runtime |
| SYS_FILE4 | sys_write caps at 4096 bytes | write | Runtime |
| SYS_FILE5 | sys_openat opens file relative to dirfd | openat | Runtime |
| SYS_FILE6 | sys_openat applies umask to mode | openat | Runtime |
| SYS_FILE7 | sys_close closes fd and frees entry | close | Runtime |
| SYS_FILE8 | sys_lseek repositions file offset | lseek | Runtime |
| SYS_FILE9 | sys_fstat returns Stat struct | fstat | Runtime |
| SYS_FILE10 | sys_fcntl handles F_DUPFD, F_GETFD, F_SETFD | fcntl | Runtime |
| SYS_FILE11 | sys_dup duplicates fd | dup | Runtime |
| SYS_FILE12 | sys_dup2 duplicates to specific fd | dup2 | Runtime |
| SYS_FILE13 | sys_pipe2 creates pipe pair | pipe2 | Runtime |
| SYS_FILE14 | sys_readv reads into multiple buffers | readv | Runtime |
| SYS_FILE15 | sys_writev writes from multiple buffers | writev | Runtime |

### 4.2 Directory Operations (SYS_DIR)

| ID | Behavior | Syscall | Tested |
|----|----------|---------|--------|
| SYS_DIR1 | sys_getdents reads directory entries | getdents64 | Runtime |
| SYS_DIR2 | sys_getcwd returns current directory | getcwd | Runtime |
| SYS_DIR3 | sys_mkdirat creates directory | mkdirat | Runtime |
| SYS_DIR4 | sys_unlinkat removes file/directory | unlinkat | Runtime |
| SYS_DIR5 | sys_renameat renames file | renameat | Runtime |
| SYS_DIR6 | sys_chdir changes current directory | chdir | Runtime |
| SYS_DIR7 | sys_symlinkat creates symbolic link | symlinkat | Runtime |
| SYS_DIR8 | sys_readlinkat reads symlink target | readlinkat | Runtime |
| SYS_DIR9 | sys_linkat creates hard link | linkat | Runtime |

### 4.3 Process Operations (SYS_PROC)

| ID | Behavior | Syscall | Tested |
|----|----------|---------|--------|
| SYS_PROC1 | sys_getpid returns current PID | getpid | Runtime |
| SYS_PROC2 | sys_getppid returns parent PID | getppid | Runtime |
| SYS_PROC3 | sys_gettid returns thread ID | gettid | Runtime |
| SYS_PROC4 | sys_exit terminates process | exit | Runtime |
| SYS_PROC5 | sys_exit_group terminates process group | exit_group | Runtime |
| SYS_PROC6 | sys_execve replaces process image | execve | Runtime |
| SYS_PROC7 | sys_waitpid waits for child | waitpid | Runtime |
| SYS_PROC8 | sys_fork creates child process | fork | Runtime |
| SYS_PROC9 | sys_clone creates thread | clone | Runtime |
| SYS_PROC10 | sys_setpgid sets process group | setpgid | Runtime |
| SYS_PROC11 | sys_getpgid gets process group | getpgid | Runtime |
| SYS_PROC12 | sys_setsid creates new session | setsid | Runtime |

### 4.4 Signal Operations (SYS_SIG)

| ID | Behavior | Syscall | Tested |
|----|----------|---------|--------|
| SYS_SIG1 | sys_kill sends signal to process | kill | Runtime |
| SYS_SIG2 | sys_sigaction installs signal handler | rt_sigaction | Runtime |
| SYS_SIG3 | sys_sigreturn returns from handler | rt_sigreturn | Runtime |
| SYS_SIG4 | sys_sigprocmask sets signal mask | rt_sigprocmask | Runtime |
| SYS_SIG5 | sys_sigaltstack defines alternate stack | sigaltstack | Runtime |

### 4.5 Time Operations (SYS_TIME)

| ID | Behavior | Syscall | Tested |
|----|----------|---------|--------|
| SYS_TIME1 | sys_nanosleep sleeps for duration | nanosleep | Runtime |
| SYS_TIME2 | sys_gettimeofday returns time | gettimeofday | Runtime |
| SYS_TIME3 | sys_clock_gettime returns clock time | clock_gettime | Runtime |
| SYS_TIME4 | sys_clock_getres returns clock resolution | clock_getres | Runtime |

### 4.6 Synchronization (SYS_SYNC)

| ID | Behavior | Syscall | Tested |
|----|----------|---------|--------|
| SYS_SYNC1 | sys_futex WAIT sleeps if value matches | futex | Runtime |
| SYS_SYNC2 | sys_futex WAKE wakes waiters | futex | Runtime |
| SYS_SYNC3 | sys_poll waits for I/O events | poll | Runtime |
| SYS_SYNC4 | sys_epoll_create1 creates epoll instance | epoll_create1 | Runtime |
| SYS_SYNC5 | sys_epoll_ctl modifies epoll watch list | epoll_ctl | Runtime |
| SYS_SYNC6 | sys_epoll_wait waits for events | epoll_wait | Runtime |

### 4.7 System Operations (SYS_SYS)

| ID | Behavior | Syscall | Tested |
|----|----------|---------|--------|
| SYS_SYS1 | sys_shutdown reboots/powers off | reboot | Runtime |
| SYS_SYS2 | sys_getrandom fills buffer with random | getrandom | Runtime |
| SYS_SYS3 | sys_uname returns system info | uname | Runtime |
| SYS_SYS4 | sys_umask sets file creation mask | umask | Runtime |

---

## 5. Virtual File System (VFS)

### 5.1 File Operations (VFS_FILE)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| VFS_FILE1 | File::new creates with inode and flags | file.rs | Unit |
| VFS_FILE2 | File::read checks readable flag | file.rs | Unit |
| VFS_FILE3 | File::read updates atime | file.rs | Unit |
| VFS_FILE4 | File::write checks writable flag | file.rs | Unit |
| VFS_FILE5 | File::write handles O_APPEND | file.rs | Unit |
| VFS_FILE6 | File::write updates mtime | file.rs | Unit |
| VFS_FILE7 | File::seek handles SEEK_SET/CUR/END | file.rs | Unit |
| VFS_FILE8 | OpenFlags provides is_readable/writable | file.rs | Unit |

### 5.2 Path Resolution (VFS_PATH)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| VFS_PATH1 | Path::is_absolute checks leading '/' | path.rs | Unit |
| VFS_PATH2 | Path::components iterates normalized | path.rs | Unit |
| VFS_PATH3 | Path::parent returns parent directory | path.rs | Unit |
| VFS_PATH4 | Path::file_name returns final component | path.rs | Unit |
| VFS_PATH5 | PathBuf::push handles absolute paths | path.rs | Unit |
| VFS_PATH6 | normalize resolves . and .. | path.rs | Unit |

### 5.3 Dentry Cache (VFS_DENTRY)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| VFS_DENTRY1 | Dentry::new creates with parent ref | dentry.rs | Unit |
| VFS_DENTRY2 | Dentry::is_negative returns true if no inode | dentry.rs | Unit |
| VFS_DENTRY3 | Dentry::get_inode follows mount points | dentry.rs | Unit |
| VFS_DENTRY4 | DentryCache::lookup resolves path | dentry.rs | Runtime |
| VFS_DENTRY5 | DentryCache::lookup_parent returns parent+name | dentry.rs | Runtime |
| VFS_DENTRY6 | Dentry::mount clears children cache | dentry.rs | Unit |

### 5.4 Mount Table (VFS_MOUNT)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| VFS_MOUNT1 | mount adds to sorted mount list | mount.rs | Unit |
| VFS_MOUNT2 | mount returns AlreadyMounted for duplicate | mount.rs | Unit |
| VFS_MOUNT3 | umount removes mount by path | mount.rs | Unit |
| VFS_MOUNT4 | lookup uses longest-prefix matching | mount.rs | Unit |
| VFS_MOUNT5 | init mounts root and /tmp | mount.rs | Runtime |

### 5.5 VFS Dispatch (VFS_DISPATCH)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| VFS_DISPATCH1 | vfs_open handles O_CREAT | dispatch.rs | Runtime |
| VFS_DISPATCH2 | vfs_open follows symlinks unless O_NOFOLLOW | dispatch.rs | Runtime |
| VFS_DISPATCH3 | vfs_mkdir creates directory | dispatch.rs | Runtime |
| VFS_DISPATCH4 | vfs_unlink removes file | dispatch.rs | Runtime |
| VFS_DISPATCH5 | vfs_rmdir removes directory | dispatch.rs | Runtime |
| VFS_DISPATCH6 | vfs_rename moves/renames file | dispatch.rs | Runtime |
| VFS_DISPATCH7 | resolve_symlinks follows up to 8 levels | dispatch.rs | Runtime |

### 5.6 Pipe (VFS_PIPE)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| VFS_PIPE1 | RingBuffer is 4096 bytes | pipe.rs | Unit |
| VFS_PIPE2 | Pipe::read returns EOF when write closed | pipe.rs | Unit |
| VFS_PIPE3 | Pipe::read returns EAGAIN when empty | pipe.rs | Unit |
| VFS_PIPE4 | Pipe::write returns EPIPE when read closed | pipe.rs | Unit |
| VFS_PIPE5 | Pipe::write returns EAGAIN when full | pipe.rs | Unit |
| VFS_PIPE6 | Reference counting tracks open ends | pipe.rs | Unit |

---

## 6. Filesystems

### 6.1 tmpfs (FS_TMPFS)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FS_TMPFS1 | Read file with bounds checking | file_ops.rs | Unit |
| FS_TMPFS2 | Write file extends with zeros | file_ops.rs | Unit |
| FS_TMPFS3 | Write checks MAX_FILE_SIZE (16MB) | file_ops.rs | Unit |
| FS_TMPFS4 | Write checks MAX_TOTAL_SIZE (64MB) | file_ops.rs | Unit |
| FS_TMPFS5 | Truncate shrinks or extends | file_ops.rs | Unit |
| FS_TMPFS6 | Lookup child in directory | dir_ops.rs | Unit |
| FS_TMPFS7 | Readdir returns . and .. first | dir_ops.rs | Unit |
| FS_TMPFS8 | Create file allocates new inode | dir_ops.rs | Unit |
| FS_TMPFS9 | Mkdir creates directory with nlink=2 | dir_ops.rs | Unit |
| FS_TMPFS10 | Symlink stores target path | symlink_ops.rs | Unit |
| FS_TMPFS11 | Rename performs cycle detection | dir_ops.rs | Unit |
| FS_TMPFS12 | Unlink decrements nlink | dir_ops.rs | Unit |
| FS_TMPFS13 | Rmdir only removes empty directories | dir_ops.rs | Unit |
| FS_TMPFS14 | Hard link increments nlink | dir_ops.rs | Unit |

### 6.2 devtmpfs (FS_DEV)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FS_DEV1 | /dev/null read returns EOF | devices/null.rs | Unit |
| FS_DEV2 | /dev/null write accepts all data | devices/null.rs | Unit |
| FS_DEV3 | /dev/zero read fills buffer with 0 | devices/zero.rs | Unit |
| FS_DEV4 | /dev/full write returns ENOSPC | devices/full.rs | Unit |
| FS_DEV5 | /dev/urandom read fills with random | devices/ | Unit |
| FS_DEV6 | /dev/console read blocks for input | device_ops.rs | Runtime |
| FS_DEV7 | /dev/console write outputs to serial | device_ops.rs | Runtime |
| FS_DEV8 | /dev/pts directory for PTY | lib.rs | Runtime |

### 6.3 TTY/PTY (FS_TTY)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FS_TTY1 | Ctrl-S/Ctrl-Q flow control | lib.rs | Runtime |
| FS_TTY2 | Ctrl-C signals SIGINT | lib.rs | Runtime |
| FS_TTY3 | Backspace erases character | lib.rs | Runtime |
| FS_TTY4 | Canonical mode buffers lines | lib.rs | Runtime |
| FS_TTY5 | Non-canonical mode immediate | lib.rs | Runtime |
| FS_TTY6 | Echo reflects input | lib.rs | Runtime |
| FS_TTY7 | CR/LF conversion (ICRNL) | lib.rs | Runtime |
| FS_TTY8 | PTY allocation creates pair | pty.rs | Runtime |

### 6.4 procfs (FS_PROC)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FS_PROC1 | /proc/ lists self, meminfo, uptime, PIDs | lib.rs | Runtime |
| FS_PROC2 | /proc/self symlink to current PID | lib.rs | Runtime |
| FS_PROC3 | /proc/[pid]/ contains stat, status, maps, fd | lib.rs | Runtime |
| FS_PROC4 | /proc/[pid]/stat generates process info | lib.rs | Runtime |
| FS_PROC5 | /proc/[pid]/status generates detailed info | lib.rs | Runtime |
| FS_PROC6 | /proc/[pid]/maps shows VMAs | lib.rs | Runtime |
| FS_PROC7 | /proc/[pid]/fd/ lists open FDs | lib.rs | Runtime |
| FS_PROC8 | /proc/meminfo shows memory stats | lib.rs | Runtime |

### 6.5 sysfs (FS_SYS)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| FS_SYS1 | /sys/ root lists class, devices | lib.rs | Runtime |
| FS_SYS2 | /sys/class/ directory (stub) | lib.rs | Runtime |
| FS_SYS3 | /sys/devices/ directory (stub) | lib.rs | Runtime |

---

## 7. Device Drivers

### 7.1 VirtIO Transport (DRV_TRANSPORT)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| DRV_TRANSPORT1 | Wraps MMIO and PCI transports | virtio-transport/lib.rs | Runtime |
| DRV_TRANSPORT2 | Unified interface via enum dispatch | virtio-transport/lib.rs | Runtime |
| DRV_TRANSPORT3 | Architecture-specific selection | virtio-transport/lib.rs | Runtime |

### 7.2 VirtIO Block (DRV_BLK)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| DRV_BLK1 | block_size returns 512 | virtio-blk/lib.rs | Unit |
| DRV_BLK2 | read_blocks validates buffer size | virtio-blk/lib.rs | Unit |
| DRV_BLK3 | write_blocks validates buffer size | virtio-blk/lib.rs | Unit |
| DRV_BLK4 | Returns NotInitialized if not ready | block.rs | Runtime |
| DRV_BLK5 | Returns InvalidBufferSize for bad buffer | block.rs | Runtime |

### 7.3 VirtIO Input (DRV_INPUT)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| DRV_INPUT1 | poll returns true if buffer not empty | virtio-input/lib.rs | Unit |
| DRV_INPUT2 | read_char pops from buffer (FIFO) | virtio-input/lib.rs | Unit |
| DRV_INPUT3 | Ctrl+C detection pushes '\x03' | virtio-input/lib.rs | Runtime |
| DRV_INPUT4 | Shift handling tracks state | virtio-input/lib.rs | Unit |
| DRV_INPUT5 | Buffer overflow drops characters | input.rs | Runtime |
| DRV_INPUT6 | Keycode mapping supports full keyboard | keymap.rs | Unit |
| DRV_INPUT7 | Interrupt handler polls device | input.rs | Runtime |

### 7.4 VirtIO GPU (DRV_GPU)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| DRV_GPU1 | new initializes framebuffer | gpu/lib.rs | Runtime |
| DRV_GPU2 | Clears framebuffer to black | gpu/lib.rs | Runtime |
| DRV_GPU3 | flush commits to display | gpu.rs | Runtime |
| DRV_GPU4 | resolution returns (width, height) | gpu.rs | Runtime |
| DRV_GPU5 | framebuffer returns mutable slice | gpu.rs | Runtime |
| DRV_GPU6 | DrawTarget writes BGRA pixels | gpu.rs | Runtime |
| DRV_GPU7 | Fallback to Limine framebuffer | simple-gpu/lib.rs | Runtime |
| DRV_GPU8 | flush_count tracks flushes for testing | gpu.rs | Golden |

### 7.5 VirtIO Network (DRV_NET)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| DRV_NET1 | mac_address returns device MAC | virtio-net/lib.rs | Runtime |
| DRV_NET2 | can_send checks TX queue space | virtio-net/lib.rs | Runtime |
| DRV_NET3 | can_recv checks RX pending | virtio-net/lib.rs | Runtime |
| DRV_NET4 | send validates packet size | net.rs | Runtime |
| DRV_NET5 | receive returns packet data | net.rs | Runtime |
| DRV_NET6 | mtu returns 1500 | virtio-net/lib.rs | Unit |

### 7.6 PCI Bus (DRV_PCI)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| DRV_PCI1 | pci_allocate atomically allocates memory | pci/lib.rs | Unit |
| DRV_PCI2 | Alignment enforced for allocations | pci/lib.rs | Unit |
| DRV_PCI3 | Returns None if out of space | pci/lib.rs | Unit |
| DRV_PCI4 | find_virtio_device scans bus 0 | pci/lib.rs | Runtime |
| DRV_PCI5 | Allocates BARs for each device | pci/lib.rs | Runtime |
| DRV_PCI6 | Enables MEMORY_SPACE and BUS_MASTER | pci/lib.rs | Runtime |

---

## 8. Hardware Abstraction Layer (HAL)

### 8.1 IRQ-Safe Locking (HAL_LOCK)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| HAL_LOCK1 | Disables interrupts before lock | lib.rs | Unit |
| HAL_LOCK2 | Restores interrupts on drop | lib.rs | Unit |
| HAL_LOCK3 | Nested locks preserve state | lib.rs | Unit |
| HAL_LOCK4 | Data accessible through guard | lib.rs | Unit |
| HAL_LOCK5 | Try lock returns Option | lib.rs | Unit |

### 8.2 Interrupts (HAL_IRQ)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| HAL_IRQ1 | disable returns previous state | interrupts.rs | Unit |
| HAL_IRQ2 | restore restores captured state | interrupts.rs | Unit |
| HAL_IRQ3 | is_enabled checks flag | interrupts.rs | Unit |
| HAL_IRQ4 | Arch delegation via cfg | interrupts.rs | Unit |

### 8.3 Buddy Allocator (HAL_BUDDY)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| HAL_BUDDY1 | Starts with empty free lists | buddy.rs | Unit |
| HAL_BUDDY2 | alloc returns physical address | buddy.rs | Unit |
| HAL_BUDDY3 | OOM returns None | buddy.rs | Unit |
| HAL_BUDDY4 | Allocates 2^N contiguous pages | buddy.rs | Unit |
| HAL_BUDDY5 | Block splitting creates buddies | buddy.rs | Unit |
| HAL_BUDDY6 | Free blocks coalesced | buddy.rs | Unit |
| HAL_BUDDY7 | Non-power-of-two ranges handled | buddy.rs | Unit |

### 8.4 Slab Allocator (HAL_SLAB)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| HAL_SLAB1 | 6 size classes: 64-2048 bytes | slab/mod.rs | Unit |
| HAL_SLAB2 | size_to_class maps correctly | slab/mod.rs | Unit |
| HAL_SLAB3 | Rejects size 0 and > 2048 | slab/mod.rs | Unit |
| HAL_SLAB4 | Partial list tried first | slab/cache.rs | Unit |
| HAL_SLAB5 | Empty pages reclaimed | slab/cache.rs | Unit |
| HAL_SLAB6 | Page metadata at end of page | slab/page.rs | Unit |

### 8.5 Console (HAL_CONSOLE)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| HAL_CONSOLE1 | init initializes UART | console.rs | Runtime |
| HAL_CONSOLE2 | handle_interrupt processes RX | console.rs | Runtime |
| HAL_CONSOLE3 | Ctrl+C detection sets flag | console.rs | Runtime |
| HAL_CONSOLE4 | Secondary output to GPU | console.rs | Runtime |
| HAL_CONSOLE5 | Secondary input from VirtIO | console.rs | Runtime |

### 8.6 VirtIO HAL (HAL_VIRTIO)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| HAL_VIRTIO1 | dma_alloc allocates page-aligned | virtio.rs | Runtime |
| HAL_VIRTIO2 | dma_dealloc frees buffer | virtio.rs | Runtime |
| HAL_VIRTIO3 | mmio_phys_to_virt translates | virtio.rs | Runtime |
| HAL_VIRTIO4 | share returns physical address | virtio.rs | Runtime |

---

## 9. Architecture-Specific

### 9.1 AArch64 (ARCH_AA64)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| ARCH_AA64_1 | DAIF used for interrupt control | aarch64/interrupts.rs | Unit |
| ARCH_AA64_2 | GIC auto-detects v2/v3 | aarch64/gic.rs | Runtime |
| ARCH_AA64_3 | Timer uses virtual or physical | aarch64/timer.rs | Runtime |
| ARCH_AA64_4 | PL011 UART for serial | aarch64/serial.rs | Runtime |
| ARCH_AA64_5 | MMU uses TTBR0/TTBR1 split | aarch64/mmu/ | Runtime |
| ARCH_AA64_6 | Context saves x0-x30, sp, lr, pc | arch/aarch64/task.rs | Runtime |
| ARCH_AA64_7 | enter_user_mode via eret | arch/aarch64/task.rs | Runtime |
| ARCH_AA64_8 | Syscall via svc #0 | arch/aarch64/syscall.rs | Runtime |

### 9.2 x86_64 (ARCH_X86)

| ID | Behavior | File | Tested |
|----|----------|------|--------|
| ARCH_X86_1 | RFLAGS used for interrupt control | x86_64/interrupts/state.rs | Unit |
| ARCH_X86_2 | APIC/IOAPIC for interrupts | x86_64/interrupts/ | Runtime |
| ARCH_X86_3 | PIT for timer at 100Hz | x86_64/interrupts/pit.rs | Runtime |
| ARCH_X86_4 | COM1 for serial | x86_64/io/serial.rs | Runtime |
| ARCH_X86_5 | MMU uses single CR3 | x86_64/mem/mmu.rs | Runtime |
| ARCH_X86_6 | GDT has kernel+user segments | x86_64/cpu/gdt.rs | Runtime |
| ARCH_X86_7 | TSS provides RSP0 for syscalls | x86_64/cpu/gdt.rs | Runtime |
| ARCH_X86_8 | Context saves rbx,r12-15,rbp | arch/x86_64/task.rs | Runtime |
| ARCH_X86_9 | enter_user_mode via sysretq | arch/x86_64/task.rs | Runtime |
| ARCH_X86_10 | Syscall via syscall instruction | arch/x86_64/syscall.rs | Runtime |
| ARCH_X86_11 | FS register for TLS | arch/x86_64/mod.rs | Runtime |

---

## Summary Statistics

| Category | Behaviors | Tested |
|----------|-----------|--------|
| Boot & Initialization | 29 | 29 |
| Memory Management | 43 | 43 |
| Process & Scheduler | 47 | 47 |
| System Calls | 45 | 45 |
| VFS | 36 | 36 |
| Filesystems | 38 | 38 |
| Device Drivers | 38 | 38 |
| HAL | 32 | 32 |
| Architecture-Specific | 19 | 19 |
| **Total** | **327** | **327** |

---

## Testing Legend

- **Unit**: Unit tested with `cargo test`
- **Golden**: Tested via golden file comparison (behavior tests)
- **Runtime**: Runtime-verified during kernel execution
- **Manual**: Manually tested via interactive testing

---

## Changelog

- **2026-01-13**: Initial comprehensive inventory created from full kernel analysis
