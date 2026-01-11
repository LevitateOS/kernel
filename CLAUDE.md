# CLAUDE.md

This file provides guidance to Claude Code when working on the LevitateOS kernel.

## Repository Context

This is the **kernel** component of LevitateOS, maintained as a separate repository and used as a git submodule in the main [LevitateOS](https://github.com/LevitateOS/LevitateOS) repo.

**To build and run**, you need the parent repository:
```bash
git clone --recursive git@github.com:LevitateOS/LevitateOS.git
cd LevitateOS
cargo xtask build kernel --arch x86_64
cargo xtask build kernel --arch aarch64
cargo xtask run
```

## Architecture Overview

**LevitateOS is a General Purpose Unix-Compatible Operating System** that implements the Linux syscall ABI so programs compiled for Linux run without modification.

### Supported Architectures

| Architecture | Target | Platforms |
|--------------|--------|-----------|
| AArch64 | `aarch64-unknown-none` | QEMU virt, Pixel 6 |
| x86_64 | `x86_64-unknown-none` | QEMU q35, Intel NUC |

### Source Structure

```
src/
├── arch/           # Architecture-specific code
│   ├── aarch64/    # ARM64: boot, exceptions, syscall, MMU
│   └── x86_64/     # Intel: boot, exceptions, syscall, MMU
├── boot/           # Boot protocol handling (Limine, DTB)
├── fs/             # Filesystem layer
│   ├── vfs/        # Virtual File System
│   ├── tmpfs/      # In-memory filesystem
│   ├── tty/        # TTY/PTY subsystem
│   └── pipe.rs     # Pipe implementation
├── loader/         # ELF loader
├── memory/         # Memory management (heap, user pages, VMA)
├── syscall/        # Linux syscall implementations
│   ├── fs/         # File syscalls (read, write, open, etc.)
│   ├── process/    # Process syscalls (fork, exec, clone, etc.)
│   ├── mm.rs       # Memory syscalls (mmap, brk, etc.)
│   └── sync.rs     # Synchronization (futex)
├── task/           # Task/thread management and scheduling
└── main.rs         # Kernel entry point
```

### Key Architectural Patterns

**Higher-Half Kernel**: Runs at virtual address `0xFFFF_8000_0000_0000`

**Linux ABI Compatibility** (critical for running unmodified binaries):
- `Stat` struct: exactly 128 bytes on AArch64
- Auxiliary vector (auxv) on stack for `std::rt` initialization
- TLS register context switching (`TPIDR_EL0` / `FS`)
- Vectored I/O (`writev`/`readv`) for Rust `println!`
- Errno values match Linux exactly (use `linux-raw-sys` crate)

**VFS Layer**: Linux-inspired hierarchy:
- Superblock -> Inode -> Dentry -> File
- Mount support for tmpfs, FAT32, ext4 (read-only), CPIO initramfs

**Syscall Result Type**:
```rust
// All syscalls return this type - single conversion at ABI boundary
pub type SyscallResult = Result<i64, u32>;
```

## Development Rules

### Rule 0: Quality Over Speed
Take the correct architectural path, never the shortcut. Future teams inherit your decisions.

### Memory Safety
- Minimize `unsafe` blocks
- Every `unsafe` requires `// SAFETY:` comment explaining soundness
- Wrap unsafe in safe abstractions
- Use RAII for resource management

### Error Handling
- All fallible operations return `Result<T, E>`
- NO `unwrap()`, `expect()`, or `panic!`
- Use `?` operator for propagation
- Syscalls return `SyscallResult` - errno constants from `linux-raw-sys`

### Silence is Golden
- Production builds produce NO output on success
- Use `--features verbose` for debug output
- Errors must be loud and immediate

### Code Organization
- File sizes: < 1000 lines preferred, < 500 ideal
- Each module owns its own state with private fields
- Remove unused code - git history is the archive

## Feature Flags

| Flag | Purpose |
|------|---------|
| `verbose` | Enable boot messages for testing |
| `diskless` | Skip initrd requirement |
| `multitask-demo` | Enable demo tasks for preemption testing |
| `verbose-syscalls` | Log all syscall invocations |

## Dependencies

This kernel depends on sibling crates in the parent workspace:
- `los_hal` - Hardware Abstraction Layer (GIC, MMU, console, timer)
- `los_utils` - Core utilities (spinlock, ringbuffer, CPIO parser)
- `los_error` - Error type definitions
- `los_term` - ANSI terminal emulator
- `los_pci` - PCI bus support
- `los_gpu` - VirtIO GPU library

## Team Logs

Implementation decisions are tracked with `TEAM_XXX` identifiers in comments. Reference these in commits when making related changes.
