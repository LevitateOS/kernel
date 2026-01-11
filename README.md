# LevitateOS Kernel

The core operating system kernel for [LevitateOS](https://github.com/LevitateOS/LevitateOS).

## Overview

**LevitateOS is a General Purpose Unix-Compatible Operating System** that aims to run any Unix program without modification. The kernel implements the Linux syscall ABI so programs compiled for Linux can run directly.

- **Language**: Rust (no_std)
- **Architectures**: AArch64, x86_64
- **Target Platforms**: QEMU virt/q35, Pixel 6, Intel NUC

## Getting Started

This repository is used as a **git submodule** within the main LevitateOS project. To work on the kernel:

```bash
# Clone the full project (includes kernel as submodule)
git clone --recursive git@github.com:LevitateOS/LevitateOS.git
cd LevitateOS

# Build the kernel
cargo xtask build kernel --arch x86_64
cargo xtask build kernel --arch aarch64

# Run in QEMU
cargo xtask run                    # x86_64 default
cargo xtask --arch aarch64 run     # AArch64

# Run tests
cargo xtask test unit              # Unit tests
cargo xtask test behavior          # Boot behavior tests
```

## Architecture

```
src/
├── arch/           # Architecture-specific (boot, exceptions, syscall)
│   ├── aarch64/
│   └── x86_64/
├── boot/           # Boot protocols (Limine, DTB)
├── fs/             # Filesystem (VFS, tmpfs, tty, pipe)
├── loader/         # ELF loader
├── memory/         # Memory management (heap, user pages, VMA)
├── syscall/        # Linux syscall implementations
└── task/           # Task management and scheduling
```

### Key Subsystems

| Subsystem | Description |
|-----------|-------------|
| **Memory** | Buddy allocator, slab allocator, VMM, mmap/brk support |
| **Syscalls** | Linux-compatible ABI for both architectures |
| **VFS** | Superblock/Inode/Dentry/File hierarchy with mount support |
| **Scheduler** | Preemptive multitasking with priority-based scheduling |

## Feature Flags

| Flag | Description |
|------|-------------|
| `verbose` | Enable boot logging for testing |
| `diskless` | Skip initrd requirement |
| `multitask-demo` | Enable demo tasks |
| `verbose-syscalls` | Log syscall invocations |

## Boot Sequence

1. **Assembly Entry** (`_start`): MMU & stack setup
2. **Rust Entry** (`kernel_main`): Subsystem initialization
   - Exception handlers, heap, console, logging
   - Interrupt controller (GIC/APIC)
   - Physical memory from DTB/ACPI
   - VirtIO device scan
   - Filesystem mount, initramfs parse
3. **PID 1**: Spawn init process

## Dependencies

The kernel uses sibling crates from the parent workspace:

| Crate | Purpose |
|-------|---------|
| `los_hal` | Hardware Abstraction Layer |
| `los_utils` | Core utilities (spinlock, ringbuffer) |
| `los_error` | Error types |
| `los_term` | Terminal emulator |
| `los_pci` | PCI bus support |
| `los_gpu` | VirtIO GPU |

## Contributing

See the main [LevitateOS repository](https://github.com/LevitateOS/LevitateOS) for contribution guidelines.

## License

See the main repository for license information.
