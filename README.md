# LevitateOS Kernel

**The AI-Written Kernel** — Part of the [LevitateOS](https://github.com/LevitateOS/LevitateOS) experiment.

> This kernel is written entirely by AI agents. It implements the Linux syscall ABI to run unmodified musl-linked binaries. The goal is capability, not code beauty.

## Quick Facts

| | |
|---|---|
| **Language** | Rust (`no_std`) |
| **Architectures** | x86_64, AArch64 |
| **Platforms** | QEMU only (real hardware aspirational) |
| **Syscalls** | 70+ implemented |
| **libc** | musl (static) |
| **Shell** | BusyBox ash |

## Getting Started

This repository is a **git submodule** of the main LevitateOS project:

```bash
# Clone the full project
git clone --recursive https://github.com/LevitateOS/LevitateOS.git
cd LevitateOS

# Build and run
./run.sh              # GUI mode
./run-term.sh         # Terminal mode (Ctrl+A X to exit)
./run-vnc.sh          # Browser at localhost:6080

# Or use xtask directly
cargo xtask build kernel --arch x86_64
cargo xtask run
```

## What Works

- **BusyBox ash shell** — interactive prompt, pipes, command substitution
- **80+ coreutils** — ls, cat, grep, sed, sort, etc.
- **fork/exec/wait** — full process lifecycle
- **VFS** — tmpfs, devtmpfs, initramfs, FAT32, ext4 (read-only)
- **Signals** — basic sigaction/sigprocmask

## Directory Structure

```
arch/               # Architecture-specific crates
├── aarch64/        # ARM64 boot, exceptions, MMU
└── x86_64/         # x86_64 boot, exceptions, MMU

levitate/           # Main kernel binary
syscall/            # Linux syscall implementations (70+)
sched/              # Scheduler and task management  
mm/                 # Memory management (buddy, VMA)
vfs/                # Virtual filesystem layer
fs/                 # Filesystem implementations
├── tmpfs/
├── devtmpfs/
├── initramfs/
├── ext4/
└── fat/
drivers/            # Device drivers
├── virtio-blk/
├── virtio-gpu/
├── virtio-input/
└── virtio-net/
```

## Key Subsystems

| Subsystem | Status | Notes |
|-----------|--------|-------|
| **Memory** | ✅ Working | Buddy allocator, VMA tracking, mmap/brk |
| **Syscalls** | ✅ Working | 70+ Linux-compatible syscalls |
| **VFS** | ✅ Working | Linux-style superblock/inode/dentry |
| **Scheduler** | ✅ Working | Preemptive round-robin |
| **Signals** | 🟡 Partial | sigaction works, delivery is basic |
| **Networking** | ❌ Not yet | Driver exists, no TCP/IP stack |

## Feature Flags

| Flag | Purpose |
|------|---------|
| `verbose` | Boot logging for debugging |
| `verbose-syscalls` | Log every syscall invocation |
| `diskless` | Skip initrd requirement |

## Boot Sequence

1. **Assembly Entry** — MMU setup, stack init
2. **Rust Entry** (`kernel_main`) — 
   - Exception handlers, heap, console
   - Interrupt controller (GIC/APIC)
   - Physical memory from DTB/ACPI
   - VirtIO device scan
   - Mount filesystems, parse initramfs
3. **PID 1** — Spawn BusyBox init

## Related

- **Main Project**: [github.com/LevitateOS/LevitateOS](https://github.com/LevitateOS/LevitateOS)
- **AI Team Logs**: See `.teams/` in main repo (469+ sessions)
- **Known Issues**: See `docs/GOTCHAS.md` in main repo

## License

MIT — See main repository.
