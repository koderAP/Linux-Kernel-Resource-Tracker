# Resource Usage Tracker & Limiter for Linux Kernel 6.1.6 and 6.13.4

> **Developed as part of a COL331 course project.**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Kernel Versions](#supported-kernel-versions)
- [Directory Structure](#directory-structure)
- [Implementation Details](#implementation-details)
  - [System Calls](#system-calls)
  - [Data Structures](#data-structures)
  - [Resource Usage Tracking & Limiting](#resource-usage-tracking--limiting)
  - [Helper Modules](#helper-modules)
- [Applying the Patch](#applying-the-patch)
- [Building & Installing the Kernel](#building--installing-the-kernel)
- [Usage Instructions](#usage-instructions)
- [Extra Features](#extra-features)
- [References](#references)

---

## Overview

This repository provides a Linux kernel patch (`res_usage.patch`) and supporting modules to enable **tracking and limiting of heap memory usage and open file descriptors** for specified processes. The solution is compatible with Linux kernel versions **6.1.6** and **6.13.4**. It introduces new system calls, helper modules, and `/proc` integration for real-time resource monitoring and enforcement.

---

## Features

- **Custom System Calls** for process registration, resource fetching, deregistration, quota setting, and quota resetting.
- **Automatic Quota Enforcement:** Processes exceeding set quotas are killed with `SIGKILL`.
- **Procfs Interface:** `/proc/tracker_status` displays all monitored processes and their current resource usage.
- **Automatic Cleanup:** Monitored entries are removed when processes exit, using a kprobe on `do_exit`.
- **Cross-architecture Support:** Works on both x86_64 and ARM64.
- **Robust Edge Case Handling:** Handles process death during registration, PID reuse, and concurrent access.

---

## Supported Kernel Versions

- **Linux 6.1.6**
- **Linux 6.13.4**

The patch (`res_usage.patch`) is provided for both versions and has been tested on x86_64 and ARM64.

---

## Directory Structure

.
├── res_usage.patch
├── res_usage_6_1_6.patch
├── report.pdf
├── modified_files/
│ ├── resource_tracker/
│ │ ├── resource_tracker.c
│ │ ├── resource_tracker_hooks.c
│ │ ├── resource_tracker.h
│ │ ├── Makefile
│ │ └── Kbuild
│ ├── modules/
│ │ ├── cleanup_kprobe.c
│ │ └── tracker.c
│ └── (other modified kernel files)
└── README.md




---

## Implementation Details

### System Calls

| System Call           | Purpose                                               |
|-----------------------|------------------------------------------------------|
| `sys_register`        | Register a process for monitoring                    |
| `sys_fetch`           | Fetch resource usage for a monitored process         |
| `sys_deregister`      | Remove a process from monitoring                     |
| `sys_resource_cap`    | Set heap/file quotas for a monitored process         |
| `sys_resource_reset`  | Reset quotas to unlimited for a monitored process    |

Syscall numbers are assigned in the appropriate syscall tables for each architecture and kernel version.

---

### Data Structures

Defined in `include/linux/resource_tracker.h`:

struct per_proc_resource {
pid_t pid;
unsigned long heapsize;
unsigned long openfile_count;
};

struct pid_node {
struct per_proc_resource *proc_resource;
struct list_head next_prev_list;
};



Each monitored process is represented as a node in a doubly-linked list, protected by a spinlock.

---

### Resource Usage Tracking & Limiting

- **Registration:** Validates PID, ensures process is alive, allocates and initializes a tracking node, and adds it to the monitored list.
- **Fetching:** Copies current resource usage from kernel space to user space.
- **Deregistration:** Removes the process from the monitored list and frees memory.
- **Quota Setting:** Adds `heap_quota` and `file_quota` fields to `task_struct`. Exceeding quotas results in `SIGKILL`.
- **Quota Reset:** Resets quotas to unlimited (`-1`).
- **Syscall Hooking:** Modifies `mmap`, `brk`, `open`, `openat`, `openat2`, and `close` syscalls to update tracked usage.

---

### Helper Modules

- **cleanup_kprobe:** Uses a kprobe on `do_exit` to ensure monitored entries are cleaned up when a process exits.
- **tracker:** Creates `/proc/tracker_status` for real-time monitoring of all tracked processes.

---

## Applying the Patch

1. **Download the Kernel Source**

2. **Apply the Patch**:

git apply < /path/to/res_usage.patch


---

## Building & Installing the Kernel

1. **Configure the Kernel:**

cp -v /boot/config-$(uname -r) .config
make menuconfig # Or 'make oldconfig'


2. **Build the Kernel:**

make -j$(nproc)
sudo make modules_install install


3. **Update Bootloader and Reboot:**

sudo update-grub
sudo reboot


4. **Verify Kernel Version:**

uname -r


---

## Usage Instructions

- **Register a Process:**

syscall(SYS_register, pid);


- **Fetch Resource Usage:**

struct per_proc_resource stats;
syscall(SYS_fetch, &stats, pid);


- **Deregister a Process:**

syscall(SYS_deregister, pid);


- **Set Quotas:**

syscall(SYS_resource_cap, pid, heap_quota_MB, file_quota);



- **Reset Quotas:**

syscall(SYS_resource_reset, pid);



- **View Monitored Processes:**

cat /proc/tracker_status



---

## Extra Features

- **Works on both x86_64 and ARM64.**
- **Automatic cleanup** of monitored entries on process exit.
- **Procfs visualization** for real-time monitoring.
- **Detailed documentation** and robust error handling.
- **Efficient memory management** and concurrency protection.

---

## References

- Assignment instructions and requirements.
- Implementation report (`report.pdf`).
- Linux kernel development documentation.

---





