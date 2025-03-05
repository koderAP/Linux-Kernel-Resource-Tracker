#ifndef RESOURCE_TRACKER_H
#define RESOURCE_TRACKER_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>

// Structure to store resource utilization of a process
struct per_proc_resource {
    pid_t pid;                 // Process ID
    unsigned long heapsize;     // Memory allocated via brk() and mmap()
    unsigned long openfile_count; // Number of open files
};

// Node structure for the doubly linked list
struct pid_node {
    struct per_proc_resource *proc_resource; // Resource utilization details
    struct list_head next_prev_list;        // Linux kernel's list mechanism
};


void print_tracked_processes(struct seq_file *m);
void update_heap_usage(pid_t pid, long byte_change);
void update_openfile_count(pid_t pid, int change);
void cleanup_monitored_entry(pid_t pid);

#endif 
