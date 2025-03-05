#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/signal.h>
#include <linux/resource_tracker.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anubhav Pandey");
MODULE_DESCRIPTION("A module to track process resource usage with a /proc interface");

extern struct list_head monitored_list;
extern spinlock_t monitored_lock;

static char my_task_state_to_char(struct task_struct *task)
{
    if (!task)
        return 'X';  // Unknown state (or Dead)

    if (task_is_running(task))
        return 'R';  // Running or Runnable

    switch (task_state_index(task)) {
        case TASK_INTERRUPTIBLE:
            return 'S';  // Sleeping (interruptible)
        case TASK_UNINTERRUPTIBLE:
            return 'D';  // Uninterruptible sleep (usually waiting for I/O)
        case __TASK_STOPPED:
            return 'T';  // Stopped (e.g., by a signal like SIGSTOP)
        case __TASK_TRACED:
            return 't';  // Traced (being debugged)
        case EXIT_ZOMBIE:
            return 'Z';  // Zombie (terminated but not reaped by parent)
        case EXIT_DEAD:
            return 'X';  // Dead (should not exist)
        default:
            return '?';  // Unknown state
    }
}


static int my_get_nr_threads(struct task_struct *task)
{
    if (task && task->signal)
         return task->signal->nr_threads;
    return 1;
}

/*
 * print_tracked_processes - Print a summary table of tracked processes.
   This function is called when the /proc/tracker_status file is read. Idea was to print the tracked processes in a tabular format, similar to top or htop.
 */
#define CENTER_ALIGN(buf, width, text) \
    snprintf(buf, sizeof(buf), "%*s%s%*s", \
             ((width - (int)strlen(text)) / 2), "", \
             text, \
             ((width - (int)strlen(text)) + 1) / 2, "") // For center alignment

void print_tracked_processes(struct seq_file *m)
{
    struct pid_node *node;
    struct task_struct *task;
    char state_char;

    seq_printf(m, "%-6s    %-16s%-4s   %-12s  %-12s    %-8s  %-8s    %s\n", 
               "PID", "COMMAND", "STAT", "HEAP(MB)", "HEAP_CAP(MB)", "FILES", "FILE_CAP", "THREADS");

    spin_lock(&monitored_lock);
    list_for_each_entry(node, &monitored_list, next_prev_list) {
        rcu_read_lock();
        task = pid_task(find_vpid(node->proc_resource->pid), PIDTYPE_PID);
        if (!task) {
            rcu_read_unlock();
            continue;
        }
        state_char = my_task_state_to_char(task);
        char heap_quota_buf[21], file_quota_buf[21];

        if (task->heap_quota == -1)
            snprintf(heap_quota_buf, sizeof(heap_quota_buf), "U");
        else
            snprintf(heap_quota_buf, sizeof(heap_quota_buf), "%lu", task->heap_quota);

        if (task->file_quota == -1)
            snprintf(file_quota_buf, sizeof(file_quota_buf), "U");
        else
            snprintf(file_quota_buf, sizeof(file_quota_buf), "%lu", task->file_quota);

        char pid_buf[8], comm_buf[18], stat_buf[6], heap_buf[14], heap_cap_buf[14];
        char files_buf[10], file_cap_buf[10], threads_buf[6];

        char pid_str[10], heap_str[14], files_str[10], threads_str[6], stat_str[2];

        snprintf(pid_str, sizeof(pid_str), "%d", task->pid);
        snprintf(heap_str, sizeof(heap_str), "%lu", node->proc_resource->heapsize / (1024 * 1024));
        snprintf(files_str, sizeof(files_str), "%lu", node->proc_resource->openfile_count);
        snprintf(threads_str, sizeof(threads_str), "%d", my_get_nr_threads(task));
        snprintf(stat_str, sizeof(stat_str), "%c", state_char);  // Convert char to string

        CENTER_ALIGN(pid_buf, 6, pid_str);
        CENTER_ALIGN(comm_buf, 16, task->comm);
        CENTER_ALIGN(stat_buf, 4, stat_str);
        CENTER_ALIGN(heap_buf, 12, heap_str);
        CENTER_ALIGN(heap_cap_buf, 12, heap_quota_buf);
        CENTER_ALIGN(files_buf, 8, files_str);
        CENTER_ALIGN(file_cap_buf, 8, file_quota_buf);
        CENTER_ALIGN(threads_buf, 6, threads_str);

        seq_printf(m, "%s %s   %s  %s  %s    %s  %s     %s\n",
            pid_buf, comm_buf, stat_buf, heap_buf, heap_cap_buf, files_buf, file_cap_buf, threads_buf);

        rcu_read_unlock();
    }
    spin_unlock(&monitored_lock);
}

static int tracker_proc_show(struct seq_file *m, void *v)
{
    print_tracked_processes(m);
    return 0;
}

static int tracker_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, tracker_proc_show, NULL);
}

static const struct proc_ops tracker_proc_ops = {
    .proc_open    = tracker_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* Module initialization: create the proc entry and print instructions */
static int __init tracker_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create("tracker_status", 0, NULL, &tracker_proc_ops);
    if (!entry) {
        printk(KERN_ERR "Failed to create /proc/tracker_status\n");
        return -ENOMEM;
    }
    printk(KERN_INFO "Tracker module loaded.\n");
    printk(KERN_INFO "To view tracked processes, run: cat /proc/tracker_status\n");
    printk(KERN_INFO "Note: Add processes to the monitoring list manually as needed.\n");
    return 0;
}

/* Module exit: remove the proc entry and free tracked list memory */
static void __exit tracker_exit(void)
{
    remove_proc_entry("tracker_status", NULL);
    // We don't need to free the list, as it the module only reads from it.
    printk(KERN_INFO "Tracker module unloaded.\n");
}

module_init(tracker_init);
module_exit(tracker_exit);
