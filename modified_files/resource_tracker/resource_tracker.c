#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/resource_tracker.h>
#include <linux/rcupdate.h>

/* Global list for monitored processes */
LIST_HEAD(monitored_list);
DEFINE_SPINLOCK(monitored_lock);

EXPORT_SYMBOL(monitored_list);
EXPORT_SYMBOL(monitored_lock);


/* register - Register a process for monitoring */
SYSCALL_DEFINE1(register, pid_t, pid)
{
    struct pid_node *node;
    struct task_struct *task;
    

    if (pid < 1)
        return -22;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        get_task_struct(task);  // Increase reference count before unlocking RCU, this makes sture that pointer is not freed anytime before we are done registering the process
    rcu_read_unlock();
    if (!task)
        return -3;

    spin_lock(&monitored_lock);
    list_for_each_entry(node, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid) {
            spin_unlock(&monitored_lock);
            return -23;
        }
    }
    

    node = kmalloc(sizeof(*node), GFP_KERNEL);
    if (!node) {
        spin_unlock(&monitored_lock);
        return -ENOMEM;
    }
    node->proc_resource = kmalloc(sizeof(struct per_proc_resource), GFP_KERNEL);
    if (!node->proc_resource) {
        kfree(node);
        spin_unlock(&monitored_lock);
        return -ENOMEM;
    }
    
    task_lock(task);
    task->heap_quota = -1;
    task->file_quota = -1;
    task_unlock(task);
    node->proc_resource->pid = pid;
    node->proc_resource->heapsize = 0;
    node->proc_resource->openfile_count = 0;

    rcu_read_lock();  
    if (task->exit_state & EXIT_ZOMBIE || task->exit_state & EXIT_DEAD) {
        task_unlock(task);
        kfree(node->proc_resource);
        kfree(node);
        spin_unlock(&monitored_lock);
        return -3;
    }
    rcu_read_unlock();

    list_add_tail(&node->next_prev_list, &monitored_list);
    printk(KERN_INFO "Registered PID %d for monitoring\n", pid);

    put_task_struct(task); // Nomore needed, so decrease reference count
    spin_unlock(&monitored_lock);

    return 0;
}

/* fetch - Return current resource usage to user space */
SYSCALL_DEFINE2(fetch, struct per_proc_resource __user *, stats, pid_t, pid)
{
    struct pid_node *node;
    struct per_proc_resource kercopy;
    
    
    int found = 0;

    if (pid < 1)
        return -22;

    spin_lock(&monitored_lock);
    list_for_each_entry(node, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid) {
            found = 1;
            break;
        }
    }
    spin_unlock(&monitored_lock);

    if (!found)
        return -22;

    printk(KERN_INFO "Fetching resource usage for PID %d\n", pid);

    kercopy = *node->proc_resource;
    kercopy.heapsize = kercopy.heapsize /(1024*1024);
    if (copy_to_user(stats, &kercopy, sizeof(struct per_proc_resource)))
        return -EFAULT;

    return 0;
}

/* deregister - Remove a process from the monitored list */
SYSCALL_DEFINE1(deregister, pid_t, pid)
{
    struct pid_node *node, *tmp;
    
    int found = 0;

    struct task_struct *task;

    /* to Verify if process exists */
    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if(task)
        get_task_struct(task);
    rcu_read_unlock();
    if(!task)
        return -3; // Process does not exist ==> Cannot deregister as cannot be in the list too

    if (pid < 1)
        return -22;

    spin_lock(&monitored_lock);
    list_for_each_entry_safe(node, tmp, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid) {
            list_del(&node->next_prev_list);
            kfree(node->proc_resource);
            kfree(node);
            found = 1;
            printk(KERN_INFO "Deregistered PID %d\n", pid);
            if(task){
                task_lock(task);
                task->heap_quota = -1;
                task->file_quota = -1;
                task_unlock(task);
            }
            break;
        }
    }
    spin_unlock(&monitored_lock);

    if(task)put_task_struct(task);

    if (!found)
        return -3;
    return 0;


}

/* resource_cap - Set resource quotas for a process.*/


SYSCALL_DEFINE3(resource_cap, pid_t, pid, long, heap_quota, long, file_quota)
{
    struct task_struct *task;
    struct pid_node *node = NULL;
    

    if (pid < 1)
        return -22;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    if (!task)
        return -3;

    
    int found = 0; 
    spin_lock(&monitored_lock);
    list_for_each_entry(node, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid){
            found = 1;
            break;
        }
    }
    if (!found){
        spin_unlock(&monitored_lock);
        return -22;
    }
    spin_unlock(&monitored_lock);

    

    rcu_read_lock();
    if (task->heap_quota != -1 || task->file_quota != -1){
        rcu_read_unlock();
        return -23;
    }
    rcu_read_unlock();

    if(heap_quota < -1 || file_quota < -1){
        put_task_struct(task); 
        return -24; // Ccccannot set negative quota
    }

    printk(KERN_INFO "Setting resource quotas for PID %d\n", pid);

    task_lock(task);
    task->heap_quota = heap_quota;
    task->file_quota = file_quota;
    task_unlock(task);


    update_heap_usage(pid, 0);
    update_openfile_count(pid, 0);
    put_task_struct(task); 
    return 0;
}

/* resource_reset - Reset resource quotas to -1 (no limit) */
SYSCALL_DEFINE1(resource_reset, pid_t, pid)
{
    struct task_struct *task;
    struct pid_node *node = NULL;
    

    if (pid < 1)
        return -22;

    rcu_read_lock();
    task = find_task_by_vpid(pid);
    if (task)
        get_task_struct(task);
    rcu_read_unlock();
    if (!task)
        return -3;

    int found = 0;
    spin_lock(&monitored_lock);
    list_for_each_entry(node, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid){
                found = 1;
                break;
            }
    }
    if (!found) {
        spin_unlock(&monitored_lock);
        return -22;
    }
    spin_unlock(&monitored_lock);

    printk(KERN_INFO "Resetting resource quotas for PID %d\n", pid);

    task_lock(task);
    task->heap_quota = -1;
    task->file_quota = -1;
    task_unlock(task);
    put_task_struct(task); 

    return 0;
}

/* Cleanup function to remove monitored entry (used for process termination) */
void cleanup_monitored_entry(pid_t pid)
{
    struct pid_node *node, *tmp;
    

    spin_lock(&monitored_lock);
    list_for_each_entry_safe(node, tmp, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid) {
            list_del(&node->next_prev_list);
            kfree(node->proc_resource);
            kfree(node);
            pr_info("Cleaned up monitored entry for PID %d\n", pid);
            break;
        }
    }
    spin_unlock(&monitored_lock);
}

EXPORT_SYMBOL(cleanup_monitored_entry);