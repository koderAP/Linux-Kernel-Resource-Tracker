#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/resource_tracker.h>
#include <linux/sched/task.h>   
#include <linux/sched/signal.h> 
#include <linux/rcupdate.h>     // rcu_read_lock, rcu_read_unlock


extern struct list_head monitored_list;
extern spinlock_t monitored_lock;

void update_heap_usage(pid_t pid, long byte_change)
{
    struct pid_node *node;
    struct task_struct *task;

    spin_lock(&monitored_lock);
    list_for_each_entry(node, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid) {
            if(node->proc_resource->heapsize + byte_change > node->proc_resource->heapsize && byte_change < 0){
                node->proc_resource->heapsize = 0;
            }else{
                node->proc_resource->heapsize += byte_change;
            }

            printk(KERN_INFO "Heap usage for PID %d: %lu\n", pid,
                   node->proc_resource->heapsize);
            spin_unlock(&monitored_lock);

            rcu_read_lock();
            task = find_task_by_vpid(pid);
            if (task && task->heap_quota != -1 && node->proc_resource->heapsize >
                   ((unsigned long) task->heap_quota)&&
                node->proc_resource->heapsize >
                   ((unsigned long) task->heap_quota * 1024 * 1024)) {

                printk(KERN_INFO "Heap usage for PID %d: %lu, but limit is %lu, so KILLING it\n", pid,
                     node->proc_resource->heapsize, task->heap_quota * 1024 * 1024);

                rcu_read_unlock();
                send_sig(SIGKILL, task, 0);
                return;
            }
            rcu_read_unlock();
            return;
        }
    }
    spin_unlock(&monitored_lock);
}

void update_openfile_count(pid_t pid, int change)
{
    struct pid_node *node;
    struct task_struct *task;

    spin_lock(&monitored_lock);
    list_for_each_entry(node, &monitored_list, next_prev_list) {
        if (node->proc_resource->pid == pid) {
            if (node->proc_resource->openfile_count + change > node->proc_resource->openfile_count && change < 0) {
                node->proc_resource->openfile_count = 0;
            } 
            else {
                node->proc_resource->openfile_count += change;
            }
            spin_unlock(&monitored_lock);
            printk(KERN_INFO "Page usage for PID %d: %lu\n", pid,
                   node->proc_resource->openfile_count);

            rcu_read_lock();
            task = find_task_by_vpid(pid);
            
            if (task && task->file_quota != -1 &&
                (node->proc_resource->openfile_count >
                 (unsigned long) task->file_quota)) {
                
                printk(KERN_INFO "Page usage for PID %d: %lu, but limit is %lu, so KILLING it\n", pid,
                   node->proc_resource->openfile_count, task->file_quota);
                
                rcu_read_unlock();
                send_sig(SIGKILL, task, 0);
                return;

            }
            rcu_read_unlock();
            return;
        }
    }
    spin_unlock(&monitored_lock);
}

