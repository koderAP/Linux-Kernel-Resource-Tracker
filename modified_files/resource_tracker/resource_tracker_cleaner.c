#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/spinlock.h>
#include <linux/resource_tracker.h>

extern void cleanup_monitored_entry(pid_t pid);

static struct kprobe kp = {
    .symbol_name = "do_exit",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    pid_t exiting_pid = current->pid;
    cleanup_monitored_entry(exiting_pid);
    return 0;
}

static int __init cleanup_kprobe_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("Failed to register kprobe: %d\n", ret);
        return ret;
    }
    pr_info("Cleanup kprobe registered at %p\n", kp.addr);
    return 0;
}

static void __exit cleanup_kprobe_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("Cleanup kprobe unregistered\n");
}

module_init(cleanup_kprobe_init);
module_exit(cleanup_kprobe_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anubhav Pandey");
MODULE_DESCRIPTION("Automatically clean monitored list on process termination");

