// implement using direct system call hooking#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <asm/unistd.h>

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
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_pc, THIS_MODULE)) {
        regs->pc = (unsigned long) hook->new;
    }
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
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION_SAFE
                    | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    if (err) {
        pr_info("debug: ftrace_set_filter_ip failed with err (%i), &hook->ops (%pR), hook->addr @%pK\n", err, &hook->ops, hook->addr);
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
