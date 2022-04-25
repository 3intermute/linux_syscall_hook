#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include "debug.h"

// struct ftrace_hook {
//     const char *name;
//     void *new;
//     void *orig;
//
//     unsigned long addr;
//     struct ftrace_ops ops;
// };

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
// in ftrace.h but not exported lol
kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;

int get_kallsyms_lookup_name(void) {
    static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    if (register_kprobe(&kp) < 0) {
        return -ENOENT;
    }

    kallsyms_lookup_name_ = (kallsyms_lookup_name_t) kp.addr;
    pr_info("debug: kallsyms_lookup_name_ %p\n", kallsyms_lookup_name_);
    unregister_kprobe(&kp);
    return 0;
}

static int fh_get_func_addr(struct ftrace_hook *hook) {
    if (!kallsyms_lookup_name_) {
        get_kallsyms_lookup_name();
    }
    hook->addr = kallsyms_lookup_name_(hook->name);
    pr_info("debug: hook->name %s\n", hook->name);
    pr_info("debug: hook->addr %p\n", hook->addr);
    if (!hook->addr) {
        return -ENOENT;
    }

    *((unsigned long*) hook->orig) = hook->addr;
    return 0;
}

static void fh_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->pc = (unsigned long) hook->new;
        pr_info("debug: reached end of fh_callback\n");
    }
}

int fh_install_hook(struct ftrace_hook *hook) {
    if (!hook) {
        return -ENOENT;
    }

    int err;
    err = fh_get_func_addr(hook);
    if (err) {
        pr_info("debug: fh_get_func_addr failed\n");
        return err;
    }

    hook->ops.func = fh_callback;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION_SAFE
                    | FTRACE_OPS_FL_IPMODIFY;

    pr_info("debug: hook state after set func + flag");
    debug_fh_hook(hook);

    // https://www.kernel.org/doc/html/v5.4/trace/ftrace-uses.html
    // hook->addr doesnt match /proc/kallsym
    err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    // err = ftrace_set_filter(&(hook->ops), hook->name, strlen(hook->name), 0);
    if (err) {
        pr_info("debug: ftrace_set_filter_ip failed\n");
        return err;
    }


    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_info("debug: register_ftrace_function failed\n");
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook) {
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
}
