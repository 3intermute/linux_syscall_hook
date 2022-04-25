// implement using direct system call hooking#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <asm/unistd.h>

struct ftrace_hook {
    const char *name;
    void *new;
    void *orig;

    uintptr_t addr;
    struct ftrace_ops ops;
};

// ---DEBUG---
void debug_fh_hook(struct ftrace_hook *hook) {
    if (!hook) {
        pr_info("debug: fh_hook NULL\n");
        return;
    }
    pr_info("debug: fh_hook.name %s\n", hook->name);
    pr_info("debug: fh_hook.new %p\n", hook->new);
    pr_info("debug: fh_hook.orig %p\n", hook->orig);
    pr_info("debug: fh_hook.addr %p\n", hook->addr);

    pr_info("debug: fh_hook.ops.func %p\n", hook->ops.func);
    pr_info("debug: fh_hook.ops.flags %p\n", hook->ops.flags);
    pr_info("debug: fh_hook.ops.private %p\n", hook->ops.private);
}
// ---DEBUG---

typedef uintptr_t (*kallsyms_lookup_name_t)(const char *symbol_name);
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

uintptr_t get_addr_of_symbol(const char *symbol_name) {
    static struct kprobe kp;
    kp.symbol_name = symbol_name;
    if (register_kprobe(&kp) < 0) {
        return -ENOENT;
    }

    uintptr_t tmp = kp.addr;
    pr_info("debug: get_addr_of_symbol before unreg %p\n", (void *) tmp);
    unregister_kprobe(&kp);
    pr_info("debug: get_addr_of_symbol after unreg %p\n", (void *) tmp);
    return tmp;
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

    *((uintptr_t*) hook->orig) = hook->addr;
    return 0;
}

uintptr_t get_syscall_addr(int syscall_number) {
    if (!kallsyms_lookup_name_) {
        get_kallsyms_lookup_name();
    }
    uintptr_t sys_call_table_ptr = kallsyms_lookup_name_("sys_call_table");
    return ((unsigned char *) sys_call_table_ptr)[syscall_number];
}

// might not match function prototype in ftrace.h
static void fh_callback(uintptr_t ip, uintptr_t parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->pc = (uintptr_t) hook->new;
        pr_info("debug: reached end of fh_callback\n");
    }
}

int fh_install_hook(struct ftrace_hook *hook) {
    if (!hook) {
        return -ENOENT;
    }

    pr_info("debug: get_syscall_addr %p\n", get_syscall_addr(__NR_kill));
    pr_info("debug: kallsyms_lookup_name_ kallsyms_relative_base %p\n", kallsyms_lookup_name_("kallsyms_relative_base"));
    pr_info("debug: _text %p\n", _text);

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
