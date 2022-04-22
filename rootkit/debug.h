struct ftrace_hook {
    const char *name;
    void *new;
    void *orig;

    uintptr_t addr;
    struct ftrace_ops ops;
};

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
