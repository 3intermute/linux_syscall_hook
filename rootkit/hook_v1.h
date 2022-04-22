// adapted from: https://gist.github.com/xcellerator/ac2c039a6bbd7782106218298f5e5ac1#file-ftrace_helper-h

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hook {
    const char *name;
    void *new;
    void *orig;

    unsigned long addr;
    struct ftrace_ops ops;
}

/*
The prototype of the callback function is as follows (as of v4.14):

void callback_func(unsigned long ip, unsigned long parent_ip,
                   struct ftrace_ops *op, struct pt_regs *regs);

@ip
    This is the instruction pointer of the function that is being traced.
    (where the fentry or mcount is within the function)
@parent_ip
    This is the instruction pointer of the function that called the the function being traced
    (where the call of the function occurred).
@op
    This is a pointer to ftrace_ops that was used to register the callback.
    This can be used to pass data to the callback via the private pointer.
@regs
    If the FTRACE_OPS_FL_SAVE_REGS or FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED flags are set in the ftrace_ops structure,
    then this will be pointing to the pt_regs structure like it would be if an breakpoint was placed at the start of the function where ftrace was tracing.
    Otherwise it either contains garbage, or NULL.
*/
static void callback_func(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *op, struct pt_regs *regs) {
    // ihttps://stackoverflow.com/questions/42966520/restoring-task-pt-regs-when-returning-to-original-function-from-ftrace-handler
    // find some way to preserve pt_regs
    regs->pc = (unsigned long) new;
}

void ftrace_install_hook(struct ftrace_hook *hook) {
    /*
    To register a function callback, a ftrace_ops is required.
    This structure is used to tell ftrace what function should be called as the callback as well as what protections the callback will perform and not require ftrace to handle.

    There is only one field that is needed to be set when registering an ftrace_ops with ftrace:

    struct ftrace_ops ops = {
          .func                    = my_callback_func,
          .flags                   = MY_FTRACE_FLAGS
          .private                 = any_private_data_structure,
    };
    */
    hook->ops.func = callback_func;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                | FTRACE_OPS_FL_RECURSION_SAFE
                | FTRACE_OPS_FL_IPMODIFY;

    // get the address of the function to hook by its name
    hook->addr = kallsyms_lookup_name(hook->name);
    if (hook->addr) {
        return -ENOENT;
    }

#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->orig) = hook->addr + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->orig) = hook->addr;
#endif

    int err;
    err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
    if (err) {
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        return err;
    }

    return 0;
}
