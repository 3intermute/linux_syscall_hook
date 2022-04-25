#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"
#include "direct_syscall_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_DESCRIPTION("syscall table hook on arm64, no ftrace");
MODULE_VERSION("1.0");

static asmlinkage int (*orig_kill) (const struct pt_regs *);

asmlinkage int new_kill(const struct pt_regs *regs) {
    pr_info("debug: hooked kill :D, pid (%i), sig (%i)\n", regs->regs[0], regs->regs[1]);
    // return orig_kill(regs);
    return 0;
}

struct direct_syscall_hook hook = {__NR_kill, new_kill, &orig_kill};

static int __init hook_test_mod_init(void) {
    pr_info("debug: module loaded\n");
    hook_syscall(&hook);
    return 0;
}

static void __exit hook_test_mod_exit(void) {
    pr_info("debug: module unloaded\n");
}


module_init(hook_test_mod_init);
module_exit(hook_test_mod_exit);
