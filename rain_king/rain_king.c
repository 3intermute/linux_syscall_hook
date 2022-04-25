#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm-generic/unistd.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"
#include "direct_syscall_hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_DESCRIPTION("syscall table hook on arm64, no ftrace");
MODULE_VERSION("1.0");

static asmlinkage int (*orig_mkdirat) (const struct pt_regs *);

asmlinkage int new_mkdirat(const struct pt_regs *regs) {
    char __user *pathname_usr_ptr = (char *) regs->regs[1];
    char pathname[NAME_MAX] = {0};
    strncpy_from_user(pathname, pathname_usr_ptr, NAME_MAX); // 256 bits
    pr_info("debug: mkdirat called :D, path (%s), fd (%i), mode (%lli)\n", pathname, (int) regs->regs[0], regs->regs[2]);
    if ((int) regs->regs[0] == -1) {
        return 0xdeadbeef;
    }
    return orig_mkdirat(regs);
}

struct direct_syscall_hook hook = {__NR_mkdirat, new_mkdirat, &orig_mkdirat};

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
