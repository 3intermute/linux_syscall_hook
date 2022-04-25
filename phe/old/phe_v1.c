#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd32.h>
#include <asm/ptrace.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"
#include "direct_syscall_hook_v1.h"

#define S_IOCTL 0xfffffff

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_DESCRIPTION("syscall table hook on arm64, no ftrace");
MODULE_VERSION("1.0");

// asmlinkage long (*orig_mkdir) (const struct pt_regs *);
asmlinkage long (*orig_mkdir) (const char __user *path, umode_t mode);

// asmlinkage long new_mkdir(const struct pt_regs *regs) {
//     pr_info("debug: got here\n");
//     pr_info("debug: regs->regs[1] (%x), regs->regs[0] (%s)\n", regs->regs[1], regs->regs[0]);
//     if (regs->regs[1] == S_IOCTL) {
//         const char *key = regs->regs[0];
//         pr_info("debug: mkdir recvd key (%s)\n", key);
//         // return 0;
//     }
//     return 0;
//     // return orig_mkdir(regs);
// }

asmlinkage long new_mkdir(const char __user *path, umode_t mode){
    pr_info("debug: path (%s), mode (%i)\n", path, mode);
    if (mode == S_IOCTL) {
        pr_info("debug: mkdir recvd key (%s)\n", path);
        // return 0;
    }
    return 0;
    // return orig_mkdir(regs);
}

struct direct_syscall_hook hook = {__NR_mkdir, new_mkdir, &orig_mkdir};

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
