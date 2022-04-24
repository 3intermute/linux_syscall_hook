#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_DESCRIPTION("syscall table hook on arm64, no ftrace");
MODULE_VERSION("1.0");

static int __init hook_test_mod_init(void) {
    pr_info("debug: module loaded\n");

    uintptr_t sys_call_table_addr = kallsyms_lookup_name_("sys_call_table");

    pte_t *sys_call_table_ptep = page_from_virt(sys_call_table_addr);
    if (!sys_call_table_ptep) {
        pr_info("debug: page_from_virt of %pK failed\n", sys_call_table_addr);
        return -ENOENT;
    }
    pr_info("debug: page_from_virt of %pK success, pte @ %pK\n", sys_call_table_addr, sys_call_table_ptep);

    pr_info("debug: ptep @ %pK, pte_write flag (%i)\n", sys_call_table_ptep, pte_write(*sys_call_table_ptep));
    pr_info("debug: flipping write protect flag...\n");
    pte_flip_write_protect(sys_call_table_ptep);
    pr_info("debug: ptep @ %pK, pte_write flag (%i)\n", sys_call_table_ptep, pte_write(*sys_call_table_ptep));
    return 0;
}

static void __exit hook_test_mod_exit(void) {
    pr_info("debug: module unloaded\n");
}


module_init(hook_test_mod_init);
module_exit(hook_test_mod_exit);
