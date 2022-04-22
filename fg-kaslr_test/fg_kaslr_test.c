#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "hook.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_VERSION("1.0");

static int __init kaslr_test_mod_init(void) {
    if (!kallsyms_lookup_name_) {
        get_kallsyms_lookup_name();
    }
    pr_info("debug: kallsyms_lookup_name _text %p\n", kallsyms_lookup_name_("_text"));
    pr_info("debug: kallsyms_lookup_name *_text %p\n", *((unsigned char *) kallsyms_lookup_name_("_text")));
    pr_info("debug: kallsyms_lookup_name __start___ksymtab %p\n", kallsyms_lookup_name_("__start___ksymtab"));
    pr_info("debug: get_kprobe_addr_of_symbol _text %p\n", get_kprobe_addr_of_symbol("_text"));
    pr_info("debug: get_kprobe_addr_of_symbol sys_call_table %p\n", get_kprobe_addr_of_symbol("sys_call_table"));
    pr_info("debug: module loaded\n");
    return 0;
}

static void __exit kaslr_test_mod_exit(void) {
    pr_info("debug: module unloaded\n");
}


module_init(kaslr_test_mod_init);
module_exit(kaslr_test_mod_exit);
