#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <asm/unistd.h>
#include <asm/memory.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_VERSION("1.0");

typedef uintptr_t (*kallsyms_lookup_name_t)(const char *symbol_name);
kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;

uintptr_t get_kprobe_addr_of_symbol(const char *sym_name) {
    static struct kprobe kp;
    kp.symbol_name = sym_name;
    if (register_kprobe(&kp) < 0) {
        pr_info("debug: get_kprobe_addr_of_symbol of %s failed\n", sym_name);
        return -ENOENT;
    }

    uintptr_t tmp = kp.addr;
    unregister_kprobe(&kp);
    pr_info("debug: get_kprobe_addr_of_symbol success, %s @ %p", sym_name, tmp);
    return tmp;
}

static int __init kaslr_test_mod_init(void) {
    kallsyms_lookup_name_ = (kallsyms_lookup_name_t) get_kprobe_addr_of_symbol("kallsyms_lookup_name");
    // https://patchwork.kernel.org/project/linux-arm-kernel/patch/1451301654-32019-2-git-send-email-ard.biesheuvel@linaro.org/
    // https://stackoverflow.com/questions/68537274/what-is-text-offset-in-the-aarch64-kernel-image-and-how-do-i-know-where-the-kern
    // https://www.spinics.net/lists/arm-kernel/msg832306.html
    // https://www.kernel.org/doc/Documentation/printk-formats.txt

    // __start___ksymtab
    // NEED TO PRINT ADDRESSES WITH %pK LOL

    // kallsyms_lookup_name
    // pr_info("debug: virt_to_phys virt (%pK) -> phys (%px)\n", 0xffffc6e076e45090, virt_to_phys(0xffffc6e076e45090));
    // pr_info("debug: phys_to_virt phys (%px) -> virt (%pK)\n", 0x1156f0000, phys_to_virt(0x1156f0000));
    pr_info("debug: kallsyms_lookup_name __arm64_sys_kill @ %pK\n", kallsyms_lookup_name_("__arm64_sys_kill"));

    // get_kprobe_addr_of_symbol("start_kernel");
    // get_kprobe_addr_of_symbol("kallsyms_lookup_name");
    //
    // pr_info("debug: kallsyms_lookup_name _text @ %p\n", kallsyms_lookup_name_("_text"));
    // pr_info("debug: kallsyms_lookup_name _head @ %p\n", kallsyms_lookup_name_("_head"));
    // pr_info("debug: kallsyms_lookup_name __start___ksymtab @ %p\n", kallsyms_lookup_name_("__start___ksymtab"));
    // pr_info("debug: kallsyms_lookup_name kallsyms_lookup_name @ %p\n", kallsyms_lookup_name_("kallsyms_lookup_name"));
    //
    // // get_kprobe_addr_of_symbol("_head");
    // // get_kprobe_addr_of_symbol("_text");
    //
    // pr_info("debug: kallsyms_lookup_name addr %p\n", &kallsyms_lookup_name_);
    // // pr_info("debug: _text symbol %p\n", _text);
    //
    // // https://github.com/torvalds/linux/blob/df0cc57e/scripts/kallsyms.c#L96
    //
    // // run 1: [  135.748285] debug: printk addr 000000002c67f20f
    // // run 2: [   36.300241] debug: printk addr 0000000062b32bb6
    // // run 2: ffffd59881995934 printk
    // // run 2: ffffd59880c10000 _text
    // pr_info("debug: printk addr %p\n", &printk);
    // pr_info("debug: printk addr %p\n", kallsyms_lookup_name_("printk"));

    pr_info("debug: module loaded\n");
    return 0;
}

static void __exit kaslr_test_mod_exit(void) {
    pr_info("debug: module unloaded\n");
}


module_init(kaslr_test_mod_init);
module_exit(kaslr_test_mod_exit);
