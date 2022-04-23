#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <asm/unistd.h>


typedef uintptr_t (*kallsyms_lookup_name_t)(const char *symbol_name);
kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;

uintptr_t get_kprobe_addr_of_symbol(const char *sym_name) {
    static struct kprobe kp = {.symbol_name = sym_name};
    if (register_kprobe(&kp) < 0) {
        pr_info("debug: get_kprobe_addr_of_symbol failed\n");
        return -ENOENT;
    }

    uintptr_t tmp = kp.addr;
    unregister_kprobe(&kp);
    pr_info("debug: get_kprobe_addr_of_symbol success, %s @ %p", symbol_name, tmp);
    return tmp;
}

void get_kallsyms_lookup_name(void) {
    kallsyms_lookup_name_ = (kallsyms_lookup_name_t) get_kprobe_addr_of_symbol("kallsyms_lookup_name");
}
