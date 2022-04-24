#include <linux/kprobes.h>

uintptr_t kprobe_get_func_addr(const char *func_name) {
    static struct kprobe kp;
    kp.symbol_name = func_name;
    if (register_kprobe(&kp) < 0) {
        pr_info("debug: kprobe_get_func_addr of %s failed\n", func_name);
        return -ENOENT;
    }

    uintptr_t tmp = kp.addr;
    unregister_kprobe(&kp);
    return tmp;
}
