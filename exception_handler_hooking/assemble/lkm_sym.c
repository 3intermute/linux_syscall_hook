#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm-generic/unistd.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_VERSION("1.0");

//
// typedef void (*fptr_t)(void);
// fptr_t fptr;
//
// static volatile int global;
// EXPORT_SYMBOL(global);
//
// void *load_global(void) {
//     return fptr;
// }

static int __init hook_test_mod_init(void) {
    // global = 1;
    // global++;
    // pr_info("debug: global %i\n", global);
    asm volatile("mov x12, #1");
    return 0;
}

static void __exit hook_test_mod_exit(void) {

}


module_init(hook_test_mod_init);
module_exit(hook_test_mod_exit);
