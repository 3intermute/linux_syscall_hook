#ifndef _EHH_H_
#define _EHH_H_

#include "resolve_kallsyms.h"
#include "set_page_flags.h"

struct ehh_hook {
    int number;

    void *new_table;
    void *orig_table;

    void *new_fn;
    void *orig_fn;
};

// new_sys_call_table symbol will not be exported without this
static volatile void fuck_gcc(void) {
}
static volatile void *new_sys_call_table;
static volatile void *el0_svc_common_;
static volatile void *el0_svc_common_hook;
static void el0_svc_common_hook_(void);


// x12 is not callee-saved
static void shellcode(void) {
    asm volatile("adrp x12, el0_svc_common_hook");
    asm volatile("ldr x12, [x12, el0_svc_common_hook]");
    asm volatile("blr x12");
}
static void shellcode_end(void) {
}
static uintptr_t shellcode_size;

static void el0_svc_common_hook_(void) {
    // todo: check syscall # and redirect to table based on value
    // pad with nops just to be sure nothing is being overwritten
    asm volatile("nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t");

    pr_info("debug: syscall hooked please god if i see this message ill be so happy : DDDDD\n");

    // asm volatile("adrp x3, new_sys_call_table");
    // asm volatile("ldr x3, [x3, new_sys_call_table]");
    asm volatile("adrp x12, el0_svc_common_");
    asm volatile("ldr x12, [x12, el0_svc_common_]");
    asm volatile("blr x12");
}

void hook_el0_svc_common(struct ehh_hook *hook) {
    el0_svc_common_hook = el0_svc_common_hook_;
    shellcode_size = (uintptr_t) shellcode_end - (uintptr_t) shellcode;

    el0_svc_common_ = kallsyms_lookup_name_("el0_svc_common.constprop.0");
    new_sys_call_table = fuck_gcc;
    new_sys_call_table = hook->new_table;

    pte_flip_write_protect(page_from_virt(el0_svc_common_));
    pte_flip_write_protect(page_from_virt(el0_svc_common_hook));
    memcpy(el0_svc_common_hook, el0_svc_common_, shellcode_size);
    memcpy(el0_svc_common_, shellcode, shellcode_size);
}

#endif
