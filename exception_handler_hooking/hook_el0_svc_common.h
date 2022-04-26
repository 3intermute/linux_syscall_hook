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

static void *new_sys_call_table = NULL;
static void *el0_svc_common_ = NULL;

static void el0_svc_common_hook(void);

static void shellcode(void) {
    __asm ("B %[addr]"
    :
    : [addr] "m" (el0_svc_common_hook)
    : "memory");
}
static void shellcode_end(void) {
}

static void el0_svc_common_hook(void) {
    // todo: check syscall # and redirect to table based on value
    // pad with nops just to be sure nothing is being overwritten
    __asm("nop\n\t"
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

    pr_info("debug: syscall hooked !\n");
    __asm ("MOV r3, %[addr]"
    :
    : [addr] "m" (new_sys_call_table)
    : "memory");
    __asm ("B %[addr]"
    :
    : [addr] "m" ((void *)((uintptr_t) el0_svc_common_ + ((uintptr_t) shellcode_end - (uintptr_t) shellcode)))
    : "memory");
}

void hook_el0_svc_common(struct ehh_hook *hook) {
    el0_svc_common_ = kallsyms_lookup_name_("el0_svc_common.constprop.0");
    new_sys_call_table = hook->new_table;

    uintptr_t shellcode_size = (uintptr_t) shellcode_end - (uintptr_t) shellcode;
    pte_flip_write_protect(page_from_virt(el0_svc_common_));
    pte_flip_write_protect(page_from_virt(el0_svc_common_hook));
    memcpy(el0_svc_common_hook, el0_svc_common_, shellcode_size);
    memcpy(el0_svc_common_, shellcode, shellcode_size);
}

#endif
