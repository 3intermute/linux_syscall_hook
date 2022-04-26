#ifndef _EHH_H_
#define _EHH_H_

#include <asm/io.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"

// hooking process:
// copy (el0_svc_common entry, length x) -> hooked_el0_svc_common
// copy shellcode (jmp hooked_el0_svc_common, length x) -> el0_svc_common
// -----------------------------
// el0_svc_common entry
// 0 ---------------
// jmp hooked_el0_svc_common
// x ---------------
// el0_svc_common body
//
// >>>>>>>>>>>
//
// hooked_el0_svc_common entry
// 0 ---------------
// OVERWRITTEN el0_svc_common body
// nop
// nop
// nop
// ...
// x ---------------
// set sys_call_table to new addr
// jmp el0_svc_common entry + x

struct ehh_hook {
    int number;

    void *new_table;
    void *orig_table;

    void *new_fn;
    void *orig_fn;
};

static volatile void  __attribute__((used)) *new_sys_call_table;
static volatile void  __attribute__((used)) *el0_svc_common_;
static volatile void  __attribute__((used)) *el0_svc_common_hook_;
static void el0_svc_common_hook(void);


// x12 is not callee-saved
static void shellcode(void) {
    asm volatile("adrp x12, el0_svc_common_hook_");
    asm volatile("ldr x12, [x12, el0_svc_common_hook_]");
    asm volatile("blr x12");
}
static void shellcode_end(void) {
}
static uintptr_t shellcode_size;

static void el0_svc_common_hook(void) {
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

    asm volatile("adrp x3, new_sys_call_table");
    asm volatile("ldr x3, [x3, new_sys_call_table]");
    asm volatile("adrp x12, el0_svc_common_");
    asm volatile("ldr x12, [x12, el0_svc_common_]");
    asm volatile("blr x12");
}
void el0_svc_common_hook_end(void) {
}

void memcpy_(void *dest, const void *src, size_t count) {
    unsigned char *dest_ = dest;
    unsigned char *src_ = src;
    size_t i = 0;
    for (i; i < count; i++) {
        // // in case dest spans across several pages
        // pte_t *ptep = page_from_virt(dest_ + i);
        // if (!pte_write(*ptep)) {
        //     pte_flip_write_protect(ptep);
        // }
        *(dest_ + i) = *(src_ + i);
    }
}

void hook_el0_svc_common(struct ehh_hook *hook) {
    shellcode_size = (uintptr_t) shellcode_end - (uintptr_t) shellcode;

    // doesnt work due to some ghetto write protection that cant be disabled via the pagetable
    // el0_svc_common_hook_ = &el0_svc_common_hook;

    uintptr_t el0_svc_common_hook_size = (uintptr_t) el0_svc_common_hook_end - (uintptr_t) el0_svc_common_hook;
    el0_svc_common_hook_ = __vmalloc(el0_svc_common_hook_size, GFP_KERNEL, PAGE_KERNEL_EXEC);
    memcpy_(el0_svc_common_hook_, el0_svc_common_hook, el0_svc_common_hook_size);

    el0_svc_common_ = kallsyms_lookup_name_("el0_svc_common.constprop.0");
    new_sys_call_table = hook->new_table;

    // pte_flip_write_protect(page_from_virt(el0_svc_common_hook_));
    pte_flip_write_protect(page_from_virt(el0_svc_common_));

    memcpy_(el0_svc_common_hook_, el0_svc_common_, shellcode_size);
    memcpy_(el0_svc_common_, shellcode, shellcode_size);
}

#endif
