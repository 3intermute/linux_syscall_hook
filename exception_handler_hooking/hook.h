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
    // overwrite stack initialization in el0_svc_common_hook (6 instructions)
    asm volatile("nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t");
    asm volatile("adrp x12, el0_svc_common_hook_");
    asm volatile("ldr x12, [x12, el0_svc_common_hook_]");
    asm volatile("blr x12");
}
static void shellcode_end(void) {
}
static uintptr_t shellcode_size;

// 0000000000000048 <el0_svc_common_hook>:
//   48:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
//   4c:	910003fd 	mov	x29, sp
//   50:	d50320ff 	xpaclri
//   54:	aa1e03e0 	mov	x0, x30
//   58:	94000000 	bl	0 <_mcount>
//   5c:	d503201f 	nop
// >>>>>>>>>>>
//   d0:	d503201f 	nop
//   d4:	90000000 	adrp	x0, 0 <shellcode>
//   d8:	91000000 	add	x0, x0, #0x0
//   dc:	94000000 	bl	0 <printk>
//   e0:	90000003 	adrp	x3, 0 <shellcode>
//   e4:	f9405863 	ldr	x3, [x3, #176]
//   e8:	9000000c 	adrp	x12, 0 <shellcode>
//   ec:	f940558c 	ldr	x12, [x12, #168]
//   f0:	d63f0180 	blr	x12
//   f4:	a8c17bfd 	ldp	x29, x30, [sp], #16
//   f8:	d65f03c0 	ret
//   fc:	d503201f 	nop


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

void hook_el0_svc_common(struct ehh_hook *hook) {
    shellcode_size = (uintptr_t) shellcode_end - (uintptr_t) shellcode;

    // doesnt work due to some ghetto write protection that cant be disabled via the pagetable
    // el0_svc_common_hook_ = &el0_svc_common_hook;

    // unnecessary, fix write protect so you dont have to do this  
    uintptr_t el0_svc_common_hook_size = (uintptr_t) el0_svc_common_hook_end - (uintptr_t) el0_svc_common_hook;
    el0_svc_common_hook_ = __vmalloc(el0_svc_common_hook_size, GFP_KERNEL, PAGE_KERNEL_EXEC);
    memcpy(el0_svc_common_hook_, el0_svc_common_hook, el0_svc_common_hook_size);

    el0_svc_common_ = kallsyms_lookup_name_("el0_svc_common.constprop.0");
    new_sys_call_table = hook->new_table;

    // pte_flip_write_protect(page_from_virt(el0_svc_common_hook_));
    pte_flip_write_protect(page_from_virt(el0_svc_common_));

    memcpy(el0_svc_common_hook_, el0_svc_common_, shellcode_size);
    memcpy(el0_svc_common_, shellcode, shellcode_size);
}

#endif
