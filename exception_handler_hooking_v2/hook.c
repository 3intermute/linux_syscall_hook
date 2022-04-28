#include "hook.h"
#include "assembler.h"

void __attribute__((naked))  el0_svc_common_hook(void) {
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

      asm volatile("mov x12, #0");
      asm volatile("ldr x12, =el0_svc_common_ptr");
      asm volatile("ldr x12, [x12]");
      asm volatile("add x12, x12, #0x18"); // shellcode_size: 24 -> 0x18
      asm volatile("blr x12");
}

uint32_t *generate_shellcode(uintptr_t el0_svc_common_hook_addr) {
    uint32_t *code = vmalloc(SHELLCODE_INS_COUNT * INS_SIZE);
    code = (uint32_t [SHELLCODE_INS_COUNT]) {
        0x0,
        0x0,
        0x0,
        0x0,
        0x8c0140f9, // ldr x12, [x12]
        0x80013fd6 // blr x12
    };
    assemble_absolute_load(0b1100, el0_svc_common_hook_addr, code);
    return code;
}

void hook_el0_svc_common(struct ehh_hook *hook) {
    new_sys_call_table_ptr = hook->new_table;
    el0_svc_common_hook_ptr = &el0_svc_common_hook;
    el0_svc_common_ptr = kallsyms_lookup_name_("el0_svc_common.constprop.0");
    pr_info("debug: orig el0_svc_common_ instructions %*ph\n", 64, el0_svc_common_ptr);

    pte_flip_write_protect(page_from_virt(el0_svc_common_hook_ptr));
    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));
    flush_tlb_all();

    void *shellcode = generate_shellcode(el0_svc_common_hook_ptr);

    memcpy(el0_svc_common_hook_ptr, el0_svc_common_ptr, SHELLCODE_INS_COUNT * INS_SIZE);
    pr_info("debug: copied el0_svc_common_ instructions %*ph\n", 64, el0_svc_common_hook_ptr);
    memcpy(el0_svc_common_ptr, shellcode, SHELLCODE_INS_COUNT * INS_SIZE);
    pr_info("debug: copied shellcode instructions %*ph\n", 64, el0_svc_common_ptr);
}
