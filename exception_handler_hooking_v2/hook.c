#include "hook.h"

void hook_el0_svc_common(struct ehh_hook *hook) {
    new_sys_call_table_ptr = hook->new_table;

    el0_svc_common_hook_ptr = el0_svc_common_hook;
    el0_svc_common_ptr = kallsyms_lookup_name_("el0_svc_common.constprop.0");
    pr_info("debug: orig el0_svc_common_ instructions %*ph\n", 64, el0_svc_common_ptr);

    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));
    pte_flip_write_protect(page_from_virt(el0_svc_common_ptr));
    flush_tlb_all();

    memcpy(el0_svc_common_hook_ptr, el0_svc_common_ptr, shellcode_size);
    pr_info("debug: copied el0_svc_common_ instructions %*ph\n", 64, el0_svc_common_hook_ptr);
    memcpy(el0_svc_common_ptr, shellcode, shellcode_size);
    pr_info("debug: copied shellcode instructions %*ph\n", 64, el0_svc_common_ptr);
}
