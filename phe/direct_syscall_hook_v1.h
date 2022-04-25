#ifndef _RESOLV_DIRECT_HOOK_H_
#define _RESOLV_DIRECT_HOOK_H_

#include <asm/unistd.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"

struct direct_syscall_hook {
    int number;
    void *new;
    void *orig;
};

static void **sys_call_table_addr = NULL;

static int resolve_syscall_table(void) {
    sys_call_table_addr = kallsyms_lookup_name_("sys_call_table");

    pte_t *sys_call_table_ptep = page_from_virt(sys_call_table_addr);
    if (!sys_call_table_ptep) {
        pr_info("debug: page_from_virt of %pK failed\n", sys_call_table_addr);
        return -ENOENT;
    }
    pr_info("debug: page_from_virt of %pK success, pte @ %pK\n", sys_call_table_addr, sys_call_table_ptep);

    // TODO: unset write bit after hook is finished
    pr_info("debug: ptep @ %pK, pte_write flag (%i)\n", sys_call_table_ptep, pte_write(*sys_call_table_ptep));
    pr_info("debug: flipping write protect flag...\n");
    pte_flip_write_protect(sys_call_table_ptep);
    pr_info("debug: ptep @ %pK, pte_write flag (%i)\n", sys_call_table_ptep, pte_write(*sys_call_table_ptep));
    return 0;
}

void hook_syscall(struct direct_syscall_hook *hook) {
    if (!sys_call_table_addr) {
        resolve_syscall_table();
    }
    hook->orig = sys_call_table_addr[hook->number];
    pr_info("DEBUG: hook->orig (%pK)\n", hook->orig);
    // pte_flip_write_protect(page_from_virt(&sys_call_table_addr[hook->number]));
    sys_call_table_addr[hook->number] = hook->new;
    pr_info("debug: hook_syscall of #%i, orig @ %pK, new @%pK, success\n", hook->number, hook->orig, hook->new);
}

void unhook_syscall(struct direct_syscall_hook *hook) {
    if (!sys_call_table_addr) {
        resolve_syscall_table();
    }
    sys_call_table_addr[hook->number] = hook->orig;
    pr_info("debug: unhook_syscall of #%i, orig restored @ %pK, new @%pK, success\n", hook->number, hook->orig, hook->new);
}

#endif
