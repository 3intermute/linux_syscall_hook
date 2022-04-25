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

void **sys_call_table_addr = NULL;

static int resolve_syscall_table(void) {
    sys_call_table_addr = kallsyms_lookup_name_("sys_call_table");
    return 0;
}

void hook_syscall(struct direct_syscall_hook *hook) {
    if (!sys_call_table_addr) {
        resolve_syscall_table();
    }
    *((uintptr_t *) hook->orig) = sys_call_table_addr[hook->number];

    pte_t *ptep = page_from_virt(&sys_call_table_addr[hook->number]);
    pr_info("debug: ptep @ %pK, pte_write flag (%i)\n", &sys_call_table_addr[hook->number], pte_write(*ptep));

    pr_info("debug: flipping write protect flag...\n");
    pte_flip_write_protect(page_from_virt(&sys_call_table_addr[hook->number]));

    ptep = page_from_virt(&sys_call_table_addr[hook->number]);
    pr_info("debug: ptep @ %pK, pte_write flag (%i)\n", &sys_call_table_addr[hook->number], pte_write(*ptep));

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
