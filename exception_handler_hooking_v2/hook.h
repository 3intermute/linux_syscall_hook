#ifndef _HOOK_H_
#define _HOOK_H_

#define SHELLCODE_INS_COUNT 6

#include <linux/vmalloc.h>
#include "resolve_kallsyms.h"
#include "set_page_flags.h"

static void  *new_sys_call_table_ptr;
static void  *el0_svc_common_ptr;
static void  *el0_svc_common_hook_ptr;

struct ehh_hook {
    int number;

    void *new_table;
    void *orig_table;

    void *new_fn;
    void *orig_fn;
};

extern void el0_svc_common_hook(void);
extern uint32_t *generate_shellcode(uintptr_t el0_svc_common_hook_addr);
extern void hook_el0_svc_common(struct ehh_hook *hook);

#endif
