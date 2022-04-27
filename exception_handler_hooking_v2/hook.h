#ifndef _HOOK_H_
#define _HOOK_H_

#include "resolve_kallsyms.h"
#include "set_page_flags.h"

// hook
extern void  *new_sys_call_table_ptr;
extern void  *el0_svc_common_ptr;
extern void  *el0_svc_common_hook_ptr;

extern void (*el0_svc_common_hook)(void);
extern void (*shellcode)(void);

extern uintptr_t shellcode_size;

struct ehh_hook {
    int number;

    void *new_table;
    void *orig_table;

    void *new_fn;
    void *orig_fn;
};

extern void hook_el0_svc_common(struct ehh_hook *hook);

#endif
