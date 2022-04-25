#ifndef _EHH_H_
#define _EHH_H_

#include "resolve_kallsyms.h"
#include "set_page_flags.h"


typedef void (*el0_svc_common_t)(struct pt_regs *regs, int scno, int sc_nr, const syscall_fn_t syscall_table[]);
static el0_svc_common_t el0_svc_common_ = NULL;

void resolve_el0_svc_common(void) {
    el0_svc_common_ = kallsyms_lookup_name_("el0_svc_common");
}

void hook_el0_svc_common(struct el0_svc_common_hook *hook) {
    if (!el0_svc_common_) {
        resolve_el0_svc_common();
    }
    
}
