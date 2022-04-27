#ifndef _COPY_SYS_CALL_TABLE_H_
#define _COPY_SYS_CALL_TABLE_H_

#include <linux/vmalloc.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include "set_page_flags.h"

void *copy_sys_call_table(void *table) {
    void *new_sys_call_table = vmalloc(sizeof(syscall_fn_t) * __NR_syscalls);
    memcpy(new_sys_call_table, table, sizeof(syscall_fn_t) * __NR_syscalls);
    return new_sys_call_table;
}

void free_new_sys_call_table(void *table) {
    vfree(table);
}

#endif
