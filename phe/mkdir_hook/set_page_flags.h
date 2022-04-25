#ifndef _SET_PAGE_FLAGS_H_
#define _SET_PAGE_FLAGS_H_

#include <asm/pgtable.h>
#include "resolve_kallsyms.h"

pte_t *page_from_virt(uintptr_t addr) {
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    struct mm_struct *init_mm_ptr = kallsyms_lookup_name_("init_mm");
    pgd = pgd_offset(init_mm_ptr, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return NULL;
    }

    pud = pud_offset(pgd, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        return NULL;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        return NULL;
    }

    ptep = pte_offset_map(pmd, addr);
    if (!ptep) {
        return NULL;
    }

    return ptep;
}

void pte_flip_write_protect(pte_t *ptep) {
    if (!pte_write(*ptep)) {
        *ptep = pte_mkwrite(pte_mkdirty(*ptep));
        *ptep = clear_pte_bit(*ptep, __pgprot((_AT(pteval_t, 1) << 7)));
        return;
    }
    pte_wrprotect(*ptep);
}

#endif
