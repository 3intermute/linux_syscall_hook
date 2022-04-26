#ifndef _SET_PAGE_FLAGS_H_
#define _SET_PAGE_FLAGS_H_

#include <asm/pgtable.h>
#include "resolve_kallsyms.h"

static struct mm_struct *init_mm_ptr = NULL;

pte_t *page_from_virt(uintptr_t addr) {
    pr_info("debug: page_from_virt called with addr %pK\n", addr);
    if (!init_mm_ptr) {
        init_mm_ptr = kallsyms_lookup_name_("init_mm");
    }

    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(init_mm_ptr, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        pr_info("debug: page_from_virt of addr %pK, pgd_offset failed", addr);
        return NULL;
    }

    // https://stackoverflow.com/questions/58743052/getting-error-when-compiling-kernel-for-page-table-walk
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return NULL;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        pr_info("debug: page_from_virt of addr %pK, pud_offset failed", addr);
        return NULL;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        pr_info("debug: page_from_virt of addr %pK, pmd_offset failed", addr);
        return NULL;
    }

    ptep = pte_offset_kernel(pmd, addr);
    if (!ptep) {
        pr_info("debug: page_from_virt of addr %pK, pte_offset_kernel failed", addr);
        return NULL;
    }

    pr_info("debug: page_from_virt virt (%pK), ptep @ %pK", addr, ptep);

    return ptep;
}

void pte_flip_write_protect(pte_t *ptep) {
    // pr_info("debug: pte_flip_write_protect called ptep @ %pK", ptep);

    if (!pte_write(*ptep)) {
        *ptep = pte_mkwrite(pte_mkdirty(*ptep));
        *ptep = clear_pte_bit(*ptep, __pgprot((_AT(pteval_t, 1) << 7)));
        pr_info("debug: pte_flip_write_protect flipped ptep @ %pK, pte_write(%i)\n", ptep, pte_write(*ptep));
        return;
    }
    *ptep = pte_wrprotect(*ptep);
    *ptep = set_pte_bit(*ptep, __pgprot((_AT(pteval_t, 1) << 7)));
    pr_info("debug: pte_flip_write_protect ptep @ %pK, pte_write(%i)\n", ptep, pte_write(*ptep));
}

#endif
