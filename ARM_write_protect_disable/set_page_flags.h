// https://www.kernel.org/doc/gorman/html/understand/understand006.html
#include <asm/pgtable.h>

pte_t *page_from_virt(uintptr_t addr) {
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *ptep;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        return NULL;
    }

    pmd = pmd_offset(pgd, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        return NULL;
    }

    ptep = pte_offset(pmd, addr);
    if (!ptep) {
        return NULL;
    }

    return = ptep;
}

void pte_flip_write_protect(pte_t *ptep) {
    if (pte_write(*ptep)) {
        pte_wrprotect(*ptep);
        return;
    }
    pte_mkwrite(*ptep);
}
