#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#define PAGESIZE 4096

extern void *fun1_ptr;
extern void *fun1_hook_ptr;

extern void fun1_hook(void);

extern void shellcode(void);
extern uintptr_t shellcode_size;

void fun1(void) {
    printf("fun1 !\n");
}

int main(void) {
    fun1_ptr = fun1;
    fun1_hook_ptr = fun1_hook;

    void *p = (char *)(((int) fun1_hook_ptr + PAGESIZE - 1) & ~(PAGESIZE - 1));
    mprotect(p , PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
    p = (char *)(((int) fun1_ptr + PAGESIZE - 1) & ~(PAGESIZE - 1));
    mprotect(p , PAGESIZE, PROT_READ | PROT_WRITE | PROT_EXEC);

    memcpy(fun1_hook_ptr, fun1, shellcode_size);
    memcpy(fun1_ptr, shellcode, shellcode_size);

    return 0;
}
