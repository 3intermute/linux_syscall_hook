#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#define PAGESIZE 4096

static volatile void  __attribute__((used)) *fun1_ptr;
static volatile void  __attribute__((used)) *fun1_hook_ptr;

void fun1(void) {
    printf("fun1 !\n");
}

static volatile void shellcode(void) {
    __asm("movz x12, #:abs_g2_nc:fun1_hook_ptr"); //  #:abs_g2 causes overflow ??
    __asm("movk x12, #:abs_g1_nc:fun1_hook_ptr");
    __asm("movk x12, #:abs_g0_nc:fun1_hook_ptr");
    __asm("ldr x12, [x12]");
    __asm("blr x12");

}
static void shellcode_end(void) {
}
static uintptr_t shellcode_size;


static volatile void fun1_hook() {
    __asm("nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t");

    __asm("mov x12, #0");

    printf("hooked !\n");

    __asm("adrp x12, fun1_ptr");
    __asm("ldr x12, [x12, fun1_ptr]");
    __asm("adrp x13, shellcode_size");
    __asm("ldr x13, [x13, shellcode_size]"); // add shellcode_size
    __asm("add x12, x12, x13");
    __asm("blr x12");
}

int main(void) {
    shellcode_size = (uintptr_t) shellcode_end - (uintptr_t) shellcode;
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
