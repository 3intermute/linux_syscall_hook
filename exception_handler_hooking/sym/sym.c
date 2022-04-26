#include <stdint.h>

static volatile void  __attribute__((used)) *sym1;
static volatile uintptr_t shellcode_size;

int main(void) {
    void *sym2 = (void *)((uintptr_t) sym1 + shellcode_size);
}
