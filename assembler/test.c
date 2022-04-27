#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <byteswap.h>

#define ABS_LOAD_INS_COUNT 4

uint32_t assemble_movk(uint32_t imm16, uint32_t hw, uint32_t rd) {
    return 0xf2800000 | (imm16 << 5) | (hw << 21) | rd;
}

void assemble_absolute_load(uint32_t rd, uintptr_t addr, uint32_t *arr) {
    arr[0] = __bswap_32(assemble_movk(addr & 0xffff, 0b0, rd));
    arr[1] = __bswap_32(assemble_movk((addr & 0xffff0000) >> 16, 0b1, rd));
    arr[2] = __bswap_32(assemble_movk((addr & 0xffff00000000) >> 32, 0b10, rd));
    arr[3] = __bswap_32(assemble_movk((addr & 0xffff000000000000) >> 48, 0b11, rd));
}

int main(void) {
    uint32_t arr[ABS_LOAD_INS_COUNT];
    // printf("%x\n", assemble_movk(0xffffd8589fcc0000 & 0xffff, 0b1, 0b0));
    // assemble_absolute_load(0b0, 0xffffd8589fcc0000, &arr);
    return 0;
}
