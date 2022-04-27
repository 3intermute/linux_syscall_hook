#include <stdio.h>
#include <stdint.h>

// https://developer.arm.com/documentation/ddi0596/2021-12/Base-Instructions/MOVK--Move-wide-with-keep-?lang=en
// movk encoding:
// 0 | 1 1 1 0 0 1 0 1 | 0 0 | 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 | 0 0 0 0 0
//------------------------------------------------------------------------
// sf|opc              |hw   |imm16                            |rd

uint32_t assemble_movk(uint32_t imm16, uint32_t hw, uint32_t rd) {
    return 0xf2800000 | (imm16 << 5) | (hw << 21) | rd;
}

int main(void) {
    uint32_t inst = assemble_movk(0b101001, 0b0, 0b11101); // movk x29, 0x29
    printf("%x\n", inst);
    return 0;
}
