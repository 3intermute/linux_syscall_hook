.section .data

.global fun1_ptr
.balign 8
.byte 1
fun1_ptr: .dword 0x0
.global fun1_hook_ptr
.balign 8
.byte 1
fun1_hook_ptr: .dword fun1_hook

.section .text
.global shellcode
shellcode:
    movz x12, #:abs_g3:fun1_hook_ptr
    movk x12, #:abs_g2_nc:fun1_hook_ptr
    movk x12, #:abs_g1_nc:fun1_hook_ptr
    movk x12, #:abs_g0_nc:fun1_hook_ptr
    ldr x12, [x12]
    blr x12
.global shellcode_size
.set shellcode_size, . - shellcode

.global fun1_hook;
fun1_hook:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    mov x12, #0
    ldr x12, =fun1_ptr
    ldr x13, =shellcode_size
    ldr x12, [x12]
    ldr x13, [x13]
    add x12, x12, x13
    blr x12
