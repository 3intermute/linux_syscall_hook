.section .data

.global new_sys_call_table_ptr
.balign 8
.byte 1
new_sys_call_table_ptr: .dword 0x0
.global el0_svc_common_ptr
.balign 8
.byte 1
el0_svc_common_ptr: .dword 0x0
.global el0_svc_common_hook_ptr
.balign 8
.byte 1
el0_svc_common_hook_ptr: .dword 0x0

.section .text
.global shellcode
shellcode:
    movz x12, #:abs_g3:el0_svc_common_hook_ptr
    movk x12, #:abs_g2_nc:el0_svc_common_hook_ptr
    movk x12, #:abs_g1_nc:el0_svc_common_hook_ptr
    movk x12, #:abs_g0_nc:el0_svc_common_hook_ptr
    ldr x12, [x12]
    blr x12
.global shellcode_size
.set shellcode_size, . - shellcode

.global el0_svc_common_hook
el0_svc_common_hook:
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
    ldr x12, =el0_svc_common_ptr
    ldr x13, =shellcode_size
    ldr x12, [x12]
    ldr x13, [x13]
    add x12, x12, x13
    blr x12
