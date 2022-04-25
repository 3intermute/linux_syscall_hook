                            .                          ..         .
                           @88>                  < .z@8"`        @88>
   .u    .                 %8P      u.    u.      !@88E          %8P      u.    u.
 .d88B :@8c        u        .     x@88k u@88c.    '888E   u       .     x@88k u@88c.      uL
="8888f8888r    us888u.   .@88u  ^"8888""8888"     888E u@8NL   .@88u  ^"8888""8888"  .ue888Nc..
  4888>'88"  .@88 "8888" ''888E`   8888  888R      888E`"88*"  ''888E`   8888  888R  d88E`"888E`
  4888> '    9888  9888    888E    8888  888R      888E .dN.     888E    8888  888R  888E  888E
  4888>      9888  9888    888E    8888  888R      888E~8888     888E    8888  888R  888E  888E
 .d888L .+   9888  9888    888E    8888  888R      888E '888&    888E    8888  888R  888E  888E
 ^"8888*"    9888  9888    888&   "*88*" 8888"     888E  9888.   888&   "*88*" 8888" 888& .888E
    "Y"      "888*""888"   R888"    ""   'Y"     '"888*" 4888"   R888"    ""   'Y"   *888" 888&
              ^Y"   ^Y'     ""                      ""    ""      ""                  `"   "888E
                                                                                     .dWi   `88E
                                                                                     4888~  J8%
                                                                                      ^"===*"`
"rain wont drop until i say so"
---------------------------------------------
a collection of tests and random bits that will eventually make up a rootkit


/ARM_write_protect_disable - flip write protection bit of vaddr through pagetable
/direct_hook_test - system call hooking via directly over-writing sys_call_table
    - some useful header files here
        -> resolve_kallsyms.h: does exactly as youd expect, uses kprobes to find kallsyms_lookup_name and then uses that to resolve syms
        -> set_page_flags.h: given a vaddr, set its corresponding PTEs flags
        -> direct_syscall_hook.h: ftrace-like wrapper for direct hooking of sys_call_table
/fg-kaslr_test - fg-kaslr bypass, this isnt actually anything important i was just using pr_info wrong
/ftrace_hook_epic_fail - FTRACE_OPS_FL_SAVE_REGS is not supported on arm64 and i spent 2 days debugging this, however this will work on x86
/phe - partial homomorphic encryption of LKM, unfinished

todo:
- dropper
- find fg-kaslr offsets via bootkit
- overwrite ftrace records
- integrate functionality of my other projects into this one
- finish rk scanner hiding via PHE
- process hiding from usermode
- network connection hiding from usermode
- redirect entire sys_call_table
- use OP-TEE to hide functions




new exception hooking process:
copy (el0_svc_common entry, length x) -> hooked_el0_svc_common
copy shellcode (jmp hooked_el0_svc_common, length x) -> el0_svc_common

el0_svc_common entry
0 ---------------
jmp hooked_el0_svc_common
x ---------------
el0_svc_common body

>>>>>>>>>>>

hooked_el0_svc_common entry
0 ---------------
OVERWRITTEN el0_svc_common body
x ---------------
set sys_call_table to new addr
jmp el0_svc_common entry + x
