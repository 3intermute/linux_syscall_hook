gcc -fPIC -fpie -pie asm.S usermode.c -o test -flinker-output=pie
