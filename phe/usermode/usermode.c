#include <sys/stat.h>
#include <stdio.h>

#define S_IOCTL 0xfffffff

int main(int argc, char *argv[]) {
    int err = mkdirat(-1, argv[1], 0);
    printf("err: %lx\n", err);
    return 0;
}
