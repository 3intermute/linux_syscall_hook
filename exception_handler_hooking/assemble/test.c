#include <stdio.h>
#include "global.h"

extern volatile int global;

int main(void) {
    global = 1;
    printf("%i\n", global);
}
