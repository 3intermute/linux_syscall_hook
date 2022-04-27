// https://stackoverflow.com/questions/64838776/understanding-arm-relocation-example-str-x0-tmp-lo12zbi-paddr

typedef void (*fun1_t)(void);

void __attribute__((used)) fun1(void) {

}

void __attribute__((used)) *fun1_ptr;

void __attribute__((used)) fun2(void) {
    fun1_ptr = &fun1;
    ((fun1_t) fun1_ptr)();
}

int main(void) {
    return 0;
}
