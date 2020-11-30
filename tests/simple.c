#include <stdio.h>

int main() {
    char buf[16];
    printf("%p\n", main);
    printf("%p\n", gets);
    gets(buf);
}
