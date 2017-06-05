#include <stdio.h>

void fake_func() {
        printf("fake\n");
}

int main () {
        printf("Entered main at address: %p\n", main);
        //   fake_func();
}

