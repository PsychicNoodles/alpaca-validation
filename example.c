#include <stdio.h>

int fake_func() {
        printf("fake\n");
        return 117; 
}

int main () {
        printf("Entered main at address: %p\n", main);
        fake_func();
        return 0; 
}

