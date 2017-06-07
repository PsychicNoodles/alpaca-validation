#include <stdio.h>
#include <stdbool.h>

bool prime(int i) {
        int n;
        for(n = 2; n < i; n++) {
                if(i % n == 0) return false;
        }

        return true;
}

int main() {
        int i;
        for(i = 2; i < 1000; i++) {
                if(prime(i)) printf("%d is prime\n", i);
        }
        return 0;
}
