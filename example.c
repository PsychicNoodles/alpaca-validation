#include <stdio.h>

typedef struct {
        int a;
        int b;
        int c;
        int d;
        int e;
        int f;
        int g;
} test_t;

typedef struct {
        int a;
        int b;
} test2_t;

test_t fake_func() {
        printf("fake\n");
        test_t t;
        printf("t is at: %p\n", &t);
        t.a = 1;
        t.b = 2;
        t.c = 3;
        return t;
}

test2_t fake2_func() {
        printf("fake2\n");
        test2_t t;
        t.a = 4;
        t.b = 5;
        return t;
}

int int_func() {
        printf("int\n");
        return 42;
}

int main () {
        printf("Entered main at address %p with fake_func at %p\n", main, (void*) fake_func);
        test_t t = fake_func();
        printf("returned t is at: %p\n", &t);
        printf("res: %d, %d, %d\n", t.a, t.b, t.c);
        /*test2_t t2 = fake2_func();
        printf("res2: %d, %d\n", t2.a, t2.b);
        int i = int_func();
        printf("int res: %d\n", i);*/
        return 0; 
}

