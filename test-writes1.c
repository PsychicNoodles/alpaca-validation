
#include <stdio.h>
int a; 
int writing_func() {
//        printf("in the writing func \n");
        a = 777;
        int b = 0;
        b = 8;
        int c = 1;
        c = 10;
        return b;
}


int main () {

        a = 0;
        
        //char* str = "hey"; 
        writing_func();

        //printf("%s\n", s.c_str());

        printf("a address and value after writing func call: %d, %p\n", a, &a);
        return 0; 


}
