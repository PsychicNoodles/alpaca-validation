
#include <stdio.h>
int a; 
int writing_func() {
        printf("in the writing func \n");
        a = 777;
        return 66;
}


int main () {

        a = 0;
        
        //char* str = "hey"; 
        if (writing_func() == 66) printf("yeey\n");

        //printf("%s\n", s.c_str());

        printf("a value after writing func call: %d\n", a);
        return 0; 


}
