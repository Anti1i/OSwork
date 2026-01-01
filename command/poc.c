#include "stdio.h"
#include "string.h"
#include "canary.h"


void shellcode() {
    
    printf("you are pwned\n");
    int i = 10000;
    while (i--)
        ;
    exit(0);
    
}

void input() {
    unsigned int local_canary=global_canary;
    char buf[8] = "1234567";
    // *buf = 'A';
    // printf("%d", buf);
    char payload[] = {
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41,
        0x00, 0x10, 0x00, 0x00};  // printf("%s\n", buf);
    strcpy(buf, payload);
    printf("%s", buf);
    __asm__ __volatile__("xchg %bx, %bx");
    if(check_canary(local_canary)) 
    assertion_failure("Stack overflow detected!", __FILE__, __BASE_FILE__, __LINE__);
    return;
}



int main(int argc, char** argv) {
    __asm__ __volatile__("xchg %bx, %bx");
    //shellcode();
    input();
    return 0;
}
