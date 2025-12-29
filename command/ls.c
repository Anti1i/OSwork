#include "stdio.h"
#include "string.h"
#include "fs.h"
#include "const.h"

int main(int args, char* argv[]) {
    char result[500];
    memset(result,0,500);
    search_dir("/", result);
    // int a = -1;
    // a = strlen(result);
    printf("YSSX__LS:%s\n",result);
    //printf("%c\n",0);
    return 0;
}
