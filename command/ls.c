#include "stdio.h"
#include "string.h"
#include "fs.h"
#include "const.h"

// int main(int args, char* argv[]) {
//     char result[500];
//     memset(result,0,500);
//     search_dir("/", result);
//     // int a = -1;
//     // a = strlen(result);
//     printf("YSSX__LS:%s\n",result);
//     //printf("%c\n",0);
//     return 0;
// }
int main(int args, char* argv[]) {
    int is_f = 0;
    for (int i = 1; i < args; ++i) {
        if (strcmp(argv[i], "-f") == 0) {
            is_f = 1;
            break;
        }
    }
    if (is_f) {
        char result[500];
        memset(result,0,500);
        search_dir("P", result);
        // int a = -1;
        // a = strlen(result);
        printf("YSSX__LS:%s\n",result);
        //printf("%c\n",0);
    } else {
        char result[500];
        memset(result,0,500);
        search_dir("/", result);
        // int a = -1;
        // a = strlen(result);
        printf("YSSX__LS:%s\n",result);
        //printf("%c\n",0);
    }
    return 0;
}

