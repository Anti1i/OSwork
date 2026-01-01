#include "stdio.h"

int main(int args, char* argv[]) {
    if (args != 2) {
        if(args == 3)
        {
            if(strcmp(argv[1], "-K") == 0)
            {
                char filename[500];
                strcpy(filename, argv[2]);
                search_dir("K", filename);
                printf("%s\n",filename);
                //printf("%s");
                return 0;
            } 
        }
        printf("please use the rm in right format\n");
    } else {
        if (unlink(argv[1]) == -1) {
            printf("rm file failed\n");
            return -1;
        }
        printf("%s is successfully removed\n", argv[1]);
    }
    return 0;
}