#include "type.h"
#include "stdio.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "fs.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "global.h"
#include "proto.h"

PUBLIC char* search_dir(char* path,char* filename) {
    MESSAGE msg;
    msg.type = SEARCH;
    // msg.pBUF[0] = 'y';
    // msg.pBUF[1] = 'j'; 
    // msg.pBUF[2] = 'q';
    memcpy(msg.pBUF, path, strlen(path));
    // printl("msg.pBug address is %d\n", msg.pBUF);
    // printl("BUF1 : %s\n", msg.pBUF);
    send_recv(BOTH, TASK_FS, &msg);
    // return msg.BUF;
    // printl("BUF2 : %s\n", msg.pBUF);
    
    memcpy(filename, msg.pBUF, strlen(msg.pBUF));
    //filename[strlen(filename)] = '\0'; 
    return filename;
}
