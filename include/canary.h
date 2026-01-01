

#ifndef _ORANGES_CANARY_H_
#define _ORANGES_CANARY_H_
extern unsigned int global_canary;
/*canary.c*/
PUBLIC void init_seed();
PUBLIC int check_canary(unsigned int local_canary) ;
extern int ticks;
#endif