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
#include "canary.h"

// 随机数生成器参数
unsigned global_canary;
static unsigned int seed = 0x12345678; // 初始种子值
static unsigned int gticks = 0;
// 设置随机数种子
void set_seed(unsigned int new_seed) {
    seed = new_seed;
}

// 生成随机数
unsigned int rand() {
    const unsigned int a = 1664525;      // 乘数
    const unsigned int c = 1013904223;  // 增量
    const unsigned int m = 0xFFFFFFFF;  // 模数 (2^32)
    seed = (a * seed + c) % m;          // 计算下一个随机数
    return seed;
}

// 初始化 Canary 值
void init_canary() {
    set_seed(gticks); // 使用时间戳作为种子
    global_canary = rand();    // 使用随机数初始化 Canary
}

// 检查 Canary 值
int check_canary(unsigned int local_canary) {
    if (local_canary != global_canary) {
        return -1;
    }
    gticks++;
    init_canary();
    return 0;
}