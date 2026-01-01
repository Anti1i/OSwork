#include "stdio.h"
#include "string.h"
#include "crypto.h"

#define BUFFER_SIZE 4096
#define MAX_LINES 1000

// 辅助函数：统计字符串中的换行符数量
int count_newlines(const char* str, int len) {
    int count = 0;
    for (int i = 0; i < len; i++) {
        if (str[i] == '\n') count++;
    }
    return count;
}

// 辅助函数：打印使用帮助
void print_usage() {
    printf("Usage:\n");
    printf("  Basic operations:\n");
    printf("    cat <filename>           - Print entire file\n");
    printf("    cat -h <n> <filename>    - Print first n lines (head)\n");
    printf("    cat -t <n> <filename>    - Print last n lines (tail)\n");
    printf("    cat -a <text> <filename> - Append text to end of file\n");
    printf("    cat -p <text> <filename> - Prepend text to beginning of file\n");
    printf("\n");
    printf("  Encryption operations (key from file):\n");
    printf("    cat -E <keyfile> <filename>      - Encrypt file\n");
    printf("    cat -D <keyfile> <filename>      - Decrypt and display file\n");
    printf("    cat -ea <keyfile> <text> <file>  - Append to encrypted file\n");
    printf("    cat -ep <keyfile> <text> <file>  - Prepend to encrypted file\n");
}

// 简单的字符串转整数函数
int str_to_int(const char* str) {
    int result = 0;
    int i = 0;

    while (str[i] >= '0' && str[i] <= '9') {
        result = result * 10 + (str[i] - '0');
        i++;
    }

    return result;
}

// 打印整个文件
int print_file(const char* filename) {
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        printf("cat: cannot open file '%s'\n", filename);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        for (int i = 0; i < bytes_read; i++) {
            printf("%c", buffer[i]);
        }
    }

    close(fd);
    return 0;
}

// 打印前 n 行
int print_head(const char* filename, int n) {
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        printf("cat: cannot open file '%s'\n", filename);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;
    int lines_printed = 0;

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0 && lines_printed < n) {
        for (int i = 0; i < bytes_read && lines_printed < n; i++) {
            printf("%c", buffer[i]);
            if (buffer[i] == '\n') {
                lines_printed++;
            }
        }
    }

    close(fd);
    return 0;
}

// 打印后 n 行
int print_tail(const char* filename, int n) {
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        printf("cat: cannot open file '%s'\n", filename);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    int total_bytes = 0;
    int bytes_read;

    while ((bytes_read = read(fd, buffer + total_bytes, BUFFER_SIZE - total_bytes)) > 0) {
        total_bytes += bytes_read;
        if (total_bytes >= BUFFER_SIZE - 1) {
            printf("cat: file too large for tail operation\n");
            close(fd);
            return -1;
        }
    }

    int newline_count = 0;
    int start_pos = total_bytes - 1;

    for (int i = total_bytes - 1; i >= 0; i--) {
        if (buffer[i] == '\n') {
            newline_count++;
            if (newline_count == n) {
                start_pos = i + 1;
                break;
            }
        }
        if (i == 0 && newline_count < n) {
            start_pos = 0;
        }
    }

    for (int i = start_pos; i < total_bytes; i++) {
        printf("%c", buffer[i]);
    }

    close(fd);
    return 0;
}

// 向文件末尾追加文本
int append_text(const char* filename, const char* text) {
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        fd = open(filename, O_CREAT | O_RDWR);
        if (fd == -1) {
            printf("cat: cannot create file '%s'\n", filename);
            return -1;
        }
    }

    lseek(fd, 0, SEEK_END);
    int text_len = strlen(text);
    int bytes_written = write(fd, text, text_len);

    if (bytes_written != text_len) {
        printf("cat: write failed\n");
        close(fd);
        return -1;
    }

    write(fd, "\n", 1);
    close(fd);
    printf("cat: text appended to '%s'\n", filename);
    return 0;
}

// 向文件开头追加文本
int prepend_text(const char* filename, const char* text) {
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        fd = open(filename, O_CREAT | O_RDWR);
        if (fd == -1) {
            printf("cat: cannot create file '%s'\n", filename);
            return -1;
        }
        write(fd, text, strlen(text));
        write(fd, "\n", 1);
        close(fd);
        printf("cat: text prepended to '%s'\n", filename);
        return 0;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read = read(fd, buffer, BUFFER_SIZE);

    if (bytes_read == -1) {
        printf("cat: read failed\n");
        close(fd);
        return -1;
    }

    close(fd);
    fd = open(filename, O_RDWR | O_TRUNC);
    if (fd == -1) {
        printf("cat: cannot reopen file '%s'\n", filename);
        return -1;
    }

    write(fd, text, strlen(text));
    write(fd, "\n", 1);

    if (bytes_read > 0) {
        write(fd, buffer, bytes_read);
    }

    close(fd);
    printf("cat: text prepended to '%s'\n", filename);
    return 0;
}

/* ========== 加密功能 ========== */

// 加密文件（明文 -> 密文）
int encrypt_file(const char* keyfile, const char* filename) {
    if (crypto_init_from_file(keyfile) != 0) {
        printf("cat: cannot read key from '%s'\n", keyfile);
        return -1;
    }

    // 读取原文件
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        printf("cat: cannot open file '%s'\n", filename);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read = read(fd, buffer, BUFFER_SIZE - sizeof(struct crypto_header));

    if (bytes_read == -1) {
        printf("cat: read failed\n");
        close(fd);
        return -1;
    }

    if (bytes_read == 0) {
        printf("cat: empty file\n");
        close(fd);
        return -1;
    }

    // 检查是否已加密
    if (crypto_is_encrypted(buffer)) {
        printf("cat: file is already encrypted\n");
        close(fd);
        return -1;
    }

    // 先计算明文的校验和（在加密之前！）
    int checksum = crypto_checksum(buffer, bytes_read);

    // 加密数据
    crypto_encrypt(buffer, bytes_read);

    // 创建加密头
    struct crypto_header header;
    header.magic[0] = 'E';
    header.magic[1] = 'N';
    header.magic[2] = 'C';
    header.magic[3] = '1';
    header.original_size = bytes_read;
    header.checksum = checksum;  // 使用明文的校验和

    // 写回文件
    close(fd);
    fd = open(filename, O_RDWR | O_TRUNC);
    if (fd == -1) {
        printf("cat: cannot reopen file\n");
        return -1;
    }

    write(fd, &header, sizeof(header));
    write(fd, buffer, bytes_read);

    close(fd);
    printf("cat: file '%s' encrypted successfully (%d bytes)\n", filename, bytes_read);
    return 0;
}

// 解密并显示文件
int decrypt_file(const char* keyfile, const char* filename) {
    if (crypto_init_from_file(keyfile) != 0) {
        printf("cat: cannot read key from '%s'\n", keyfile);
        return -1;
    }

    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        printf("cat: cannot open file '%s'\n", filename);
        return -1;
    }

    // 读取加密头
    struct crypto_header header;
    int bytes_read = read(fd, &header, sizeof(header));

    if (bytes_read != sizeof(header)) {
        printf("cat: invalid file format\n");
        close(fd);
        return -1;
    }

    // 验证魔数
    if (!crypto_is_encrypted(header.magic)) {
        printf("cat: file is not encrypted\n");
        close(fd);
        return -1;
    }

    // 读取加密数据
    char buffer[BUFFER_SIZE];
    bytes_read = read(fd, buffer, header.original_size);

    if (bytes_read != header.original_size) {
        printf("cat: file corrupted\n");
        close(fd);
        return -1;
    }

    // 解密
    crypto_decrypt(buffer, bytes_read);

    // 验证校验和
    int checksum = crypto_checksum(buffer, bytes_read);
    if (checksum != header.checksum) {
        printf("cat: decryption failed (wrong key or corrupted file)\n");
        close(fd);
        return -1;
    }

    // 显示解密内容
    for (int i = 0; i < bytes_read; i++) {
        printf("%c", buffer[i]);
    }

    close(fd);
    return 0;
}

// 向加密文件追加文本
int encrypt_append(const char* keyfile, const char* text, const char* filename) {
    if (crypto_init_from_file(keyfile) != 0) {
        printf("cat: cannot read key from '%s'\n", keyfile);
        return -1;
    }

    // 先解密文件
    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        printf("cat: cannot open file '%s'\n", filename);
        return -1;
    }

    struct crypto_header header;
    read(fd, &header, sizeof(header));

    if (!crypto_is_encrypted(header.magic)) {
        printf("cat: file is not encrypted\n");
        close(fd);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read = read(fd, buffer, header.original_size);

    crypto_decrypt(buffer, bytes_read);

    // 追加新文本
    int text_len = strlen(text);
    buffer[bytes_read] = '\n';
    bytes_read++;

    for (int i = 0; i < text_len && bytes_read < BUFFER_SIZE; i++) {
        buffer[bytes_read++] = text[i];
    }

    // 先计算明文的校验和（在加密之前！）
    int checksum = crypto_checksum(buffer, bytes_read);

    // 重新加密
    crypto_encrypt(buffer, bytes_read);

    // 更新头部
    header.original_size = bytes_read;
    header.checksum = checksum;  // 使用明文的校验和

    // 写回
    close(fd);
    fd = open(filename, O_RDWR | O_TRUNC);
    write(fd, &header, sizeof(header));
    write(fd, buffer, bytes_read);

    close(fd);
    printf("cat: text appended to encrypted file\n");
    return 0;
}

// 向加密文件开头插入文本
int encrypt_prepend(const char* keyfile, const char* text, const char* filename) {
    if (crypto_init_from_file(keyfile) != 0) {
        printf("cat: cannot read key from '%s'\n", keyfile);
        return -1;
    }

    int fd = open(filename, O_RDWR);
    if (fd == -1) {
        printf("cat: cannot open file '%s'\n", filename);
        return -1;
    }

    struct crypto_header header;
    read(fd, &header, sizeof(header));

    if (!crypto_is_encrypted(header.magic)) {
        printf("cat: file is not encrypted\n");
        close(fd);
        return -1;
    }

    char buffer[BUFFER_SIZE];
    char temp[BUFFER_SIZE];
    int bytes_read = read(fd, buffer, header.original_size);

    crypto_decrypt(buffer, bytes_read);

    // 插入文本到开头
    int text_len = strlen(text);
    int new_size = 0;

    for (int i = 0; i < text_len; i++) {
        temp[new_size++] = text[i];
    }
    temp[new_size++] = '\n';

    for (int i = 0; i < bytes_read && new_size < BUFFER_SIZE; i++) {
        temp[new_size++] = buffer[i];
    }

    // 先计算明文的校验和（在加密之前！）
    int checksum = crypto_checksum(temp, new_size);

    // 加密新内容
    crypto_encrypt(temp, new_size);

    // 更新头部
    header.original_size = new_size;
    header.checksum = checksum;  // 使用明文的校验和

    // 写回
    close(fd);
    fd = open(filename, O_RDWR | O_TRUNC);
    write(fd, &header, sizeof(header));
    write(fd, temp, new_size);

    close(fd);
    printf("cat: text prepended to encrypted file\n");
    return 0;
}

/* ========== 主函数 ========== */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    // cat <filename> - 打印整个文件
    if (argc == 2) {
        return print_file(argv[1]);
    }

    if (argc < 3) {
        print_usage();
        return -1;
    }

    const char* option = argv[1];

    // 基本操作
    if (strcmp(option, "-h") == 0 && argc == 4) {
        return print_head(argv[3], str_to_int(argv[2]));
    }

    if (strcmp(option, "-t") == 0 && argc == 4) {
        return print_tail(argv[3], str_to_int(argv[2]));
    }

    if (strcmp(option, "-a") == 0 && argc == 4) {
        return append_text(argv[3], argv[2]);
    }

    if (strcmp(option, "-p") == 0 && argc == 4) {
        return prepend_text(argv[3], argv[2]);
    }

    // 加密操作
    if (strcmp(option, "-E") == 0 && argc == 4) {
        return encrypt_file(argv[2], argv[3]);
    }

    if (strcmp(option, "-D") == 0 && argc == 4) {
        return decrypt_file(argv[2], argv[3]);
    }

    if (strcmp(option, "-ea") == 0 && argc == 5) {
        return encrypt_append(argv[2], argv[3], argv[4]);
    }

    if (strcmp(option, "-ep") == 0 && argc == 5) {
        return encrypt_prepend(argv[2], argv[3], argv[4]);
    }

    // 未知选项
    printf("cat: unknown option or invalid arguments\n");
    print_usage();
    return -1;
}
