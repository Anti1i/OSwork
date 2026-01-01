# OrangeS ZUC加密使用说明

## 目录
1. [ZUC算法简介](#一zuc算法简介)
2. [实现特性](#二实现特性)
3. [使用方法](#三使用方法)
4. [API接口](#四api接口)
5. [示例代码](#五示例代码)
6. [安全性说明](#六安全性说明)

---

## 一、ZUC算法简介

### 1.1 什么是ZUC

**ZUC（祖冲之算法）** 是中国自主设计的流密码算法，以中国古代数学家祖冲之命名。

**主要特点**：
- **国密算法**：中国密码行业标准（GM/T 0001-2012）
- **流密码**：加密和解密操作相同，通过XOR密钥流实现
- **4G/5G应用**：用于LTE和5G移动通信的机密性和完整性保护
- **高性能**：硬件和软件实现都具有很高的效率

### 1.2 ZUC算法结构

```
输入: 128-bit密钥 + 128-bit初始向量(IV)
         ↓
    ┌────────────┐
    │  密钥加载  │  ← 将密钥和IV加载到LFSR
    └─────┬──────┘
          ↓
    ┌────────────┐
    │ 初始化阶段 │  ← 运行32轮，建立内部状态
    └─────┬──────┘
          ↓
    ┌────────────┐
    │ 密钥流生成 │  ← 持续生成32-bit密钥流字
    └─────┬──────┘
          ↓
      密钥流输出
```

**核心组件**：
1. **LFSR（线性反馈移位寄存器）**：16个31-bit寄存器
2. **BR（比特重组）**：将LFSR状态重组为4个32-bit字
3. **F（非线性函数）**：包含S盒和线性变换
4. **R1, R2（记忆单元）**：32-bit寄存器

---

## 二、实现特性

### 2.1 OrangeS的ZUC实现

本实现基于ZUC v1.6规范，做了以下适配：

| 特性 | 说明 |
|------|------|
| 算法版本 | ZUC v1.6 (2011) |
| 密钥长度 | 128-bit (16字节) |
| IV长度 | 128-bit (16字节) |
| 输出 | 32-bit密钥流字 |
| 模式 | 流密码模式（加密=解密） |
| 密码头 | "ZUC1" (替代旧的"ENC1") |

### 2.2 与旧加密方式的区别

| 项目 | 旧实现 (XOR+CBC) | 新实现 (ZUC) |
|------|-----------------|-------------|
| 算法类型 | 简单XOR+CBC | 流密码 |
| 安全强度 | 低（易破解） | 高（军用级） |
| 密钥长度 | 可变（4-64字节） | 固定128-bit（内部） |
| 加密速度 | 快 | 中（初始化较慢） |
| 标准符合 | 无 | 符合GM/T 0001-2012 |
| 文件标识 | "ENC1" | "ZUC1" |

### 2.3 兼容性

**⚠️ 重要提示**：
- 使用ZUC加密的文件**不兼容**旧的XOR加密
- 文件头标识已从 `ENC1` 改为 `ZUC1`
- 旧加密文件需要重新加密才能使用ZUC

---

## 三、使用方法

### 3.1 cat命令加密文件

#### 创建密钥文件
```bash
$ echo "MySecretPassword123" > /keyfile
```

#### 加密文件
```bash
$ cat -E /keyfile /mydata.txt
cat: file '/mydata.txt' encrypted successfully (256 bytes)
```

#### 解密并显示文件
```bash
$ cat -D /keyfile /mydata.txt
[解密后的文件内容]
```

#### 向加密文件追加内容
```bash
$ cat -ea /keyfile "New text" /mydata.txt
cat: text appended to encrypted file
```

#### 向加密文件开头插入内容
```bash
$ cat -ep /keyfile "Header text" /mydata.txt
cat: text prepended to encrypted file
```

### 3.2 命令行参数说明

```
cat -E <keyfile> <filename>        - 加密文件
cat -D <keyfile> <filename>        - 解密并显示文件
cat -ea <keyfile> <text> <file>    - 向加密文件追加文本
cat -ep <keyfile> <text> <file>    - 向加密文件开头插入文本
```

**参数**：
- `<keyfile>`：包含密码的文件路径
- `<filename>`：要加密/解密的文件路径
- `<text>`：要追加/插入的文本内容

---

## 四、API接口

### 4.1 头文件

```c
#include "crypto.h"
#include "zuc.h"
```

### 4.2 核心函数

#### crypto_init() - 初始化加密系统
```c
int crypto_init(const char* key, int key_len);
```
**参数**：
- `key`：密码字符串
- `key_len`：密码长度（4-64字节）

**返回值**：
- `0`：成功
- `-1`：失败（密钥长度无效）

**说明**：
从用户密码派生128-bit ZUC密钥和IV

---

#### crypto_encrypt() - 加密数据
```c
int crypto_encrypt(char* data, int len);
```
**参数**：
- `data`：要加密的数据（原地加密）
- `len`：数据长度（字节）

**返回值**：
- `0`：成功
- `-1`：失败（未初始化）

**说明**：
使用ZUC流密码加密数据

---

#### crypto_decrypt() - 解密数据
```c
int crypto_decrypt(char* data, int len);
```
**参数**：
- `data`：要解密的数据（原地解密）
- `len`：数据长度（字节）

**返回值**：
- `0`：成功
- `-1`：失败（未初始化）

**说明**：
使用ZUC流密码解密数据（操作与加密相同）

---

#### crypto_is_encrypted() - 检查文件是否加密
```c
int crypto_is_encrypted(const char* data);
```
**参数**：
- `data`：文件头部数据

**返回值**：
- `1`：文件已加密（魔数为"ZUC1"）
- `0`：文件未加密

---

### 4.3 ZUC底层接口

#### zuc_init() - 初始化ZUC状态
```c
void zuc_init(zuc_state_t* state,
              const unsigned char* key,
              const unsigned char* iv);
```
**参数**：
- `state`：ZUC状态结构体指针
- `key`：128-bit密钥（16字节）
- `iv`：128-bit初始向量（16字节）

---

#### zuc_generate_keystream() - 生成密钥流
```c
void zuc_generate_keystream(zuc_state_t* state,
                            unsigned int* keystream,
                            int num_words);
```
**参数**：
- `state`：ZUC状态结构体指针
- `keystream`：输出缓冲区（32-bit字数组）
- `num_words`：生成的密钥流字数

---

#### zuc_crypt() - 加密/解密数据
```c
void zuc_crypt(zuc_state_t* state,
               const unsigned char* input,
               unsigned char* output,
               int length);
```
**参数**：
- `state`：ZUC状态结构体指针
- `input`：输入数据
- `output`：输出数据（可与input相同）
- `length`：数据长度（字节）

---

## 五、示例代码

### 5.1 简单加密/解密示例

```c
#include "type.h"
#include "crypto.h"
#include "stdio.h"

int main() {
    char data[] = "Hello, this is secret data!";
    int data_len = strlen(data);
    const char* password = "MyPassword123";

    printf("原始数据: %s\n", data);

    // 初始化加密系统
    if (crypto_init(password, strlen(password)) != 0) {
        printf("加密初始化失败\n");
        return 1;
    }

    // 加密数据
    crypto_encrypt(data, data_len);
    printf("加密后: (二进制数据)\n");

    // 解密数据
    crypto_decrypt(data, data_len);
    printf("解密后: %s\n", data);

    return 0;
}
```

### 5.2 文件加密示例

```c
#include "type.h"
#include "crypto.h"
#include "stdio.h"
#include "fs.h"

int encrypt_file_example(const char* filename, const char* password) {
    char buffer[1024];
    int fd, bytes_read;

    // 打开文件
    fd = open(filename, O_RDWR);
    if (fd < 0) {
        return -1;
    }

    // 读取文件内容
    bytes_read = read(fd, buffer, sizeof(buffer));

    // 初始化加密
    crypto_init(password, strlen(password));

    // 创建加密头
    struct crypto_header header;
    memcpy(header.magic, CRYPTO_MAGIC, CRYPTO_MAGIC_LEN); // "ZUC1"
    header.original_size = bytes_read;
    header.checksum = crypto_checksum(buffer, bytes_read);

    // 加密数据
    crypto_encrypt(buffer, bytes_read);

    // 写回文件
    lseek(fd, 0, SEEK_SET);
    write(fd, &header, sizeof(header));
    write(fd, buffer, bytes_read);

    close(fd);
    return 0;
}
```

### 5.3 直接使用ZUC API

```c
#include "type.h"
#include "zuc.h"
#include "stdio.h"

int main() {
    zuc_state_t state;
    unsigned char key[16] = {0x00, 0x01, 0x02, ..., 0x0F};
    unsigned char iv[16] = {0x10, 0x11, 0x12, ..., 0x1F};
    unsigned char plaintext[] = "Secret message";
    unsigned char ciphertext[256];
    int len = strlen((char*)plaintext);

    // 初始化ZUC
    zuc_init(&state, key, iv);

    // 加密
    zuc_crypt(&state, plaintext, ciphertext, len);
    printf("密文: (二进制)\n");

    // 解密（重新初始化）
    zuc_init(&state, key, iv);
    zuc_crypt(&state, ciphertext, plaintext, len);
    printf("明文: %s\n", plaintext);

    return 0;
}
```

---

## 六、安全性说明

### 6.1 密码强度建议

**强密码要求**：
- 长度至少12个字符
- 包含大小写字母、数字和特殊字符
- 避免使用字典单词或个人信息

**示例**：
```
✅ 强密码: "MyP@ssw0rd!2026#ZUC"
❌ 弱密码: "123456"
❌ 弱密码: "password"
```

### 6.2 密钥管理

**密钥文件保护**：
```bash
# 创建密钥文件
$ echo "StrongPassword!@#123" > /secret.key

# 限制访问权限（如果系统支持）
# chmod 600 /secret.key

# 使用后删除密钥文件
$ rm /secret.key
```

**⚠️ 安全警告**：
- 不要将密钥硬编码在程序中
- 不要通过不安全的通道传输密钥
- 定期更换密钥

### 6.3 已知限制

本实现为**教育演示目的**，存在以下限制：

| 限制项 | 说明 |
|--------|------|
| 密钥派生 | 简化的密码派生，非标准PBKDF2 |
| IV管理 | 从密码派生，而非随机生成 |
| 完整性保护 | 简单校验和，非HMAC |
| 侧信道攻击 | 未考虑时间/功耗分析 |

**生产环境建议**：
- 使用标准的密钥派生函数（如PBKDF2、scrypt）
- 为每次加密生成随机IV
- 使用HMAC-SHA256进行完整性验证
- 实现侧信道攻击防护

### 6.4 ZUC算法安全性

**标准认证**：
- 国家密码管理局认证
- 3GPP TS 35.222标准
- ISO/IEC国际标准候选

**已知分析**：
- 至今未发现实用的密码分析攻击
- 理论安全强度：128-bit
- 抗线性/差分/代数攻击

**使用场景**：
- ✅ 文件加密
- ✅ 通信加密
- ✅ 数据保护
- ❌ 不适合密码哈希（应使用bcrypt/scrypt）
- ❌ 不适合数字签名（应使用RSA/ECDSA）

---

## 七、常见问题

### Q1: 为什么从XOR改为ZUC？

**A**: XOR+CBC是简单的教学加密，安全性很低。ZUC是工业级流密码，提供：
- 更高的安全强度（128-bit）
- 抗现代密码分析攻击
- 符合国际/国家标准

### Q2: ZUC加密速度如何？

**A**:
- **初始化阶段**：较慢（32轮运算）
- **加密阶段**：快速（流密码特性）
- **总体**：中等速度，适合文件加密

### Q3: 能解密旧的XOR加密文件吗？

**A**: 不能。两种算法不兼容。需要：
1. 用旧版本解密文件
2. 保存明文
3. 用新版本重新加密

### Q4: 如何验证加密是否成功？

**A**: 检查文件头：
```c
char header[4];
read(fd, header, 4);
if (memcmp(header, "ZUC1", 4) == 0) {
    printf("文件已使用ZUC加密\n");
}
```

### Q5: 密钥丢失怎么办？

**A**: 无法恢复！ZUC是强加密算法，没有密钥无法解密。务必：
- 备份密钥文件
- 记住密码
- 考虑使用密钥管理系统

---

## 八、参考资料

### 8.1 官方文档

- **ZUC规范**: "The ZUC-128 Stream Cipher Algorithm" v1.6 (2011)
- **3GPP标准**: TS 35.222 "Specification of the 3GPP Confidentiality and Integrity Algorithms 128-EEA3 & 128-EIA3"
- **国密标准**: GM/T 0001-2012 "祖冲之序列密码算法"

### 8.2 相关文件

| 文件 | 说明 |
|------|------|
| `include/zuc.h` | ZUC算法头文件 |
| `lib/zuc.c` | ZUC算法实现 |
| `include/crypto.h` | 加密接口头文件 |
| `lib/crypto.c` | 加密接口实现 |
| `command/cat.c` | cat命令实现（支持加密） |

### 8.3 技术支持

**问题反馈**：
- GitHub Issues: https://github.com/your-repo/issues
- 文档位置: `/docs/ZUC加密使用说明.md`

---

**文档版本**: 1.0
**创建日期**: 2026-01-01
**最后更新**: 2026-01-01
**适用系统**: OrangeS v0.11+
