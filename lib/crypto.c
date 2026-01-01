/*************************************************************************//**
 *****************************************************************************
 * @file   crypto.c
 * @brief  ZUC encryption/decryption implementation
 * @author Orange'S Development Team
 * @date   2025
 *****************************************************************************
 *****************************************************************************/

#include "type.h"
#include "crypto.h"
#include "string.h"
#include "stdio.h"

/* Global key storage */
static unsigned char g_expanded_key[256];
static int g_key_initialized = 0;

/* ========== ZUC Algorithm Implementation ========== */

/* ZUC S-boxes */
static const unsigned char S0[256] = {
    0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,
    0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,
    0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,
    0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,
    0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,
    0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,
    0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,
    0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,
    0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,
    0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,
    0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,
    0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,
    0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,
    0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,
    0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,
    0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60
};

static const unsigned char S1[256] = {
    0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,
    0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,
    0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,
    0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,
    0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,
    0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,
    0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,
    0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,
    0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,
    0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,
    0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,
    0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,
    0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,
    0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,
    0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,
    0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2
};

/* ZUC State */
static unsigned int LFSR[16];
static unsigned int R1, R2;

/* ZUC Constants */
static const unsigned char D[16] = {
    0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30
};

/* Addition in GF(2^31-1) */
static unsigned int AddM(unsigned int a, unsigned int b) {
    unsigned int c = a + b;
    return (c & 0x7FFFFFFF) + (c >> 31);
}

/* Multiplication by 2 in GF(2^31-1) */
static unsigned int MulByPow2(unsigned int x, int k) {
    return ((x << k) | (x >> (31 - k))) & 0x7FFFFFFF;
}

/* Rotate left */
#define ROT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Linear transformation L1 */
static unsigned int L1(unsigned int X) {
    return X ^ ROT(X, 2) ^ ROT(X, 10) ^ ROT(X, 18) ^ ROT(X, 24);
}

/* Linear transformation L2 */
static unsigned int L2(unsigned int X) {
    return X ^ ROT(X, 8) ^ ROT(X, 14) ^ ROT(X, 22) ^ ROT(X, 30);
}

/* S-box lookup */
static unsigned int S(unsigned int X) {
    unsigned int Y;
    unsigned char *p = (unsigned char*)&X;
    unsigned char *q = (unsigned char*)&Y;

    q[0] = S0[p[0]];
    q[1] = S1[p[1]];
    q[2] = S0[p[2]];
    q[3] = S1[p[3]];

    return Y;
}

/* LFSR with initialization mode */
static void LFSRWithInitMode(unsigned int u) {
    unsigned int f, v;

    f = LFSR[0];
    v = MulByPow2(LFSR[0], 8);
    f = AddM(f, v);
    v = MulByPow2(LFSR[4], 20);
    f = AddM(f, v);
    v = MulByPow2(LFSR[10], 21);
    f = AddM(f, v);
    v = MulByPow2(LFSR[13], 17);
    f = AddM(f, v);
    v = MulByPow2(LFSR[15], 15);
    f = AddM(f, v);

    f = AddM(f, u);

    /* Shift LFSR */
    for (int i = 0; i < 15; i++) {
        LFSR[i] = LFSR[i + 1];
    }
    LFSR[15] = f;
}

/* LFSR with work mode */
static void LFSRWithWorkMode() {
    unsigned int f, v;

    f = LFSR[0];
    v = MulByPow2(LFSR[0], 8);
    f = AddM(f, v);
    v = MulByPow2(LFSR[4], 20);
    f = AddM(f, v);
    v = MulByPow2(LFSR[10], 21);
    f = AddM(f, v);
    v = MulByPow2(LFSR[13], 17);
    f = AddM(f, v);
    v = MulByPow2(LFSR[15], 15);
    f = AddM(f, v);

    /* Shift LFSR */
    for (int i = 0; i < 15; i++) {
        LFSR[i] = LFSR[i + 1];
    }
    LFSR[15] = f;
}

/* Bit reorganization */
static void BitReorganization(unsigned int *X0, unsigned int *X1, unsigned int *X2, unsigned int *X3) {
    *X0 = ((LFSR[15] & 0x7FFF8000) << 1) | (LFSR[14] & 0xFFFF);
    *X1 = ((LFSR[11] & 0xFFFF) << 16) | (LFSR[9] >> 15);
    *X2 = ((LFSR[7] & 0xFFFF) << 16) | (LFSR[5] >> 15);
    *X3 = ((LFSR[2] & 0xFFFF) << 16) | (LFSR[0] >> 15);
}

/* F function */
static unsigned int F(unsigned int X0, unsigned int X1, unsigned int X2) {
    unsigned int W, W1, W2, u, v;

    W = (X0 ^ R1) + R2;
    W1 = R1 + X1;
    W2 = R2 ^ X2;

    u = L1((W1 << 16) | (W2 >> 16));
    v = L2((W2 << 16) | (W1 >> 16));

    R1 = S(u);
    R2 = S(v);

    return W;
}

/* ZUC initialization */
static void ZUC_Init(const unsigned char *key, const unsigned char *iv) {
    int i;
    unsigned int X0, X1, X2, X3, W;

    /* Load key and IV into LFSR */
    for (i = 0; i < 16; i++) {
        LFSR[i] = ((unsigned int)key[i] << 23) | ((unsigned int)D[i] << 8) | iv[i];
    }

    R1 = 0;
    R2 = 0;

    /* 32 initialization rounds */
    for (i = 0; i < 32; i++) {
        BitReorganization(&X0, &X1, &X2, &X3);
        W = F(X0, X1, X2);
        LFSRWithInitMode((W >> 1) & 0x7FFFFFFF);
    }

    /* One more round for work mode */
    BitReorganization(&X0, &X1, &X2, &X3);
    F(X0, X1, X2);
    LFSRWithWorkMode();
}

/* Generate one keystream word */
static unsigned int ZUC_GenerateKeyword() {
    unsigned int X0, X1, X2, X3, Z;

    BitReorganization(&X0, &X1, &X2, &X3);
    Z = F(X0, X1, X2) ^ X3;
    LFSRWithWorkMode();

    return Z;
}

/**
 * @brief Simple PRNG for key expansion
 */
static unsigned int prng_state = 0x12345678;

static unsigned int simple_rand() {
    prng_state = prng_state * 1103515245 + 12345;
    return (prng_state / 65536) % 32768;
}

static void simple_srand(unsigned int seed) {
    prng_state = seed;
}

/**
 * @brief Generate expanded key from password
 */
PUBLIC int crypto_expand_key(const char* password, int pass_len, unsigned char* key_out) {
    int i, j;
    unsigned int seed = 0;

    if (pass_len < MIN_KEY_LEN || pass_len > MAX_KEY_LEN) {
        return -1;
    }

    /* Calculate seed from password */
    for (i = 0; i < pass_len; i++) {
        seed = seed * 31 + (unsigned char)password[i];
    }

    simple_srand(seed);

    /* Generate 256-byte expanded key */
    for (i = 0; i < 256; i++) {
        /* Mix password characters with pseudo-random values */
        key_out[i] = (unsigned char)(simple_rand() ^ password[i % pass_len]);

        /* Additional mixing */
        for (j = 0; j < i % 3; j++) {
            key_out[i] = (key_out[i] + password[j % pass_len]) & 0xFF;
        }
    }

    return 0;
}

/**
 * @brief Initialize the crypto system with a key
 */
PUBLIC int crypto_init(const char* key, int key_len) {
    if (crypto_expand_key(key, key_len, g_expanded_key) != 0) {
        return -1;
    }

    g_key_initialized = 1;
    return 0;
}

/**
 * @brief Encrypt data in-place using ZUC stream cipher
 */
PUBLIC int crypto_encrypt(char* data, int len) {
    int i, j;
    unsigned char iv[16];
    unsigned char key[16];
    unsigned int keystream_word;
    unsigned char *keystream_bytes = (unsigned char*)&keystream_word;

    if (!g_key_initialized) {
        return -1;
    }

    /* Prepare 16-byte key from expanded key */
    for (i = 0; i < 16; i++) {
        key[i] = g_expanded_key[i];
    }

    /* Prepare 16-byte IV from expanded key (using different offset) */
    for (i = 0; i < 16; i++) {
        iv[i] = g_expanded_key[i + 16];
    }

    /* Initialize ZUC with key and IV */
    ZUC_Init(key, iv);

    /* Discard first keystream word (as per ZUC specification) */
    ZUC_GenerateKeyword();

    /* Encrypt data using ZUC keystream */
    for (i = 0; i < len; i += 4) {
        /* Generate 4 bytes of keystream */
        keystream_word = ZUC_GenerateKeyword();

        /* XOR with plaintext */
        for (j = 0; j < 4 && (i + j) < len; j++) {
            data[i + j] ^= keystream_bytes[j];
        }
    }

    return 0;
}

/**
 * @brief Decrypt data in-place using ZUC stream cipher
 */
PUBLIC int crypto_decrypt(char* data, int len) {
    int i, j;
    unsigned char iv[16];
    unsigned char key[16];
    unsigned int keystream_word;
    unsigned char *keystream_bytes = (unsigned char*)&keystream_word;

    if (!g_key_initialized) {
        return -1;
    }

    /* Prepare 16-byte key from expanded key */
    for (i = 0; i < 16; i++) {
        key[i] = g_expanded_key[i];
    }

    /* Prepare 16-byte IV from expanded key (using different offset) */
    for (i = 0; i < 16; i++) {
        iv[i] = g_expanded_key[i + 16];
    }

    /* Initialize ZUC with key and IV */
    ZUC_Init(key, iv);

    /* Discard first keystream word (as per ZUC specification) */
    ZUC_GenerateKeyword();

    /* Decrypt data using ZUC keystream (same as encryption for stream cipher) */
    for (i = 0; i < len; i += 4) {
        /* Generate 4 bytes of keystream */
        keystream_word = ZUC_GenerateKeyword();

        /* XOR with ciphertext */
        for (j = 0; j < 4 && (i + j) < len; j++) {
            data[i + j] ^= keystream_bytes[j];
        }
    }

    return 0;
}

/**
 * @brief Check if a file is encrypted
 */
PUBLIC int crypto_is_encrypted(const char* data) {
    int i;

    for (i = 0; i < CRYPTO_MAGIC_LEN; i++) {
        if (data[i] != CRYPTO_MAGIC[i]) {
            return 0;
        }
    }

    return 1;
}

/**
 * @brief Calculate simple checksum
 */
PUBLIC int crypto_checksum(const char* data, int len) {
    int i;
    int sum = 0;

    for (i = 0; i < len; i++) {
        sum += (unsigned char)data[i];
        sum = (sum * 31) & 0xFFFFFF; /* Keep it in reasonable range */
    }

    return sum;
}

/**
 * @brief Initialize crypto system by reading key from file
 */
PUBLIC int crypto_init_from_file(const char* keyfile_path) {
    int fd;
    char key_buffer[MAX_KEY_LEN + 1];
    int bytes_read;

    /* Open key file */
    fd = open(keyfile_path, O_RDWR);
    if (fd == -1) {
        return -1;
    }

    /* Read key from file */
    bytes_read = read(fd, key_buffer, MAX_KEY_LEN);
    close(fd);

    if (bytes_read < MIN_KEY_LEN) {
        return -1;
    }

    /* Remove trailing newline if present */
    if (bytes_read > 0 && key_buffer[bytes_read - 1] == '\n') {
        bytes_read--;
    }

    /* Null terminate */
    key_buffer[bytes_read] = '\0';

    /* Initialize with the key */
    return crypto_init(key_buffer, bytes_read);
}
