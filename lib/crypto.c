/*************************************************************************//**
 *****************************************************************************
 * @file   crypto.c
 * @brief  Simple encryption/decryption implementation
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
 * @brief Encrypt data in-place using simple XOR + CBC
 */
PUBLIC int crypto_encrypt(char* data, int len) {
    int i;
    unsigned char prev = 0x5A; /* Initial vector */

    if (!g_key_initialized) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        /* Simple encryption: XOR with key and previous byte (CBC) */
        unsigned char key_byte = g_expanded_key[i % 256];

        /* XOR with key and previous byte only (no position factor) */
        unsigned char encrypted = (unsigned char)data[i] ^ key_byte ^ prev;

        prev = encrypted;
        data[i] = (char)encrypted;
    }

    return 0;
}

/**
 * @brief Decrypt data in-place
 */
PUBLIC int crypto_decrypt(char* data, int len) {
    int i;
    unsigned char prev = 0x5A; /* Same initial vector */

    if (!g_key_initialized) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        unsigned char key_byte = g_expanded_key[i % 256];

        /* Reverse the encryption (no position factor) */
        unsigned char encrypted = (unsigned char)data[i];
        unsigned char decrypted = encrypted ^ key_byte ^ prev;

        prev = encrypted;
        data[i] = (char)decrypted;
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
