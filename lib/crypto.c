/*************************************************************************//**
 *****************************************************************************
 * @file   crypto.c
 * @brief  Encryption/decryption implementation using ZUC algorithm
 * @author Orange'S Development Team
 * @date   2026
 *
 * Changed from simple XOR to ZUC (祖冲之) stream cipher for enhanced security
 *****************************************************************************
 *****************************************************************************/

#include "type.h"
#include "crypto.h"
#include "zuc.h"
#include "string.h"
#include "stdio.h"

/* Global ZUC state */
static zuc_state_t g_zuc_state;
static int g_key_initialized = 0;

/**
 * @brief Generate expanded key from password (kept for compatibility)
 * Note: This is now primarily used for legacy support
 */
PUBLIC int crypto_expand_key(const char* password, int pass_len, unsigned char* key_out) {
    int i;

    if (pass_len < MIN_KEY_LEN || pass_len > MAX_KEY_LEN) {
        return -1;
    }

    /* Simple expansion: repeat password to fill 256 bytes */
    for (i = 0; i < 256; i++) {
        key_out[i] = (unsigned char)password[i % pass_len];
    }

    return 0;
}

/**
 * @brief Initialize the crypto system with a key (using ZUC)
 */
PUBLIC int crypto_init(const char* key, int key_len) {
    if (key_len < MIN_KEY_LEN || key_len > MAX_KEY_LEN) {
        return -1;
    }

    /* Initialize ZUC with password-based key derivation */
    zuc_init_with_password(&g_zuc_state, key, key_len);

    g_key_initialized = 1;
    return 0;
}

/**
 * @brief Encrypt data in-place using ZUC stream cipher
 */
PUBLIC int crypto_encrypt(char* data, int len) {
    zuc_state_t temp_state;

    if (!g_key_initialized) {
        return -1;
    }

    /* Create a copy of state for encryption (to allow re-initialization) */
    memcpy(&temp_state, &g_zuc_state, sizeof(zuc_state_t));

    /* Re-initialize with same key for fresh keystream */
    zuc_init(&temp_state, g_zuc_state.key, g_zuc_state.iv);

    /* Encrypt using ZUC */
    zuc_crypt(&temp_state, (unsigned char*)data, (unsigned char*)data, len);

    return 0;
}

/**
 * @brief Decrypt data in-place using ZUC stream cipher
 * Note: For stream ciphers, encryption and decryption are the same operation
 */
PUBLIC int crypto_decrypt(char* data, int len) {
    zuc_state_t temp_state;

    if (!g_key_initialized) {
        return -1;
    }

    /* Create a copy of state for decryption */
    memcpy(&temp_state, &g_zuc_state, sizeof(zuc_state_t));

    /* Re-initialize with same key for fresh keystream */
    zuc_init(&temp_state, g_zuc_state.key, g_zuc_state.iv);

    /* Decrypt using ZUC (same as encryption for stream cipher) */
    zuc_crypt(&temp_state, (unsigned char*)data, (unsigned char*)data, len);

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
