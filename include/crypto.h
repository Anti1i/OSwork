/*************************************************************************//**
 *****************************************************************************
 * @file   crypto.h
 * @brief  Simple encryption/decryption library for Orange'S OS
 * @author Orange'S Development Team
 * @date   2025
 *****************************************************************************
 *****************************************************************************/

#ifndef _ORANGES_CRYPTO_H_
#define _ORANGES_CRYPTO_H_

/* Magic header for encrypted files */
#define CRYPTO_MAGIC "ENC1"
#define CRYPTO_MAGIC_LEN 4

/* Key management */
#define MAX_KEY_LEN 64
#define MIN_KEY_LEN 4

/**
 * @struct crypto_header
 * @brief Header structure for encrypted files
 */
struct crypto_header {
    char magic[4];        /* "ENC1" magic number */
    int original_size;    /* Original file size before encryption */
    int checksum;         /* Simple checksum for integrity */
};

/* Function prototypes */

/**
 * @brief Initialize the crypto system with a key
 * @param key The encryption key (string)
 * @param key_len Length of the key
 * @return 0 on success, -1 on error
 */
int crypto_init(const char* key, int key_len);

/**
 * @brief Encrypt data in-place
 * @param data Buffer containing data to encrypt
 * @param len Length of data
 * @return 0 on success, -1 on error
 */
int crypto_encrypt(char* data, int len);

/**
 * @brief Decrypt data in-place
 * @param data Buffer containing data to decrypt
 * @param len Length of data
 * @return 0 on success, -1 on error
 */
int crypto_decrypt(char* data, int len);

/**
 * @brief Check if a file is encrypted
 * @param data First few bytes of the file
 * @return 1 if encrypted, 0 if not
 */
int crypto_is_encrypted(const char* data);

/**
 * @brief Calculate simple checksum
 * @param data Data buffer
 * @param len Length of data
 * @return Checksum value
 */
int crypto_checksum(const char* data, int len);

/**
 * @brief Generate expanded key from password
 * @param password User password
 * @param pass_len Password length
 * @param key_out Output buffer for expanded key (must be at least 256 bytes)
 * @return 0 on success, -1 on error
 */
int crypto_expand_key(const char* password, int pass_len, unsigned char* key_out);

/**
 * @brief Initialize crypto system by reading key from file
 * @param keyfile_path Path to the key file
 * @return 0 on success, -1 on error
 */
int crypto_init_from_file(const char* keyfile_path);

#endif /* _ORANGES_CRYPTO_H_ */
