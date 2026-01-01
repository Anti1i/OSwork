/*************************************************************************//**
 *****************************************************************************
 * @file   zuc.h
 * @brief  ZUC Stream Cipher Algorithm (祖冲之算法)
 * @author Orange'S Development Team
 * @date   2026
 *
 * ZUC is a stream cipher designed for 4G/5G mobile communications.
 * This is a simplified implementation for educational purposes.
 *****************************************************************************
 *****************************************************************************/

#ifndef _ORANGES_ZUC_H_
#define _ORANGES_ZUC_H_

/* ZUC algorithm constants */
#define ZUC_KEY_LEN     16  /* 128 bits */
#define ZUC_IV_LEN      16  /* 128 bits */

/**
 * @struct zuc_state
 * @brief ZUC algorithm state structure
 */
typedef struct {
    unsigned int LFSR[16];      /* Linear Feedback Shift Register */
    unsigned int R1;            /* Register R1 */
    unsigned int R2;            /* Register R2 */
    unsigned int key[16];       /* Internal key storage */
    unsigned int iv[16];        /* Initialization Vector */
    int initialized;            /* Initialization flag */
} zuc_state_t;

/**
 * @brief Initialize ZUC state with key and IV
 * @param state ZUC state structure
 * @param key 128-bit key (16 bytes)
 * @param iv 128-bit initialization vector (16 bytes)
 */
void zuc_init(zuc_state_t* state, const unsigned char* key, const unsigned char* iv);

/**
 * @brief Generate keystream words
 * @param state ZUC state structure
 * @param keystream Output buffer for keystream (4 bytes per word)
 * @param num_words Number of 32-bit words to generate
 */
void zuc_generate_keystream(zuc_state_t* state, unsigned int* keystream, int num_words);

/**
 * @brief Encrypt/Decrypt data using ZUC
 * @param state ZUC state structure
 * @param input Input data
 * @param output Output data (can be same as input for in-place operation)
 * @param length Data length in bytes
 */
void zuc_crypt(zuc_state_t* state, const unsigned char* input,
               unsigned char* output, int length);

/**
 * @brief Initialize ZUC with password (simplified key derivation)
 * @param state ZUC state structure
 * @param password User password string
 * @param pass_len Password length
 */
void zuc_init_with_password(zuc_state_t* state, const char* password, int pass_len);

#endif /* _ORANGES_ZUC_H_ */
