#ifndef AES_H
#define AES_H

#include <stdint.h>
#include "crypto_utility.h"

/* Define cipher type constants */
#define AES_CIPHER_ECB 0
#define AES_CIPHER_CBC 1

/* Define key type constants */
#define AES_KEY_128 0
#define AES_KEY_192 1
#define AES_KEY_256 2

size_t aes_encrypt(unsigned char **output, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type);
size_t aes_decrypt(unsigned char **output, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type);

#endif