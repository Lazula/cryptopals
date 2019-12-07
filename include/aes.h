#ifndef AES_H
#define AES_H

#include <stdint.h>
#include "repeating_key_xor.h"

/* Define cipher type constants */
#define AES_CIPHER_ECB 0
#define AES_CIPHER CBC 1

/* Define key type constants */
#define AES_KEY_128 0
#define AES_KEY_192 1
#define AES_KEY_256 2

unsigned int aes_encrypt(unsigned char **output, unsigned char *input, size_t input_size, unsigned char *key, uint8_t cipher_type, uint8_t key_type);
unsigned int aes_decrypt(unsigned char **output, unsigned char *input, size_t input_size, unsigned char *key, uint8_t cipher_type, uint8_t key_type);

#endif
