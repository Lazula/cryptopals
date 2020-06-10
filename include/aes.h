#ifndef AES_H
#define AES_H

#include "crypto_utility.h"

/* Define cipher type constants */
#define AES_CIPHER_ECB 0
#define AES_CIPHER_CBC 1

/* Define key type constants */
#define AES_KEY_128 0
#define AES_KEY_192 1
#define AES_KEY_256 2

int aes_encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type);
int aes_decrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type);
signed char is_aes_ecb(unsigned char *data, size_t data_size);
int generate_random_aes_key(unsigned char **output, uint8_t key_type);

#endif
