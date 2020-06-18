#ifndef AES_H
#define AES_H

#include "crypto_utility.h"

enum AES_CIPHER_TYPES {
	AES_CIPHER_ECB = 0,
	AES_CIPHER_CBC = 1,
	AES_CIPHER_CTR = 2
};

enum AES_KEY_TYPES {
	AES_KEY_128 = 0,
	AES_KEY_192 = 1,
	AES_KEY_256 = 2
};

int aes_encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type);
int aes_decrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type);
int is_aes_ecb(unsigned char *data, size_t data_size);
int generate_random_aes_key(unsigned char **output, uint8_t key_type);

#endif
