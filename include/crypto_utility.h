#ifndef CRYPTO_UTILITY_H
#define CRYPTO_UTILITY_H

size_t pkcs7_pad(unsigned char **output, unsigned char *input, size_t input_size, size_t block_size);
size_t pkcs7_unpad(unsigned char **output, unsigned char *input, size_t input_size, size_t block_size);

#endif
