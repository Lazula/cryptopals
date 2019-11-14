#ifndef DECRYPT_SINGLE_BYTE_XOR_H
#define DECRYPT_SINGLE_BYTE_XOR_H

#include <stddef.h>

unsigned int decrypt_single_byte_xor(unsigned char *output,  unsigned char *output_key, unsigned char *input_data, size_t input_size);

#endif
