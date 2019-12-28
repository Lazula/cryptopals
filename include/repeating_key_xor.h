#ifndef REPEATING_KEY_XOR_H
#define REPEATING_KEY_XOR_H

#include <stddef.h>

void repeating_key_xor(unsigned char *output_data, unsigned char *input_data, size_t input_size, unsigned char *key, size_t key_size);

#endif
