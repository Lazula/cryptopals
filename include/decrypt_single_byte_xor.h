#ifndef DECRYPT_SINGLE_BYTE_XOR_H
#define DECRYPT_SINGLE_BYTE_XOR_H

#include <stddef.h>

double decrypt_single_byte_xor(char *output, char *output_key, char *input_data, size_t input_size);
double decrypt_single_byte_xor_fast(char *output, char *output_key, char *input_data, size_t input_size);

#endif
