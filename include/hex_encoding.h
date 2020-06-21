#ifndef HEX_ENCODE_H
#define HEX_ENCODE_H

#include <stddef.h>

int hex_encode(char **output_string_ptr, unsigned char *input_data, size_t input_size);
int hex_decode(unsigned char **output_data_ptr, size_t *output_data_size_ptr, char *input_string);
int hex_print(unsigned char *input, size_t input_size);

#endif
