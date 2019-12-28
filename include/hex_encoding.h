#ifndef HEX_ENCODE_H
#define HEX_ENCODE_H

#include <stddef.h>

size_t hex_encode(char **output_string, unsigned char *input_data, size_t input_size);
size_t hex_decode(unsigned char **output_data, char *input_string);

#endif
