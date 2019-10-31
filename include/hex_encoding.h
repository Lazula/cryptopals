#ifndef HEX_ENCODE_H
#define HEX_ENCODE_H

#include <stddef.h>

unsigned int hex_encode(unsigned char *output_string, unsigned char *input_data, size_t input_size);
unsigned int hex_decode(unsigned char *output_data, unsigned char *input_string);

#endif
