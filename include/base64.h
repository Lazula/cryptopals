#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

unsigned int base64_encode(unsigned char *output_string, unsigned char *input_data, size_t input_size);
unsigned int base64_decode(unsigned char **output_data, unsigned char *input_string);

#endif
