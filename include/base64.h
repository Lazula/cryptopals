#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

size_t base64_encode(char **output_string, unsigned char *input_data, size_t input_size);
size_t base64_decode(unsigned char **output_data, char *input_string);

#endif
