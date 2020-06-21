#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

int base64_encode(char **output_string_ptr, unsigned char *input_data, size_t input_size);
int base64_decode(unsigned char **output_data_ptr, size_t *output_data_size_ptr, char *input_string);

#endif
