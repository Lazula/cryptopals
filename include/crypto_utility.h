#ifndef CRYPTO_UTILITY_H
#define CRYPTO_UTILITY_H

#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* No, the C99 (this program is C89 regardless) uint8_t type is not guaranteed to exist in stdint.h
 * Yes, this code could be written in a way that works properly with CHAR_BIT >=8
 * No, I will not take the effort to do so, because so much other code in this project incidentally
 * relies on CHAR_BIT == 8.
 */
#if CHAR_BIT == 8
typedef unsigned char uint8_t;
#else
#error No 8-bit type available. Cannot typedef uint8_t.
#endif

/* 32-bit maximum */
#if UINT_MAX == 4294967295
typedef unsigned int uint32_t;
#elif ULONG_MAX == 4294967295
typedef unsigned long uint32_t;
#else
#error No 32-bit type available. Cannot typedef uint32_t.
#endif

int pkcs7_pad(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, size_t block_size);
int pkcs7_unpad(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, size_t block_size);

#endif
