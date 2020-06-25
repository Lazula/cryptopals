#ifndef SHAONE_H
#define SHAONE_H

#include "local_endian.h"
#include "crypto_utility.h"

#define SHA1_DIGEST_SIZE 20

/* Standard external wrapper around the internal sha1 function. */
int sha1(unsigned char **output_ptr, unsigned char *input, size_t input_size);

/* Standard function to prepend a secret key to a message before hashing. */
int key_prefix_sha1(unsigned char **output_ptr, unsigned char *input, size_t input_size, unsigned char *key, size_t key_size);

/* Easily represent a sha1 hash as a printable string. */
int sha1_hash_to_string(char **output_ptr, unsigned char *input);

#endif
