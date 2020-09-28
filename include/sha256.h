#ifndef SHATWOFIFTYSIX_H
#define SHATWOFIFTYSIX_H

#include "local_endian.h"
#include "crypto_utility.h"

#define SHA256_DIGEST_SIZE 32

/* Not intended for outside use, but available if state needs to be set */
int sha256_internal(unsigned char **output_ptr, unsigned char *input, size_t input_size, \
		    uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3, \
		    uint32_t h4, uint32_t h5, uint32_t h6, uint32_t h7);

/* Standard external wrapper around the internal sha1 function. */
int sha256(unsigned char **output_ptr, unsigned char *input, size_t input_size);

/* Standard function to prepend a secret key to a message before hashing. */
int key_prefix_sha256(unsigned char **output_ptr, unsigned char *input, size_t input_size, unsigned char *key, size_t key_size);

/* Easily represent a sha256 hash as a printable string. */
int sha256_hash_to_string(char **output_ptr, unsigned char *input);

#endif
