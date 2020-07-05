#ifndef SHAONE_H
#define SHAONE_H

#include "local_endian.h"
#include "crypto_utility.h"

#define SHA1_DIGEST_SIZE 20


int sha1_append_data(unsigned char **output_hash_ptr, unsigned char *input_hash, size_t previous_message_length, \
		     unsigned char *input_data, size_t input_data_size);
int sha1_pad_data(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size, size_t bytes_already_processed);


/* Not intended for outside use, but available if state needs to be set */
int sha1_internal(unsigned char **output_ptr, unsigned char *input, size_t input_size, \
		  uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3, uint32_t h4, size_t bytes_already_processed);

/* Standard external wrapper around the internal sha1 function. */
int sha1(unsigned char **output_ptr, unsigned char *input, size_t input_size);

/* Standard function to prepend a secret key to a message before hashing. */
int key_prefix_sha1(unsigned char **output_ptr, unsigned char *input, size_t input_size, unsigned char *key, size_t key_size);

/* Produce a forged hash using length extension with input_hash as the starting state.
 * hmac_validate_func is then used to try to find the original message length so that
 * the final forged message can include padding and the correct ml value.
 *
 * Returns 0 on success, 1 on failure, or -1 if any output ptrptr is NULL
 */
int sha1_extend_forge_hmac(unsigned char **forged_hash_ptr, unsigned char **forged_message_ptr, size_t *forged_message_size_ptr, \
			   unsigned char *input_hash, unsigned char *input_data, size_t input_data_size, \
			   unsigned char *original_message, size_t original_message_size, \
			   int (*validate_hmac)(unsigned char *forged_hmac, unsigned char *forged_message, size_t forged_message_len) );

/* Easily represent a sha1 hash as a printable string. */
int sha1_hash_to_string(char **output_ptr, unsigned char *input);

#endif
