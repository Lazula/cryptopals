#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../md4.h"

#define DEBUG_MD4 0

/* "static" variable undefined at end of file.
 * Must be a define instead of a variable to
 * be accepted with const variables.
 */
#define MD4_BLOCK_SIZE 64

/* Internal auxiliary functions */
#define MD4_INTERNAL_FUNC_F(X, Y, Z) (((X) & (Y)) | ((~(X)) & (Z)))
#define MD4_INTERNAL_FUNC_G(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define MD4_INTERNAL_FUNC_H(X, Y, Z) ((X) ^ (Y) ^ (Z))

/* Extend an existing MD4 hash, passing the given hash into the internal MD4 function
 * as the five internal register values.
 *
 * You must provide the length of the previous message.
 */
int md4_append_data(unsigned char **output_hash_ptr, unsigned char *input_hash, size_t previous_message_length, unsigned char *input_data, size_t input_data_size){
	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;

	size_t padded_previous_message_length;

	/* Retrieve state values */
	memcpy(&a, input_hash+(sizeof(uint32_t)*0), sizeof(uint32_t));
	memcpy(&b, input_hash+(sizeof(uint32_t)*1), sizeof(uint32_t));
	memcpy(&c, input_hash+(sizeof(uint32_t)*2), sizeof(uint32_t));
	memcpy(&d, input_hash+(sizeof(uint32_t)*3), sizeof(uint32_t));

	a = UINT32_HOST_TO_LITTLE_ENDIAN(a);
	b = UINT32_HOST_TO_LITTLE_ENDIAN(b);
	c = UINT32_HOST_TO_LITTLE_ENDIAN(c);
	d = UINT32_HOST_TO_LITTLE_ENDIAN(d);

	/* Get the correct message length. */
	md4_pad_data(NULL, &padded_previous_message_length, NULL, previous_message_length, 0);

	/* Acquire the hash that will be used with the padded original message
 	 * and appended with out input.
	 */
	return md4_internal(output_hash_ptr, input_data, input_data_size, a, b, c, d, padded_previous_message_length);
}

int md4_pad_data(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size, size_t bytes_already_processed){
	size_t bytes_to_add;
	
	size_t padded_data_size;
	unsigned char *padded_data;

	uint32_t b;
	uint32_t b_little_endian;

	/* Get number of padding bytes */
	bytes_to_add = MD4_BLOCK_SIZE - (((input_data_size % MD4_BLOCK_SIZE) + (sizeof(uint32_t) * 2)) % MD4_BLOCK_SIZE);
	if(bytes_to_add == MD4_BLOCK_SIZE) bytes_to_add = 0;

	/* Get total size */
	padded_data_size = input_data_size + bytes_to_add + (sizeof(uint32_t) * 2);

	/* Assign output variables */
	/* Write size if possible */
	if(!output_size_ptr) return 1;
	*output_size_ptr = padded_data_size;

	/* Before checking if we should leave for lack of output buffer */
	if(!output_ptr) return 1;
	if( ! (*output_ptr) ) *output_ptr = malloc(padded_data_size);

	/* Nicer than using (*output_ptr) everywhere */
	padded_data = *output_ptr;

	memcpy(padded_data, input_data, input_data_size);
	memset(padded_data+input_data_size, 0, bytes_to_add+sizeof(uint32_t));

	padded_data[input_data_size] = (unsigned char) 0x80;

	b = (input_data_size + bytes_already_processed) * CHAR_BIT;
	b_little_endian = UINT32_HOST_TO_LITTLE_ENDIAN(b);
	memcpy(padded_data+input_data_size+bytes_to_add+sizeof(uint32_t), &b_little_endian, sizeof(uint32_t));

	return 0;
}



/* Not intended for outside use. Use one of the wrapper functions if possible.
 *
 * a, b, c, d are the big-endian MD4 register values to use.
 * bytes_already_processed in used when appending data to an existing hash. It should be a multiple of 64.
 *
 * Reference: https://tools.ietf.org/html/rfc1320
 */
int md4_internal(unsigned char **output_ptr, unsigned char *input, size_t input_size, \
		 uint32_t a, uint32_t b, uint32_t c, uint32_t d, size_t bytes_already_processed){
	size_t i, j;

	uint8_t *preprocessed_input = NULL;
	size_t preprocessed_input_size;

	uint8_t current_block[MD4_BLOCK_SIZE];

	uint8_t out[MD4_DIGEST_SIZE];

	uint32_t X[16];

	uint32_t aa;
	uint32_t bb;
	uint32_t cc;
	uint32_t dd;

	md4_pad_data(&preprocessed_input, &preprocessed_input_size, input, input_size, bytes_already_processed);

	for(i = 0; i < preprocessed_input_size; i += MD4_BLOCK_SIZE){
		memcpy(current_block, preprocessed_input+i, MD4_BLOCK_SIZE);
		for(j = 0; j < 16; j++){
			memcpy(&X[j], current_block+(j*sizeof(uint32_t)), sizeof(uint32_t));
			X[j] = UINT32_HOST_TO_LITTLE_ENDIAN(X[j]);
		}

		#if DEBUG_MD4 && 1
			printf("Initial 16 word values:\n");
			for(j = 0; j < 16; j++) printf("X[%02lu] = 0x%08x\n", j, X[j]);
			printf("\n");
		#endif

		aa = a;
		bb = b;
		cc = c;
		dd = d;

		#if DEBUG_MD4 && 1
			printf("Initial little-endian state values:\n");
			printf("a = 0x%08x\n", a);
			printf("b = 0x%08x\n", b);
			printf("c = 0x%08x\n", c);
			printf("d = 0x%08x\n", d);
			printf("\n");
		#endif

		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_F(b, c, d) + X[ 0], 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_F(a, b, c) + X[ 1], 7);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_F(d, a, b) + X[ 2], 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_F(c, d, a) + X[ 3], 19);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_F(b, c, d) + X[ 4], 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_F(a, b, c) + X[ 5], 7);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_F(d, a, b) + X[ 6], 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_F(c, d, a) + X[ 7], 19);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_F(b, c, d) + X[ 8], 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_F(a, b, c) + X[ 9], 7);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_F(d, a, b) + X[10], 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_F(c, d, a) + X[11], 19);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_F(b, c, d) + X[12], 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_F(a, b, c) + X[13], 7);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_F(d, a, b) + X[14], 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_F(c, d, a) + X[15], 19);

		#if DEBUG_MD4 && 1
			printf("Little-endian state values after round 1:\n");
			printf("a = 0x%08x\n", a);
			printf("b = 0x%08x\n", b);
			printf("c = 0x%08x\n", c);
			printf("d = 0x%08x\n", d);
			printf("\n");
		#endif

		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_G(b, c, d) + X[ 0] + 0x5a827999, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_G(a, b, c) + X[ 4] + 0x5a827999, 5);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_G(d, a, b) + X[ 8] + 0x5a827999, 9);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_G(c, d, a) + X[12] + 0x5a827999, 13);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_G(b, c, d) + X[ 1] + 0x5a827999, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_G(a, b, c) + X[ 5] + 0x5a827999, 5);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_G(d, a, b) + X[ 9] + 0x5a827999, 9);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_G(c, d, a) + X[13] + 0x5a827999, 13);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_G(b, c, d) + X[ 2] + 0x5a827999, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_G(a, b, c) + X[ 6] + 0x5a827999, 5);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_G(d, a, b) + X[10] + 0x5a827999, 9);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_G(c, d, a) + X[13] + 0x5a827999, 13);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_G(b, c, d) + X[ 3] + 0x5a827999, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_G(a, b, c) + X[ 7] + 0x5a827999, 5);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_G(d, a, b) + X[11] + 0x5a827999, 9);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_G(c, d, a) + X[15] + 0x5a827999, 13);

		#if DEBUG_MD4 && 1
			printf("Little-endian state values after round 2:\n");
			printf("a = 0x%08x\n", a);
			printf("b = 0x%08x\n", b);
			printf("c = 0x%08x\n", c);
			printf("d = 0x%08x\n", d);
			printf("\n");
		#endif

		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_H(b, c, d) + X[ 0] + 0x6Ed9Eba1, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_H(a, b, c) + X[ 8] + 0x6Ed9Eba1, 9);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_H(d, a, b) + X[ 4] + 0x6Ed9Eba1, 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_H(c, d, a) + X[12] + 0x6Ed9Eba1, 15);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_H(b, c, d) + X[ 2] + 0x6Ed9Eba1, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_H(a, b, c) + X[10] + 0x6Ed9Eba1, 9);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_H(d, a, b) + X[ 6] + 0x6Ed9Eba1, 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_H(c, d, a) + X[14] + 0x6Ed9Eba1, 15);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_H(b, c, d) + X[ 1] + 0x6Ed9Eba1, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_H(a, b, c) + X[ 9] + 0x6Ed9Eba1, 9);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_H(d, a, b) + X[ 5] + 0x6Ed9Eba1, 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_H(c, d, a) + X[13] + 0x6Ed9Eba1, 15);
		a = UINT32_ROTATE_LEFT(a + MD4_INTERNAL_FUNC_H(b, c, d) + X[ 3] + 0x6Ed9Eba1, 3);
		d = UINT32_ROTATE_LEFT(d + MD4_INTERNAL_FUNC_H(a, b, c) + X[11] + 0x6Ed9Eba1, 9);
		c = UINT32_ROTATE_LEFT(c + MD4_INTERNAL_FUNC_H(d, a, b) + X[ 7] + 0x6Ed9Eba1, 11);
		b = UINT32_ROTATE_LEFT(b + MD4_INTERNAL_FUNC_H(c, d, a) + X[15] + 0x6Ed9Eba1, 15);

		a += aa;
		b += bb;
		c += cc;
		d += dd;
	}

	#if DEBUG_MD4 && 1
		printf("Final little-endian state values:\n");
		printf("a = 0x%08x\n", a);
		printf("b = 0x%08x\n", b);
		printf("c = 0x%08x\n", c);
		printf("d = 0x%08x\n", d);
		printf("\n");
	#endif

	a = UINT32_LITTLE_TO_HOST_ENDIAN(a);
	b = UINT32_LITTLE_TO_HOST_ENDIAN(b);
	c = UINT32_LITTLE_TO_HOST_ENDIAN(c);
	d = UINT32_LITTLE_TO_HOST_ENDIAN(d);

	memcpy(out+(sizeof(uint32_t)*0), &a, sizeof(uint32_t));
	memcpy(out+(sizeof(uint32_t)*1), &b, sizeof(uint32_t));
	memcpy(out+(sizeof(uint32_t)*2), &c, sizeof(uint32_t));
	memcpy(out+(sizeof(uint32_t)*3), &d, sizeof(uint32_t));

	if(output_ptr != NULL){
		if(*output_ptr == NULL) *output_ptr = malloc(MD4_DIGEST_SIZE);
		memcpy(*output_ptr, out, MD4_DIGEST_SIZE);
	}

	/* Zero all memory. */
	memset(preprocessed_input, 0, preprocessed_input_size);
	free(preprocessed_input);
	preprocessed_input = NULL;

	preprocessed_input_size = a = b = c = d = 0;
	aa = bb = cc = dd = 0;
	for(i = 0; i < 16; i++) X[i] = 0;
	for(i = 0; i < MD4_DIGEST_SIZE; i++) out[i] = 0;
	for(i = 0; i < MD4_BLOCK_SIZE; i++) current_block[i] = 0;
	i = j = 0;

	return 0;
}

/* External md4 function. Sets default state values. */
int md4(unsigned char **output_ptr, unsigned char *input, size_t input_size){
	uint32_t a = 0x67452301;
	uint32_t b = 0xEFCDAB89;
	uint32_t c = 0x98BADCFE;
	uint32_t d = 0x10325476;

	return md4_internal(output_ptr, input, input_size, a, b, c, d, 0);
}

int key_prefix_md4(unsigned char **output_ptr, unsigned char *input, size_t input_size, unsigned char *key, size_t key_size){
	unsigned char *combined_data = NULL;
	size_t combined_data_size;

	if(input == NULL || key == NULL) return 1;

	combined_data_size = input_size + key_size;
	combined_data = malloc(combined_data_size);

	memcpy(combined_data, key, key_size);
	memcpy(combined_data+key_size, input, input_size);

	md4(output_ptr, combined_data, combined_data_size);

	free(combined_data);

	return 0;
}

/* Produce a forged hash using length extension with input_hash as the starting state.
 * validate_hmac() is then used to try to find the original message length so that
 * the final forged message can include padding and the correct ml value.
 *
 * Returns 0 on success, 1 on failure, or -1 if any output ptrptr is NULL
 */
int md4_extend_forge_hmac(unsigned char **forged_hash_ptr, unsigned char **forged_message_ptr, size_t *forged_message_size_ptr, \
			   unsigned char *input_hash, unsigned char *input_data, size_t input_data_size, \
			   unsigned char *original_message, size_t original_message_size, \
			   int (*validate_hmac)(unsigned char *forged_hmac, unsigned char *forged_message, size_t forged_message_len) ){
	unsigned char *forged_hash = NULL;

	unsigned char *original_message_with_garbage_key_bytes = NULL;
	size_t original_message_with_garbage_key_bytes_size;

	unsigned char *padded_original_message_with_garbage_key_bytes = NULL;
	size_t padded_original_message_with_garbage_key_bytes_size;

	unsigned char *padded_original_message = NULL;
	size_t padded_original_message_size;

	unsigned char *full_forged_message = NULL;
	size_t full_forged_message_size;

	size_t guessed_key_size;

	if(!forged_hash_ptr || !forged_message_ptr || !forged_message_size_ptr) return -1;


	/* Guess key sizes up to 100 before giving up */
	for(guessed_key_size = 0; guessed_key_size < 100; guessed_key_size++){
		md4_append_data(&forged_hash, input_hash, guessed_key_size+original_message_size, input_data, input_data_size);

		/* Prepend garbage key bytes to get the correct number of
		 * padding bytes and ml value.
		 */
		original_message_with_garbage_key_bytes_size = original_message_size + guessed_key_size;
		original_message_with_garbage_key_bytes = malloc(original_message_with_garbage_key_bytes_size);
		memset(original_message_with_garbage_key_bytes, 'A', guessed_key_size);
		memcpy(original_message_with_garbage_key_bytes+guessed_key_size, original_message, original_message_size);

		/* Get the padding that would be used with the given key size */
		md4_pad_data(&padded_original_message_with_garbage_key_bytes, &padded_original_message_with_garbage_key_bytes_size,
			      original_message_with_garbage_key_bytes, original_message_with_garbage_key_bytes_size, 0);
		free(original_message_with_garbage_key_bytes);
		original_message_with_garbage_key_bytes = NULL;

		/* Remove the garbage key bytes from the padded message */
		padded_original_message_size = padded_original_message_with_garbage_key_bytes_size - guessed_key_size;
		padded_original_message = malloc(padded_original_message_size);
		memcpy(padded_original_message, padded_original_message_with_garbage_key_bytes+guessed_key_size, padded_original_message_size);
		free(padded_original_message_with_garbage_key_bytes);
		padded_original_message_with_garbage_key_bytes = NULL;

		/* Add the message extension */
		full_forged_message_size = padded_original_message_size + input_data_size;
		full_forged_message = malloc(full_forged_message_size);
		memcpy(full_forged_message, padded_original_message, padded_original_message_size);
		memcpy(full_forged_message+padded_original_message_size, input_data, input_data_size);
		free(padded_original_message);

		/* Finally, pass our padded message with the extension
		 * to validate_hmac() to see if we have the correct size.
		 */
		if(validate_hmac(forged_hash, full_forged_message, full_forged_message_size)){
			if(*forged_hash_ptr == NULL) *forged_hash_ptr = malloc(MD4_DIGEST_SIZE);
			if(*forged_message_ptr == NULL) *forged_message_ptr = malloc(full_forged_message_size);

			memcpy(*forged_hash_ptr, forged_hash, MD4_DIGEST_SIZE);
			memcpy(*forged_message_ptr, full_forged_message, full_forged_message_size);
			*forged_message_size_ptr = full_forged_message_size;

			free(forged_hash);
			free(full_forged_message);
			return 0;
		}

		free(forged_hash);
		free(full_forged_message);

		forged_hash = NULL;
	}

	return 1;
}

int md4_hash_to_string(char **output_ptr, unsigned char *input){
	size_t i;

	if(output_ptr == NULL){
		return 1;
	}else{
		if(*output_ptr == NULL) *output_ptr = malloc((MD4_DIGEST_SIZE*2)+1);
		(*output_ptr)[MD4_DIGEST_SIZE*2] = '\0';
	}

	for(i = 0; i < MD4_DIGEST_SIZE; i++){
		sprintf((*output_ptr)+(i*2), "%02x", input[i]);
	}

	return 0;
}

#undef MD4_BLOCK_SIZE
#undef MD4_INTERNAL_FUNC_F
#undef MD4_INTERNAL_FUNC_G
#undef MD4_INTERNAL_FUNC_H
