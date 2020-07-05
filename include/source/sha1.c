#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sha1.h"

#define DEBUG_SHA1 0

/* "static" variable undefined at end of file.
 * Must be a define instead of a variable to
 * be accepted with const variables.
 */
#define SHA1_BLOCK_SIZE 64

/* Extend an existing SHA1 hash, passing the given hash into the internal SHA1 function
 * as the five internal register values.
 *
 * You must provide the length of the previous message.
 */
int sha1_append_data(unsigned char **output_hash_ptr, unsigned char *input_hash, size_t previous_message_length, unsigned char *input_data, size_t input_data_size){
	uint32_t h0;
	uint32_t h1;
	uint32_t h2;
	uint32_t h3;
	uint32_t h4;

	size_t padded_previous_message_length;

	/* Retrieve state values */
	memcpy(&h0, input_hash+(sizeof(uint32_t)*0), sizeof(uint32_t));
	memcpy(&h1, input_hash+(sizeof(uint32_t)*1), sizeof(uint32_t));
	memcpy(&h2, input_hash+(sizeof(uint32_t)*2), sizeof(uint32_t));
	memcpy(&h3, input_hash+(sizeof(uint32_t)*3), sizeof(uint32_t));
	memcpy(&h4, input_hash+(sizeof(uint32_t)*4), sizeof(uint32_t));

	h0 = UINT32_T_HOST_TO_BIG_ENDIAN(h0);
	h1 = UINT32_T_HOST_TO_BIG_ENDIAN(h1);
	h2 = UINT32_T_HOST_TO_BIG_ENDIAN(h2);
	h3 = UINT32_T_HOST_TO_BIG_ENDIAN(h3);
	h4 = UINT32_T_HOST_TO_BIG_ENDIAN(h4);

	/* Get the correct message length. */
	sha1_pad_data(NULL, &padded_previous_message_length, NULL, previous_message_length, 0);

	/* Acquire the hash that will be used with the padded original message
 	 * and appended with out input.
	 */
	return sha1_internal(output_hash_ptr, input_data, input_data_size, h0, h1, h2, h3, h4, padded_previous_message_length);
}

int sha1_pad_data(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size, size_t bytes_already_processed){
	size_t bytes_to_add;
	
	size_t padded_data_size;
	unsigned char *padded_data;

	uint32_t ml;
	uint32_t ml_big_endian;


	/* Get number of padding bytes */
	bytes_to_add = SHA1_BLOCK_SIZE - (((input_data_size % SHA1_BLOCK_SIZE) + (sizeof(uint32_t) * 2)) % SHA1_BLOCK_SIZE);
	if(bytes_to_add == SHA1_BLOCK_SIZE) bytes_to_add = 0;

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

	ml = (input_data_size + bytes_already_processed) * CHAR_BIT;
	ml_big_endian = UINT32_T_HOST_TO_BIG_ENDIAN(ml);
	memcpy(padded_data+input_data_size+bytes_to_add+sizeof(uint32_t), &ml_big_endian, sizeof(uint32_t));

	return 0;
}



/* Not intended for outside use. Use one of the wrapper functions if possible.
 *
 * h0-4 are the big-endian SHA1 register values to use.
 * bytes_already_processed in used when appending data to an existing hash. It should be a multiple of 64.
 */
int sha1_internal(unsigned char **output_ptr, unsigned char *input, size_t input_size, \
		  uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3, uint32_t h4, size_t bytes_already_processed){
	size_t i, j;

	uint8_t *preprocessed_input = NULL;
	size_t preprocessed_input_size;

	uint8_t current_block[SHA1_BLOCK_SIZE];

	uint8_t hh[SHA1_DIGEST_SIZE];

	uint32_t w[80];

	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t k;

	uint32_t temp;

	sha1_pad_data(&preprocessed_input, &preprocessed_input_size, input, input_size, bytes_already_processed);

	for(i = 0; i < preprocessed_input_size; i += SHA1_BLOCK_SIZE){
		memcpy(current_block, preprocessed_input+i, SHA1_BLOCK_SIZE);
		for(j = 0; j < 16; j++){
			memcpy(&w[j], current_block+(j*sizeof(uint32_t)), sizeof(uint32_t));
			w[j] = UINT32_T_HOST_TO_BIG_ENDIAN(w[j]);
		}

		#if DEBUG_SHA1 && 1
			printf("Initial 16 word values:\n");
			for(j = 0; j < 16; j++) printf("w[%02lu] = 0x%08x\n", j, w[j]);
			printf("\n");
		#endif

		for(j = 16; j < 80; j++){
			w[j] = UINT32_T_ROTATE_LEFT((w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]), 1);
		}


		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;

		for(j = 0; j < 80; j++){
			if(j < 20){
				f = (b & c) | ((~b) & d);
				k = 0x5A827999;
			}else if(j < 40){
				f = b ^ c ^ d;
				k = 0x6ED9EBA1;
			}else if(j < 60){
				f = (b & c) | (b & d) | (c & d);
				k = 0x8F1BBCDC;
			}else{
				f = b ^ c ^ d;
				k = 0xCA62C1D6;
			}

			temp = UINT32_T_ROTATE_LEFT(a, 5) + f + e + k + w[j];
			e = d;
			d = c;
			c = UINT32_T_ROTATE_LEFT(b, 30);
			b = a;
			a = temp;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
	}

	#if DEBUG_SHA1 && 1
		printf("Final big-endian state values:\n");
		printf("h0 = 0x%08x\n", h0);
		printf("h1 = 0x%08x\n", h1);
		printf("h2 = 0x%08x\n", h2);
		printf("h3 = 0x%08x\n", h3);
		printf("h4 = 0x%08x\n", h4);
		printf("\n");
	#endif

	h0 = UINT32_T_BIG_TO_HOST_ENDIAN(h0);
	h1 = UINT32_T_BIG_TO_HOST_ENDIAN(h1);
	h2 = UINT32_T_BIG_TO_HOST_ENDIAN(h2);
	h3 = UINT32_T_BIG_TO_HOST_ENDIAN(h3);
	h4 = UINT32_T_BIG_TO_HOST_ENDIAN(h4);

	memcpy(hh+(sizeof(uint32_t)*0), &h0, sizeof(uint32_t));
	memcpy(hh+(sizeof(uint32_t)*1), &h1, sizeof(uint32_t));
	memcpy(hh+(sizeof(uint32_t)*2), &h2, sizeof(uint32_t));
	memcpy(hh+(sizeof(uint32_t)*3), &h3, sizeof(uint32_t));
	memcpy(hh+(sizeof(uint32_t)*4), &h4, sizeof(uint32_t));

	if(output_ptr != NULL){
		if(*output_ptr == NULL) *output_ptr = malloc(SHA1_DIGEST_SIZE);
		memcpy(*output_ptr, hh, SHA1_DIGEST_SIZE);
	}

	/* Zero all memory. */
	memset(preprocessed_input, 0, preprocessed_input_size);
	free(preprocessed_input);
	preprocessed_input = NULL;

	preprocessed_input_size = h0 = h1 = h2 = h3 = h4 = 0;
	a = b = c = d = e = f = k = temp = 0;
	for(i = 0; i < 80; i++) w[i] = 0;
	for(i = 0; i < SHA1_DIGEST_SIZE; i++) hh[i] = 0;
	for(i = 0; i < SHA1_BLOCK_SIZE; i++) current_block[i] = 0;
	i = j = 0;

	return 0;
}

/* External sha1 function. Sets default state values. */
int sha1(unsigned char **output_ptr, unsigned char *input, size_t input_size){
	uint32_t h0 = 0x67452301;
	uint32_t h1 = 0xEFCDAB89;
	uint32_t h2 = 0x98BADCFE;
	uint32_t h3 = 0x10325476;
	uint32_t h4 = 0xC3D2E1F0;

	return sha1_internal(output_ptr, input, input_size, h0, h1, h2, h3, h4, 0);
}

int key_prefix_sha1(unsigned char **output_ptr, unsigned char *input, size_t input_size, unsigned char *key, size_t key_size){
	unsigned char *combined_data = NULL;
	size_t combined_data_size;

	if(input == NULL || key == NULL) return 1;

	combined_data_size = input_size + key_size;
	combined_data = malloc(combined_data_size);

	memcpy(combined_data, key, key_size);
	memcpy(combined_data+key_size, input, input_size);

	sha1(output_ptr, combined_data, combined_data_size);

	free(combined_data);

	return 0;
}

/* Produce a forged hash using length extension with input_hash as the starting state.
 * validate_hmac() is then used to try to find the original message length so that
 * the final forged message can include padding and the correct ml value.
 *
 * Returns 0 on success, 1 on failure, or -1 if any output ptrptr is NULL
 */
int sha1_extend_forge_hmac(unsigned char **forged_hash_ptr, unsigned char **forged_message_ptr, size_t *forged_message_size_ptr, \
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
		sha1_append_data(&forged_hash, input_hash, guessed_key_size+original_message_size, input_data, input_data_size);

		/* Prepend garbage key bytes to get the correct number of
		 * padding bytes and ml value.
		 */
		original_message_with_garbage_key_bytes_size = original_message_size + guessed_key_size;
		original_message_with_garbage_key_bytes = malloc(original_message_with_garbage_key_bytes_size);
		memset(original_message_with_garbage_key_bytes, 'A', guessed_key_size);
		memcpy(original_message_with_garbage_key_bytes+guessed_key_size, original_message, original_message_size);

		/* Get the padding that would be used with the given key size */
		sha1_pad_data(&padded_original_message_with_garbage_key_bytes, &padded_original_message_with_garbage_key_bytes_size,
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
			if(*forged_hash_ptr == NULL) *forged_hash_ptr = malloc(SHA1_DIGEST_SIZE);
			if(*forged_message_ptr == NULL) *forged_message_ptr = malloc(full_forged_message_size);

			memcpy(*forged_hash_ptr, forged_hash, SHA1_DIGEST_SIZE);
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

int sha1_hash_to_string(char **output_ptr, unsigned char *input){
	size_t i;

	if(output_ptr == NULL){
		return 1;
	}else{
		if(*output_ptr == NULL) *output_ptr = malloc((SHA1_DIGEST_SIZE*2)+1);
		(*output_ptr)[SHA1_DIGEST_SIZE*2] = '\0';
	}

	for(i = 0; i < SHA1_DIGEST_SIZE; i++){
		sprintf((*output_ptr)+(i*2), "%02x", input[i]);
	}

	return 0;
}

#undef SHA1_BLOCK_SIZE
