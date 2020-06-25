/* TODO
 * [DONE] -get the algorithm working
 * [UP NEXT] -create a sha1_internal() function with state arguments
 *  that is called from sha1() to provide the option to
 *  use a more low-level interface
 * -sha1_extend() should use sha1_internal()
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sha1.h"

#define DEBUG_SHA1 0

/* "static" variable undefined at end of file */
#define SHA1_BLOCK_SIZE 64

/* Not intended for outside use. Use one of the wrapper functions if possible. */
static int sha1_internal(unsigned char **output_ptr, unsigned char *input, size_t input_size, \
			 uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3, uint32_t h4){
	size_t i, j;

	uint8_t *preprocessed_input;
	size_t preprocessed_input_size;

	uint8_t current_block[SHA1_BLOCK_SIZE];

	size_t bytes_to_add;

	uint8_t hh[SHA1_DIGEST_SIZE];

	uint32_t ml;
	uint32_t ml_big_endian;

	uint32_t w[80];

	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t k;

	uint32_t temp;

	bytes_to_add = SHA1_BLOCK_SIZE - (((input_size % SHA1_BLOCK_SIZE) + (sizeof(uint32_t) * 2)) % SHA1_BLOCK_SIZE);
	if(bytes_to_add == SHA1_BLOCK_SIZE) bytes_to_add = 0;

	preprocessed_input_size = input_size + bytes_to_add + (sizeof(uint32_t) * 2);
	preprocessed_input = malloc(preprocessed_input_size);

	memcpy(preprocessed_input, input, input_size);
	memset(preprocessed_input+input_size, 0, bytes_to_add);

	preprocessed_input[input_size] = (unsigned char) 0x80;

	memset(preprocessed_input+input_size+bytes_to_add, 0, sizeof(uint32_t));

	ml = input_size * CHAR_BIT;
	ml_big_endian = UINT32_T_HOST_TO_BIG_ENDIAN(ml);
	memcpy(preprocessed_input+input_size+bytes_to_add+sizeof(uint32_t), &ml_big_endian, sizeof(uint32_t));

	#if DEBUG_SHA1 && 1
		printf("ml = 0x%08x (%u)\n", ml, ml);
		printf("ml_big_endian = 0x%08x\n", ml_big_endian);
		printf("[DEBUG_SHA1] Preprocessed input:\n");
		for(i = 0; i < preprocessed_input_size; i++) printf("%02x", preprocessed_input[i]);
		printf("\n");
		for(i = 0; i < input_size; i++) printf(" %c", preprocessed_input[i]);
		printf("\n");
	#endif

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

	free(preprocessed_input);

	/* Zero all memory. */
	memset(preprocessed_input, 0, preprocessed_input_size);
	preprocessed_input_size = h0 = h1 = h2 = h3 = h4 = 0;
	a = b = c = d = e = f = k = temp = ml = ml_big_endian = bytes_to_add = 0;
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

	return sha1_internal(output_ptr, input, input_size, h0, h1, h2, h3, h4);
}

int key_prefix_sha1(unsigned char **output_ptr, unsigned char *input, size_t input_size, unsigned char *key, size_t key_size){
	unsigned char *combined_data;
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
