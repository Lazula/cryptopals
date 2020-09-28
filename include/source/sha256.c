#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sha256.h"

#define DEBUG_SHA256 0

/* "static" variable undefined at end of file.
 * Must be a define instead of a variable to
 * be accepted with const variables.
 */
#define SHA256_BLOCK_SIZE 64

static int sha256_pad_data(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size){
	size_t bytes_to_add;

	size_t padded_data_size;
	unsigned char *padded_data;

	uint32_t ml;
	uint32_t ml_big_endian;

	/* Get number of padding bytes */
	bytes_to_add = SHA256_BLOCK_SIZE - (((input_data_size % SHA256_BLOCK_SIZE) + (sizeof(uint32_t) * 2)) % SHA256_BLOCK_SIZE);
	if(bytes_to_add == SHA256_BLOCK_SIZE) bytes_to_add = 0;

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

	ml = input_data_size * CHAR_BIT;
	ml_big_endian = UINT32_HOST_TO_BIG_ENDIAN(ml);
	memcpy(padded_data+input_data_size+bytes_to_add+sizeof(uint32_t), &ml_big_endian, sizeof(uint32_t));

	return 0;
}

/* Not intended for outside use. Use one of the wrapper functions if possible.
 *
 * h0-7 are the big-endian SHA1 register values to use.
 */
int sha256_internal(unsigned char **output_ptr, unsigned char *input, size_t input_size, \
		    uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3, \
		    uint32_t h4, uint32_t h5, uint32_t h6, uint32_t h7){
	size_t i, j;

	uint8_t *preprocessed_input = NULL;
	size_t preprocessed_input_size;

	uint32_t w[64];
	const uint32_t k[64] = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	uint32_t a;
	uint32_t b;
	uint32_t c;
	uint32_t d;
	uint32_t e;
	uint32_t f;
	uint32_t g;
	uint32_t h;

	uint32_t temp1;
	uint32_t temp2;

	sha256_pad_data(&preprocessed_input, &preprocessed_input_size, input, input_size);

	for(i = 0; i < preprocessed_input_size; i += SHA256_BLOCK_SIZE){
		for(j = 0; j < 16; j++){
			memcpy(&w[j], (preprocessed_input+i)+(j*sizeof(uint32_t)), sizeof(uint32_t));
			w[j] = UINT32_HOST_TO_BIG_ENDIAN(w[j]);
		}

		#if DEBUG_SHA256 && 1
			printf("Initial 16 word values:\n");
			for(j = 0; j < 16; j++) printf("w[%02lu] = 0x%08x\n", j, w[j]);
			printf("\n");
		#endif

		for(j = 16; j < 64; j++){
			w[j] = w[j-16] + \
				(UINT32_ROTATE_RIGHT(w[j-15],  7) ^ UINT32_ROTATE_RIGHT(w[j-15], 18) ^ (w[j-15] >>  3)) + \
				 w[j-7] + \
				(UINT32_ROTATE_RIGHT(w[j- 2], 17) ^ UINT32_ROTATE_RIGHT(w[j- 2], 19) ^ (w[j- 2] >> 10));
		}


		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;
		f = h5;
		g = h6;
		h = h7;

		for(j = 0; j < 64; j++){
			temp1 = h + \
				(UINT32_ROTATE_RIGHT(e, 6) ^ UINT32_ROTATE_RIGHT(e, 11) ^ UINT32_ROTATE_RIGHT(e, 25)) + \
				((e & f) ^ ((~e) & g)) + k[j] + w[j];
			temp2 = (UINT32_ROTATE_RIGHT(a, 2) ^ UINT32_ROTATE_RIGHT(a, 13) ^ UINT32_ROTATE_RIGHT(a, 22)) + \
				((a & b) ^ (a & c) ^ (b & c));

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	#if DEBUG_SHA256 && 1
		printf("Final big-endian state values:\n");
		printf("h0 = 0x%08x\n", h0);
		printf("h1 = 0x%08x\n", h1);
		printf("h2 = 0x%08x\n", h2);
		printf("h3 = 0x%08x\n", h3);
		printf("h4 = 0x%08x\n", h4);
		printf("h5 = 0x%08x\n", h5);
		printf("h6 = 0x%08x\n", h6);
		printf("h7 = 0x%08x\n", h7);
		printf("\n");
	#endif

	h0 = UINT32_BIG_TO_HOST_ENDIAN(h0);
	h1 = UINT32_BIG_TO_HOST_ENDIAN(h1);
	h2 = UINT32_BIG_TO_HOST_ENDIAN(h2);
	h3 = UINT32_BIG_TO_HOST_ENDIAN(h3);
	h4 = UINT32_BIG_TO_HOST_ENDIAN(h4);
	h5 = UINT32_BIG_TO_HOST_ENDIAN(h5);
	h6 = UINT32_BIG_TO_HOST_ENDIAN(h6);
	h7 = UINT32_BIG_TO_HOST_ENDIAN(h7);

	if(output_ptr != NULL){
		if(*output_ptr == NULL) *output_ptr = malloc(SHA256_DIGEST_SIZE);
	}

	memcpy(*output_ptr+(sizeof(uint32_t)*0), &h0, sizeof(uint32_t));
	memcpy(*output_ptr+(sizeof(uint32_t)*1), &h1, sizeof(uint32_t));
	memcpy(*output_ptr+(sizeof(uint32_t)*2), &h2, sizeof(uint32_t));
	memcpy(*output_ptr+(sizeof(uint32_t)*3), &h3, sizeof(uint32_t));
	memcpy(*output_ptr+(sizeof(uint32_t)*4), &h4, sizeof(uint32_t));
	memcpy(*output_ptr+(sizeof(uint32_t)*5), &h5, sizeof(uint32_t));
	memcpy(*output_ptr+(sizeof(uint32_t)*6), &h6, sizeof(uint32_t));
	memcpy(*output_ptr+(sizeof(uint32_t)*7), &h7, sizeof(uint32_t));

	/* Zero all memory. */
	memset(preprocessed_input, 0, preprocessed_input_size);
	free(preprocessed_input);
	preprocessed_input = NULL;

	preprocessed_input_size = h0 = h1 = h2 = h3 = h4 = h5 = h6 = h7 = 0;
	a = b = c = d = e = f = g = h = temp1 = temp2 = 0;
	for(i = 0; i < 64; i++) w[i] = 0;
	i = j = 0;

	return 0;
}

/* External sha256 function. Sets default state values. */
int sha256(unsigned char **output_ptr, unsigned char *input, size_t input_size){
	uint32_t h0 = 0x6A09E667;
	uint32_t h1 = 0xBB67AE85;
	uint32_t h2 = 0x3C6EF372;
	uint32_t h3 = 0xA54FF53A;
	uint32_t h4 = 0x510E527F;
	uint32_t h5 = 0x9B05688C;
	uint32_t h6 = 0x1F83D9AB;
	uint32_t h7 = 0x5BE0CD19;

	return sha256_internal(output_ptr, input, input_size, h0, h1, h2, h3, h4, h5, h6, h7);
}

int key_prefix_sha256(unsigned char **output_ptr, unsigned char *input, size_t input_size, unsigned char *key, size_t key_size){
	unsigned char *combined_data = NULL;
	size_t combined_data_size;

	if(input == NULL || key == NULL) return 1;

	combined_data_size = input_size + key_size;
	combined_data = malloc(combined_data_size);

	memcpy(combined_data, key, key_size);
	memcpy(combined_data+key_size, input, input_size);

	sha256(output_ptr, combined_data, combined_data_size);

	free(combined_data);

	return 0;
}

int sha256_hash_to_string(char **output_ptr, unsigned char *input){
	size_t i;

	if(output_ptr == NULL){
		return 1;
	}else{
		if(*output_ptr == NULL) *output_ptr = malloc((SHA256_DIGEST_SIZE*2)+1);
		(*output_ptr)[SHA256_DIGEST_SIZE*2] = '\0';
	}

	for(i = 0; i < SHA256_DIGEST_SIZE; i++){
		sprintf((*output_ptr)+(i*2), "%02x", input[i]);
	}

	return 0;
}

#undef SHA256_BLOCK_SIZE
