/*
 * Reference used:
 * ECB Mode
 * https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
 * CBC Mode
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../aes.h"

/*
 * State is always 128 bits, regardless of key size and cipher type
 */
struct aes_state {
	uint8_t key_type;
	uint8_t cipher_type;
	uint8_t bytes[4][4];
};

/* 
 * AES keys in the key schedule are always 128 bits. The number of derived keys depends on the given key size.
 */
struct aes_key {
	uint8_t bytes[4][4];
};

uint32_t sub_word(uint32_t word);
uint32_t rot_word(uint32_t word);
void expand_key(struct aes_key *key_schedule[15], uint8_t key_type, uint8_t *key);
void add_round_key(struct aes_state *state, struct aes_key *current_key);
void cipher(struct aes_state *state, struct aes_key *key_schedule[15]);
void inv_cipher(struct aes_state *state, struct aes_key *key_schedule[15]);
void sub_bytes(struct aes_state *state);
void shift_rows(struct aes_state *state);
void mix_columns(struct aes_state *state);
void inv_sub_bytes(struct aes_state *state);
void inv_shift_rows(struct aes_state *state);
void inv_mix_columns(struct aes_state *state);
uint8_t gf_mult(uint8_t multiplicand, uint8_t multiplier);

/* 
 * Debugging functions which print out a given state/key
 */
void dump_state(struct aes_state *state);
void dump_key(struct aes_key *key);

static const uint8_t sub_box[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t inv_sub_box[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint32_t round_constants[10] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

/*
 * Parameters:
 * **output: Automatically allocates *output for the correct size if == NULL
 * *input: Data to be encrypted. Binary safe.
 * *key: The main AES key. 16, 24, or 32 bytes based on key_type.
 * *initialization_vector: Used for CBC mode. Unused in ECB mode - can be 0.
 * cipher_type: Uses constants defined in aes.h such as AES_CIPHER_ECB to select cipher mode.
 * key_type: Uses constants defined in aes.h such as AES_KEY_128 to select key size. Currently supports 128, 192, and 256.
 * 
 * Returns: The size of the PKCS#7 padded and encrypted data block. Multiple of 16.
 * 
 * Notes:
 * - There may be a better way to handle the initialization vector since it isn't always used.
 */
size_t aes_encrypt(unsigned char **output, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type){
	uint8_t *padded_input = NULL;
	size_t padded_input_size;
	uint8_t *ciphertext;
	size_t output_size;
	struct aes_state *state;
	struct aes_state *prev_state;
	struct aes_key *key_schedule[15];
	
	uint8_t i, j;
	size_t state_index;
	
	uint8_t *input_ptr;
	uint8_t *output_ptr;
	
	
	padded_input_size = pkcs7_pad(&padded_input, input, input_size, 16);
	ciphertext = malloc(padded_input_size);
	
	if(output != NULL){
		if(*output == NULL){
			*output = malloc(padded_input_size);
		}
	}

	output_size = padded_input_size;
	
	state = malloc(sizeof(struct aes_state));
	state -> key_type = key_type;
	state -> cipher_type = cipher_type;
	
	prev_state = NULL;
	if(cipher_type == AES_CIPHER_CBC) prev_state = malloc(sizeof(struct aes_state));
	
	for(i = 0; i < 15; i++) key_schedule[i] = malloc(sizeof(struct aes_key));
		
	expand_key(key_schedule, state -> key_type, key);
	
	for(state_index = 0; state_index < padded_input_size; state_index += 16){
		input_ptr = (uint8_t *)(padded_input+state_index);
		for(i = 0; i < 4; i++){
			for(j = 0; j < 4; j++){
				/*
				 * AES states organize the data by column 
				 * "AAAABBBBCCCCDDDD"
				 * is placed in the matrix as follows:
				 * A B C D
				 * A B C D
				 * A B C D
				 * A B C D
				 */
				state -> bytes[i][j] = *(input_ptr+(j*4)+i);
			}
		}
		
		if(cipher_type == AES_CIPHER_CBC){
			if(state_index == 0){
				/* Apply IV */
				for(i = 0; i < 4; i++){
					for(j = 0; j < 4; j++){
						state -> bytes[i][j] ^= *(initialization_vector+(j*4)+i);
					}
				}
			}else{
				/* Apply previous ciphertext block */
				for(i = 0; i < 4; i++){
					for(j = 0; j < 4; j++){
						state -> bytes[i][j] ^= prev_state -> bytes[i][j];
					}
				}
			}
		}
		
		cipher(state, key_schedule);
		if(cipher_type == AES_CIPHER_CBC) memcpy(prev_state, state, sizeof(struct aes_state));
		
		output_ptr = (uint8_t *)((*output)+state_index);
		for(i = 0; i < 4; i++){
			for(j = 0; j < 4; j++){
				*(output_ptr+(j*4)+i) = state -> bytes[i][j];
			}
		}
	}
	
	if(cipher_type == AES_CIPHER_CBC) free(prev_state);	
	for(i = 0; i < 15; i++) free(key_schedule[i]);
	free(state);
	free(ciphertext);
	free(padded_input);
	
	return output_size;
}

/* 
 * Parameters:
 * *state: AES state to have cipher applied
 * *key_schedule: The AES key schedule to use
 * 
 * Returns: void
 */
void cipher(struct aes_state *state, struct aes_key *key_schedule[15]){
	uint8_t rounds;
	uint8_t round;
	
	switch(state -> key_type){
		/* 128 */
		case 0:
			rounds = 10;
			break;
		/* 192 */
		case 1:
			rounds = 12;
			break;
		/* 256 */
		case 2:
			rounds = 14;
			break;
		default:
			fprintf(stderr, "Invalid cipher type in cipher() on line %d in file %s.\n", __LINE__, __FILE__);
			exit(EXIT_FAILURE);
			break;
	}
	
	/* First round (0) */
	add_round_key(state, key_schedule[0]);
	
	/* Middle rounds (1 -> rounds-1) */
	for(round = 1; round < rounds; round++){
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, key_schedule[round]);
	}
	
	/* Final round (rounds) */
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, key_schedule[rounds]);
}

/*
 * Parameters:
 * **output: Automatically allocates *output for the correct size if == NULL (intended for binary data - will not add space for trailing \0)
 * *input: Data to be decrypted. Binary safe.
 * *key: The main AES key. 16, 24, or 32 bytes based on key_type.
 * *initialization_vector: Used for CBC mode. Unused in ECB mode - can be 0.
 * cipher_type: Uses constants defined in aes.h such as AES_CIPHER_ECB to select cipher mode.
 * key_type: Uses constants defined in aes.h such as AES_KEY_128 to select key size. Currently supports 128, 192, and 256.
 * 
 * Returns: The size of the PKCS#7 unpadded and decrypted data block.
 * 
 * Notes:
 * - There may be a better way to handle the initialization vector since it isn't always used.
 */
size_t aes_decrypt(unsigned char **output, unsigned char *input, size_t input_size, unsigned char *key, unsigned char *initialization_vector, uint8_t cipher_type, uint8_t key_type){
	uint8_t *cleartext = malloc(input_size);
	struct aes_state *state;
	struct aes_state *prev_state = NULL;
	struct aes_state *temp_state = NULL;
	struct aes_key *key_schedule[15];
	
	size_t state_index;
	uint8_t i, j;
	
	uint8_t *input_ptr;
	uint8_t *cleartext_ptr;
	
	size_t unpadded_output_size;
	
	state = malloc(sizeof(struct aes_state));
	state -> key_type = key_type;
	state -> cipher_type = cipher_type;
	
	if(cipher_type == AES_CIPHER_CBC){
		prev_state = malloc(sizeof(struct aes_state));
		temp_state = malloc(sizeof(struct aes_state));
	}
	
	for(i = 0; i < 15; i++){
		key_schedule[i] = malloc(sizeof(struct aes_key));
	}
	
	expand_key(key_schedule, state -> key_type, key);
	
	for(state_index = 0; state_index < input_size; state_index += 16){
		input_ptr = (uint8_t *)(input+state_index);
		for(i = 0; i < 4; i++){
			for(j = 0; j < 4; j++){
				state -> bytes[i][j] = *(input_ptr+(j*4)+i);
			}
		}
		
		if(cipher_type == AES_CIPHER_CBC){
			memcpy(temp_state, state, sizeof(struct aes_state));
		}
		
		inv_cipher(state, key_schedule);
		
		if(cipher_type == AES_CIPHER_CBC){
			if(state_index == 0){
				/* Apply IV */
				for(i = 0; i < 4; i++){
					for(j = 0; j < 4; j++){
						state -> bytes[i][j] ^= *(initialization_vector+(j*4)+i);
					}
				}
			}else{
				/* Apply previous ciphertext block */
				for(i = 0; i < 4; i++){
					for(j = 0; j < 4; j++){
						state -> bytes[i][j] ^= prev_state -> bytes[i][j];
					}
				}
			}
		}
		
		if(cipher_type == AES_CIPHER_CBC){
			memcpy(prev_state, temp_state, sizeof(struct aes_state));
		}
		
		cleartext_ptr = (uint8_t *)(cleartext+state_index);
		for(i = 0; i < 4; i++){
			for(j = 0; j < 4; j++){
				*(cleartext_ptr+(j*4)+i) = state -> bytes[i][j];
			}
		}
	}
	
	unpadded_output_size = pkcs7_unpad(output, cleartext, input_size, 16);
	
	if(cipher_type == AES_CIPHER_CBC){
		free(prev_state);
		free(temp_state);
	}
	for(i = 0; i < 15; i++) free(key_schedule[i]);
	free(state);
	free(cleartext);
	
	return unpadded_output_size;
}

/* 
 * Parameters:
 * *state: AES state to have inv_cipher applied
 * *key_schedule: The AES key schedule to use
 * 
 * Returns: void
 */
void inv_cipher(struct aes_state *state, struct aes_key *key_schedule[15]){
	uint8_t rounds;
	uint8_t round;
	
	switch(state -> key_type){
		/* 128 */
		case 0:
			rounds = 10;
			break;
		/* 192 */
		case 1:
			rounds = 12;
			break;
		/* 256 */
		case 2:
			rounds = 14;
			break;
		default:
			fprintf(stderr, "Invalid cipher type in inv_cipher() on line %d in file %s.\n", __LINE__, __FILE__);
			exit(EXIT_FAILURE);
			break;
	}
	
	/* First round (rounds) */
	add_round_key(state, key_schedule[rounds]);
		
	/* Middle rounds (1 -> rounds-1) */
	for(round = rounds-1; round > 0; round--){
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, key_schedule[round]);
		inv_mix_columns(state);
	}
	
	/* Final round (0) */
	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, key_schedule[0]);
}

/* 
 * Parameters:
 * *key_schedule: AES key schedule to fill
 * key_type: Uses constants defined in aes.h
 * key: The main AES key
 * 
 * Returns: void
 */
void expand_key(struct aes_key *key_schedule[15], uint8_t key_type, uint8_t *key){
	/* AES-256 generates 15 keys, 128 and 192 generate fewer */
	uint32_t all_words[60];
	uint8_t words_in_key, num_rounds;
	
	uint32_t temp;
	uint8_t *temp_ptr;
	uint8_t *word_ptr;
	
	uint8_t i, j, k;
	
	switch(key_type){
		/* AES-128 */
		case 0:
			words_in_key = 4;
			num_rounds = 10;
			break;
		/* AES-192 */
		case 1:
			words_in_key = 6;
			num_rounds = 12;
			break;
		/* AES-256 */
		case 2:
			words_in_key = 8;
			num_rounds = 14;
			break;
		default:
			fprintf(stderr, "Invalid cipher type in expand_key() on line %d in file %s.\n", __LINE__, __FILE__);
			exit(EXIT_FAILURE);
	}
	
	/* Copy initial words into word array */
	for(i = 0; i < words_in_key; i++){
		memcpy(&all_words[i], key+(i*4), 4);
		
		/* Account for little-endianness */
		temp = all_words[i];
		temp_ptr = (uint8_t *) &temp;
		word_ptr = (uint8_t *) &all_words[i];
		
		for(j = 0; j < 4; j++){
			temp_ptr[j] = word_ptr[3-j];
		}
		
		all_words[i] = temp;
	}
	
	/* Key expansion */
	for(i = words_in_key; i < (4 * (num_rounds+1)); i++){
		temp = all_words[i-1];
		if(i % words_in_key == 0){
			temp = sub_word(rot_word(temp)) ^ round_constants[(i / words_in_key)-1];
		}else if(words_in_key == 8 && i % words_in_key == 4){
			temp = sub_word(temp);
		}
		all_words[i] = all_words[i - words_in_key] ^ temp;
	}
	
	/* Copy words into key schedule */
	for(i = 0; i < 15; i++){
		for(j = 0; j < 4; j++){
			temp = all_words[i*4+j];
			word_ptr = (uint8_t *) &temp;
			
			for(k = 0; k < 4; k++){
				key_schedule[i] -> bytes[k][j] = word_ptr[3-k];
			}
		}
	}
}

/* 
 * Apply the key for the current round.
 */
void add_round_key(struct aes_state *state, struct aes_key *current_key){
	uint8_t i, j;
	for(i = 0; i < 4; i++){
		for(j = 0; j < 4; j++){
			state -> bytes[i][j] ^= current_key -> bytes[i][j];
		}
	}
}

/*
 * Apply the Rinjdael substitution box to the current state
 */
void sub_bytes(struct aes_state *state){
	uint8_t i, j;
	
	for(i = 0; i < 4; i++){
		for(j = 0; j < 4; j++){
			state -> bytes[i][j] = sub_box[state -> bytes[i][j]];
		}
	}
}

/* 
 * Perform Galois field multiplication for each column
 */
void mix_columns(struct aes_state *state){
	uint8_t temp[4];
	uint8_t i;
	
	for(i = 0; i < 4; i++){
		temp[0] = gf_mult(state -> bytes[0][i], 2) ^ gf_mult(state -> bytes[1][i], 3) ^ state -> bytes[2][i] ^ state -> bytes[3][i];
		temp[1] = state -> bytes[0][i] ^ gf_mult(state -> bytes[1][i], 2) ^ gf_mult(state -> bytes[2][i], 3) ^ state -> bytes[3][i];
		temp[2] = state -> bytes[0][i] ^ state -> bytes[1][i] ^ gf_mult(state -> bytes[2][i], 2) ^ gf_mult(state -> bytes[3][i], 3);
		temp[3] = gf_mult(state -> bytes[0][i], 3) ^ state -> bytes[1][i] ^ state -> bytes[2][i] ^ gf_mult(state -> bytes[3][i], 2);
		
		state -> bytes[0][i] = temp[0];
		state -> bytes[1][i] = temp[1];
		state -> bytes[2][i] = temp[2];
		state -> bytes[3][i] = temp[3];
	}
}

/* 
 * Rotate rows by row number
 */
void shift_rows(struct aes_state *state){
	uint8_t temp;
	
	/* Do nothing with row 0 */
	
	/* Shift row 1 */
	temp = state -> bytes[1][0];
	state -> bytes[1][0] = state -> bytes[1][1];
	state -> bytes[1][1] = state -> bytes[1][2];
	state -> bytes[1][2] = state -> bytes[1][3];
	state -> bytes[1][3] = temp;
	
	/* Shift row 2 */
	temp = state -> bytes[2][0];
	state -> bytes[2][0] = state -> bytes[2][2];
	state -> bytes[2][2] = temp;
	temp = state -> bytes[2][1];
	state -> bytes[2][1] = state -> bytes[2][3];
	state -> bytes[2][3] = temp;
	
	/* Shift row 3 */
	temp = state -> bytes[3][3];
	state -> bytes[3][3] = state -> bytes[3][2];
	state -> bytes[3][2] = state -> bytes[3][1];
	state -> bytes[3][1] = state -> bytes[3][0];
	state -> bytes[3][0] = temp;
}

/* 
 * Inverse mix_columns. Performs Galois field multiplication based on the inverse of the mix_columns constants.
 */
void inv_mix_columns(struct aes_state *state){	
	uint8_t temp[4];
	uint8_t i;
	
	for(i = 0; i < 4; i++){
		temp[0] = gf_mult(state -> bytes[0][i], 14) ^ gf_mult(state -> bytes[1][i], 11) ^ gf_mult(state -> bytes[2][i], 13) ^ gf_mult(state -> bytes[3][i], 9);
		temp[1] = gf_mult(state -> bytes[0][i], 9) ^ gf_mult(state -> bytes[1][i], 14) ^ gf_mult(state -> bytes[2][i], 11) ^ gf_mult(state -> bytes[3][i], 13);
		temp[2] = gf_mult(state -> bytes[0][i], 13) ^ gf_mult(state -> bytes[1][i], 9) ^ gf_mult(state -> bytes[2][i], 14) ^ gf_mult(state -> bytes[3][i], 11);
		temp[3] = gf_mult(state -> bytes[0][i], 11) ^ gf_mult(state -> bytes[1][i], 13) ^ gf_mult(state -> bytes[2][i], 9) ^ gf_mult(state -> bytes[3][i], 14);
		
		state -> bytes[0][i] = temp[0];
		state -> bytes[1][i] = temp[1];
		state -> bytes[2][i] = temp[2];
		state -> bytes[3][i] = temp[3];
	}
}

/* 
 * Shift rows backwards
 */
void inv_shift_rows(struct aes_state *state){
	uint8_t temp;
	
	/* Do nothing with row 0 */
	
	/* Shift row 1 backwards */
	temp = state -> bytes[1][3];
	state -> bytes[1][3] = state -> bytes[1][2];
	state -> bytes[1][2] = state -> bytes[1][1];
	state -> bytes[1][1] = state -> bytes[1][0];
	state -> bytes[1][0] = temp;
	
	/* Shift row 2 backwards */
	temp = state -> bytes[2][0];
	state -> bytes[2][0] = state -> bytes[2][2];
	state -> bytes[2][2] = temp;
	temp = state -> bytes[2][1];
	state -> bytes[2][1] = state -> bytes[2][3];
	state -> bytes[2][3] = temp;
	
	/* Shift row 3 backwards */
	temp = state -> bytes[3][0];
	state -> bytes[3][0] = state -> bytes[3][1];
	state -> bytes[3][1] = state -> bytes[3][2];
	state -> bytes[3][2] = state -> bytes[3][3];
	state -> bytes[3][3] = temp;
}

/* 
 * Apply inverse Rijndael substitution box
 */
void inv_sub_bytes(struct aes_state *state){
	uint8_t i, j;
	
	for(i = 0; i < 4; i++){
		for(j = 0; j < 4; j++){
			state -> bytes[i][j] = inv_sub_box[state -> bytes[i][j]];
		}
	}
}

/* 
 * Apply substitution box to a word
 */
uint32_t sub_word(uint32_t word){
	uint8_t *word_as_uint8_t_ptr = (uint8_t *) &word;
	uint8_t i;
	
	for(i = 0; i < 4; i++){
		/* Cast as uint8_t * in order to address by byte index */
		word_as_uint8_t_ptr[i] = sub_box[word_as_uint8_t_ptr[i]];
	}
		
	return word;
}

/*
 * Move top byte to bottom and move the rest up
 */
uint32_t rot_word(uint32_t word){
	uint8_t bytes[4];
	uint32_t out_word;
	uint8_t *out_word_ptr = (uint8_t *) &out_word;
	
	uint8_t i;
	uint8_t temp;
	
	/* Account for little-endianness */
	for(i = 0; i < 4; i++){
		bytes[i] = ((uint8_t *) &word)[3-i];
	}
	
	/* Rotate */
	temp = bytes[0];
	bytes[0] = bytes[1];
	bytes[1] = bytes[2];
	bytes[2] = bytes[3];
	bytes[3] = temp;
	
	
	/* Return to little-endian */
	for(i = 0; i < 4; i++){
		out_word_ptr[i] = bytes[3-i];
	}
	
	return out_word;
}

/* 
 * Galois field multiplication
 */
uint8_t gf_mult(uint8_t multiplicand, uint8_t multiplier){
	uint8_t result = 0;
	uint8_t msb;
	uint8_t i;
	
	for(i = 0; i < 8; i++){
		if(multiplier & 1){
			result ^= multiplicand;
		}
		
		msb = multiplicand & 0x80;
		multiplicand <<= 1;
		if(msb){
			multiplicand ^= 0x1B;
		}
		multiplier >>= 1;
	}
	
	return result;
}

/*
 * DEBUG
 * Dump an AES state to stdout
 */
void dump_state(struct aes_state *state){
	uint8_t i;
	for(i = 0; i < 4; i++){
		printf("%02x %02x %02x %02x\n", state -> bytes[i][0], state -> bytes[i][1], state -> bytes[i][2], state -> bytes[i][3]);
	}
	puts("\n");
}

/* 
 * DEBUG
 * Dump an AES schedule key to stdout
 */
void dump_key(struct aes_key *key){
	uint8_t i;
	for(i = 0; i < 4; i++){
		printf("%02x %02x %02x %02x\n", key -> bytes[i][0], key -> bytes[i][1], key -> bytes[i][2], key -> bytes[i][3]);
	}
	puts("\n");
}

/* 
 * Checks for duplicate AES blocks. If any are found based on given key type, very likely to be ECB
 * Returns: 0 on success (if at least 2 blocks are the same)
 * 1 on failure (no match)
 * -1 on size not multiple of 16
 */
signed char is_aes_ecb(unsigned char *data, size_t data_size){
	/* Break data into blocks of block_size and check for duplicates */
	size_t const BLOCK_SIZE = 16;
	size_t blocks;
	unsigned char *current_i_block, *current_j_block;
	size_t i, j;

	if(data_size % BLOCK_SIZE != 0) return -1;

	current_i_block = malloc(BLOCK_SIZE);
	current_j_block = malloc(BLOCK_SIZE);
	blocks = data_size / BLOCK_SIZE;

	for(i = 0; i < blocks; i++){
		memcpy(current_i_block, data+(i*BLOCK_SIZE), BLOCK_SIZE);
		for(j = i + 1; j < blocks; j++){
			memcpy(current_j_block, data+(j*BLOCK_SIZE), BLOCK_SIZE);
			if(!memcmp(current_i_block, current_j_block, BLOCK_SIZE)){
				free(current_i_block);
				free(current_j_block);
				return 0;
			}
		}
	}
	
	free(current_i_block);
	free(current_j_block);

	return 1;
}

/*
 * Returns 0 on success
 * Returns 1 on failure to read from /dev/urandom
 * Returns -1 on invalid key type
 */
int generate_random_aes_key(unsigned char **output, uint8_t key_type){
	FILE *urandom_file = fopen("/dev/urandom", "r");

	size_t key_size;
	switch(key_type){
		case AES_KEY_128:
			key_size = 16;
			break;
		case AES_KEY_192:
			key_size = 24;
			break;
		case AES_KEY_256:
			key_size = 32;
			break;
		default:
			fclose(urandom_file);
			return -1;
			break;
	}
	
	if(output != NULL){
		if(*output == NULL){
			*output = malloc(key_size);
		}
	}
	
	if(fread(*output, sizeof(char), key_size, urandom_file) != key_size){
		fclose(urandom_file);
		return 1;
	}
	
	fclose(urandom_file);
	return 0;
}
