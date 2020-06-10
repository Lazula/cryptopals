#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../include/base64.h"
#include "../../include/aes.h"


#define USE_SET_SECRET 0
#define DEBUG 0

#define USE_RANDOM_KEY 0
#define USE_RANDOM_INITIALIZATION_VECTOR 0

unsigned char *KEY = NULL;
unsigned char *IV = NULL;
const size_t BLOCK_SIZE = 16;

int get_encrypted_message(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char **initialization_vector_ptr);
int authenticate(unsigned char *input_data, size_t input_data_size, unsigned char *initialization_vector);

int main(){
	size_t i, j;

	size_t num_decrypted_bytes;
	size_t current_block;
	size_t index_in_block_to_decrypt;
	size_t num_padding;

	unsigned char *initialization_vector = NULL;
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_size;

	unsigned char *poisoned_encrypted_data;
	unsigned char *poisoned_initialization_vector;

	unsigned char current_ciphertext_byte;
	unsigned char current_decrypted_byte;
	unsigned char *decrypted_data = NULL;

	unsigned char *unpadded_decrypted_data = NULL;
	size_t unpadded_decrypted_data_size;

	char *decrypted_string = NULL;

	int authentication_result;

	/* BEGIN SETUP */
	#if USE_RANDOM_KEY
	generate_random_aes_key(&KEY, AES_KEY_128);
	#else
	KEY = (unsigned char *) "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
	#endif

	#if USE_RANDOM_INITIALIZATION_VECTOR
	generate_random_aes_key(&IV, AES_KEY_128);
	#else
	IV = (unsigned char *) "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
	#endif
	/* END SETUP */

	get_encrypted_message(&encrypted_data, &encrypted_data_size, &initialization_vector);
	decrypted_data = malloc(encrypted_data_size);
	poisoned_encrypted_data = malloc(BLOCK_SIZE*2);
	poisoned_initialization_vector = malloc(BLOCK_SIZE);

	for(num_decrypted_bytes = 0; num_decrypted_bytes < encrypted_data_size; num_decrypted_bytes++){
		current_block = num_decrypted_bytes / BLOCK_SIZE;
		index_in_block_to_decrypt = (BLOCK_SIZE - (num_decrypted_bytes % BLOCK_SIZE)) - 1;
		num_padding = BLOCK_SIZE - index_in_block_to_decrypt;

		#if DEBUG
		printf("\nnum_decrypted_bytes = %lu\n", num_decrypted_bytes);
		printf("index_in_block_to_decrypt = %lu\n", index_in_block_to_decrypt);
		printf("num_padding = %lu\n", num_padding);
		printf("current_block = %lu\n", current_block);
		#endif

		if(current_block > 0){
			memcpy(poisoned_encrypted_data, encrypted_data + ((current_block-1) * BLOCK_SIZE), BLOCK_SIZE*2);
			if(current_block > 1){
				/* If we have decrypted bytes for use as IV, do so */
				memcpy(poisoned_initialization_vector, decrypted_data + ((current_block-2) * BLOCK_SIZE), BLOCK_SIZE);
			}else{
				/* Otherwise, use the normal IV */
				memcpy(poisoned_initialization_vector, initialization_vector, BLOCK_SIZE);
			}
			current_ciphertext_byte = poisoned_encrypted_data[index_in_block_to_decrypt];
			for(j = index_in_block_to_decrypt+1; j < BLOCK_SIZE; j++)
				poisoned_encrypted_data[j] ^= decrypted_data[(current_block * BLOCK_SIZE) + j] ^ num_padding;
		}else{
			memcpy(poisoned_encrypted_data, encrypted_data, BLOCK_SIZE);
			memcpy(poisoned_initialization_vector, initialization_vector, BLOCK_SIZE);
			current_ciphertext_byte = poisoned_initialization_vector[index_in_block_to_decrypt];
			for(j = index_in_block_to_decrypt+1; j < BLOCK_SIZE; j++)
				poisoned_initialization_vector[j] ^= decrypted_data[j] ^ num_padding;
		}

		for(i = 0; i < 256; i++){
			if(current_block > 0){
				/* Blocks 1 -> N: Use two blocks; modify first block */

				poisoned_encrypted_data[index_in_block_to_decrypt] = current_ciphertext_byte;
				poisoned_encrypted_data[index_in_block_to_decrypt] ^= (unsigned char) i;
				authentication_result = authenticate(poisoned_encrypted_data, BLOCK_SIZE*2, poisoned_initialization_vector);

			}else{
				/* Block 0: Use one block; modify IV */

				poisoned_initialization_vector[index_in_block_to_decrypt] = current_ciphertext_byte;
				poisoned_initialization_vector[index_in_block_to_decrypt] ^= (unsigned char) i;
				authentication_result = authenticate(encrypted_data, BLOCK_SIZE, poisoned_initialization_vector);
			}

			if(authentication_result == 0){
				current_decrypted_byte = i ^ num_padding;
				#if DEBUG
				printf("Decrypted byte: '%c' (0x%02x)\n", current_decrypted_byte, current_decrypted_byte);
				#endif
				decrypted_data[(current_block * BLOCK_SIZE) + index_in_block_to_decrypt] = current_decrypted_byte;
				if(i == 0){
					/* Block was not changed and already has padding.
					 * Keep going to find the actual value.
					 * If this was not an error, the decrypted byte that was already set will
					 * not be overwritten, and continuing is harmless.
					 */
					continue;
				}

				break;
			}
		}
	}

	free(encrypted_data);
	free(poisoned_encrypted_data);
	free(initialization_vector);
	free(poisoned_initialization_vector);

	pkcs7_unpad(&unpadded_decrypted_data, &unpadded_decrypted_data_size, decrypted_data, encrypted_data_size, BLOCK_SIZE);
	free(decrypted_data);

	decrypted_string = malloc(unpadded_decrypted_data_size+1);
	memcpy(decrypted_string, unpadded_decrypted_data, unpadded_decrypted_data_size);
	decrypted_string[unpadded_decrypted_data_size] = '\0';
	free(unpadded_decrypted_data);

	printf("%s\n", decrypted_string);

	free(decrypted_string);

	return 0;
}

/* Encrypt a randomly-selected message in CBC mode
 */
int get_encrypted_message(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char **initialization_vector_ptr){
	#if ! USE_SET_SECRET
	char *base64_encoded_secrets[10] = {
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
	};
	#endif

	unsigned char *secret = NULL;
	size_t secret_size;

	unsigned char *encrypted_secret = NULL;
	size_t encrypted_secret_size;

	#if USE_SET_SECRET
	secret_size = BLOCK_SIZE*2;
	secret = malloc(secret_size);
	memcpy(secret, "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH00001111", secret_size);
	#else
	srand(time(NULL));
	secret_size = base64_decode(&secret, base64_encoded_secrets[rand() % 10]);
	#endif

	aes_encrypt(&encrypted_secret, &encrypted_secret_size, secret, secret_size, KEY, IV, AES_CIPHER_CBC, AES_KEY_128);

	free(secret);

	if(output_ptr != NULL){
		if(*output_ptr == NULL) *output_ptr = malloc(encrypted_secret_size);
		memcpy(*output_ptr, encrypted_secret, encrypted_secret_size);
	}

	if(output_size_ptr != NULL) *output_size_ptr = encrypted_secret_size;

	if(initialization_vector_ptr != NULL){
		if(*initialization_vector_ptr == NULL) *initialization_vector_ptr = malloc(BLOCK_SIZE);
		memcpy(*initialization_vector_ptr, IV, BLOCK_SIZE);
	}

	free(encrypted_secret);

	return 0;
}

/* Decrypts data, then checks for valid padding.
 * Returns:
 * 0 if data was properly padded.
 * 1 if data was not properly padded.
 */
int authenticate(unsigned char *input_data, size_t input_data_size, unsigned char *initialization_vector){
	unsigned char *decrypted_data = NULL;
	size_t decrypted_data_size;

	int return_val;



	if(aes_decrypt(&decrypted_data, &decrypted_data_size, input_data, input_data_size, KEY, initialization_vector, AES_CIPHER_CBC, AES_KEY_128) == 0
	   && decrypted_data_size < input_data_size){
		/* Good padding */
		return_val = 0;
	}else{
		/* Bad padding */
		return_val = 1;
	}

	free(decrypted_data);

	return return_val;
}
