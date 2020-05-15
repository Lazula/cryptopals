#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "../../include/base64.h"
#include "../../include/hex_encoding.h"
#include "../../include/aes.h"

/* DEBUG
 * 0: off
 * 1: Displays basic diagnostic
 *     information
 * 2: Displays each character as it is
 *     decrypted.
 * 3: Displays information about each
 *     plaintext and ciphertext,
 *     including the ciphertext for
 *     needle_map
 */
#define DEBUG 0

/* DEBUG_DECRYPTION_TABLE
 * 0: off
 * 1: print decrypted bytes sent to
 *     function
 * 2: print detailed information about
 *     decryption table as it is being
 *     constructed
 */
#define DEBUG_DECRYPTION_TABLE 0

/* USE_RANDOM_KEY
 * 0: use set key
 * 1: generate random key at runtime
 */
#define USE_RANDOM_KEY 1

size_t BLOCK_SIZE = 0;
unsigned char *KEY = NULL;

char *base64_encoded_secret_data;
unsigned char *secret_data;
size_t secret_data_size;


struct encryption_map {
	unsigned char *ciphertext;
	unsigned char last_plaintext_byte;
};


int compare_encryption_maps(const void *p1, const void *p2){
	struct encryption_map *e1 = *((struct encryption_map **) p1);
	struct encryption_map *e2 = *((struct encryption_map **) p2);
	return memcmp(e1 -> ciphertext, e2 -> ciphertext, BLOCK_SIZE);
}

unsigned char *get_block(unsigned char *input, size_t block, size_t block_size);
int populate_decryption_table(struct encryption_map **decryption_table, unsigned char *input_data, size_t input_data_size, unsigned char *decrypted_data, size_t decrypted_data_size, size_t current_block, size_t block_size);
size_t encrypt(unsigned char **output, size_t *output_size, unsigned char *input_data, size_t input_data_size);

int main(void){
	size_t i;

	struct encryption_map *decryption_table[256];
	struct encryption_map **correct_map_ptr;
	struct encryption_map *correct_map;

	struct encryption_map *needle_map;
	unsigned char *needle_map_ciphertext_unculled = NULL;
	unsigned char *needle_map_ciphertext = NULL;

	unsigned char *decrypted_data = NULL;
	size_t decrypted_data_size = 0;
	char *decrypted_string = NULL;

	unsigned char *input_data = NULL;
	size_t input_data_size;
	size_t num_set_bytes;
	size_t current_block;

	unsigned char *current_encrypted_data = NULL;
	size_t current_encrypted_data_size;
	size_t padded_secret_size;
	size_t found_secret_size;


	/* BEGIN SETUP */

	/* Prepare secret key */
	#if USE_RANDOM_KEY
	generate_random_aes_key(&KEY, AES_KEY_128);
	#else
	KEY = (unsigned char *) "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
	#endif

	/* Decode secret in memory */
	base64_encoded_secret_data = (char *) "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
					      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
					      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
					      "YnkK";
	secret_data = NULL;
	secret_data_size = base64_decode(&secret_data, base64_encoded_secret_data);

	encrypt(NULL, &padded_secret_size, NULL, 0);

	/* Discover block size */
	for(input_data_size = 1; input_data_size < 1024; input_data_size++){
		input_data = malloc(input_data_size);
		memset(input_data, 'A', input_data_size);
		encrypt(NULL, &current_encrypted_data_size, input_data, input_data_size);
		free(input_data);

		/* When a new block is added, block size is the difference in size */
		if(current_encrypted_data_size > padded_secret_size){
			BLOCK_SIZE = current_encrypted_data_size - padded_secret_size;
			break;
		}
	}

	if(BLOCK_SIZE == 0){
		fprintf(stderr, "Failed to find block size.\n");
		exit(EXIT_FAILURE);
	}else{
		printf("Found block size: %lu\n", BLOCK_SIZE);
	}

	/* Find secret size */
	found_secret_size = 0;
	for(input_data_size = 1; input_data_size <= BLOCK_SIZE; input_data_size++){
		input_data = malloc(input_data_size);
		memset(input_data, 'A', input_data_size);
		encrypt(&current_encrypted_data, &current_encrypted_data_size, input_data, input_data_size);

		free(input_data);
		free(current_encrypted_data);
		current_encrypted_data = NULL;

		if(current_encrypted_data_size > padded_secret_size){
			found_secret_size = padded_secret_size - (input_data_size - 1);
			printf("Found secret size using encryption oracle: %lu\n", found_secret_size);
			break;
		}
	}

	/* Detect AES in ECB mode */
	current_encrypted_data = NULL;
	input_data_size = BLOCK_SIZE * 2;
	input_data = malloc(input_data_size);
	memset(input_data, 'A', input_data_size);
	encrypt(&current_encrypted_data, &current_encrypted_data_size, input_data, input_data_size);

	if(is_aes_ecb(current_encrypted_data, current_encrypted_data_size) == 0){
		printf("Successfully detected AES-ECB.\n");
	}else{
		fprintf(stderr, "Failed to detect AES-ECB.\n");
		exit(EXIT_FAILURE);
	}

	free(current_encrypted_data);
	free(input_data);

	/* Allocate and initialize decryption table objects */
	for(i = 0; i < 256; i++){
		decryption_table[i] = (struct encryption_map *) malloc(sizeof(struct encryption_map));
		decryption_table[i] -> ciphertext = (unsigned char *) malloc(BLOCK_SIZE);
		memset(decryption_table[i] -> ciphertext, 0, BLOCK_SIZE);
		decryption_table[i] -> last_plaintext_byte = (unsigned char) 0;
	}
	
	/* Allocate needle map */
	needle_map = (struct encryption_map *) malloc(sizeof(struct encryption_map));
	needle_map -> ciphertext = (unsigned char *) malloc(BLOCK_SIZE);


	input_data = NULL;
	current_block = 0;
	/* END SETUP */

	printf("Beginning decryption, this may take a moment...\n");
	/* Decryption loop */
	for(i = 0; i < found_secret_size; i++){
		/* (BLOCK_SIZE-1) -> 0 for each block */
		num_set_bytes = ((padded_secret_size - i) - 1) % BLOCK_SIZE;

		input_data_size = num_set_bytes + decrypted_data_size;
		input_data = realloc(input_data, input_data_size);

		memset(input_data, 'A', num_set_bytes);
		if(decrypted_data_size > 0){
			memcpy(input_data+num_set_bytes, decrypted_data, decrypted_data_size);
		}


		/* If not on first loop and just after a block boundary */
		if(decrypted_data_size > 0 && num_set_bytes == 15){
			/* Decrement current block */
			current_block++;
			#if DEBUG >= 1
			printf("Moving to block %lu\n", current_block);
			#endif
		}

		size_t needle_map_ciphertext_unculled_size;
		/* only include set bytes (controlled input) for encryption
		 * decrypted bytes are only used for finding all possible last bytes
		 * adding them here would make them appear twice
		 */
		encrypt(&needle_map_ciphertext_unculled, &needle_map_ciphertext_unculled_size, input_data, num_set_bytes);
		needle_map_ciphertext = get_block(needle_map_ciphertext_unculled, current_block, BLOCK_SIZE);
		memcpy(needle_map -> ciphertext, needle_map_ciphertext, BLOCK_SIZE);

		#if DEBUG >= 3
		printf("\nnum_set_bytes: %lu, block %lu, decrypted_data_size: %lu, input_data_size: %lu\n", num_set_bytes, current_block, decrypted_data_size, input_data_size);
		printf("Plaintext bytes: ");
		hex_print(input_data, input_data_size);
		if(input_data_size == 0) printf("\n");
		printf("Full ciphertext: ");
		hex_print(needle_map_ciphertext_unculled, needle_map_ciphertext_unculled_size);
		printf("Correct ciphertext block: ");
		hex_print(needle_map_ciphertext, BLOCK_SIZE);
		#endif
		free(needle_map_ciphertext);

		/* Get all possible ciphertexts and find last plaintext byte using the needle */
		/* Use num_set_bytes so that decrypted data is not copied multiple times */
		populate_decryption_table(decryption_table, input_data, num_set_bytes, decrypted_data, decrypted_data_size, current_block, BLOCK_SIZE);
		qsort(decryption_table, 256, sizeof(struct encryption_map *), compare_encryption_maps);
		correct_map_ptr = bsearch(&needle_map, decryption_table, 256, sizeof(struct encryption_map *), compare_encryption_maps);

		if(correct_map_ptr == NULL){
			/* bsearch returns NULL on failure to find */
			fprintf(stderr, "Could not find correct encryption map.\n");
			decrypted_string = malloc(decrypted_data_size+1);
			memcpy(decrypted_string, decrypted_data, decrypted_data_size);
			decrypted_string[decrypted_data_size] = '\0';
			fprintf(stderr, "Decrypted bytes: %s\n", decrypted_string);
			/* This shouldn't occur in normal execution aside from bugs and is here for debug purposes */
			exit(EXIT_FAILURE);
		}

		correct_map = * (struct encryption_map **) correct_map_ptr;
		#if DEBUG >= 2
		printf("Found correct encryption map. Decrypted character '%c'.\n", correct_map -> last_plaintext_byte);
		#endif
		
		decrypted_data_size++;
		decrypted_data = realloc(decrypted_data, decrypted_data_size);
		decrypted_data[decrypted_data_size-1] = correct_map -> last_plaintext_byte;
		
		free(needle_map_ciphertext_unculled);
		needle_map_ciphertext_unculled = NULL;

	}

	#if DEBUG >= 1
	printf("decrypted_data: ");
	hex_print(decrypted_data, decrypted_data_size);
	#endif

	/* Prepare null-terminated string */
	decrypted_string = malloc(decrypted_data_size+1);
	memcpy(decrypted_string, decrypted_data, decrypted_data_size);
	decrypted_string[decrypted_data_size] = '\0';

	printf("Decrypted string: \"%s\"\n", decrypted_string);
	free(decrypted_string);

	for(i = 0; i < 256; i++){
		free(decryption_table[i] -> ciphertext);
		free(decryption_table[i]);
	}

	free(decrypted_data);
	free(needle_map -> ciphertext);
	free(needle_map);
	free(input_data);

	return 0;
}

/* Returns a new block_size-sized unsigned char pointer containing the selected
 * block of data with the given block size.
 */
unsigned char *get_block(unsigned char *input, size_t block, size_t block_size){
	unsigned char *output;

	output = malloc(block_size);
	memcpy(output, input+(block*block_size), block_size);

	return output;
}

int populate_decryption_table(struct encryption_map **decryption_table, unsigned char *input_data, size_t input_data_size, unsigned char *decrypted_data, size_t decrypted_data_size, size_t current_block, size_t block_size){
	size_t i;

	unsigned char *decryption_table_input;
	size_t decryption_table_input_size;

	unsigned char *encrypted_data_unculled = NULL;
	unsigned char *encrypted_data;

	#if DEBUG_DECRYPTION_TABLE >= 2
	unsigned char *plaintext;
	size_t plaintext_size;
	#endif

	decryption_table_input_size = input_data_size + decrypted_data_size + 1;
	decryption_table_input = malloc(decryption_table_input_size);

	/* Copy given bytes */
	memcpy(decryption_table_input, input_data, input_data_size);

	if(decrypted_data_size > 0){
		/* Include previous decrypted bytes */
		memcpy(decryption_table_input + input_data_size, decrypted_data, decrypted_data_size);
		#if DEBUG_DECRYPTION_TABLE
		printf("decrypted bytes: ");
		hex_print(decrypted_data, decrypted_data_size);
		#endif
	}

	for(i = 0; i < 256; i++){
		/* Check all possible last-byte values */
		decryption_table_input[decryption_table_input_size-1] = (unsigned char) i;

		encrypt(&encrypted_data_unculled, NULL, decryption_table_input, decryption_table_input_size);

		encrypted_data = get_block(encrypted_data_unculled, current_block, block_size);
		memcpy(decryption_table[i] -> ciphertext, encrypted_data, block_size);
		free(encrypted_data);

		decryption_table[i] -> last_plaintext_byte = decryption_table_input[decryption_table_input_size-1];
	
		#if DEBUG_DECRYPTION_TABLE >= 2
		printf("decryption_table[%lu] full plaintext: ", i);
		hex_print(decryption_table_input, decryption_table_input_size);

		plaintext_size = decryption_table_input_size % 16;
		plaintext = get_block(decryption_table_input, current_block, plaintext_size);
		printf("decryption_table[%lu] plaintext block: ", i);
		hex_print(plaintext, plaintext_size);
		free(plaintext);

		printf("decryption_table[%lu] -> ciphertext: ", i);
		hex_print(decryption_table[i] -> ciphertext, BLOCK_SIZE);
		printf("decryption_table[%lu] -> last_plaintext_byte: %02x\n\n", i, decryption_table[i] -> last_plaintext_byte);
		#endif

		free(encrypted_data_unculled);
		encrypted_data_unculled = NULL;
	}

	free(decryption_table_input);
	return 0;
}

/* 
 * Prepends input, if any, to secret data before encrypting with key
 *
 * Returns size of encrypted data
 */
size_t encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size){
	unsigned char *combined_data = NULL;
	size_t combined_data_size;

	unsigned char *encrypted_combined_data = NULL;
	size_t encrypted_combined_data_size;
	
	combined_data_size = input_data_size + secret_data_size;
	combined_data = malloc(combined_data_size);

	if(input_data_size > 0) memcpy(combined_data, input_data, input_data_size);
	memcpy(combined_data+input_data_size, secret_data, secret_data_size);

	encrypted_combined_data_size = aes_encrypt(&encrypted_combined_data, combined_data, combined_data_size, KEY, NULL, AES_CIPHER_ECB, AES_KEY_128);

	#if DEBUG_ENCRYPT_FUNC
	printf("Combined data: ");
	hex_print(combined_data, combined_data_size);

	printf("Encrypted combined data: ");
	hex_print(encrypted_combined_data, encrypted_combined_data_size);
	printf("\n");
	#endif

	if(output_ptr != NULL){
		if(*output_ptr == NULL) *output_ptr = malloc(encrypted_combined_data_size);
		memcpy(*output_ptr, encrypted_combined_data, encrypted_combined_data_size);
	}

	if(output_size_ptr != NULL) *output_size_ptr = encrypted_combined_data_size;

	free(combined_data);
	free(encrypted_combined_data);

	return encrypted_combined_data_size;
}
