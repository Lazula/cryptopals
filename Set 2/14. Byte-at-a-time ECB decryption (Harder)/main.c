#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

/* DEBUG_ENCRYPT_FUNC
 * 0: off
 * 1: print combined and encrypted data
 *    for each encrypt call
 */
#define DEBUG_ENCRYPT_FUNC 0

/* DEBUG_DECRYPTION_TABLE
 * 0: off
 * 1: print decrypted bytes sent to
 *     function
 * 2: print detailed information about
 *     decryption table as it is being
 *     constructed
 */
#define DEBUG_DECRYPTION_TABLE 0

/* DEBUG_PREFIX
 * 0: off
 * 1: display the secret prefix when it
 *    is generated
 */
#define DEBUG_PREFIX 0

/* USE_RANDOM_PREFIX
 * 0: use set prefix
 * 1: generate random prefix at runtime
 */
#define USE_RANDOM_PREFIX 1

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

unsigned char *prefix_data = NULL;
size_t prefix_data_size;

struct encryption_map {
	unsigned char *ciphertext;
	unsigned char last_plaintext_byte;
};

int generate_prefix(unsigned char **prefix_ptr, size_t *prefix_size_ptr);
unsigned char *get_block(unsigned char *input, size_t block, size_t block_size);
int populate_decryption_table(struct encryption_map **decryption_table, unsigned char *input_data, size_t input_data_size, unsigned char *decrypted_data, size_t decrypted_data_size, size_t current_block, size_t block_size);
size_t encrypt(unsigned char **output, size_t *output_size, unsigned char *input_data, size_t input_data_size);

int main(void){
	size_t i, j;

	struct encryption_map *decryption_table[256];
	struct encryption_map *correct_map;

	struct encryption_map *needle_map;
	unsigned char *needle_map_ciphertext_unculled = NULL;
	size_t needle_map_ciphertext_unculled_size;
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
	unsigned char *last_encrypted_data = NULL;
	size_t last_encrypted_data_size;

	size_t padded_secret_size;
	size_t found_secret_size;
	size_t found_prefix_size;

	size_t num_input_bytes_in_first_input_block;
	size_t block_with_first_input_byte;

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

	#if USE_RANDOM_PREFIX
	generate_prefix(&prefix_data, &prefix_data_size);
	#else
	prefix_data_size = 20;
	prefix_data = malloc(prefix_data_size);
	memset(prefix_data, 'a', prefix_data_size);
	#endif

	#if DEBUG_PREFIX
	printf("Using prefix (size %lu): ", prefix_data_size);
	hex_print(prefix_data, prefix_data_size);
	#endif

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


	/* Find first block that contains input */
	encrypt(&last_encrypted_data, &last_encrypted_data_size, NULL, 0);

	input_data_size = 1;
	input_data = malloc(input_data_size);
	input_data[0] = 'A';
	encrypt(&current_encrypted_data, &current_encrypted_data_size, input_data, input_data_size);

	for(i = 0; i < (current_encrypted_data_size / BLOCK_SIZE); i++){
		if(memcmp(current_encrypted_data+(i*BLOCK_SIZE), last_encrypted_data+(i*BLOCK_SIZE), BLOCK_SIZE)){
			block_with_first_input_byte = i;
			break;
		}
	}

	free(input_data);
	input_data = NULL;
	free(current_encrypted_data);
	current_encrypted_data = NULL;
	free(last_encrypted_data);
	last_encrypted_data = NULL;

	printf("First input byte appears in block %lu\n", block_with_first_input_byte);

	/* Find prefix size */
	for(input_data_size = BLOCK_SIZE*2; input_data_size < BLOCK_SIZE*3; input_data_size++){
		input_data = malloc(input_data_size);
		memset(input_data, 'A', input_data_size);
		encrypt(&current_encrypted_data, &current_encrypted_data_size, input_data, input_data_size);
		free(input_data);
		/* make sure not to attempt to detect matching blocks before our input! */
		if(is_aes_ecb(current_encrypted_data + (block_with_first_input_byte*BLOCK_SIZE), \
				current_encrypted_data_size - (block_with_first_input_byte*BLOCK_SIZE)) == 0){
			num_input_bytes_in_first_input_block = input_data_size - (BLOCK_SIZE*2);
			free(current_encrypted_data);
			current_encrypted_data = NULL;
			break;
		}
		free(current_encrypted_data);
		current_encrypted_data = NULL;
	}

	/* calculation above gives 0 when on block boundary */
	if(num_input_bytes_in_first_input_block == 0) num_input_bytes_in_first_input_block = BLOCK_SIZE;
	found_prefix_size = (block_with_first_input_byte*BLOCK_SIZE) + (BLOCK_SIZE - num_input_bytes_in_first_input_block);

	printf("Found prefix size: %lu\n", found_prefix_size);

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
			found_secret_size = padded_secret_size - ((input_data_size + found_prefix_size) - 1);
			printf("Found secret size using encryption oracle: %lu\n", found_secret_size);
			break;
		}
	}

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
	current_block = block_with_first_input_byte+1;
	/* END SETUP */

	printf("Starting at block %lu.\n", current_block);
	printf("Beginning decryption, this may take a moment...\n");
	/* Decryption loop */
	for(i = 0; i < found_secret_size; i++){
		/* (BLOCK_SIZE-1) -> 0 for each block */
		/* Add bytes to reach boundary */
		num_set_bytes = (((padded_secret_size - i) - 1) % BLOCK_SIZE) + num_input_bytes_in_first_input_block;

		input_data_size = num_set_bytes + decrypted_data_size;
		input_data = realloc(input_data, input_data_size);

		memset(input_data, 'A', num_set_bytes);
		if(decrypted_data_size > 0){
			memcpy(input_data+num_set_bytes, decrypted_data, decrypted_data_size);
		}


		/* If not on first loop and just after a block boundary */
		if(decrypted_data_size > 0 && num_set_bytes - num_input_bytes_in_first_input_block == 15){
			/* Decrement current block */
			current_block++;
			#if DEBUG >= 1
			printf("Moving to block %lu\n", current_block);
			#endif
		}

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

		correct_map = NULL;
		for(j = 0; j < 256; j++){
			if(memcmp(needle_map -> ciphertext, decryption_table[j] -> ciphertext, BLOCK_SIZE) == 0){
				correct_map = decryption_table[j];
				break;
			}
		}

		if(correct_map == NULL){
			fprintf(stderr, "Could not find correct encryption map.\n");
			decrypted_string = malloc(decrypted_data_size+1);
			memcpy(decrypted_string, decrypted_data, decrypted_data_size);
			decrypted_string[decrypted_data_size] = '\0';
			fprintf(stderr, "Decrypted bytes: %s\n", decrypted_string);
			/* This shouldn't occur in normal execution aside from bugs and is here for debug purposes */
			exit(EXIT_FAILURE);
		}

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
 * This version adds the global prefix before the input
 *
 * Returns size of encrypted data
 */
size_t encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size){

	unsigned char *combined_data = NULL;
	size_t combined_data_size;

	unsigned char *encrypted_combined_data = NULL;
	size_t encrypted_combined_data_size;

	
	combined_data_size = prefix_data_size + input_data_size + secret_data_size;
	combined_data = malloc(combined_data_size);

	memcpy(combined_data, prefix_data, prefix_data_size);
	if(input_data_size > 0) memcpy(combined_data+prefix_data_size, input_data, input_data_size);
	memcpy(combined_data+prefix_data_size+input_data_size, secret_data, secret_data_size);

	aes_encrypt(&encrypted_combined_data, &encrypted_combined_data_size, combined_data, combined_data_size, KEY, NULL, AES_CIPHER_ECB, AES_KEY_128);

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

int generate_prefix(unsigned char **prefix_ptr, size_t *prefix_size_ptr){
	size_t i;

	/* the global scope variables of the same names are shadowed */
	unsigned char *prefix_data;
	size_t prefix_data_size;

	srand(time(NULL));
	prefix_data_size = (rand() % 64) + 1;
	prefix_data = malloc(prefix_data_size);

	for(i = 0; i < prefix_data_size; i++){
		prefix_data[i] = (unsigned char) (rand() % 256);
	}

	if(prefix_ptr != NULL){
		if(*prefix_ptr == NULL){
			*prefix_ptr = malloc(prefix_data_size);
			memcpy(*prefix_ptr, prefix_data, prefix_data_size);
		}
	}

	if(prefix_size_ptr != NULL){
		*prefix_size_ptr = prefix_data_size;
	}

	free(prefix_data);
	return 0;
}
