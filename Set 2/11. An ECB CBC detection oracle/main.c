#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

int generate_random_aes_key(unsigned char **output, uint8_t key_type);
size_t random_encryptor(unsigned char **output, unsigned char *input, size_t input_size, uint8_t key_type);

/* 
 * This challenge is written in a very confusing way if you're not already aware of the concept
 * I thought it would be an extension to the ECB detection challenge,
 * but the actual challenge is to analyze whether a function is using ECB or CBC.
 * We can use our own input and analyze the result
 */

#define CHEAT
#ifdef CHEAT
static unsigned char cheat_answer;
#endif

int main(void){
	const size_t KIBIBYTE = 1024; /* 1 KiB = 1024 bytes */
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_size;

	size_t input_string_size;
	char *input_string;

	char is_ecb;

	input_string_size = KIBIBYTE;
	input_string = malloc(input_string_size);
	/* All 'A's makes it easy to detect patterns  */
	memset(input_string, 'A', input_string_size-1);
	input_string[input_string_size-1] = '\0';
	
	encrypted_data_size = random_encryptor(&encrypted_data, (unsigned char *) input_string, input_string_size, AES_KEY_128);
	
	is_ecb = is_aes_ecb(encrypted_data, encrypted_data_size, AES_KEY_128);
	
	/*asm("int3");*/

	if(is_ecb == 0){
		printf("Should be ECB.\n");
	}else if(is_ecb == 1){
		printf("Should be CBC.\n");
	}else{
		printf("Error in is_aes_ecb.\n");
	}

	#ifdef CHEAT
		printf("Actual method used: ");
		if(cheat_answer == 0){
			printf("ECB\n");
		}else if(cheat_answer == 1){
			printf("CBC\n");
		}
	#endif
	
	free(encrypted_data);
	free(input_string);

	return 0;
}

/* 
 * Adds 5-10 bytes before and after given input, then encrypts new buffer
 * with either ECB or CBC, chosen randomly
 *
 * Returns 0 on success
 * Returns -1 on failure to read from /dev/urandom
 */
size_t random_encryptor(unsigned char **output, unsigned char *input, size_t input_size, uint8_t key_type){
	FILE *urandom_file;
	unsigned char *key = NULL;
	unsigned char *initialization_vector = NULL;
	unsigned char *new_input = NULL;
	size_t new_input_size;

	unsigned char *prefix = NULL;
	unsigned char *postfix = NULL;
	
	unsigned char cipher_choice;
	unsigned char prefix_length, postfix_length;

	size_t output_size;
	
	srand(time(NULL));
	
	/* rand() % n = [0, n-1] */
	/* 5 - 10 */
	prefix_length = (rand() % 6) + 5;
	postfix_length = (rand() % 6) + 5;

	prefix = malloc(prefix_length);
	postfix = malloc(postfix_length);

	urandom_file = fopen("/dev/urandom", "r");
	
	fread(prefix, sizeof(char), prefix_length, urandom_file);
	fread(postfix, sizeof(char), postfix_length, urandom_file);
	
	/* build the new buffer */
	new_input_size = input_size+prefix_length+postfix_length;
	new_input = malloc(new_input_size);
	memcpy(new_input, prefix, prefix_length);
	memcpy(new_input+prefix_length, input, input_size);
	memcpy(new_input+prefix_length+input_size, postfix, postfix_length);
	
	free(prefix);
	free(postfix);
	fclose(urandom_file);
	/* 50/50 ECB/CBC 
	 * 0 or 1
	 */
	cipher_choice = rand() % 2;
	#ifdef CHEAT
		cheat_answer = cipher_choice;
	#endif

	/* random key */
	generate_random_aes_key(&key, key_type);
	
	if(cipher_choice == 0){
		output_size = aes_encrypt(output, new_input, new_input_size, key, NULL, AES_CIPHER_ECB, key_type);
	}else{/*(cipher_choice == 1)*/
		/* random IV - IV is always 16 bytes, the size of an AES round key/AES-128 key  */
		generate_random_aes_key(&initialization_vector, AES_KEY_128);
		output_size = aes_encrypt(output, new_input, new_input_size, key, initialization_vector, AES_CIPHER_CBC, key_type);
		free(initialization_vector);
	}

	free(key);
	free(new_input);

	return output_size;
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
			return -1;
			break;
	}
	
	if(output != NULL){
		if(*output == NULL){
			*output = malloc(key_size);
		}
	}
	
	if(fread(*output, sizeof(char), key_size, urandom_file) != key_size){
		return 1;
	}
	
	fclose(urandom_file);
	return 0;
}
