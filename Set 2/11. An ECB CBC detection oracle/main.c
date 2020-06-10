#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

int random_encryptor(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, uint8_t key_type);

/* 
 * This challenge is written in a very confusing way if you're not already aware of the concept
 * I thought it would be an extension to the ECB detection challenge,
 * but the actual challenge is to analyze whether a function is using ECB or CBC.
 * We can use our own input and analyze the result
 */

#define CHEAT 0
#if CHEAT
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
	
	random_encryptor(&encrypted_data, &encrypted_data_size, (unsigned char *) input_string, input_string_size, AES_KEY_128);
	
	is_ecb = is_aes_ecb(encrypted_data, encrypted_data_size);
	
	if(is_ecb == 0){
		printf("Should be ECB.\n");
	}else if(is_ecb == 1){
		printf("Should be CBC. (is_aes_ecb generic failure to detect ECB)\n");
	}else{
		printf("Error in is_aes_ecb.\n");
	}

	#if CHEAT
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

/* Adds 5-10 bytes before and after given input, then encrypts new buffer
 * with either ECB or CBC, chosen randomly
 */
int random_encryptor(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, uint8_t key_type){
	size_t i;

	unsigned char *key = NULL;
	unsigned char *initialization_vector = NULL;
	unsigned char *new_input = NULL;
	size_t new_input_size;

	unsigned char *prefix = NULL;
	unsigned char *postfix = NULL;
	
	unsigned char cipher_choice;
	unsigned char prefix_length, postfix_length;
	
	srand(time(NULL));
	
	/* rand() % n = [0, n-1] */
	/* 5 - 10 */
	prefix_length = (rand() % 6) + 5;
	postfix_length = (rand() % 6) + 5;

	prefix = malloc(prefix_length);
	for(i = 0; i < prefix_length; i++){
		prefix[i] = (unsigned char) (rand() % 256);
	}

	postfix = malloc(postfix_length);
	for(i = 0; i < postfix_length; i++){
		postfix[i] = (unsigned char) (rand() % 256);
	}

	/* build the new buffer */
	new_input_size = input_size+prefix_length+postfix_length;
	new_input = malloc(new_input_size);
	memcpy(new_input, prefix, prefix_length);
	memcpy(new_input+prefix_length, input, input_size);
	memcpy(new_input+prefix_length+input_size, postfix, postfix_length);
	
	free(prefix);
	free(postfix);

	/* 50/50 ECB/CBC 
	 * 0 or 1
	 */
	cipher_choice = rand() % 2;
	#if CHEAT
	cheat_answer = cipher_choice;
	#endif

	/* random key */
	generate_random_aes_key(&key, key_type);
	
	if(cipher_choice == 0){
		aes_encrypt(output_ptr, output_size_ptr, new_input, new_input_size, key, NULL, AES_CIPHER_ECB, key_type);
	}else{/*(cipher_choice == 1)*/
		/* random IV - IV is always 16 bytes, the size of an AES round key/AES-128 key  */
		generate_random_aes_key(&initialization_vector, AES_KEY_128);
		aes_encrypt(output_ptr, output_size_ptr, new_input, new_input_size, key, initialization_vector, AES_CIPHER_CBC, key_type);
		free(initialization_vector);
	}

	free(key);
	free(new_input);

	return 0;
}
