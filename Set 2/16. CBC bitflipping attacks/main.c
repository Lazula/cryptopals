#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/aes.h"

#define USE_RANDOM_KEY 1
#define USE_RANDOM_INITIALIZATION_VECTOR 1
#define DEBUG_AUTHENTICATION 0

unsigned char *KEY = NULL;
unsigned char *IV = NULL;
const size_t BLOCK_SIZE = 16;

int encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size);
int authenticate(unsigned char *input_data, size_t input_data_size);

int main(){
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_size;

	unsigned char *input_data;
	size_t input_data_size;

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

	input_data_size = BLOCK_SIZE*2;
	input_data = malloc(input_data_size);
	memset(input_data, 'A', BLOCK_SIZE);
	memcpy(input_data+BLOCK_SIZE, ":admin<true:", 12);

	encrypt(&encrypted_data, &encrypted_data_size, input_data, input_data_size);
	free(input_data);

	/* Apply bit flips to first block - ciphetext prepends 2 blocks, so add BLOCK_SIZE*2.
	 * They are applied to the next block via CBC's XORing with the previous block
	 * before encryption
	 */
	/* ':' = 0x3A ^ 0x1 = 0x3B = ';' */
	encrypted_data[32] ^= 0x1;
	/* '<' = 0x3C ^ 0x1 = 0x3D = '=' */
	encrypted_data[38] ^= 0x1;
	/* ':' = 0x3A ^ 0x1 = 0x3B = ';' */
	encrypted_data[43] ^= 0x1;

	if(authenticate(encrypted_data, encrypted_data_size)){
		printf("Successfully authenticated.\n");
	}else{
		printf("Failed to authenticate.\n");
	}

	free(encrypted_data);

	return 0;
}

/* Prepend and append set data to input, then encrypt in CBC mode
 */
int encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size){
	size_t i;

	char *prefix = "comment1=cooking%20MCs;userdata=";
	char *postfix = ";comment2=%20like%20a%20pound%20of%20bacon";

	unsigned char *combined_data;
	size_t combined_data_size;

	unsigned char *encrypted_combined_data = NULL;
	size_t encrypted_combined_data_size;

	combined_data_size = strlen(prefix) + input_data_size + strlen(postfix);
	combined_data = malloc(combined_data_size);

	memcpy(combined_data, prefix, strlen(prefix));
	if(input_data_size > 0) memcpy(combined_data+strlen(prefix), input_data, input_data_size);
	memcpy(combined_data+strlen(prefix)+input_data_size, postfix, strlen(postfix));
	
	/* Replace all ';' and '=' in input with '-' to prevent injection */
	for(i = strlen(prefix); i < strlen(prefix) + input_data_size; i++){
		if(combined_data[i] == ';' || combined_data[i] == '='){
			combined_data[i] = '-';
		}
	}

	aes_encrypt(&encrypted_combined_data, &encrypted_combined_data_size, combined_data, combined_data_size, KEY, IV, AES_CIPHER_CBC, AES_KEY_128);

	if(output_ptr != NULL){
		if(*output_ptr == NULL) *output_ptr = malloc(encrypted_combined_data_size);
		memcpy(*output_ptr, encrypted_combined_data, encrypted_combined_data_size);
	}

	if(output_size_ptr != NULL) *output_size_ptr = encrypted_combined_data_size;

	free(combined_data);
	free(encrypted_combined_data);

	return 0;
}

/* Decrypt input and return 1 if it contains ";admin=true;", else return 0
 */
int authenticate(unsigned char *input_data, size_t input_data_size){
	size_t i;

	unsigned char *decrypted_data = NULL;
	size_t decrypted_data_size;

	#if DEBUG_AUTHENTICATION
	char *decrypted_string;
	#endif

	aes_decrypt(&decrypted_data, &decrypted_data_size, input_data, input_data_size, KEY, IV, AES_CIPHER_CBC, AES_KEY_128);
	
	#if DEBUG_AUTHENTICATION
	decrypted_string = malloc(decrypted_data_size+1);
	memcpy(decrypted_string, decrypted_data, decrypted_data_size);
	decrypted_string[decrypted_data_size] = '\0';
	printf("Checking authentication for \"%s\"\n", decrypted_string);
	free(decrypted_string);
	#endif

	for(i = 0; i < decrypted_data_size - 11; i++){
		if(memcmp(decrypted_data+i, ";admin=true;", 11) == 0){
			free(decrypted_data);
			return 1;
		}
	}

	free(decrypted_data);
	return 0;
}

