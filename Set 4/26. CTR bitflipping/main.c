#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/aes.h"

#define DEBUG_AUTHENTICATION 0

static unsigned char *KEY = NULL;
static unsigned char *NONCE = NULL;

int encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size);
int authenticate(unsigned char *input_data, size_t input_data_size);

int main(){
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_size;

	unsigned char *input_data;
	size_t input_data_size;

	input_data_size = 12;
	input_data = malloc(input_data_size);
	memcpy(input_data, ":admin<true:", 12);

	encrypt(&encrypted_data, &encrypted_data_size, input_data, input_data_size);
	free(input_data);

	/* Apply bit flips to first block - ciphertext prepends 2 blocks, so add BLOCK_SIZE*2.
	 * Unlike CBC, where bit errors in a given ciphertext block will reproduce the same
	 * bit errors in the plaintext of the next block, CTR mode will cause the bit errors
	 * to occur in the same plaintext block.
	 */
	#if 1
	/* ':' = 0x3A ^ 0x1 = 0x3B = ';' */
	encrypted_data[32] ^= 0x1;
	/* '<' = 0x3C ^ 0x1 = 0x3D = '=' */
	encrypted_data[38] ^= 0x1;
	/* ':' = 0x3A ^ 0x1 = 0x3B = ';' */
	encrypted_data[43] ^= 0x1;
	#endif

	if(authenticate(encrypted_data, encrypted_data_size)){
		printf("Successfully authenticated.\n");
	}else{
		printf("Failed to authenticate.\n");
	}

	free(encrypted_data);

	free(KEY);
	free(NONCE);

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

	if(KEY == NULL) generate_random_aes_key(&KEY, AES_KEY_128);
	if(NONCE == NULL) generate_random_aes_key(&NONCE, AES_KEY_128);

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

	aes_encrypt(&encrypted_combined_data, &encrypted_combined_data_size, combined_data, combined_data_size, KEY, NONCE, AES_CIPHER_CTR, AES_KEY_128);

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

	if(KEY == NULL || NONCE == NULL) return 2;
	aes_decrypt(&decrypted_data, &decrypted_data_size, input_data, input_data_size, KEY, NONCE, AES_CIPHER_CTR, AES_KEY_128);
	
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

