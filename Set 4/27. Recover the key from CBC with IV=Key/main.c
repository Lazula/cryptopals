#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/aes.h"

#define DEBUG_USE_SET_KEY 0
#define DEBUG_SHOW_KEY 0
#define DEBUG_AUTHENTICATION 0

unsigned char *KEY = NULL;
const size_t BLOCK_SIZE = 16;

int encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input_data, size_t input_data_size);
int authenticate(unsigned char **decrypted_data_ptr, size_t *decrypted_data_size_ptr, unsigned char *input_data, size_t input_data_size);

int main(){
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_size;

	unsigned char *input_data;
	size_t input_data_size;

	unsigned char *modified_encrypted_data;

	unsigned char *decrypted_data = NULL;
	size_t decrypted_data_size;

	unsigned char *recovered_key;

	size_t i;

	input_data_size = BLOCK_SIZE*3;
	input_data = malloc(input_data_size);
	memset(input_data, 'A', BLOCK_SIZE*3);

	encrypt(&encrypted_data, &encrypted_data_size, input_data, input_data_size);
	free(input_data);

	modified_encrypted_data = malloc(BLOCK_SIZE*3);
	memcpy(modified_encrypted_data, encrypted_data+BLOCK_SIZE*2, BLOCK_SIZE);
	memset(modified_encrypted_data+BLOCK_SIZE, 0, BLOCK_SIZE);
	memcpy(modified_encrypted_data+BLOCK_SIZE*2, encrypted_data+BLOCK_SIZE*2, BLOCK_SIZE);
	
	recovered_key = malloc(BLOCK_SIZE);

	if(authenticate(&decrypted_data, &decrypted_data_size, modified_encrypted_data, BLOCK_SIZE*3) == -1){
		printf("Forced plaintext decryption with malicious ciphertext.\n");

		for(i = 0; i < BLOCK_SIZE; i++){
			recovered_key[i] = decrypted_data[i] ^ decrypted_data[BLOCK_SIZE*2 + i];
		}

		printf("Recovered key used as IV:\n");
		hex_print(recovered_key, BLOCK_SIZE);
		printf("\n");
		free(decrypted_data);
	}

	free(encrypted_data);
	free(modified_encrypted_data);
	free(recovered_key);

	#if ! DEBUG_USE_SET_KEY
	free(KEY);
	#endif

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

	unsigned char valid_ascii = 1;

	#if DEBUG_USE_SET_KEY
	if(KEY == NULL) KEY = (unsigned char *) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
	#else
	if(KEY == NULL) generate_random_aes_key(&KEY, AES_KEY_128);
	#endif

	#if DEBUG_SHOW_KEY
	printf("Using key:\n");
	hex_print(KEY, BLOCK_SIZE);
	printf("\n");
	#endif

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

		if(combined_data[i] > 0x7E){
			valid_ascii = 0;
			break;
		}
	}

	aes_encrypt(&encrypted_combined_data, &encrypted_combined_data_size, combined_data, combined_data_size, KEY, KEY, AES_CIPHER_CBC, AES_KEY_128);

	if(output_ptr != NULL){
		if(*output_ptr == NULL) *output_ptr = malloc(encrypted_combined_data_size);
		memcpy(*output_ptr, encrypted_combined_data, encrypted_combined_data_size);
	}

	if(output_size_ptr != NULL) *output_size_ptr = encrypted_combined_data_size;

	free(combined_data);
	free(encrypted_combined_data);

	if(valid_ascii) return 0;
	else return -1;
}

/* Decrypt input and return -1 if it contains non-ASCII characters, 
 * then 0 if it contains ";admin=true;", or 1 if it does not.
 */
int authenticate(unsigned char **decrypted_data_ptr, size_t *decrypted_data_size_ptr, unsigned char *input_data, size_t input_data_size){
	size_t i;

	unsigned char *decrypted_data = NULL;
	size_t decrypted_data_size;

	unsigned char valid_ascii = 1;

	#if DEBUG_AUTHENTICATION
	char *decrypted_string;
	#endif

	if(KEY == NULL) return 2;
	aes_decrypt(&decrypted_data, &decrypted_data_size, input_data, input_data_size, KEY, KEY, AES_CIPHER_CBC, AES_KEY_128);
	
	#if DEBUG_AUTHENTICATION
	decrypted_string = malloc(decrypted_data_size+1);
	memcpy(decrypted_string, decrypted_data, decrypted_data_size);
	decrypted_string[decrypted_data_size] = '\0';
	printf("Checking authentication for \"%s\"\n", decrypted_string);
	free(decrypted_string);
	#endif

	for(i = 0; i < decrypted_data_size - 11; i++){
		if(decrypted_data[i] > 0x7E){
			valid_ascii = 0;
			break;
		}
	}

	for(i = 0; i < decrypted_data_size - 11; i++){
		if(!memcmp(decrypted_data+i, ";admin=true;", 11)){
			free(decrypted_data);
			return 0;
		}
	}

	if(decrypted_data_ptr != NULL){
		if(*decrypted_data_ptr == NULL) *decrypted_data_ptr = malloc(decrypted_data_size);
		memcpy(*decrypted_data_ptr, decrypted_data, decrypted_data_size);
	}
	if(decrypted_data_size_ptr != NULL) *decrypted_data_size_ptr = decrypted_data_size;

	free(decrypted_data);
	if(valid_ascii) return 1;
	else return -1;
}
