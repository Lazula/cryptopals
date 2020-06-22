#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

#define DEBUG 0
#define DEBUG_USE_SET_KEY 0

/* Provide all nulls to edit. This will give you the keystream used to encrypt the ciphertext. */

static unsigned char *KEY = NULL;

int get_encrypted_data(unsigned char **output_ptr, size_t *output_size_ptr);
int edit(unsigned char *ciphertext_out, size_t offset, unsigned char *ciphertext_in, size_t input_size, unsigned char *new_plaintext, size_t new_plaintext_size);

int main(){
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_size;

	unsigned char *new_plaintext = NULL;
	size_t new_plaintext_size;

	unsigned char *recovered_keystream = NULL;

	char *recovered_plaintext = NULL;

	size_t i;

	get_encrypted_data(&encrypted_data, &encrypted_data_size);

	new_plaintext_size = encrypted_data_size;
	new_plaintext = malloc(new_plaintext_size);

	memset(new_plaintext, '\0', new_plaintext_size);

	recovered_keystream = malloc(encrypted_data_size);
	edit(recovered_keystream, 0, encrypted_data, encrypted_data_size, new_plaintext, new_plaintext_size);

	free(new_plaintext);

	recovered_plaintext = malloc(new_plaintext_size+1);
	for(i = 0; i < new_plaintext_size; i++){
		recovered_plaintext[i] = encrypted_data[i] ^ recovered_keystream[i];
	}
	recovered_plaintext[new_plaintext_size] = '\0';

	free(encrypted_data);
	free(recovered_keystream);

	printf("%s\n", recovered_plaintext);

	free(recovered_plaintext);
	free(KEY);

	return 0;
}

int get_encrypted_data(unsigned char **output_ptr, size_t *output_size_ptr){
	FILE *data_file = NULL;

	char *line_buffer = NULL;
	size_t line_buffer_size;

	char *input_buffer = NULL;
	size_t input_buffer_size;

	char *linebreak = NULL;

	unsigned char *ecb_encrypted_data = NULL;
	size_t ecb_encrypted_data_size;

	unsigned char *decrypted_data = NULL;
	size_t decrypted_data_size;

	line_buffer_size = 1024;
	input_buffer_size = 1024*1024;

	line_buffer = malloc(line_buffer_size);
	input_buffer = malloc(input_buffer_size);

	data_file = fopen("data.txt", "r");

	while(fgets(line_buffer, line_buffer_size, data_file) != NULL){
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		strncat(input_buffer, line_buffer, line_buffer_size);
	}
	free(line_buffer);

	fclose(data_file);

	base64_decode(&ecb_encrypted_data, &ecb_encrypted_data_size, input_buffer);
	free(input_buffer);

	aes_decrypt(&decrypted_data, &decrypted_data_size, ecb_encrypted_data, ecb_encrypted_data_size, (unsigned char *) "YELLOW SUBMARINE", NULL, AES_CIPHER_ECB, AES_KEY_128);
	free(ecb_encrypted_data);

	if(KEY == NULL) generate_random_aes_key(&KEY, AES_KEY_128);

	aes_encrypt(output_ptr, output_size_ptr, decrypted_data, decrypted_data_size, KEY, NULL, AES_CIPHER_CTR, AES_KEY_128);

	free(decrypted_data);

	return 0;
}

int edit(unsigned char *ciphertext_out, size_t offset, unsigned char *ciphertext_in, size_t input_size, unsigned char *new_plaintext, size_t new_plaintext_size){
	unsigned char *decrypted_input = NULL;

	aes_decrypt(&decrypted_input, NULL, ciphertext_in, input_size, KEY, NULL, AES_CIPHER_CTR, AES_KEY_128);

	memcpy(decrypted_input+offset, new_plaintext, new_plaintext_size);

	aes_encrypt(&ciphertext_out, NULL, decrypted_input, input_size, KEY, NULL, AES_CIPHER_CTR, AES_KEY_128);

	free(decrypted_input);

	return 0;
}
