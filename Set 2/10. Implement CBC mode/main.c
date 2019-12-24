#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

int main(int argc, char *argv[]){
	FILE *data_file;
	//input_buffer accepts up to 1MB-1 with lines up to the same length
	size_t input_buffer_size = 1048576;
	size_t line_buffer_size = input_buffer_size;
	unsigned char *input_buffer = calloc(input_buffer_size, sizeof(unsigned char)), *line_buffer = calloc(line_buffer_size, sizeof(unsigned char)), *linebreak = NULL, *raw_encrypted_data = NULL;
	
	data_file = fopen("data.txt", "r");
	
	while(getdelim((char **)&line_buffer, &line_buffer_size, '\n', data_file) > -1){
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		if(strlen(input_buffer) + strlen(line_buffer) > input_buffer_size){
			printf("Input length is greater than maximum size %zu\n", input_buffer_size);
			exit(EXIT_FAILURE);
		}
		strncat(input_buffer, line_buffer, line_buffer_size);
	}
	free(line_buffer);
	fclose(data_file);
	
	size_t raw_data_size = base64_decode(&raw_encrypted_data, input_buffer);
	
	free(input_buffer);
	
	//key file should be in the format [LENGTH]\n[DATA], e.g. "16\nYELLOW SUBMARINE"
	FILE *key_file = fopen("key.txt", "r");
	//128 bits = 16 bytes
	size_t key_size = 16;
	unsigned char *key = calloc(key_size, sizeof(unsigned char));
	if(fread(key, 1, key_size, key_file) != key_size){
		printf("Key was not 16 bytes. Quitting.\n");
		exit(EXIT_FAILURE);
	}
	fclose(key_file);
	
	unsigned char *initialization_vector = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	unsigned char *decrypted_data = NULL;
	
	size_t decrypted_data_size = aes_decrypt(&decrypted_data, raw_encrypted_data, raw_data_size, key, initialization_vector, AES_CIPHER_CBC, AES_KEY_128);

	/* Copy raw data bytes into a buffer with space for a null byte */
	unsigned char *decrypted_string = malloc(decrypted_data_size+1);
	memcpy(decrypted_string, decrypted_data, decrypted_data_size);
	decrypted_string[decrypted_data_size] = '\0';
	free(decrypted_data);
	
	printf("%s", decrypted_string);
	
	free(decrypted_string);	
	free(raw_encrypted_data);
	free(key);
}
