#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

int main(void){
	FILE *data_file;
	/* input_buffer accepts up to 1MB-1 with lines up to the same length */
	size_t input_buffer_size = 1048576;
	size_t line_buffer_size = input_buffer_size;
	char *input_buffer = malloc(input_buffer_size);
	char *line_buffer = malloc(line_buffer_size);
	char *linebreak = NULL;
	unsigned char *raw_encrypted_data = NULL;
	size_t raw_data_size;

	char *key_file_name = "key.txt";
	FILE *key_file;
	size_t key_buf_size = 512;
	char *key_buf, *endptr;
	size_t key_size;

	unsigned char *key;

	unsigned char *decrypted_data = NULL;
	size_t decrypted_data_size;

	size_t decrypted_string_size;
	char *decrypted_string;

	data_file = fopen("data.txt", "r");
	
	while(fgets(line_buffer, line_buffer_size, data_file) != NULL){
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		if(strlen(input_buffer) + strlen(line_buffer) > input_buffer_size){
			printf("Input length is greater than maximum size %lu\n", input_buffer_size);
			exit(EXIT_FAILURE);
		}
		strncat(input_buffer, line_buffer, line_buffer_size);
	}

	free(line_buffer);
	fclose(data_file);
	
	base64_decode(&raw_encrypted_data, &raw_data_size, input_buffer);
	
	free(input_buffer);
	
	/* key file should be in the format [LENGTH]\n[DATA], e.g. "16\nYELLOW SUBMARINE"
	 * any data beyond the given size is not read */
	key_file = fopen(key_file_name, "r");
	key_buf = malloc(key_buf_size);
	
	fgets(key_buf, key_buf_size, key_file);
	key_size = strtol(key_buf, &endptr, 10);
	if(key_buf == endptr){
		printf("Failed to read key size from %s\n", key_file_name);
		exit(EXIT_FAILURE);
	}

	key = malloc(key_size);

	if(fread(key, 1, key_size, key_file) != key_size){
		printf("Could not read %lu bytes. Quitting.\n", key_size);
		exit(EXIT_FAILURE);
	}

	fclose(key_file);
	
	decrypted_data = NULL;
	
	aes_decrypt(&decrypted_data, &decrypted_data_size, raw_encrypted_data, raw_data_size, key, NULL, AES_CIPHER_ECB, AES_KEY_128);
	
	decrypted_string_size = decrypted_data_size+1;
	decrypted_string = malloc(decrypted_string_size);
	memcpy(decrypted_string, decrypted_data, decrypted_data_size);
	decrypted_string[decrypted_string_size-1] = '\0';
	
	printf("%s", decrypted_string);
	
	free(raw_encrypted_data);
	free(decrypted_data);
	free(decrypted_string);
	free(key);
	free(key_buf);

	return 0;
}
