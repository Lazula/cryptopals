#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

int main(void){
	FILE *data_file;
	size_t input_buffer_size = 1048576; /* 1MB-1 */
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

	unsigned char *initialization_vector;
	unsigned char *decrypted_data;
	size_t decrypted_data_size;
	unsigned char *decrypted_string;

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
	
	raw_data_size = base64_decode(&raw_encrypted_data, input_buffer);
	
	free(input_buffer);
	
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
		printf("Key was not 16 bytes. Quitting.\n");
		exit(EXIT_FAILURE);
	}
	
	fclose(key_file);
	
	initialization_vector = (unsigned char *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	decrypted_data = NULL;
	
	decrypted_data_size = aes_decrypt(&decrypted_data, raw_encrypted_data, raw_data_size, key, initialization_vector, AES_CIPHER_CBC, AES_KEY_128);

	/* Copy raw data bytes into a buffer with space for a null byte */
	decrypted_string = malloc(decrypted_data_size+1);
	memcpy(decrypted_string, decrypted_data, decrypted_data_size);
	decrypted_string[decrypted_data_size] = '\0';
	free(decrypted_data);
	
	printf("%s", decrypted_string);
	
	free(decrypted_string);	
	free(raw_encrypted_data);
	free(key);
	free(key_buf);

	return 0;
}
