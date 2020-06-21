#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/fixed_xor.h"

int main(void){
	FILE *data_file;
	FILE *key_file;
	size_t data_buffer_size = 1024;
	size_t key_buffer_size = data_buffer_size;
	char *hex_encoded_data = malloc(data_buffer_size);
	char *hex_encoded_key = malloc(key_buffer_size);
	char *linebreak;
	unsigned char *raw_data = NULL;
	size_t raw_data_size;
	unsigned char *raw_key = NULL;
	size_t raw_key_size;
	unsigned char *decrypted_data = NULL;
	char *hex_encoded_decrypted_string = NULL;
	
	data_file = fopen("data.txt", "r");
	fgets(hex_encoded_data, data_buffer_size, data_file);
	if((linebreak = strchr(hex_encoded_data, '\n')) != NULL) *linebreak = '\0';
	fclose(data_file);
	
	hex_decode(&raw_data, &raw_data_size, hex_encoded_data);
	
	key_file = fopen("key.txt", "r");
	fgets(hex_encoded_key, key_buffer_size, key_file);
	if((linebreak = strchr(hex_encoded_key, '\n')) != NULL) *linebreak = '\0';
	fclose(key_file);
	
	hex_decode(&raw_key, &raw_key_size, hex_encoded_key);
	if(raw_data_size != raw_key_size){
		printf("Data and key size differ. Cannot use fixed_xor.");
		exit(EXIT_FAILURE);
	}
	
	decrypted_data = malloc(raw_data_size);
	
	fixed_xor(decrypted_data, raw_data, raw_key, raw_data_size);
		
	hex_encode(&hex_encoded_decrypted_string, decrypted_data, raw_data_size);
	
	printf("%s\n", hex_encoded_decrypted_string);
	
	free(decrypted_data);
	free(hex_encoded_data);
	free(hex_encoded_key);
	free(raw_data);
	free(raw_key);
	
	return 0;
}
