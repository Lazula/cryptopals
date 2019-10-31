#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/fixed_xor.h"

int main(int argc, char *argv[]){
	FILE *data_file;
	FILE *key_file;
	size_t data_buffer_size = 1024;
	size_t key_buffer_size = data_buffer_size;
	unsigned char *hex_encoded_data = calloc(data_buffer_size, 1);
	unsigned char *hex_encoded_key = calloc(key_buffer_size, 1);
	unsigned char *raw_data;
	unsigned char *raw_key;
	
	data_file = fopen("data.txt", "r");
	fscanf(data_file, "%1023s", hex_encoded_data);
	fclose(data_file);
	
	size_t raw_data_size = (strlen(hex_encoded_data)/2)+1;
	raw_data = calloc(raw_data_size, 1);
	
		
	hex_decode(raw_data, hex_encoded_data);
	
	key_file = fopen("key.txt", "r");
	fscanf(key_file, "%1023s", hex_encoded_key);
	fclose(key_file);
	
	size_t raw_key_size = raw_data_size;
	raw_key = calloc(raw_key_size, 1);
	
	hex_decode(raw_key, hex_encoded_key);
	
	unsigned char *decrypted_data = calloc(raw_data_size, 1);
	
	fixed_xor(decrypted_data, raw_data, raw_key, raw_data_size);
		
	size_t encoded_decrypted_data_size = (raw_data_size*2)-1;
	unsigned char *encoded_decrypted_data = calloc(encoded_decrypted_data_size, 1);
	
	//don't include the trailing null byte	
	hex_encode(encoded_decrypted_data, decrypted_data, raw_data_size-1);
	
	printf("%s\n", encoded_decrypted_data);
	
	free(hex_encoded_data);
	free(hex_encoded_key);
	free(raw_data);
	free(raw_key);
}
