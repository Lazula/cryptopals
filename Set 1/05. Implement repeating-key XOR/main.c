#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"

int main(int argc, char *argv[]){
	FILE *data_file;
	size_t input_buffer_size = 1024;
	size_t input_string_length, hex_encoded_output_size;
	unsigned char *input_buffer = calloc(input_buffer_size, 1);
	
	data_file = fopen("data.txt", "r");
	
	size_t i;
	if(data_file != NULL){
		fread(input_buffer, 1, input_buffer_size-1, data_file);
	}
	
	unsigned char *encrypted_data, *hex_encoded_encrypted_data, *linebreak;
	unsigned char *key = "ICE";
	size_t key_size = 3;
	
	linebreak = strrchr(input_buffer, '\n');
	//delete last linebreak, if it exists
	if(linebreak != NULL) memset(linebreak, 0, 1);
	
	input_string_length = strlen(input_buffer);
	
	encrypted_data = calloc(input_string_length, 1);
	
	repeating_key_xor(encrypted_data, input_buffer, input_string_length, key, key_size);
	
	hex_encoded_output_size = hex_encode(&hex_encoded_encrypted_data, encrypted_data, input_string_length);
	
	printf("%s\n", hex_encoded_encrypted_data);
	
	
	free(input_buffer);
	free(encrypted_data);
	free(hex_encoded_encrypted_data);
	
	fclose(data_file);
}
