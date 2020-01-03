#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"

int main(){
	FILE *data_file;
	size_t input_buffer_size = 1024;
	size_t input_string_length;
	char *input_buffer = malloc(input_buffer_size);
	
	data_file = fopen("data.txt", "r");
	
	if(data_file != NULL){
		fread(input_buffer, 1, input_buffer_size-1, data_file);
	}
	input_buffer[input_buffer_size-1] = '\0';
	
	unsigned char *encrypted_data;
	char *hex_encoded_encrypted_data = NULL, *linebreak;
	char *key = "ICE";
	size_t key_size = 3;
	
	linebreak = strrchr(input_buffer, '\n');
	//delete last linebreak, if it exists
	if(linebreak != NULL) *linebreak = '\0';
	
	input_string_length = strlen(input_buffer);
	
	encrypted_data = malloc(input_string_length);
	
	repeating_key_xor(encrypted_data, (unsigned char *) input_buffer, input_string_length, (unsigned char *) key, key_size);
	
	hex_encode(&hex_encoded_encrypted_data, encrypted_data, input_string_length);
	
	printf("%s\n", hex_encoded_encrypted_data);
	
	
	free(input_buffer);
	free(encrypted_data);
	free(hex_encoded_encrypted_data);
	
	fclose(data_file);
}
