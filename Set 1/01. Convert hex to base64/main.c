#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/base64.h"

int main(void){
	FILE *input_file;
	
	size_t input_buffer_size = 1024;
	char *hex_encoded_string = malloc(input_buffer_size);
	unsigned char *raw_data = NULL;
	size_t raw_data_size;
	char *base64_encoded_string = NULL;
	char *linebreak;
	
	input_file = fopen("input.txt", "r");
	
	fgets(hex_encoded_string, input_buffer_size, input_file);
	if((linebreak = strchr(hex_encoded_string, '\n')) != NULL) *linebreak = '\0';
	fclose(input_file);
	
	hex_decode(&raw_data, &raw_data_size, hex_encoded_string);
	
	base64_encode(&base64_encoded_string, raw_data, raw_data_size);
	
	printf("%s\n", base64_encoded_string);
	
	free(hex_encoded_string);
	free(base64_encoded_string);
	free(raw_data);
	
	return 0;
}
