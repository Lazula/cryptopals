#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/base64.h"

int main(int argc, char *argv[]){
	FILE *input_file;
	
	size_t input_buffer_size = 1024;
	unsigned char *hex_encoded_string = calloc(input_buffer_size, 1);
	
	input_file = fopen("input.txt", "r");
	
	fscanf(input_file, "%1023s", hex_encoded_string);
	fclose(input_file);
	
	unsigned char *raw_data;
	size_t raw_data_size = hex_decode(&raw_data, hex_encoded_string);
	
	unsigned char *base64_encoded_text;
	base64_encode(&base64_encoded_text, raw_data, raw_data_size);
	
	printf("%s\n", base64_encoded_text);
	
	free(hex_encoded_string);
	free(base64_encoded_text);
	free(raw_data);
}
