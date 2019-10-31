#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/base64.h"

int main(int argc, char *argv[]){
	FILE *input_file;
	
	size_t input_buffer_size = 1024;
	unsigned char *hex_encoded_string = calloc(input_buffer_size, 1);
	unsigned char *raw_data;
	
	input_file = fopen("input.txt", "r");
	
	fscanf(input_file, "%1023s", hex_encoded_string);
	fclose(input_file);
	
	size_t raw_data_size = strlen(hex_encoded_string)/2;
	raw_data = calloc(raw_data_size, 1);
	
	//The length of a base64 encoded string is 4n/3. You must also round up to the nearest multiple of 4 to account for padding.
	size_t base64_encoded_text_length = ((((4 * raw_data_size) / 3) + 3) & ~3) + 1;
	unsigned char *base64_encoded_text = calloc(base64_encoded_text_length, 1);
	
	hex_decode(raw_data, hex_encoded_string);
	
	//Encode, discard trailing null
	base64_encode(base64_encoded_text, raw_data, raw_data_size);
	
	printf("%s\n", base64_encoded_text);
	
	free(base64_encoded_text);
	free(raw_data);
}
