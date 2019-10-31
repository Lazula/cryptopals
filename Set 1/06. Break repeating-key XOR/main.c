#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"

int main(int argc, char *argv[]){
	FILE *data_file;
	//input_buffer accepts up to 1MB-1 with lines up to the same length
	size_t input_buffer_size = 1048576;
	size_t line_buffer_size = input_buffer_size;
	size_t input_string_length, hex_encoded_output_size;
	unsigned char *input_buffer = calloc(input_buffer_size, 1), *line_buffer = calloc(line_buffer_size, 1), *linebreak, *raw_encrypted_data;
	
	data_file = fopen("data.txt", "r");
	
	while(getdelim((char **)&line_buffer, &line_buffer_size, '\n', data_file) > -1){
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		strncat(input_buffer, line_buffer, line_buffer_size);
	}
	free(line_buffer);
	
	//input_buffer is now a single block of b64-encoded data
	
	size_t raw_data_size = ((strlen(input_buffer) * 3) / 4) + 1;
	raw_encrypted_data = calloc(raw_data_size, 1);
	
	base64_decode(raw_encrypted_data, input_buffer);
	
	
	
	free(input_buffer);
	fclose(data_file);
}
