#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t hex_decode(unsigned char **output_data, char *input_string){
	//Check for non-multiple of 2 length
	if(strlen(input_string) % 2 != 0){
		return 0;
	}
	//Check for non-hex characters
	for(unsigned int i = 0; i < strlen(input_string); i++){
		if(strchr("0123456789abcdefABCDEF", input_string[i]) == NULL){
			return 0;
		}
	}
	
	size_t output_size = strlen(input_string)/2;
	if(*output_data == NULL) *output_data = malloc(output_size);
	
	char *current_input_chars = malloc(3);
	current_input_chars[2] = '\0';
	unsigned char current_decoded_char;
	size_t current_char_index = 0;
	
	while(current_char_index < strlen(input_string)){
		current_input_chars[0] = input_string[current_char_index++];
		current_input_chars[1] = input_string[current_char_index++];
		//input is guaranteed to be ASCII text, so string methods are safe to use
		current_decoded_char = (unsigned char) strtol(current_input_chars, NULL, 16);
		//we could build a buffer and then memcpy, but working directly on the output is faster
		(*output_data)[(current_char_index/2) - 1] = current_decoded_char;
	}
	
	free(current_input_chars);
	return output_size;
}

size_t hex_encode(char **output_string, unsigned char *input_data, size_t input_size){
	size_t output_size = input_size*2 + 1;
	unsigned char current_input_char;
	unsigned char *current_output_chars = malloc(3);
	current_output_chars[2] = '\0';
	
	if(*output_string == NULL) *output_string = malloc(output_size);
	
	for(unsigned int i = 0; i < input_size; i++){
		current_input_char = input_data[i];
		//hex-encode current char
		sprintf((char *) current_output_chars, "%02x", current_input_char);
		//build output char-by-char
		memcpy(*output_string + (i*2), current_output_chars, 2);
	}
	
	(*output_string)[output_size-1] = '\0';
	
	free(current_output_chars);
	return output_size;
}

