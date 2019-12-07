#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t hex_decode(unsigned char **output_data, unsigned char *input_string){
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
	*output_data = calloc(output_size, sizeof(unsigned char));
        
	unsigned char *current_input_chars = calloc(3, sizeof(unsigned char));
	unsigned char current_decoded_char;
	unsigned int current_char_index = 0;
	
	while(current_char_index < strlen(input_string)){
		current_input_chars[0] = input_string[current_char_index++];
		current_input_chars[1] = input_string[current_char_index++];
		//input is guaranteed to be ASCII text, so string methods are safe to use
		current_decoded_char = (char) strtol(current_input_chars, NULL, 16);
		//we could build a buffer and then memcpy, but working directly on the output is faster
		(*output_data)[(current_char_index/2) - 1] = current_decoded_char;
	}
	
	free(current_input_chars);
	return output_size;
}

size_t hex_encode(unsigned char **output_string, unsigned char *input_data, size_t input_size){
	size_t output_size = input_size*2 + 1;
        unsigned char current_input_char;
        unsigned char *current_output_chars = calloc(3, 1);
        
	*output_string = calloc(output_size, sizeof(unsigned char));
	
        for(unsigned int i = 0; i < input_size; i++){
                current_input_char = input_data[i];
                //hex-encode current char
                sprintf(current_output_chars, "%02x", current_input_char);
                //build output char-by-char
                memcpy(*output_string + (i*2), current_output_chars, 2);
        }
        
        free(current_output_chars);
	return output_size;
}

