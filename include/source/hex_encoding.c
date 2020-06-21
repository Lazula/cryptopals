#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../hex_encoding.h"

int hex_encode(char **output_string_ptr, unsigned char *input_data, size_t input_size){
	size_t i;
	size_t output_size;
	unsigned char current_input_char;
	char current_output_chars[3] = {0};

	if(output_string_ptr == NULL) return 1;

	output_size = (input_size * 2) + 1;

	if(*output_string_ptr == NULL) *output_string_ptr = malloc(output_size);

	for(i = 0; i < input_size; i++){
		current_input_char = input_data[i];
		/* hex-encode current char */
		sprintf(current_output_chars, "%02x", current_input_char);
		/* build output char-by-char */
		memcpy((*output_string_ptr) + (i*2), current_output_chars, 2);
	}

	(*output_string_ptr)[output_size-1] = '\0';

	return 0;
}

int hex_decode(unsigned char **output_data_ptr, size_t *output_data_size_ptr, char *input_string){
	size_t i;
	size_t output_size;
	size_t current_char_index;
	char current_input_chars[3] = {0};
	unsigned char current_decoded_char;

	/* non-multiple of 2 length is an invalid hex string */
	if(strlen(input_string) % 2 != 0) return 1;

	/* Check for non-hex characters */
	for(i = 0; i < strlen(input_string); i++){
		if(strchr("0123456789abcdefABCDEF", input_string[i]) == NULL) return 2;
	}

	if(output_data_ptr == NULL) return 3;

	output_size = strlen(input_string)/2;
	if(*output_data_ptr == NULL) *output_data_ptr = malloc(output_size);
	if(output_data_size_ptr != NULL) *output_data_size_ptr = output_size;

	current_char_index = 0;

	while(current_char_index < strlen(input_string)){
		current_input_chars[0] = input_string[current_char_index++];
		current_input_chars[1] = input_string[current_char_index++];
		/* input is guaranteed to be ASCII text, so string methods are safe to use */
		current_decoded_char = (unsigned char) strtol(current_input_chars, NULL, 16);
		/* we could build a buffer and then memcpy, but working directly on the output is faster */
		(*output_data_ptr)[(current_char_index/2) - 1] = current_decoded_char;
	}

	return 0;
}

int hex_print(unsigned char *input, size_t size){
	char *encoded = NULL;
	
	if(input == NULL || size == 0){
		return 2;
	}
	
	if(hex_encode(&encoded, input, size)){
		/* failure to encode */
		return 1;
	}
	
	printf("%s", encoded);

	free(encoded);

	return 0;
}
