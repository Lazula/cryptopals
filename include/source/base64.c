#include <stdlib.h>
#include <string.h>

#include "../base64.h"

/*
 * Parameters:
 * **output_string: Automatically allocates *output_string for the correct size if == NULL
 * *input_data: Data to be encoded. Binary safe.
 * input_size: Size of the block to be encoded
 * 
 * Returns: Size of output buffer, including trailing null byte
 * 
 * Notes
 * Encodes an arbitrary block of data to padded base64 (to encode a string, use strlen as input_size)
 */
size_t base64_encode(char **output_string, unsigned char *input_data, size_t input_size){
	const char *const base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
	unsigned char current_input_bytes[4] = "", current_output_sextets[5] = "", *output_buffer = NULL;
	unsigned int num_padding = 0;
	
	/* (4n/3) for unpadded length, + 3 bitwise &~3 to round up to multiple of 4 for padded length, plus \0 */
	size_t base64_encoded_string_size = ((((4 * input_size) / 3) + 3) & ~3 ) + 1;
	char *base64_encoded_string = calloc(base64_encoded_string_size, sizeof(char));
	
	output_buffer = malloc(5);
	output_buffer[4] = '\0';
	
	size_t index;
	/* work in 3-byte blocks, 3*8=24/6=4 */
	for(index = 0; index < input_size;){
		current_input_bytes[0] = input_data[index++];
		
		if(index < input_size){
			current_input_bytes[1] = input_data[index++];
		}else{
			current_input_bytes[1] = '\0';
			num_padding = 2;
		}
		
		if(index < input_size){
			current_input_bytes[2] = input_data[index++];
		}else{
			current_input_bytes[2] = '\0';
			num_padding = 1;
		}
		
		/* this garbage actually works, somehow */
		/* match top 6 bits in char 0 */
		current_output_sextets[0] = (current_input_bytes[0] & 0xFC) >> 2;
		/* match bottom 2 bits in char 0 and top 4 in char 1 */
		current_output_sextets[1] = ((current_input_bytes[0] & 0x03) << 4) + ((current_input_bytes[1] & 0xF0) >> 4);
		/* match bottom 4 bits in char 1 and top 2 in char 2 */
		current_output_sextets[2] = ((current_input_bytes[1] & 0x0F) << 2) + ((current_input_bytes[2] & 0xC0) >> 6);
		/* match bottom 6 bits in char 2 */
		current_output_sextets[3] = current_input_bytes[2] & 0x3F;
		
		size_t output_index;
		for(output_index = 0; output_index < 4; output_index++){
			output_buffer[output_index] = base64_table[(unsigned char) current_output_sextets[output_index]];
		}
		strncat(base64_encoded_string, (char *) output_buffer, 4);
	}
	
	/* Go from len-(1+num_padding) to the end, replacing with = */
	for(size_t padding_check_index = strlen(base64_encoded_string) - num_padding; padding_check_index < strlen(base64_encoded_string); padding_check_index++){
		strncpy(base64_encoded_string + padding_check_index, "=", 2);
	}
	
	if(*output_string == NULL) *output_string = malloc(base64_encoded_string_size);
	
	memcpy(*output_string, base64_encoded_string, base64_encoded_string_size);
	free(base64_encoded_string);
	free(output_buffer);
	return base64_encoded_string_size;
}

/*
 * this does not suppport unpadded base64
 * Pass an uninitialized pointer or you will leak memory.
 * Returns output data size (does not include null byte)
 */
/*
 * Parameters:
 * **output_data: Automatically allocates *output_data for the correct size if == NULL
 * *input_string: Data to be encoded. Not binary safe - should be a padded base64 string.
 * 
 * Returns: Size of output buffer
 * 
 * Notes
 * Decodes an arbitrary block of base64 encoded data
 * Does not support unpadded base64
 */
size_t base64_decode(unsigned char **output_data, char *input_string){
	const char *const base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
	char *current_input_chars = malloc(5), *current_input_sextets = malloc(4), *output_buffer = NULL, base64index = 0;
	current_input_chars[4] = '\0';
	current_input_sextets[3] = '\0';
	unsigned char *current_output_bytes = malloc(3);
	current_output_bytes[2] = '\0';
	
	char *first_pad = strchr(input_string, '=');
	/* If there is no padding, set first_pad to the index of the terminating null byte */
	if(first_pad == NULL) first_pad = strchr(input_string, '\0');
	
	size_t num_padding = strlen(first_pad);
	size_t input_size = strlen(input_string) - num_padding;
	size_t output_data_size = ((input_size + num_padding) * 3) / 4;
	output_buffer = malloc(output_data_size);
	size_t index, output_index = 0, j;
	
	for(index = 0; index < input_size; index += 4){
		/* Make sure we are working with empty memory - strncpy won't replace any bytes after the first null, e.g. {'a', 'b', '\0', 'd', \0}
		 * 'd' is from the last copy and there are only two chars left
		 */
		memset(current_input_chars, 0, 4);
		
		strncpy(current_input_chars, input_string+index, 4);
		/* replace = with null for the actual values
		 * work backwards with strrchr or you'll miss the second one!
		 */
		while(strrchr(current_input_chars, '=') != NULL){
			*strrchr(current_input_chars, '=') = '\0';
		}
		/* get the actual sextet values based on base64 table index */
		for(j = 0; j <= 3; j++){
			base64index = (char) (strchr(base64_table, current_input_chars[j]) - base64_table);
			if((int)base64index == 64){
				current_input_sextets[j] = '\0';
			}else{
				current_input_sextets[j] = (char) (base64index);
			}
			
		}
		
		/* byte 0 = (sextet 0 << 2) + (top 2 bits of sextet 1 >> 4) */
		current_output_bytes[0] = ((current_input_sextets[0] << 2) & 0xFC) + ((current_input_sextets[1] >> 4) & 0x03);
		/* byte 1 = (bottom 4 bits of sextet 1 << 4) + (top 4 bits of sextet 2 >> 2) */
		current_output_bytes[1] = ((current_input_sextets[1] << 4) & 0xF0) + ((current_input_sextets[2] >> 2) & 0x0F);
		/* byte 2 = (bottom 2 bits of sextet 2 << 6) + sextet 3 */
		current_output_bytes[2] = ((current_input_sextets[2] << 6) & 0xC0) + current_input_sextets[3];
		
		/* Output bytes are NOT string-safe. */
		memcpy(output_buffer+output_index, current_output_bytes, 3);
		output_index += 3;
	}
	
	*output_data = malloc(output_data_size);
	
	memcpy(*output_data, output_buffer, output_data_size);
	
	free(current_input_sextets);
	free(current_output_bytes);
	free(current_input_chars);
	free(output_buffer);
	
	return output_data_size;
}
