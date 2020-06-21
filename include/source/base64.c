#include <stdlib.h>
#include <string.h>

#include "../base64.h"

/* Encode a block of data to padded base64 */
int base64_encode(char **output_string_ptr, unsigned char *input_data, size_t input_size){
	const char *const base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	unsigned char current_input_bytes[4] = {0}, current_output_sextets[5] = {0};
	char output_buffer[5] = {0};
	unsigned int num_padding = 0;

	size_t base64_encoded_string_size;
	char *base64_encoded_string;

	size_t index, output_index, padding_check_index;

	/* (4n/3) for unpadded length, + 3 bitwise &~3 to round up to multiple of 4 for padded length, plus \0 */
	base64_encoded_string_size = ((((4 * input_size) / 3) + 3) & ~3 ) + 1;
	base64_encoded_string = malloc(base64_encoded_string_size);
	/* string memory needs to be initialized for strncat to work properly */
	memset(base64_encoded_string, 0, base64_encoded_string_size);

	/* work in 3-byte blocks, 3*8=24/6=4 */
	for(index = 0; index < input_size; index += 3){
		current_input_bytes[0] = input_data[index];

		if(index+1 < input_size){
			current_input_bytes[1] = input_data[index+1];
		}else{
			current_input_bytes[1] = '\0';
			if(num_padding == 0) num_padding = 2;
		}

		if(index+2 < input_size){
			current_input_bytes[2] = input_data[index+2];
		}else{
			current_input_bytes[2] = '\0';
			if(num_padding == 0) num_padding = 1;
		}

		/* match top 6 bits in char 0 */
		current_output_sextets[0] = (current_input_bytes[0] & 0xFC) >> 2;
		/* match bottom 2 bits in char 0 and top 4 in char 1 */
		current_output_sextets[1] = ((current_input_bytes[0] & 0x03) << 4) + ((current_input_bytes[1] & 0xF0) >> 4);
		/* match bottom 4 bits in char 1 and top 2 in char 2 */
		current_output_sextets[2] = ((current_input_bytes[1] & 0x0F) << 2) + ((current_input_bytes[2] & 0xC0) >> 6);
		/* match bottom 6 bits in char 2 */
		current_output_sextets[3] = current_input_bytes[2] & 0x3F;

		for(output_index = 0; output_index < 4; output_index++){
			output_buffer[output_index] = base64_table[(unsigned char) current_output_sextets[output_index]];
		}

		strncat(base64_encoded_string, output_buffer, 4);
	}

	/* Go from len-(1+num_padding) to the end, replacing with = */
	for(padding_check_index = strlen(base64_encoded_string) - num_padding; padding_check_index < strlen(base64_encoded_string); padding_check_index++){
		base64_encoded_string[padding_check_index] = '=';
	}

	if(output_string_ptr != NULL){
		if(*output_string_ptr == NULL) *output_string_ptr = malloc(base64_encoded_string_size);
		memcpy(*output_string_ptr, base64_encoded_string, base64_encoded_string_size);
	}

	free(base64_encoded_string);
	return 0;
}

/* Decodes an arbitrary block of base64 encoded data. Padding is not nexessary. */
int base64_decode(unsigned char **output_data_ptr, size_t *output_data_size_ptr, char *input_string){
	const char *const base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	char current_input_chars[5] = {0}, current_input_sextets[4] = {0}, *output_buffer = NULL, base64index = 0;
	unsigned char current_output_bytes[3] = {0};

	size_t num_padding;
	size_t input_size, input_size_with_padding;
	size_t output_data_size;
	size_t index, output_index, j;
	
	char *first_pad;

	memset(current_input_chars, 0, 5);
	memset(current_input_sextets, 0, 4);
	memset(current_output_bytes, 0, 3);

	first_pad = strchr(input_string, '=');
	/* If there is no padding, set first_pad to the index of the terminating null byte */
	if(first_pad == NULL) first_pad = strchr(input_string, '\0');
	num_padding = strlen(first_pad);
	input_size_with_padding = strlen(input_string);
	input_size = input_size_with_padding - num_padding;

	/* Add all but the last four-character block */
	output_data_size = ((input_size_with_padding-4) * 3) / 4;
	/* Add appropriate length based on number of padding characters */
	if(num_padding == 2){
		output_data_size += 1;
	}else if(num_padding == 1){
		output_data_size += 2;
	}else{
		output_data_size += 3;
	}

	output_index = 0;

	output_buffer = malloc(output_data_size);

	for(index = 0; index < input_size; index += 4){
		/* Make sure we are working with empty memory - strncpy won't replace
		 * any bytes after the first null, e.g. {'a', 'b', '\0', 'd', \0}
		 * 'd' is from the last copy and there are only two chars left, so
		 * it would be in the encoded data if we left it there.
		 */
		memset(current_input_chars, 0, 4);

		strncpy(current_input_chars, input_string+index, 4);

		/* Replace = with null for the actual values
		 * Work backwards with strrchr or we'll miss the second one, if present.
		 */
		while(strrchr(current_input_chars, '=') != NULL){
			*strrchr(current_input_chars, '=') = '\0';
		}

		/* Get the actual sextet values based on base64 table index */
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

		if(output_data_size - output_index >= 3){
			memcpy(output_buffer+output_index, current_output_bytes, 3);
		}else{
			/* Avoid writing out-of-bounds */
			memcpy(output_buffer+output_index, current_output_bytes, output_data_size - output_index);
		}
		output_index += 3;
	}

	if(output_data_ptr != NULL){
		if(*output_data_ptr == NULL) *output_data_ptr = malloc(output_data_size);
		memcpy(*output_data_ptr, output_buffer, output_data_size);
	}

	if(output_data_size_ptr != NULL) *output_data_size_ptr = output_data_size;

	free(output_buffer);

	return 0;
}
