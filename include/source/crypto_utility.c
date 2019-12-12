#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* 
 * Add PKCS#7 padding to input with given block size.
 * Expects *output to be either a pointer to allocated memory of the correct size or a null pointer.
 * *output will only be overwritten if == NULL to avoid potential memory leakage being overlooked
 * Returns the size of *output (input_size + padding_amount)
 */
size_t pkcs7_pad(unsigned char **output, unsigned char *input, size_t input_size, size_t block_size){
	/* 16 - (24 % 16) = 8 padding*/
	size_t padding_amount = block_size - (input_size % block_size);
	
	/* Account for 16 - ([multiple of 16] % 16) = 16 */
	if(padding_amount == 16) padding_amount = 0;
	size_t output_size = input_size + padding_amount;
	
	/* Avoid memory leakage, only overwrite null pointer */
	if(*output == NULL) *output = calloc(output_size, sizeof(unsigned char));
	
	/* Copy data into *output and apply padding, if applicable */
	memcpy(*output, input, input_size);
	if(padding_amount > 0) memset(*output+input_size, padding_amount, padding_amount);
	
	return output_size;
}

/* 
 * Remove PKCS#7 padding from input with given block size.
 * Returns output_size
 */
size_t pkcs7_unpad(unsigned char **output, unsigned char *input, size_t input_size, size_t block_size){
	unsigned char last_char = input[input_size-1];
	unsigned char *padding_ptr = input+input_size-last_char;
	size_t padding_amount = last_char;
	
	_Bool is_padding = 0;
	if(last_char < block_size && last_char > 0) is_padding = 1;
	
	unsigned char *pad_check_buf = malloc(last_char);
	memset(pad_check_buf, last_char, last_char);
	
	size_t output_size = input_size;
	/* Make sure the last N chars actually are last_char */
	if(is_padding && memcmp(pad_check_buf, padding_ptr, last_char) == 0){
		output_size = input_size-last_char;
	}
	
	if(*output == NULL) *output = malloc(output_size);
	memcpy(*output, input, output_size);
	
	free(pad_check_buf);
	
	return output_size;
}
