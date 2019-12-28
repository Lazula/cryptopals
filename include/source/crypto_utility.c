#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* 
 * Parameters:
 * **output: Automatically allocates *output for the correct size if == NULL
 * *input: Data to pad
 * input_size: Size of data to pad
 * block_size: Size to pad to a multiple of
 * 
 * Returns: size of *output (input_size + padding_amount)
 * 
 * Notes
 * Add PKCS#7 padding to input with given block size.
 */
size_t pkcs7_pad(unsigned char **output, unsigned char *input, size_t input_size, size_t block_size){
	/* 16 - (24 % 16) = 8 padding*/
	size_t padding_amount = block_size - (input_size % block_size);
	
	/* Account for 16 - ([multiple of 16] % 16) = 16 */
	if(padding_amount == block_size) padding_amount = 0;
	
	size_t output_size = input_size + padding_amount;
	
	/* Avoid memory leakage, only overwrite null pointer */
	if(*output == NULL) *output = malloc(output_size);
	
	/* Copy data into *output and apply padding, if applicable */
	memcpy(*output, input, input_size);
	if(padding_amount > 0) memset(*output+input_size, padding_amount, padding_amount);
	
	return output_size;
}

/* 
 * Parameters:
 * **output: Automatically allocates *output for the correct size if == NULL (only enough for raw data, does not add space for trailing \0)
 * *input: Data to unpad
 * input_size: Size of data to unpad
 * block_size: Block size used (used for checking if last char can be padding)
 * 
 * Returns: size of *output (input_size - last_char OR input_size if not padded)
 * 
 * Notes
 * Remove PKCS#7 padding from input with given block size.
 */
size_t pkcs7_unpad(unsigned char **output, unsigned char *input, size_t input_size, size_t block_size){
	unsigned char last_char = input[input_size-1];
	unsigned char *padding_ptr = input+input_size-last_char;
	size_t output_size = input_size;
	
	/* padding chars cannot be >= block_size or == \0 */
	unsigned char *pad_check_buf = NULL;
	if(last_char < block_size && last_char > 0){
		pad_check_buf = malloc(last_char);
		memset(pad_check_buf, last_char, last_char);
		
		/* Make sure the last N chars actually are last_char */
		if(memcmp(pad_check_buf, padding_ptr, last_char) == 0){
			output_size = input_size-last_char;
		}
	}
	
	if(pad_check_buf != NULL) free(pad_check_buf);
	
	/* Remember to check for null ptrptr */
	if(output != NULL){
		if(*output == NULL){
			*output = malloc(output_size);
		}
	}
	
	memcpy(*output, input, output_size);
	
	return output_size;
}
