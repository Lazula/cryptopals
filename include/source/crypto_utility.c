#include "../crypto_utility.h"

/* 
 * Parameters:
 * **output_ptr: Automatically allocates *output_ptr for the correct size if == NULL
 * *output_size_ptr: Automatically sets *output_size_ptr to output size if != NULL
 * *input: Data to pad
 * input_size: Size of data to pad
 * block_size: Size to pad to a multiple of
 * 
 * Returns: 0 if padding was added, 1 if padding was not added
 * *output_ptr will always be allocated, even if padding is not added
 * 
 * Notes
 * Add PKCS#7 padding to input with given block size.
 */
int pkcs7_pad(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, size_t block_size){
	size_t padding_amount;
	size_t output_size;
	
	/* 16 - (24 % 16) = 8 padding */
	/* 16 - (32 % 16) = 16 padding */
	padding_amount = block_size - (input_size % block_size);
	
	output_size = input_size + padding_amount;
	
	if(output_ptr != NULL){
		if(*output_ptr == NULL){
			*output_ptr = malloc(output_size);
		}
	}
	
	if(output_size_ptr != NULL) *output_size_ptr = output_size;

	/* Copy data into *output_ptr and apply padding, if applicable */
	memcpy(*output_ptr, input, input_size);
	if(padding_amount > 0){
		memset(*output_ptr+input_size, padding_amount, padding_amount);
		return 0;
	}else{
		return 1;
	}
}

/* 
 * Parameters:
 * **output_ptr: Automatically allocates *output_ptr for the correct size if == NULL and successful unpad
 * *output_size_ptr: Sets *output_size_ptr to output size if != NULL and successful unpad
 * *input: Data to unpad
 * input_size: Size of data to unpad
 * block_size: Block size used (used for checking if last char can be padding)
 * 
 * Returns: 
 * 0 on success
 * 1 on bad padding (will not allocate *output_ptr or set *output_size_ptr)
 * 
 */
int pkcs7_unpad(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, size_t block_size){
	unsigned char flag_bad_padding = 0;
	unsigned char last_char = input[input_size-1];
	unsigned char *padding_ptr = input+input_size-last_char;
	unsigned char *pad_check_buf = NULL;
	size_t output_size = input_size;

	/* padding chars cannot be > block_size or == \0 */
	if(last_char <= block_size && last_char > 0){
		pad_check_buf = malloc(last_char);
		memset(pad_check_buf, last_char, last_char);
		
		/* Make sure the last N chars actually are last_char */
		if(memcmp(pad_check_buf, padding_ptr, last_char) == 0){
			output_size = input_size-last_char;
		}else{
			flag_bad_padding = 1;
		}
	}
	
	if(pad_check_buf != NULL) free(pad_check_buf);
	
	if(output_ptr != NULL && flag_bad_padding == 0){
		if(*output_ptr == NULL){
			*output_ptr = malloc(output_size);
		}

		memcpy(*output_ptr, input, output_size);
	}

	if(output_size_ptr != NULL && flag_bad_padding == 0) *output_size_ptr = output_size;
	
	if(flag_bad_padding == 0){
		return 0;
	}else{
		return 1;
	}
}
