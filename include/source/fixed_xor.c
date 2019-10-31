#include <stdlib.h>
#include <string.h>

/* 
 * Applies a key of length *size* to an input of length *size and places it in an output buffer of at least length *size*.
 * size should include space for a null-terminator
 * Error cases:
 * Providing either input_string or key of non-'size' length causes undefined behavior.
 * The function trusts that it is being given valid input.
 */
unsigned int fixed_xor(unsigned char *output_data, unsigned char *input_data, unsigned char *key, size_t size){
	unsigned char *encoded_text = calloc(size, 1);

	unsigned int i;
	for(i = 0; i < size; i++){
		encoded_text[i] = input_data[i] ^ key[i];
	}
	
	memcpy(output_data, encoded_text, size);
	free(encoded_text);
	return 0;
}
