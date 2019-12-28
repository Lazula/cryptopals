#include <stddef.h>

/* 
 * Applies a key of length *size* to an input of length *size and places it in an output buffer of at least length *size*.
 * size should include space for a null-terminator
 * Error cases:
 * Providing either input_string or key of non-'size' length causes undefined behavior.
 * The function trusts that it is being given valid input.
 */
void fixed_xor(unsigned char *output_data, unsigned char *input_data, unsigned char *key, size_t size){
	size_t i;
	for(i = 0; i < size; i++){
		output_data[i] = input_data[i] ^ key[i];
	}
}
