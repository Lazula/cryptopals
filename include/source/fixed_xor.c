#include <stddef.h>

#include "../fixed_xor.h"

/* 
 * Applies a key of length *size* to an input of length *size and places it in an output buffer.
 * The output buffer may be larger than size, but not smaller.
 * The data is treated as binary. If you want to store the output as text, the output buffer should be size+1 with a null byte at the end.
 */
void fixed_xor(unsigned char *output_data, unsigned char *input_data, unsigned char *key, size_t size){
	size_t i;
	for(i = 0; i < size; i++){
		output_data[i] = input_data[i] ^ key[i];
	}
}
