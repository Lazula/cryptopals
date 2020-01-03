#include <stddef.h>

#include "../repeating_key_xor.h"

/*
 * Applies the given key of length key_size to input_data, repeating as many times as needed.
 * Adapted from fixed_xor(unsigned char *output_data, unsigned char *input_data, unsigned char *key, size_t size)
 * output_data and input_data must be the same size
 */
void repeating_key_xor(unsigned char *output_data, unsigned char *input_data, size_t input_size, unsigned char *key, size_t key_size){
	size_t i;
	for(i = 0; i < input_size; i++){
		output_data[i] = input_data[i] ^ key[i % key_size];
	}
}
