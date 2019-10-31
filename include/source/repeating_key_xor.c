#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Applies the given key of length key_size to input_data, repeating as many times as needed.
 * Adapted from fixed_xor(unsigned char *output_data, unsigned char *input_data, unsigned char *key, size_t size)
 * output_data and input_data must be the same size
 */
unsigned int repeating_key_xor(unsigned char *output_data, unsigned char *input_data, size_t input_size, unsigned char *key, size_t key_size){
	unsigned char *encrypted_data = calloc(input_size, 1);
	
	size_t i;
	for(i = 0; i < input_size; i++){
		encrypted_data[i] = input_data[i] ^ key[i % key_size];
	}
	
	memcpy(output_data, encrypted_data, input_size);
	free(encrypted_data);
}
