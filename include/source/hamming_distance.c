#include <string.h>
#include <stddef.h>

/*
 * Hamming distance is the number of different bits between two strings of equal length, e.g. 0b1100 to 0b1011 has a Hamming distance 3
 * This can be easily calculated using XOR on each index and counting the '1' bits (use the example above to try it out yourself - 1100 ^ 1011 = 0111 -> 3)
 * A longer example: 11000100 ^ 10101110 = 01101010 -> 4
 */
unsigned int hamming_distance(unsigned char *data1, unsigned char *data2, size_t input_size){
	unsigned int distance = 0;
	unsigned char current_byte;
	
	size_t i;
	for(i = 0; i < input_size; i++){
		//check lowest bit and then shift
		for(current_byte = data1[i] ^ data2[i]; current_byte > 0; current_byte /= 2){
			if(current_byte & 1) distance++;
		}
	}
	
	return distance;
}

