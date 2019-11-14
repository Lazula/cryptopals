#include <stdlib.h>
#include <string.h>

#include "../repeating_key_xor.h"
#include "../frequency_analysis.h"


/*
 * This function makes a best-effort attempt to use analyze_english_plaintext_viability_fast to find a single-byte xor key based on plaintext viability scores
 * output will contain either a string, or, if no ASCII-valid string was found, be set to all null bytes
 * output should be a pointer to a char array of length input_size+1, to account for a full string + null terminator
 * output_key will hold the 1-byte key used to decrypt the output
 * return value is the viability score given to the output.
 * This function IS binary safe on input.
 */
unsigned int decrypt_single_byte_xor(unsigned char *output,  unsigned char *output_key, unsigned char *input_data, size_t input_size){
	size_t decrypted_string_size = input_size+1;
	unsigned char *decrypted_string = calloc(decrypted_string_size, 1);
	unsigned char current_key, best_key = 0, valid_ascii;
	unsigned int current_key_score, best_key_score = 0;
	
	do{
		valid_ascii = 1;
		current_key++;
		repeating_key_xor(decrypted_string, input_data, input_size, &current_key, 1);
		size_t i;
		for(i = 0; i < input_size; i++){
			//any non-ascii character
			//if(decrypted_string[i] < 1 || decrypted_string[i] > 126){
			if(decrypted_string[i] < 32 || decrypted_string[i] > 126){
				valid_ascii = 0;
				break;
			}
		}
		
		if(valid_ascii){
			current_key_score = analyze_english_plaintext_viability_fast(decrypted_string);
			if(current_key_score > best_key_score){
				best_key_score = current_key_score;
				best_key = current_key;
				//printf("new best score %d for key %#02x with output text %s\n", best_key_score, best_key, decrypted_string);
			}
		}
	}while(current_key < 255);
	
	repeating_key_xor(decrypted_string, input_data, input_size, &best_key, 1);
	*output_key = best_key;
	
	if(output != NULL){
		if(strlen(decrypted_string) < input_size){
			memset(output, 0, decrypted_string_size);
		}else{
			strncpy(output, decrypted_string, input_size);
		}
	}
	
	free(decrypted_string);
	
	return best_key_score;
}
