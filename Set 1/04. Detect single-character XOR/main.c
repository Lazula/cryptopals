#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"
#include "../../include/frequency_analysis.h"

unsigned int attempt_single_byte_xor_decode(unsigned char *output, unsigned char *output_key, unsigned char *input_data, size_t input_size);

int main(int argc, char *argv[]){
	FILE *data_file;
	//arbitrary based on given input, other sizes use it as reference
	size_t data_buffer_size = 62;
	size_t raw_data_size = (data_buffer_size-2)/2;
	unsigned char *hex_encoded_data = calloc(data_buffer_size, 1);
	unsigned char *raw_data = calloc(raw_data_size, 1);
	
	data_file = fopen("data.txt", "r");
	
	size_t decrypted_data_size = raw_data_size+1;
	unsigned char *decrypted_data = calloc(decrypted_data_size, 1), *best_answer = calloc(decrypted_data_size, 1), *best_answer_hex = calloc(data_buffer_size, 1), *output_key = calloc(1, 1);
	unsigned int current_output_score, best_output_score = 0, line_number = 0, answer_line_number = 0;
	unsigned char current_best_key;
	while(getline((char **) &hex_encoded_data, &data_buffer_size, data_file) != -1){
		line_number++;
		char *linebreak = strchr(hex_encoded_data, '\n');
		if(linebreak != NULL) memset(linebreak, 0, 1);
		
		//update size
		raw_data_size = (strlen(hex_encoded_data)-1)/2;
		
		//Decode the string
		hex_decode(raw_data, hex_encoded_data);
		
		current_output_score = attempt_single_byte_xor_decode(decrypted_data, output_key, raw_data, raw_data_size);
		
		if(current_output_score > best_output_score){
			best_output_score = current_output_score;
			current_best_key = *output_key;
			answer_line_number = line_number;
			strncpy(best_answer, decrypted_data, decrypted_data_size);
			strncpy(best_answer_hex, hex_encoded_data, data_buffer_size);
		}
	}
	
	fclose(data_file);
	
	printf("Best answer \"%s\" found on line %d from hex-encoded data \"%s\" with key %#02x\n", best_answer, answer_line_number, best_answer_hex, current_best_key);
	
	
	free(hex_encoded_data);
	free(decrypted_data);
	free(raw_data);
	free(best_answer);
	free(best_answer_hex);
}

/*
 * This function makes a best-effort attempt to use analyze_english_plaintext_viability to find a single-byte xor key based on plaintext viability scores
 * output will contain either a string, or, if no ASCII-valid string was found, be set to all null bytes
 * output should be a pointer to a char array of length input_size+1, to account for a full string + null terminator
 * output_key will hold the 1-byte key used to decrypt the output
 * return value is the viability score given to the output.
 * This function IS binary safe on input.
 */
unsigned int attempt_single_byte_xor_decode(unsigned char *output,  unsigned char *output_key, unsigned char *input_data, size_t input_size){
	size_t decrypted_string_size = input_size+1;
	unsigned char *decrypted_string = calloc(decrypted_string_size, 1);
	unsigned char current_key, best_key = 0, valid_ascii;
	unsigned int current_key_score, best_key_score = 0, output_score;
	
	do{
		valid_ascii = 1;
		current_key++;
		repeating_key_xor(decrypted_string, input_data, input_size, &current_key, 1);
		size_t i;
		for(i = 0; i < input_size; i++){
			//any non-ascii character
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
	
	strlen(decrypted_string) < input_size ? memset(output, 0, decrypted_string_size) : strncpy(output, decrypted_string, input_size);
	
	free(decrypted_string);
	
	return best_key_score;
}

