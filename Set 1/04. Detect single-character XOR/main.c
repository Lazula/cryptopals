#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"
#include "../../include/frequency_analysis.h"
#include "../../include/decrypt_single_byte_xor.h"

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
		
		current_output_score = decrypt_single_byte_xor(decrypted_data, output_key, raw_data, raw_data_size);
		
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
