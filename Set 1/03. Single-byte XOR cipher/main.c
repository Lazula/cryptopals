#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"
#include "../../include/frequency_analysis.h"

int main(int argc, char *argv[]){
	FILE *data_file;
	size_t data_buffer_size = 70;
	unsigned char *hex_encoded_data = calloc(data_buffer_size, 1);
	unsigned char *raw_data;
	
	data_file = fopen("data.txt", "r");
	getline((char **) &hex_encoded_data, &data_buffer_size, data_file);
	fclose(data_file);
	char *linebreak = strchr(hex_encoded_data, '\n');
	if(linebreak != NULL) memset(linebreak, 0, 1);
	
	size_t raw_data_size = (data_buffer_size-2)/2;
	raw_data = calloc(raw_data_size, 1);
	
	hex_decode(raw_data, hex_encoded_data);
	
	size_t decrypted_string_size = raw_data_size+1;
	unsigned char *decrypted_string = calloc(raw_data_size, 1);
	unsigned char current_key = 0, best_key, valid_ascii;
	unsigned int current_key_score, best_key_score = 0;
	
	do{
		valid_ascii = 1;
		current_key++;
		repeating_key_xor(decrypted_string, raw_data, raw_data_size, &current_key, 1);
		size_t i;
		for(i = 0; i < raw_data_size; i++){
			//any non-ascii character or null byte
			if(decrypted_string[i] < 1 || decrypted_string[i] > 126){
				valid_ascii = 0;
				break;
			}
		}
		
		if(valid_ascii){
			current_key_score = analyze_english_plaintext_viability_fast(decrypted_string);
			if(current_key_score > best_key_score){
				best_key_score = current_key_score;
				best_key = current_key;
			}
		}
	}while(current_key < 255);
	
	repeating_key_xor(decrypted_string, raw_data, raw_data_size, &best_key, 1);
	
	printf("Best answer \"%s\" from hex data \"%s\" with key %#02hhx\n", decrypted_string, hex_encoded_data, best_key);
	
	free(hex_encoded_data);
	free(decrypted_string);
	free(raw_data);
}
