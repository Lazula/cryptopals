#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>

#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"
#include "../../include/frequency_analysis.h"

int main(void){
	FILE *data_file;
	/* previously 70 */
	size_t data_buffer_size = 128;
	char *hex_encoded_data = malloc(data_buffer_size);
	unsigned char *raw_data = NULL;
	size_t raw_data_size;
	char *linebreak;
	size_t decrypted_string_size;
	char *decrypted_string;
	unsigned char current_key, best_key, valid_ascii;
	double current_key_score, best_key_score;
	size_t i;
	
	data_file = fopen("data.txt", "r");
	fgets(hex_encoded_data, data_buffer_size, data_file);
	fclose(data_file);
	if((linebreak = strchr(hex_encoded_data, '\n')) != NULL) *linebreak = '\0';
	
	raw_data_size = hex_decode(&raw_data, hex_encoded_data);
	
	decrypted_string_size = raw_data_size+1;
	decrypted_string = malloc(decrypted_string_size);
	decrypted_string[decrypted_string_size-1] = '\0';
	current_key = 0;
	best_key_score = DBL_MAX;
	
	do{
		valid_ascii = 1;
		current_key++;
		repeating_key_xor((unsigned char *) decrypted_string, raw_data, raw_data_size, &current_key, 1);
		for(i = 0; i < raw_data_size; i++){
			/* any non-ascii character or null byte */
			if(decrypted_string[i] < 1 || decrypted_string[i] > 126){
				valid_ascii = 0;
				break;
			}
		}
		
		if(valid_ascii){
			current_key_score = analyze_english_plaintext_viability(decrypted_string);
			if(current_key_score < best_key_score){
				best_key_score = current_key_score;
				best_key = current_key;
			}
		}
	}while(current_key < 255);
	
	repeating_key_xor((unsigned char *) decrypted_string, raw_data, raw_data_size, &best_key, 1);
	
	printf("Best answer \"%s\" from hex data \"%s\" with key %#02x\n", decrypted_string, hex_encoded_data, best_key);
	
	free(hex_encoded_data);
	free(decrypted_string);
	free(raw_data);
	
	return 0;
}
