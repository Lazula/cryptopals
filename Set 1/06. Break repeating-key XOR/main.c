#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>

#include "../../include/base64.h"
#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"
#include "../../include/hamming_distance.h"
#include "../../include/decrypt_single_byte_xor.h"

#define DEBUG 0

int main(void){
	FILE *data_file;
	/* input_buffer accepts up to 1MB-1 with lines up to the same length */
	size_t input_buffer_size = 1048576;
	size_t line_buffer_size = input_buffer_size;
	char *input_buffer = malloc(input_buffer_size), *line_buffer = malloc(line_buffer_size), *linebreak;
	unsigned char *raw_encrypted_data = NULL;
	size_t raw_data_size;
	
	size_t keysize, found_keysize, trial, num_trials;
	unsigned int total_edit_distance;
	double average_edit_distance, best_edit_distance = DBL_MAX;
	char *byteset_one, *byteset_two;
	
	size_t byteset_size;
	unsigned char *current_byteset, *key;
	char *current_output;
	unsigned char current_key_byte;
	size_t i, j;
	
	size_t decrypted_string_size;
	char *decrypted_string;
	
	data_file = fopen("data.txt", "r");
	
	while(fgets(line_buffer, line_buffer_size, data_file) != NULL){
		if((linebreak = strchr(line_buffer, '\n')) != NULL) *linebreak = '\0';
		if(strlen(input_buffer) + strlen(line_buffer) > input_buffer_size){
			printf("Input length is greater than maximum size %lu\n", input_buffer_size);
			exit(EXIT_FAILURE);
		}
		strncat(input_buffer, line_buffer, line_buffer_size);
	}
	free(line_buffer);
	fclose(data_file);
	
	/* input_buffer is now a single block of b64-encoded data */
	base64_decode(&raw_encrypted_data, &raw_data_size, input_buffer);
	
	free(input_buffer);
	
	for(keysize = 2; keysize <= 40; keysize++){
		total_edit_distance = 0;
		
		byteset_one = malloc(keysize);
		byteset_two = malloc(keysize);
		
		num_trials = (raw_data_size / keysize) - 1;
		
		for(trial = 0; trial < num_trials; trial++){
			memcpy(byteset_one, raw_encrypted_data + (keysize * trial), keysize);
			memcpy(byteset_two, raw_encrypted_data + (keysize * (trial+1)), keysize);
			total_edit_distance += hamming_distance(byteset_one, byteset_two, keysize) / keysize;
		}
		
		average_edit_distance = (double)total_edit_distance / num_trials;
		
		if(average_edit_distance < best_edit_distance){
			best_edit_distance = average_edit_distance;
			found_keysize = keysize;
			#if DEBUG
				printf("new best keysize %ld|edit distance %f|total %d|num_trials %lu\n", keysize, average_edit_distance, total_edit_distance, num_trials);
			#endif
		}
		
		free(byteset_one);
		free(byteset_two);
	}

	#if DEBUG
		printf("Most likely key length: %lu, with normalized edit distance of %f.\nblocks to decrypt are %lu bytes long.\n", found_keysize, best_edit_distance, raw_data_size / found_keysize);
	#endif
	
	byteset_size = raw_data_size / found_keysize;
	current_byteset = malloc(byteset_size);
	key = malloc(found_keysize);
	current_output = malloc(byteset_size+1);
	current_key_byte = 0;

	for(i = 0; i < found_keysize; i++){
		#if DEBUG
			printf("Working on set %lu\n", i);
		#endif
		/* reset memory */
		memset(current_byteset, 0, byteset_size);
		for(j = 0; j < byteset_size; j++){
			current_byteset[j] = raw_encrypted_data[(found_keysize*j)+i];
		}
		decrypt_single_byte_xor(current_output, &current_key_byte, current_byteset, byteset_size);
		#if DEBUG
			printf("current_key_byte: 0x%.2x\n", current_key_byte);
		#endif
		key[i] = current_key_byte;
	}
	
	decrypted_string_size = raw_data_size;
	decrypted_string = malloc(decrypted_string_size);
	repeating_key_xor((unsigned char *) decrypted_string, raw_encrypted_data, raw_data_size, key, found_keysize);
	decrypted_string[decrypted_string_size-1]= '\0';
	
	printf("%s\n", decrypted_string);
	
	free(raw_encrypted_data);
	free(decrypted_string);
	free(current_byteset);
	free(current_output);
	free(key);

	return 0;
}
