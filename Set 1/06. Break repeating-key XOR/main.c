#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>

#include "../../include/base64.h"
#include "../../include/hex_encoding.h"
#include "../../include/repeating_key_xor.h"
#include "../../include/hamming_distance.h"
#include "../../include/decrypt_single_byte_xor.h"

int main(int argc, char *argv[]){
	FILE *data_file;
	//input_buffer accepts up to 1MB-1 with lines up to the same length
	size_t input_buffer_size = 1048576;
	size_t line_buffer_size = input_buffer_size;
	unsigned char *input_buffer = calloc(input_buffer_size, 1), *line_buffer = calloc(line_buffer_size, 1), *linebreak, *raw_encrypted_data;
	
	data_file = fopen("data.txt", "r");
	
	while(getdelim((char **)&line_buffer, &line_buffer_size, '\n', data_file) > -1){
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		strncat(input_buffer, line_buffer, line_buffer_size);
	}
	free(line_buffer);
	fclose(data_file);
	
	//input_buffer is now a single block of b64-encoded data
	
	size_t raw_data_size = ((strlen(input_buffer) * 3) / 4) + 1;
	raw_encrypted_data = calloc(raw_data_size, 1);
	
	base64_decode(raw_encrypted_data, input_buffer);
	
	free(input_buffer);
	
	size_t keysize, found_keysize, trials;
	unsigned int total_edit_distance;
	double average_edit_distance, best_edit_distance = DBL_MAX;
	unsigned char *byteset_one, *byteset_two;
	
	for(keysize = 2; keysize <= 40; keysize++){
		total_edit_distance = 0;
		
		byteset_one = calloc(keysize, 1);
		byteset_two = calloc(keysize, 1);
		
		for(trials = 0; trials < raw_data_size / keysize; trials++){
			memcpy(byteset_one, raw_encrypted_data + (keysize * trials), keysize);
			memcpy(byteset_two, raw_encrypted_data + (keysize * (trials+1)), keysize);
			total_edit_distance += hamming_distance(byteset_one, byteset_two, keysize) / keysize;
			trials++;
		}
		
		average_edit_distance = (double)total_edit_distance / trials;
		
		if(average_edit_distance < best_edit_distance){
			best_edit_distance = average_edit_distance;
			found_keysize = keysize;
			//printf("new best keysize %ld|edit distance %lf|total %d|trials %d\n", keysize, average_edit_distance, total_edit_distance, trials);
		}
		
		free(byteset_one);
		free(byteset_two);
	}
	
	printf("Most likely key length: %lu, with normalized edit distance of %lf.\nblocks to decrypt are %lu bytes long.\n", found_keysize, best_edit_distance, raw_data_size / found_keysize);
	
	size_t byteset_size = raw_data_size / found_keysize;
	unsigned char *current_byteset = calloc(byteset_size, 1), *current_output = calloc(byteset_size+1, 1), *key = calloc(found_keysize+1, 1);
	unsigned char current_key_byte = 0;
	printf("raw_encrypted_data@ %p - %p\n", raw_encrypted_data, raw_encrypted_data+raw_data_size);
	printf("current_byteset@ %p - %p\n", current_byteset, current_byteset+byteset_size);
	printf("current_output@ %p - %p\n", current_output, current_output+byteset_size+1);
	size_t i, j;
	for(i = 0; i < found_keysize; i++){
		printf("Working on set %lu\n", i);
		//reset memory
		memset(current_byteset, byteset_size, 0);
		for(j = 0; j < byteset_size; j++){
			memcpy(current_byteset+j, raw_encrypted_data+((found_keysize*j)+i), 1);
		}
		decrypt_single_byte_xor(current_output, &current_key_byte, current_byteset, byteset_size);
		printf("current_output: %s\n", current_output);
		printf("current_key_byte: %#02hhx\n", current_key_byte);
		key[i] = current_key_byte;
	}
	
	free(current_byteset);
	free(current_output);
	free(key);
}
