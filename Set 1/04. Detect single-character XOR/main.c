#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <float.h>

#include "../../include/hex_encoding.h"
#include "../../include/decrypt_single_byte_xor.h"

#define DEBUG 0

int main(void){
	FILE *data_file;
	size_t data_buffer_size = 1024;
	size_t raw_data_size;
	size_t hex_encoded_data_size;
	char *hex_encoded_data = malloc(data_buffer_size);
	unsigned char *raw_data = NULL;

	size_t decrypted_data_size;
	char *decrypted_data, *best_answer = NULL, *best_answer_hex = NULL;
	unsigned char *output_key = malloc(sizeof(unsigned char));
	unsigned int line_number = 0, answer_line_number = 0;
	double current_output_score, best_output_score = 0;
	unsigned char current_best_key;
	char *linebreak;

	data_file = fopen("data.txt", "r");

	while(fgets(hex_encoded_data, data_buffer_size, data_file) != NULL){
		line_number++;
		linebreak = strchr(hex_encoded_data, '\n');
		if(linebreak != NULL) *linebreak = '\0';

		hex_encoded_data_size = strlen(hex_encoded_data);
		hex_decode(&raw_data, &raw_data_size, hex_encoded_data);
		decrypted_data_size = raw_data_size+1;
		decrypted_data = malloc(decrypted_data_size);

		current_output_score = decrypt_single_byte_xor_fast(decrypted_data, output_key, raw_data, raw_data_size-1);

		if(current_output_score > best_output_score){
			if(best_answer_hex != NULL) free(best_answer_hex);
			if(best_answer != NULL) free(best_answer);
			best_output_score = current_output_score;
			current_best_key = *output_key;
			answer_line_number = line_number;
			best_answer_hex = malloc(hex_encoded_data_size+1);

			best_answer = malloc(decrypted_data_size+1);
			best_answer[decrypted_data_size] = '\0';

			memcpy(best_answer, decrypted_data, decrypted_data_size);
			memcpy(best_answer_hex, hex_encoded_data, hex_encoded_data_size);
			best_answer_hex[hex_encoded_data_size] = '\0';

			#if DEBUG
				printf("new best key %#02x with score %f with text \"%s\"\n", current_best_key, best_output_score, decrypted_data);
			#endif
		}

		free(raw_data);
		raw_data = NULL;
		free(decrypted_data);
		decrypted_data = NULL;
	}

	fclose(data_file);

	printf("Best answer \"%s\" found on line %d from hex-encoded data \"%s\" with key %#02x\n", best_answer, answer_line_number, best_answer_hex, current_best_key);

	if(best_answer_hex != NULL) free(best_answer_hex);
	if(best_answer != NULL) free(best_answer);
	free(output_key);
	free(hex_encoded_data);

	return 0;
}
