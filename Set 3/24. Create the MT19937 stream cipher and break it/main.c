#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../../include/mt19937.h"

#define DEBUG 0

int encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size);

int main(){
	unsigned char *encrypted_data = NULL;
	size_t encrypted_data_size;

	char *input = "victim_username";
	size_t const input_size = strlen(input);

	unsigned char *decrypted_output;

	uint32_t token;

	size_t input_index_in_encrypted_data;

	uint32_t found_seed = 0;
	uint32_t i;

	encrypt(&encrypted_data, &encrypted_data_size, (unsigned char *) input, input_size);
	decrypted_output = malloc(encrypted_data_size);

	input_index_in_encrypted_data = encrypted_data_size - (input_size + sizeof(uint32_t));

	for(i = 0; i < 0xFFFF; i++){
		mt_encrypt(decrypted_output, encrypted_data, encrypted_data_size, i);
		if(!memcmp(decrypted_output + input_index_in_encrypted_data, input, input_size)){
			found_seed = i;
			break;
		}

	}

	/* The token follows the username in memory */
	memcpy(&token, decrypted_output + input_index_in_encrypted_data + input_size, sizeof(uint32_t));

	printf("Found 16-bit seed 0x%.4X\n", found_seed);
	printf("Found secret token 0x%.8X\n", token);

	free(encrypted_data);
	free(decrypted_output);

	return 0;
}

/* Secret format:
 * N = rand() % 64
 * [N random bytes] || Input || 32-bit token
 */
int encrypt(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size){
	unsigned char *input_buffer;
	size_t input_buffer_size;
	size_t num_prefix_bytes;

	uint32_t seed;
	uint32_t token;

	size_t i;

	int return_val;
	
	seed = (uint32_t) (time(NULL) % 0xFFFF);

	srand(time(NULL));
	num_prefix_bytes = rand() % 64;
	token = rand() % 0xFFFFFFFF;

	input_buffer_size = input_size + num_prefix_bytes + sizeof(uint32_t);
	input_buffer = malloc(input_buffer_size);

	for(i = 0; i < num_prefix_bytes; i++){
		input_buffer[i] = (unsigned char) rand() % 256;
	}
	
	memcpy(input_buffer+num_prefix_bytes, input, input_size);
	memcpy(input_buffer+num_prefix_bytes+input_size, &token, sizeof(uint32_t));

	if(output_ptr != NULL) if(*output_ptr == NULL) *output_ptr = malloc(input_buffer_size);
	if(output_size_ptr != NULL) *output_size_ptr = input_buffer_size;

	return_val = mt_encrypt(*output_ptr, input_buffer, input_buffer_size, seed);

	free(input_buffer);

#	if DEBUG
		printf("[DEBUG] encrypt() seed = 0x%.4X\n", seed);
		printf("[DEBUG] encrypt() token = 0x%.8X\n", token);
#	endif

	return return_val;
}
