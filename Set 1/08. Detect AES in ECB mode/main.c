#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/aes.h"

signed char is_aes_ecb(unsigned char *data, size_t data_size, uint8_t key_type);

int main(void){
	FILE *data_file = fopen("data.txt", "r");
	size_t line_buffer_size = 1048576; /* 1MB - 1 */
	char *line_buffer = malloc(line_buffer_size);
	char *linebreak = NULL;
	unsigned char *raw_encrypted_data = NULL;
	size_t raw_data_size;
	signed char found_ecb_128, found_ecb_192, found_ecb_256;
	
	while(fgets(line_buffer, line_buffer_size, data_file) != NULL){
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		raw_encrypted_data = NULL;
		raw_data_size = hex_decode(&raw_encrypted_data, line_buffer);

		found_ecb_128 = is_aes_ecb(raw_encrypted_data, raw_data_size, AES_KEY_128);
		if(found_ecb_128 == 0){
			printf("Found potential AES-128-ECB: %s\n", line_buffer);
		}
		
		found_ecb_192 = is_aes_ecb(raw_encrypted_data, raw_data_size, AES_KEY_192);
		if(found_ecb_192 == 0){
			printf("Found potential AES-192-ECB: %s\n", line_buffer);
		}
		
		found_ecb_256 = is_aes_ecb(raw_encrypted_data, raw_data_size, AES_KEY_256);
		if(found_ecb_256 == 0){
			printf("Found potential AES-256-ECB: %s\n", line_buffer);
		}
		
		free(raw_encrypted_data);
	}
	
	fclose(data_file);
	free(line_buffer);

	return 0;
}

/* 
 * Returns: 0 on success (if at least 2 blocks are the same), 1 on failure (no match), and -1 on invalid key type
 */
signed char is_aes_ecb(unsigned char *data, size_t data_size, uint8_t key_type){
	/* Break data into blocks of block_size and check for duplicates */
	size_t block_size, blocks;
	unsigned char *current_i_block, *current_j_block;
	size_t i, j;

	switch(key_type){
		case AES_KEY_128:
			block_size = 16;
			break;
		case AES_KEY_192:
			block_size = 24;
			break;
		case AES_KEY_256:
			block_size = 32;
			break;
		default:
			/* Invalid key type */
			return -1;
			break;
	}
	
	current_i_block = malloc(block_size);
	current_j_block = malloc(block_size);
	blocks = data_size / block_size;

	for(i = 0; i < blocks; i++){
		memcpy(current_i_block, data+(i*block_size), block_size);
		for(j = i + 1; j < blocks; j++){
			memcpy(current_j_block, data+(j*block_size), block_size);
			if(!memcmp(current_i_block, current_j_block, block_size)){
				free(current_i_block);
				free(current_j_block);
				return 0;
			}
		}
	}
	
	free(current_i_block);
	free(current_j_block);

	return 1;
}
