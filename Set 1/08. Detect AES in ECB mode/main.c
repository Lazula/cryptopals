#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/aes.h"

unsigned char is_aes_ecb(unsigned char *data, size_t data_size, uint8_t key_type);

int main(){
	FILE *const data_file = fopen("data.txt", "r");
	//line_buffer accepts up to 1MB-1
	size_t line_buffer_size = 1048576;
	char *line_buffer = malloc(line_buffer_size);
	char *linebreak = NULL;
	unsigned char *raw_encrypted_data = NULL;
	
	while(fgets(line_buffer, line_buffer_size, data_file) != NULL){
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		raw_encrypted_data = NULL;
		const size_t raw_data_size = hex_decode(&raw_encrypted_data, line_buffer);
		unsigned char found_ecb_128 = is_aes_ecb(raw_encrypted_data, raw_data_size, AES_KEY_128);
		if(found_ecb_128){
			printf("Found potential AES-128-ECB: %s\n", line_buffer);
		}
		
		unsigned char found_ecb_192 = is_aes_ecb(raw_encrypted_data, raw_data_size, AES_KEY_192);
		if(found_ecb_192){
			printf("Found potential AES-192-ECB: %s\n", line_buffer);
		}
		
		unsigned char found_ecb_256 = is_aes_ecb(raw_encrypted_data, raw_data_size, AES_KEY_256);
		if(found_ecb_256){
			printf("Found potential AES-256-ECB: %s\n", line_buffer);
		}
		
		free(raw_encrypted_data);
	}
	
	fclose(data_file);
	free(line_buffer);
}

unsigned char is_aes_ecb(unsigned char *data, size_t data_size, uint8_t key_type){
	/* Break data into blocks of block_size and check for duplicates */
	size_t block_size;
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
			/* Invalid key size */
			return 2;
			break;
	}
	
	unsigned char *const current_i_block = calloc(block_size, sizeof(unsigned char)), *const current_j_block = calloc(block_size, sizeof(unsigned char));
	size_t const blocks = data_size / block_size;
	for(size_t i = 0; i < blocks; i++){
		memcpy(current_i_block, data+(i*block_size), block_size);
		for(size_t j = i + 1; j < blocks; j++){
			memcpy(current_j_block, data+(j*block_size), block_size);
			if(!memcmp(current_i_block, current_j_block, block_size)){
				free(current_i_block);
				free(current_j_block);
				return 1;
			}
		}
	}
	
	free(current_i_block);
	free(current_j_block);
	return 0;
}
