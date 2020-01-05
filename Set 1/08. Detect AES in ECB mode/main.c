#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/aes.h"

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
