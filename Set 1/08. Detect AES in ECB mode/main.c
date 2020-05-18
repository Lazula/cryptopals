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
	size_t current_line;

	current_line = 0;
	while(fgets(line_buffer, line_buffer_size, data_file) != NULL){
		current_line++;
		linebreak = strchr(line_buffer, '\n');
		if(linebreak != NULL) *linebreak = '\0';
		raw_encrypted_data = NULL;
		raw_data_size = hex_decode(&raw_encrypted_data, line_buffer);

		if(is_aes_ecb(raw_encrypted_data, raw_data_size) == 0){
			printf("Detected AES-ECB on line %lu with hex data: %s\n", current_line, line_buffer);
		}
		
		free(raw_encrypted_data);
	}
	
	fclose(data_file);
	free(line_buffer);

	return 0;
}
