#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/crypto_utility.h"

int main(){
	char *input = "YELLOW SUBMARINE";
	unsigned char *padded_data = NULL;
	char *padded_string = NULL;
	const size_t block_size = 20;
	size_t padded_data_size;
	size_t padded_string_size;
		
	padded_data_size = pkcs7_pad(&padded_data, input, strlen(input), block_size);
	padded_string_size = padded_data_size+1;
	padded_string = malloc(padded_string_size);

	memcpy(padded_string, padded_data, padded_data_size);
	padded_string[padded_string_size-1] = '\0';
	
	printf("%s\n", padded_string);
	
	free(padded_data);
	free(padded_string);
}
