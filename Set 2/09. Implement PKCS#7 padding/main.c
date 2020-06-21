#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/crypto_utility.h"
#include "../../include/hex_encoding.h"

int main(){
	char *input = "YELLOW SUBMARINE";
	unsigned char *padded_data = NULL;
	char *padded_string = NULL;
	const size_t block_size = 20;
	size_t padded_data_size;
	size_t padded_string_size;
	char *hex_encoded_padded_data_string = NULL;
		
	pkcs7_pad(&padded_data, &padded_data_size, (unsigned char *) input, strlen(input), block_size);
	padded_string_size = padded_data_size+1;
	padded_string = malloc(padded_string_size);

	memcpy(padded_string, padded_data, padded_data_size);
	padded_string[padded_string_size-1] = '\0';
	
	printf("Raw bytes: \"%s\"\n", padded_string);
	
	hex_encode(&hex_encoded_padded_data_string, padded_data, padded_data_size);

	printf("Hex encoded: \"%s\"\n", hex_encoded_padded_data_string);
	
	free(padded_data);
	free(padded_string);
	free(hex_encoded_padded_data_string);

	return 0;
}
