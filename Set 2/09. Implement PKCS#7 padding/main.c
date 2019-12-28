#include <stdio.h>
#include <stdlib.h>

#include "../../include/crypto_utility.h"

int main(){
	char *input = "YELLOW SUBMARINE";
	unsigned char *padded = NULL;
	
	const size_t block_size = 20;
		
	pkcs7_pad(&padded, (unsigned char *) input, 16, block_size);
	printf("%s\n", padded);
	
	free(padded);
}
