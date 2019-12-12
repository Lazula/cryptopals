#include <stdio.h>
#include <stdlib.h>

#include "../../include/crypto_utility.h"

int main(int argc, char *argv[]){
	unsigned char *const input = "YELLOW SUBMARINE", *padded = NULL;
	
	size_t const block_size = 20;
		
	pkcs7_pad(&padded, input, 16, block_size);
	printf("%s\n", padded);
	
	free(padded);
}
