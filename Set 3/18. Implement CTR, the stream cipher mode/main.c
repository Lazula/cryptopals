#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

unsigned char *KEY;
unsigned char *NONCE;

int main(){
	char *base64_encoded_ciphertext =
		"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9"
		"qvY/2syLXzhPweyyMTJULu/6/kXX0KSv"
		"oOLSFQ==";

	unsigned char *ciphertext = NULL;
	size_t ciphertext_size;

	unsigned char *plaintext = NULL;
	size_t plaintext_size;

	KEY = (unsigned char *) malloc(16);
	memcpy(KEY, "YELLOW SUBMARINE", 16);

	NONCE = malloc(8);
	memset(NONCE, 0, 8);

	ciphertext_size = base64_decode(&ciphertext, base64_encoded_ciphertext);

	aes_decrypt(&plaintext, &plaintext_size, ciphertext, ciphertext_size, KEY, NONCE, AES_CIPHER_CTR, AES_KEY_128);

	printf("%s\n", plaintext);

	free(KEY);
	free(NONCE);
	free(ciphertext);
	free(plaintext);

	return 0;
}
