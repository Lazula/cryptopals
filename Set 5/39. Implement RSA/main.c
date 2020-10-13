#include <stdio.h>

#include "rsa.h"

#define DEBUG 0

int main(){
	apnum_ptr N;

	rsa_keypair_ptr pair;

	char *input = "test input";
	char *encrypted = NULL;
	char *decrypted = NULL;

	apnum_randinit();

	N = new_apnum();

	/* 512-bit keys */
	decode_apnum_from_hex(
		N,
		"10000000000000000000000000000000"
		"00000000000000000000000000000000"
		"00000000000000000000000000000000"
		"000000000000000000000000000000000"
	);

	pair = new_rsa_keypair();

	rsa_generate_keypair(pair, N);
	free_apnum(N);

	printf("Using keypair:\n");
	print_rsa_keypair(pair);

	printf("Input string: \"%s\"\n", input);

	rsa_encrypt_str(&encrypted, input, pair -> public_key, pair -> mod);
	printf("Encrypted string: \"%s\"\n", encrypted);

	rsa_decrypt_str(&decrypted, encrypted, pair -> private_key, pair -> mod);
	printf("Decrypted string: \"%s\"\n", decrypted);

	free(encrypted);
	free(decrypted);

	free_rsa_keypair(pair);

	return 0;
}
