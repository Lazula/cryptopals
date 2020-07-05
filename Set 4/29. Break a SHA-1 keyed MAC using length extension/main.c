#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../include/hex_encoding.h"
#include "../../include/sha1.h"

#define DEBUG 0
#define DEBUG_USE_SET_KEY 0

static char *KEY = NULL;

int generate_ascii_key(char **key);
int validate_sha1_hmac(unsigned char *given_hash, unsigned char *message, size_t message_len);

int main(){
	char *captured_message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
	char *message_extension = ";admin=true";

	unsigned char *forged_message = NULL;
	size_t forged_message_size;

	unsigned char *captured_hash = NULL;
	unsigned char *forged_hash = NULL;

	#if DEBUG_USE_SET_KEY
		KEY = malloc(17);
		strcpy(KEY, "AAAABBBBCCCCDDDD");
	#else
		generate_ascii_key(&KEY);
	#endif

	key_prefix_sha1(&captured_hash, (unsigned char *) captured_message, strlen(captured_message), (unsigned char *) KEY, strlen(KEY));

	sha1_extend_forge_hmac(&forged_hash, &forged_message, &forged_message_size,
			       captured_hash, (unsigned char *) message_extension, strlen(message_extension),
			       (unsigned char *) captured_message, strlen(captured_message),
			       validate_sha1_hmac);

	if(!forged_hash || !forged_message){
		printf("Did not receive forged hash or forged message from sha1_extend_forge_hmac().\n");
		exit(1);
	}

	printf("Key-prefix SHA1 with captured message: ");
	hex_print(captured_hash, SHA1_DIGEST_SIZE);
	printf("\nForged key-prefix SHA1 with message extension: ");
	hex_print(forged_hash, SHA1_DIGEST_SIZE);
	printf("\n");

	printf("Verifying HMAC validation.\n");
	if(validate_sha1_hmac(forged_hash, forged_message, forged_message_size)){
		printf("Successfully validated with forged hash ");
		hex_print(forged_hash, SHA1_DIGEST_SIZE);
		printf(".\n");
	}else{
		printf("Failed to validate with forged hash.\n");
	}

	free(KEY);
	free(captured_hash);
	free(forged_hash);
	free(forged_message);
	return 0;
}

int validate_sha1_hmac(unsigned char *given_hash, unsigned char *message, size_t message_len){
	size_t i;
	unsigned char *expected_hash = NULL;

	unsigned char valid_hash = 1;

	#if DEBUG
	char *given_hash_as_str = NULL;
	char *expected_hash_as_str = NULL;
	#endif

	key_prefix_sha1(&expected_hash, message, message_len, (unsigned char *) KEY, strlen(KEY));

	for(i = 0; i < SHA1_DIGEST_SIZE; i++){
		if(expected_hash[i] != given_hash[i]){
			valid_hash = 0;
		}
	}


	#if DEBUG
	sha1_hash_to_string(&given_hash_as_str, given_hash);
	sha1_hash_to_string(&expected_hash_as_str, expected_hash);

	if(!valid_hash)
		printf("Given hash %s does not match expected hash %s\n", given_hash_as_str, expected_hash_as_str);
	else printf("Given hash %s matches expected hash %s\n", given_hash_as_str, expected_hash_as_str);

	free(given_hash_as_str);
	free(expected_hash_as_str);
	#endif

	free(expected_hash);
	return valid_hash;
}

int generate_ascii_key(char **key_ptr){
	size_t i;
	size_t key_len;

	srand(time(NULL));

	key_len = rand() % 30;

	if(key_ptr == NULL) return 1;
	else if(*key_ptr == NULL) *key_ptr = malloc(key_len+1);

	/* Generate ASCII characters  '!' (33) through '~' (126) */
	for(i = 0; i < key_len; i++) (*key_ptr)[i] = (char) ((rand() % (126+1-33)) + 33);
	(*key_ptr)[key_len] = '\0';

	return 0;
}
