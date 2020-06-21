#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/aes.h"
#include "../../include/fixed_xor.h"
#include "../../include/frequency_analysis.h"

#define DEBUG 0
#define DEBUG_USE_SET_KEY 0

#if DEBUG
#	include "../../include/hex_encoding.h"
#	include "../../include/source/hex_encoding.c"
#endif

#ifndef SIZE_MAX
#	define SIZE_MAX ((size_t) (-1))
#endif

static unsigned char *KEY = NULL;
static unsigned char *NONCE = NULL;
static size_t BLOCK_SIZE = 16;

int get_secrets(unsigned char **encrypted_secrets, size_t *encrypted_secret_sizes);
int initialize_key_and_nonce();
int free_key_and_nonce();

#define IS_ASCII(c) (c >= 0x20 && c <= 0x7e)

int main(){
	size_t i, j;
	unsigned char current_keystream_byte_guess;
	unsigned char best_keystream_byte;
	unsigned char current_decrypted_char;

	double current_score;
	double best_score;

	char current_decrypted_bytes_as_string[61] = {0};
	char best_decrypted_bytes_as_string[61] = {0};

	unsigned char *encrypted_secrets[60] = {NULL};
	size_t encrypted_secret_sizes[60] = {0};

	size_t shortest_secret_size = SIZE_MAX;

	unsigned char *secret_buffer;
	size_t secret_buffer_size;

	unsigned char *keystream;
	size_t keystream_size;

	char *plaintexts[60] = {NULL};

	initialize_key_and_nonce();
	get_secrets(encrypted_secrets, encrypted_secret_sizes);
	free_key_and_nonce();

	for(i = 0; i < 60; i++){
		if(encrypted_secret_sizes[i] < shortest_secret_size)
			shortest_secret_size = encrypted_secret_sizes[i];
	}

	#if DEBUG
		printf("Shortest secret is %lu bytes long.\n", shortest_secret_size);
	#endif

	for(i = 0; i < 60; i++) plaintexts[i] = malloc(shortest_secret_size+1);

	keystream_size = shortest_secret_size;
	keystream = malloc(keystream_size);

	secret_buffer_size = keystream_size * 60;
	secret_buffer = malloc(secret_buffer_size);

	for(i = 0; i < 60; i++) memcpy(secret_buffer+(i*shortest_secret_size), encrypted_secrets[i], shortest_secret_size);

	for(i = 0; i < keystream_size; i++){
		best_score = 0;

		for(current_keystream_byte_guess = 0;;current_keystream_byte_guess++){

			for(j = 0; j < 60; j++){
				current_decrypted_char = secret_buffer[(j*shortest_secret_size)+i] ^ current_keystream_byte_guess;
				if(IS_ASCII(current_decrypted_char)){
					current_decrypted_bytes_as_string[j] = current_decrypted_char;
				}else break;

				if(j == 59){
					current_score = analyze_english_plaintext_viability_fast(current_decrypted_bytes_as_string);
					if(current_score > best_score){
						best_score = current_score;
						best_keystream_byte = current_keystream_byte_guess;
						strcpy(best_decrypted_bytes_as_string, current_decrypted_bytes_as_string);
					}
				}
			}

			if(current_keystream_byte_guess == 255) break;
		}

		#if DEBUG
			printf("best keystream byte 0x%02x from decrypted chars \"%s\"\n", best_keystream_byte, best_decrypted_bytes_as_string);
		#endif

		keystream[i] = best_keystream_byte;
	}

	printf("Secrets are truncated to the shortest common length.\n");

	for(i = 0; i < 60; i++){
		fixed_xor((unsigned char *) plaintexts[i], encrypted_secrets[i], keystream, keystream_size);
		plaintexts[i][keystream_size] = '\0';
		printf("%s\n", plaintexts[i]);
	}

	for(i = 0; i < 60; i++){
		free(plaintexts[i]);
		free(encrypted_secrets[i]);
	}

	free(keystream);
	free(secret_buffer);

	return 0;
}

int get_secrets(unsigned char **encrypted_secrets, size_t *encrypted_secret_sizes){
	size_t i;
	FILE *secrets_file;
	char line_buffer[256];

	unsigned char *current_raw_secret = NULL;
	size_t current_raw_secret_size;

	secrets_file = fopen("secrets.txt", "r");
	for(i = 0; i < 60; i++){
		fgets(line_buffer, 256, secrets_file);
		base64_decode(&current_raw_secret, &current_raw_secret_size, line_buffer);
		aes_encrypt(&encrypted_secrets[i], &encrypted_secret_sizes[i], current_raw_secret, current_raw_secret_size, KEY, NONCE, AES_CIPHER_CTR, AES_KEY_128);

		free(current_raw_secret);
		current_raw_secret = NULL;
	}

	fclose(secrets_file);

	return 0;
}

int initialize_key_and_nonce(){
	#if DEBUG_USE_SET_KEY
		KEY = malloc(BLOCK_SIZE);
		memset(KEY, 0, BLOCK_SIZE);
	#else
		generate_random_aes_key(&KEY, AES_KEY_128);
	#endif

	NONCE = malloc(BLOCK_SIZE/2);
	memset(NONCE, 0, BLOCK_SIZE/2);

	return 0;
}

int free_key_and_nonce(){
	#if ! DEBUG_USE_SET_KEY
		free(KEY);
	#endif

	free(NONCE);

	return 0;
}
