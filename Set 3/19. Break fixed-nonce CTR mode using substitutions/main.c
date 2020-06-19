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
#include "../../include/hex_encoding.h"
#include "../../include/source/hex_encoding.c"
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
	size_t num_decrypted_bytes;

	double current_score;
	double best_score;

	char current_decrypted_bytes_as_string[41] = {0};
	char best_decrypted_bytes_as_string[41] = {0};

	unsigned char *encrypted_secrets[40] = {NULL};
	size_t encrypted_secret_sizes[40] = {0};

	unsigned char *keystream;
	size_t keystream_size = 0;

	char *guessed_plaintexts[40] = {NULL};

	initialize_key_and_nonce();
	get_secrets(encrypted_secrets, encrypted_secret_sizes);
	free_key_and_nonce();

	for(i = 0; i < 40; i++){
		guessed_plaintexts[i] = malloc(encrypted_secret_sizes[i]+1);
		if(encrypted_secret_sizes[i] > keystream_size)
			keystream_size = encrypted_secret_sizes[i];
	}
	keystream = malloc(keystream_size);

	for(i = 0; i < keystream_size; i++){
		best_score = 0;

		for(current_keystream_byte_guess = 0;;current_keystream_byte_guess++){
			/* reset decrypted bytes in case not all 40 characters are used */
			memset(current_decrypted_bytes_as_string, 0, 41);
			num_decrypted_bytes = 0;

			for(j = 0; j < 40; j++){
				/* Account for different ciphertext lengths; only attempt if a character actually exists */
				if(i < encrypted_secret_sizes[j]){
					current_decrypted_char = encrypted_secrets[j][i] ^ current_keystream_byte_guess;
					if(IS_ASCII(current_decrypted_char)){
						current_decrypted_bytes_as_string[num_decrypted_bytes] = current_decrypted_char;
						num_decrypted_bytes++;
					}else break;
				}

				if(j == 39){
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

	for(i = 0; i < 40; i++){
		fixed_xor((unsigned char *) guessed_plaintexts[i], encrypted_secrets[i], keystream, encrypted_secret_sizes[i]);
		guessed_plaintexts[i][encrypted_secret_sizes[i]] = '\0';
		printf("%s\n", guessed_plaintexts[i]);
	}

	for(i = 0; i < 40; i++){
		free(guessed_plaintexts[i]);
		free(encrypted_secrets[i]);
	}

	free(keystream);

	return 0;
}

int get_secrets(unsigned char **encrypted_secrets, size_t *encrypted_secret_sizes){
	unsigned char *current_raw_secret = NULL;
	size_t current_raw_secret_size;

	static char *base64_encoded_secrets[40] = {
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	};

	size_t i;

	for(i = 0; i < 40; i++){
		current_raw_secret_size = base64_decode(&current_raw_secret, base64_encoded_secrets[i]);
		aes_encrypt(&encrypted_secrets[i], &encrypted_secret_sizes[i], current_raw_secret, current_raw_secret_size, KEY, NONCE, AES_CIPHER_CTR, AES_KEY_128);

		free(current_raw_secret);
		current_raw_secret = NULL;
	}

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
