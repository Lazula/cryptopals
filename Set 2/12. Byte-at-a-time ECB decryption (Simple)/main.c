//TODO switch back to C89
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

struct encryption_map {
	unsigned char *ciphertext;
	unsigned char last_plaintext_byte;
};

int main(void){
	size_t i, j;

	size_t num_known_in_data;

	char *base64_encoded_unknown_data =
		"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
		"YnkK";
	unsigned char *unknown_data = NULL;
	size_t unknown_data_size;

	unsigned char *combined_data = NULL;
	size_t combined_data_size;

	unsigned char *encrypted_combined_data = NULL;
	size_t encrypted_combined_data_size;

	unsigned char *last_encrypted_data = NULL;
	size_t last_encrypted_data_size;

	unsigned char *key = NULL;

	size_t block_size = 0;

	struct encryption_map *decryption_table[256];

	unsigned char current_plaintext_byte;
	unsigned char current_decrypted_byte;

	unsigned char *decrypted_data;
	char *decrypted_string;

	unknown_data_size = base64_decode(&unknown_data, base64_encoded_unknown_data);

	generate_random_aes_key(&key, AES_KEY_128);

	/* start finding block size */
	for(num_known_in_data = 1; num_known_in_data < 64; num_known_in_data++){
		combined_data_size = num_known_in_data + unknown_data_size;
		combined_data = malloc(combined_data_size);

		memset(combined_data, 'A', num_known_in_data);
		memcpy(combined_data+num_known_in_data, unknown_data, unknown_data_size);

		encrypted_combined_data_size = aes_encrypt(&encrypted_combined_data, combined_data, combined_data_size, key, NULL, AES_CIPHER_ECB, AES_KEY_128);
		if(is_aes_ecb(encrypted_combined_data, encrypted_combined_data_size, AES_KEY_128) == 0){
			fprintf(stderr, "Failed to detect ECB with %lu bytes of input.\n", num_known_in_data);
			if(combined_data_size < 8){
				fprintf(stderr, "NOTE: Less than 8 bytes of input were given. This may be a false positive.\n");
			}
		}

		/* Skip checking first block because there is nothing to compare with
		 * Just assign last_encrypted_data and move to the next cycle
		 */
		if(num_known_in_data == 1){
			last_encrypted_data_size = encrypted_combined_data_size;
			last_encrypted_data = malloc(last_encrypted_data_size);
			memcpy(last_encrypted_data, encrypted_combined_data, last_encrypted_data_size);

			free(combined_data);
			continue;
		}

		/* Compare the encrypted blocks
		 * If they are the same, we reached the block size one cycle ago.
		 */
		if(!memcmp(encrypted_combined_data, last_encrypted_data, num_known_in_data-1)){
			free(combined_data);
			free(last_encrypted_data);
			free(encrypted_combined_data);

			block_size = num_known_in_data-1;

			break;
		}

		free(last_encrypted_data);
		
		last_encrypted_data_size = encrypted_combined_data_size;
		last_encrypted_data = malloc(last_encrypted_data_size);
		memcpy(last_encrypted_data, encrypted_combined_data, last_encrypted_data_size);

		free(combined_data);
		free(encrypted_combined_data);
		encrypted_combined_data = NULL;
	}
	/* end finding block size */

	/* failed to find */
	if(block_size == 0){
		fprintf(stderr, "Failed to find block size.\n");
	}else{
		printf("Found block size: %lu\n", block_size);
	}


	combined_data = malloc(block_size);
	memset(combined_data, 'A', block_size-1);
	encrypted_combined_data = NULL;

	/* populate decryption table */
	for(current_plaintext_byte = 0; current_plaintext_byte < 255; current_plaintext_byte++){
		combined_data[block_size-1] = current_plaintext_byte;
		aes_encrypt(&encrypted_combined_data, combined_data, block_size, key, NULL, AES_CIPHER_ECB, AES_KEY_128);

		decryption_table[current_plaintext_byte] = malloc(sizeof(struct encryption_map));
		decryption_table[current_plaintext_byte] -> ciphertext = malloc(block_size);
		memcpy(decryption_table[current_plaintext_byte] -> ciphertext, encrypted_combined_data, block_size);

		decryption_table[current_plaintext_byte] -> last_plaintext_byte = current_plaintext_byte;

		free(encrypted_combined_data);
		encrypted_combined_data = NULL;
	}

	decrypted_data = malloc(unknown_data_size);

	/* Use ciphertext lookup to decrypt byte-by-byte,
	 * using the last byte of the block as a pre-made reference
	 * Unfortunately just using the ciphertext byte as index can easiy cause collisions,
	 * so using it as a direct lookup index is ineffective
	 */
	for(i = 0; i < unknown_data_size; i++){
		combined_data[block_size-1] = unknown_data[i];

		/* Get the byte to decrypt */
		aes_encrypt(&encrypted_combined_data, combined_data, block_size, key, NULL, AES_CIPHER_ECB, AES_KEY_128);

		for(j = 0; j < 255; j++){
			/* If ciphetext are the same, last plaintext byte will match */
			if(!memcmp(decryption_table[j] -> ciphertext, encrypted_combined_data, block_size)){
				current_decrypted_byte = decryption_table[j] -> last_plaintext_byte;
			}
		}

		decrypted_data[i] = current_decrypted_byte;

		free(encrypted_combined_data);
		encrypted_combined_data = NULL;
	}
	
	decrypted_string = malloc(unknown_data_size+1);
	decrypted_string[unknown_data_size] = '\0';
	memcpy(decrypted_string, decrypted_data, unknown_data_size);

	printf("Recovered plaintext: %s", decrypted_string);

	for(i = 0; i < 255; i++){
		free(decryption_table[i] -> ciphertext);
		free(decryption_table[i]);
	}
	free(combined_data);
	free(decrypted_data);
	free(decrypted_string);
	free(key);
	free(unknown_data);
}
