#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/base64.h"
#include "../../include/aes.h"

int main(int argc, char *argv[]){
	unsigned char *encrypted_data = NULL;
	
	FILE *rand_file = fopen("/dev/urandom", "r");
	//128 bits = 16 bytes
	size_t key_size = 16;
	unsigned char *key = malloc(key_size);
	if(fread(key, sizeof(char), key_size, rand_file) != key_size){
		printf("Failed to read %zu bytes from /dev/urandom into key @ line %d in %s\nQuitting.\n", key_size, __LINE__, __FILE__);
		exit(EXIT_FAILURE);
	}
	
	size_t data_size = 16;
	unsigned char *data = malloc(key_size);
	if(fread(data, sizeof(char), data_size, rand_file) != data_size){
		printf("Failed to read %zu bytes from /dev/urandom into data @ line %d in %s\nQuitting.\n", key_size, __LINE__, __FILE__);
		exit(EXIT_FAILURE);
	}
	
	fclose(rand_file);
	
	
	unsigned char *initialization_vector = malloc(16);
	unsigned char *decrypted_data = NULL;
	
	aes_encrypt(&encrypted_data, data, data_size, key, initialization_vector, AES_CIPHER_CBC, AES_KEY_128);
	
	printf("%s\n", decrypted_data);
	
	free(encrypted_data);
	free(key);
}

/*
 * Returns 0 on success
 * On incorrect key size, returns 1
 */
/*unsigned int generate_random_aes_key(unsigned char **output, uint8_t key_type){
	int urandom_fd = open("/dev/urandom", O_RDONLY);
	
	size_t key_size;
	switch(key_type){
		case AES_KEY_128:
			key_size = 16;
			break;
		case AES_KEY_192:
			key_size = 24;
			break;
		case AES_KEY_256:
			key_size = 32;
			break;
		default:
			return 1;
			break;
	}
	
	
	if(*output == NULL) *output = malloc();
	
	read(urandom_fd, *output, key_size);
	
	close(urandom_fd);
	return 0;
}*/

/*add_random_data(){
	
}*/
