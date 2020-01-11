#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/hex_encoding.h"
#include "../../include/aes.h"

struct dict_entry {
	char *key;
	char *value;
};

struct dict {
	size_t length;
	struct dict_entry **entries;
};

int parse_dict(struct dict *output_dict, char *input);
int get_dict_entry(char **output, char *input, struct dict *given_dict);
int clean_free_dict(struct dict *input);

int main(void){
	const size_t BLOCK_SIZE = 16;

	size_t i;
	char *user_profile =
		"email=A@AAAAAAAA"
		"AAAA.com&uid=10&"
		"role=user";
	char *admin_profile =
		"email=B@BBBBBBBB"
		"BBBB.com&uid=20&"
		"role=admin";
	size_t poisoned_profile_data_size;
	unsigned char *poisoned_profile_data = NULL;
	char *poisoned_profile;

	size_t encrypted_profile_size;
	unsigned char *encrypted_user_profile = NULL;
	unsigned char *encrypted_admin_profile = NULL;
	unsigned char *encrypted_poisoned_profile;

	unsigned char *key;

	struct dict *user_profile_dict = malloc(sizeof(struct dict));
	struct dict *admin_profile_dict = malloc(sizeof(struct dict));
	struct dict *poisoned_profile_dict = malloc(sizeof(struct dict));

	generate_random_aes_key(&key, AES_KEY_128);

	encrypted_profile_size = aes_encrypt(&encrypted_user_profile, (unsigned char *) user_profile, strlen(user_profile), key, NULL, AES_CIPHER_ECB, AES_KEY_128);
	aes_encrypt(&encrypted_admin_profile, (unsigned char *) admin_profile, strlen(admin_profile) ,key, NULL, AES_CIPHER_ECB, AES_KEY_128);
	
	encrypted_poisoned_profile = malloc(encrypted_profile_size);
	/* copy user data to a new poisoned ciphertext */
	memcpy(encrypted_poisoned_profile, encrypted_user_profile, encrypted_profile_size);
	/* poison the ciphertext by replacing "role=user[padding]" with "role=admin[padding]" */
	memcpy(encrypted_poisoned_profile + (BLOCK_SIZE*2), encrypted_admin_profile + (BLOCK_SIZE*2), BLOCK_SIZE);

	poisoned_profile_data_size = aes_decrypt(&poisoned_profile_data, encrypted_poisoned_profile, encrypted_profile_size, key, NULL, AES_CIPHER_ECB, AES_KEY_128);

	free(key);

	poisoned_profile = malloc(poisoned_profile_data_size+1);
	memcpy(poisoned_profile, poisoned_profile_data, poisoned_profile_data_size);
	poisoned_profile[poisoned_profile_data_size] = '\0';

	
	if(parse_dict(user_profile_dict, user_profile) != 0){
		fprintf(stderr, "Failed to allocate memory for user_profile_dict dictionary struct.\n");
		clean_free_dict(user_profile_dict);
		exit(EXIT_FAILURE);
	}
	
	if(parse_dict(admin_profile_dict, admin_profile) != 0){
		fprintf(stderr, "Failed to allocate memory for admin_profile_dict dictionary struct.\n");
		clean_free_dict(admin_profile_dict);
		exit(EXIT_FAILURE);
	}

	if(parse_dict(poisoned_profile_dict, poisoned_profile) != 0){
		fprintf(stderr, "Failed to allocate memory for poisoned_proile_dict dictionary struct.\n");
		clean_free_dict(poisoned_profile_dict);
		exit(EXIT_FAILURE);
	}

	printf("Known admin profile:\n");
	for(i = 0; i < admin_profile_dict -> length; i++){
		printf("%s:%s\n", admin_profile_dict -> entries[i] -> key, admin_profile_dict -> entries[i] -> value);
	}

	printf("\nCrafted user profile:\n");
	for(i = 0; i < user_profile_dict -> length; i++){
		printf("%s:%s\n", user_profile_dict -> entries[i] -> key, user_profile_dict -> entries[i] -> value);
	}

	printf("\nParsed poisoned profile:\n");
	for(i = 0; i < poisoned_profile_dict -> length; i++){
		printf("%s:%s\n", poisoned_profile_dict -> entries[i] -> key, poisoned_profile_dict -> entries[i] -> value);
	}

	free(poisoned_profile_data);
	free(poisoned_profile);
	free(encrypted_user_profile);
	free(encrypted_admin_profile);
	free(encrypted_poisoned_profile);
	clean_free_dict(user_profile_dict);
	clean_free_dict(admin_profile_dict);
	clean_free_dict(poisoned_profile_dict);

	return 0;
}

/* 
 * Yes, I know this problem has been solved before, and in much better ways.
 * No, that's not the point.
 * 
 * Returns 0 on success.
 * Returns 1 on failure to allocate memory for output
 */
int parse_dict(struct dict *output_dict, char *input){
	size_t i;
	size_t num_entries = 0;

	char *next_arg_stop;
	size_t next_arg_length;
	
	char *current_arg_str;

	char *key_ptr, *val_ptr;
	size_t key_len, val_len;

	for(i = 0; i < strlen(input); i++){
		if(input[i] == '='){
			num_entries++;
		}
	}
	
	output_dict -> length = num_entries;
	/* allocate the entry pointer array */
	output_dict -> entries = malloc(num_entries * sizeof(struct dict_entry *));
	if(output_dict -> entries == NULL) return 1;

	for(i = 0; i < num_entries; i++){
		output_dict -> entries[i] = output_dict -> entries[i];
		output_dict -> entries[i] = malloc(sizeof(struct dict_entry));
		if(output_dict -> entries[i] == NULL) return 1;
		/* read until end of value definition */
		next_arg_stop = strchr((const char *) input, '&');
		/* last arg, stop at end of string */
		if(next_arg_stop == NULL) next_arg_stop = input + strlen(input);
		/* hopefully no UB after accounting for NULL */
		next_arg_length = next_arg_stop - input;
		current_arg_str = malloc(next_arg_length+1);
		strncpy(current_arg_str, input, next_arg_length);
		current_arg_str[next_arg_length] = '\0';

		key_ptr = current_arg_str;
		key_len = strchr(key_ptr, '=') - key_ptr;
		val_ptr = current_arg_str + key_len + 1;
		val_len = strlen(val_ptr);

		output_dict -> entries[i] -> key = malloc(key_len+1);
		if(output_dict -> entries[i] -> key == NULL) return 1;
		memcpy(output_dict -> entries[i] -> key, key_ptr, key_len);
		output_dict -> entries[i] -> key[key_len] = '\0';

		output_dict -> entries[i] -> value = malloc(val_len+1);
		if(output_dict -> entries[i] -> value == NULL) return 1;
		memcpy(output_dict -> entries[i] -> value, val_ptr, val_len);
		output_dict -> entries[i] -> value[val_len] = '\0';

		/* if not on last arg, update input location (add 1 to get past '&') */
		if(next_arg_stop != input+strlen(input)) input = input+next_arg_length+1;
		free(current_arg_str);
	}

	return 0;
}

/* 
 * Pass dictionary and input string, will get value for that key.
 * 
 * Returns 1 on failure to alloate memory for output
 * Returns 0 on success
 * Returns -1 if given any null pointers
 */
int get_dict_entry(char **output, char *input, struct dict *given_dict){
	size_t i;
	size_t output_size;
	char *val;

	for(i = 0; i < given_dict -> length; i++){
		if(!strcmp(given_dict -> entries[i] -> key, input)){
			val = given_dict -> entries[i] -> value;
			output_size = strlen(val)+1;
			break;
		}
	}

	if(output != NULL){
		if(*output == NULL){
			*output = malloc(output_size);
			if(*output == NULL) return 1;
		}
	}else{
		return -1;
	}

	if(input == NULL) return -1;
	if(given_dict == NULL) return -1;

	strncpy(*output, val, output_size);

	return 0;
}

/* 
 * Frees all memory for a dict that may not be allocated and all entries that may or may not be allocated
 */
int clean_free_dict(struct dict *input){
	size_t i;
	if(input != NULL){
		if(input -> entries != NULL){
			for(i = 0; i < input -> length; i++){
				if(input -> entries[i] != NULL){
					if(input -> entries[i] -> key != NULL) free(input -> entries[i] -> key);
					if(input -> entries[i] -> value != NULL) free(input -> entries[i] -> value);
					free(input -> entries[i]);
				}
			}

			free(input -> entries);
		}

		free(input);
	}

	return 0;
}
