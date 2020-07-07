#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../include/hex_encoding.h"
#include "../../include/sha1.h"

#define DEBUG 0

static unsigned char *FILE_HASH = NULL;

int initialize_file_hash(char *file_name);
int validate_sha1_hmac(unsigned char *given_hash);

/* The challenge says to reduce the sleep until the previous solution break,
 * but that would require switching to measuring with clock cycles which
 * is not the point. I've just switched from 50ms delay to 5ms. */

int main(){
	size_t i, j;

	char *file_name = "data.bin";

	unsigned char *forged_hash = NULL;

	clock_t timer_start;
	clock_t timer_end;

	clock_t msecs_taken;

	if(initialize_file_hash(file_name)){
		printf("Failed to read file \"%s\".\n", file_name);
		return 1;
	}

	forged_hash = malloc(SHA1_DIGEST_SIZE);
	memset(forged_hash, 0, SHA1_DIGEST_SIZE);

	printf("Starting HMAC timing-based brute-force. This will take some time.\n");

	for(i = 0; i < SHA1_DIGEST_SIZE; i++){
		for(j = 0; j < 256; j++){
			forged_hash[i] = (unsigned char) (j & 0xFF);

			timer_start = clock();
			validate_sha1_hmac(forged_hash);
			timer_end = clock();

			msecs_taken = (timer_end - timer_start) / (CLOCKS_PER_SEC / 1000);

			/* Check if an additional byte was processed
			 * @ 5 ms / byte.
			 * e.g. Checking the third byte will take 10ms
			 * if incorrect and 15ms when correct. */
			if(msecs_taken > (clock_t) (5 * i)){
				#if DEBUG
				printf("\nFound hash byte 0x%02lx @ %ldms\n\n", j, msecs_taken);
				#else
				printf("%02lx", j);
				fflush(stdout);
				#endif
				break;

				#if DEBUG
			}else{
				printf("Rejected hash byte 0x%02lx @ %ldms\n\n", j, msecs_taken);
				#endif
			}
		}
	}

	printf("\n");

	free(FILE_HASH);
	free(forged_hash);
	return 0;
}

int validate_sha1_hmac(unsigned char *given_hash){
	size_t i;
	unsigned char *expected_hash = NULL;

	unsigned char valid_hash = 1;

	clock_t start_time;
	clock_t time_waited_in_ms;

	unsigned char wait_more;

	#if DEBUG
	char *given_hash_as_str = NULL;
	char *expected_hash_as_str = NULL;
	#endif

	expected_hash = FILE_HASH;

	for(i = 0; i < SHA1_DIGEST_SIZE; i++){
		if(expected_hash[i] != given_hash[i]){
			valid_hash = 0;
		}

		if(valid_hash){
			/* Wait 50 ms */
			start_time = clock();
			time_waited_in_ms = 0;
			wait_more = 1;
			while(wait_more){
				time_waited_in_ms = (clock() - start_time) / (CLOCKS_PER_SEC / 1000);
				if(time_waited_in_ms >= 5){
					wait_more = 0;
				}
			}
		}else{
			break;
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

	return valid_hash;
}

int initialize_file_hash(char *file_name){
	FILE *input_file;

	unsigned char *file_contents;
	size_t file_size;

	input_file = fopen(file_name, "r");

	if(!input_file){
		printf("Failed to open file \"%s\".\n", file_name);
		return 1;
	}

	fseek(input_file, 0, SEEK_END);
	file_size = ftell(input_file);
	file_contents = malloc(file_size);
	rewind(input_file);

	fread(file_contents, sizeof(char), file_size, input_file);
	fclose(input_file);

	sha1(&FILE_HASH, file_contents, file_size);

	free(file_contents);

	return 0;
}
