#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/sha1.h"

int main(){
	char *key = "The ";
	char *wrong_key = "A ";
	char *input_data = "quick brown fox jumps over the lazy dog";

	unsigned char *good_sha1sum = NULL;
	unsigned char *bad_sha1sum = NULL;

	char *good_sha1sum_str = NULL;
	char *bad_sha1sum_str = NULL;

	key_prefix_sha1(&good_sha1sum, (unsigned char *) input_data, strlen(input_data), (unsigned char *) key, strlen(key));
	key_prefix_sha1(&bad_sha1sum, (unsigned char *) input_data, strlen(input_data), (unsigned char *) wrong_key, strlen(wrong_key));

	sha1_hash_to_string(&good_sha1sum_str, good_sha1sum);
	sha1_hash_to_string(&bad_sha1sum_str, bad_sha1sum);

	printf("Message: \"quick brown fox jumps over the lazy dog\"\n");
	printf("Hash with good key \"The \":\n%s\n", good_sha1sum_str);
	printf("Hash with bad key \"A \":\n%s\n", bad_sha1sum_str);

	free(good_sha1sum);
	free(bad_sha1sum);
	free(good_sha1sum_str);
	free(bad_sha1sum_str);

	return 0;
}
