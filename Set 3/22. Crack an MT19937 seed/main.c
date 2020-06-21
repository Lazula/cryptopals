#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../../include/mt19937.h"

uint32_t generate_recent_mt();

int main(){
	uint32_t i;
	uint32_t current_time_seed = (uint32_t) time(NULL);
	uint32_t found_past_seed;

	uint32_t recent_rng_result = generate_recent_mt();
	uint32_t current_rng_result;

	for(i = 40; i <= 1000; i++){
		mt_seed(current_time_seed-i);
		current_rng_result = mt_rand();

		if(current_rng_result == recent_rng_result){
			found_past_seed = current_time_seed-i;
			printf("Found seed %u seconds in the past: %u (0x%.8X)\n", i, found_past_seed, found_past_seed);
			break;
		}
	}

	return 0;
}

/* Generate a MT seed using a time between 40 and 1000 seconds, inclusive, in the past,
 * then return the first RNG value.
 */
uint32_t generate_recent_mt(){
	uint32_t recent_time_seed;

	srand(time(NULL));
	recent_time_seed = (uint32_t) time(NULL) - ((rand() % 961) + 40);

	mt_seed(recent_time_seed);

	return mt_rand();
}
