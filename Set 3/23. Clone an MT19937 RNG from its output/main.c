#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../../include/mt19937.h"

/* The seed is not known to main()
 * While we just use the current time, the
 * attack works on any seed.
 */
void setup(){ mt_seed((uint32_t) time(NULL)); }

int main(){
	uint32_t i;

	uint32_t outputs[624];
	uint32_t cloned_state[624];

	setup();

	for(i = 0; i < 624; i++) outputs[i] = mt_rand();

	mt_clone_state(cloned_state, outputs);
	mt_set_state(cloned_state);

	printf("Replicated state.\n");
	printf("First RNG value from original state: %u\n", outputs[0]);
	printf("First RNG value from cloned state: %u\n", mt_rand());

	return 0;
}
