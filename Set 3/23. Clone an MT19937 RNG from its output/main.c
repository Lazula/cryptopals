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

	uint32_t cloned_output;

	setup();

	for(i = 0; i < 624; i++) outputs[i] = mt_rand();

	mt_clone_state(cloned_state, outputs);
	mt_set_state(cloned_state, 0);

	cloned_output = mt_rand();

	printf("Replicated state.\n");
	printf("First RNG value from original state: %u (0x%.8X)\n", outputs[0], outputs[0]);
	printf("First RNG value from cloned state: %u (0x%.8X)\n", cloned_output, cloned_output);

	return 0;
}
