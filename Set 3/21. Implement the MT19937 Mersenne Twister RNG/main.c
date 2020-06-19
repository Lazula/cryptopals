#include <stdio.h>
#include <stdlib.h>

#include "../../include/mt19937.h"

int main(){
	size_t i;
	uint32_t seed = 5489;

	mt_seed(seed);

	printf("First 10 random values with default seed 5489:\n");
	for(i = 0; i < 10; i++){
		printf("%X", mt_rand());
		if(i < 9) printf(" ");
	}
	printf("\n");

	return 0;
}
