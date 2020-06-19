#ifndef MT19937_H
#define MT19937_H

#include "crypto_utility.h"

void mt_seed(int seed);
uint32_t mt_rand();

#endif
