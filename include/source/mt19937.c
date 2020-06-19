#include "../mt19937.h"

/* Defined constants */
static const uint32_t w = 32;
static const uint32_t n = 624;
static const uint32_t m = 397;
static const uint32_t a = 0x9908B0DF;
static const uint32_t u = 11;
static const uint32_t d = 0xFFFFFFFF;
static const uint32_t s = 7;
static const uint32_t b = 0x9D2C5680;
static const uint32_t t = 15;
static const uint32_t c = 0xEFC60000;
static const uint32_t l = 18;
static const uint32_t f = 1812433253;

/* Internal variables */
static uint32_t MT[624]; /* Using n here causes a compiler error */
static uint32_t index = 625;
static const uint32_t lower_mask = 0x7FFFFFFF;
static const uint32_t upper_mask = 0x80000000;

static void twist();

void mt_seed(int seed){
	uint32_t i;

	index = n;
	MT[0] = seed;
	for(i = 1; i < n; i++)
		MT[i] = f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i;
}

/* 32-bit random number generator */
uint32_t mt_rand(){
	uint32_t y;

	if(index >= n){
		if(index > n) mt_seed(5489);
		twist();
	}

	y = MT[index];
	y ^= ((y >> u) & d);
	y ^= ((y << s) & b);
	y ^= ((y << t) & c);
	y ^= (y >> l);

	index++;

	return y;
}

static void twist(){
	uint32_t i;
	uint32_t x;
	uint32_t xA;

	for(i = 0; i < n; i++){
		x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask);
		xA = x >> 1;
		if(x % 2) xA ^= a;
		MT[i] = MT[(i + m) % n] ^ xA;
	}

	index = 0;
}
