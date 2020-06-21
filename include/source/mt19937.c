#include "../mt19937.h"

/* Defined constants */
static const uint32_t w = 32;
static const uint32_t n = 624;
static const uint32_t m = 397;
static const uint32_t a = 0x9908B0DF;
static const uint32_t u = 11;
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

/* Internal state value generator */
static void twist();

/* RNG function requires a seed */
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
	y ^= (y >> u);
	y ^= ((y << s) & b);
	y ^= ((y << t) & c);
	y ^= (y >> l);

	index++;

	return y;
}

/* Retrieve the internal state */
void mt_get_state(uint32_t *out_MT, uint32_t *out_index_ptr){
	uint32_t i;
	for(i = 0; i < 624; i++) out_MT[i] = MT[i];
	if(out_index_ptr != NULL) *out_index_ptr = index;
}

/* Alter the internal state manually */
void mt_set_state(uint32_t *new_MT, uint32_t new_index){
	uint32_t i;
	for(i = 0; i < 624; i++) MT[i] = new_MT[i];
	index = new_index;
}

/* Get the state value used to generate a given output. */
uint32_t mt_get_state_value_from_output(uint32_t y){
	uint8_t i;
	y ^= (y >> l);
	y ^= ((y << t) & c);
	for(i = 0; i < s; i++) y ^= ((y << s) & b);
	for(i = 0; i < 3; i++) y ^= (y >> u);

	return y;
}

/* Generate the associated states for a set of 624
 * outputs that correspond to an internal MT19927
 * state.
 * 
 * The output of this function can be passed to
 * mt_set_state().
 */
void mt_clone_state(uint32_t *cloned_state, uint32_t *outputs){
	uint32_t i;
	for(i = 0; i < 624; i++) cloned_state[i] = mt_get_state_value_from_output(outputs[i]);
}

/* Populate internal state */
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

/* Return a new random number as its constituent bytes */
static void mt_keystream(unsigned char output[4]){
	uint32_t rand_out;
	rand_out = mt_rand();

	output[0] = rand_out & 0xFF;
	output[1] = (rand_out >> 8) & 0xFF;
	output[2] = (rand_out >> 16) & 0xFF;
	output[3] = (rand_out >> 24) & 0xFF;
}

/* Generate a new state using a 16-bit seed, then encrypt
 * the given input with numbers generated from the state.
 * 
 * Any existing internal state is preserved.
 * 
 * Return values:
 * 0: No error to report.
 * 1: Either input or output are NULL.
 * 2: seed has more than 16 bits.
 */
int mt_encrypt(unsigned char *output, unsigned char *input, size_t input_size, uint32_t seed){
	uint32_t preserved_state[624];
	uint32_t preserved_index;

	unsigned char keystream_buffer[4];

	size_t bytes_in_block;
	size_t i, j;

	if(output == NULL || input == NULL) return 1;
	if(seed & 0xFFFF0000) return 2;

	mt_get_state(preserved_state, &preserved_index);

	mt_seed(seed);

	bytes_in_block = 4;
	for(i = 0; i < input_size; i += 4){
		mt_keystream(keystream_buffer);
		if(input_size - i < 4) bytes_in_block = input_size - i;
		for(j = 0; j < bytes_in_block; j++){
			output[i + j] = input[i + j] ^ keystream_buffer[j];
		}
	}

	mt_set_state(preserved_state, preserved_index);

	return 0;
}
