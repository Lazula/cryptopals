#ifndef MT19937_H
#define MT19937_H

#include "crypto_utility.h"

/* External RNG functions */
void mt_seed(int seed);
uint32_t mt_rand();

/* Alter the internal state manually */
void mt_set_state(uint32_t *new_MT, uint32_t new_index);

/* Retrieve the internal state */
void mt_get_state(uint32_t *out_MT, uint32_t *out_index_ptr);

/* Get the state value used to generate a given output. */
uint32_t mt_get_state_value_from_output(uint32_t y);

/* Get the state values for a set of outputs that can be
 * passed to mt_set_state() to clone the RNG
 */
void mt_clone_state(uint32_t *cloned_state, uint32_t *outputs);

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
int mt_encrypt(unsigned char *output, unsigned char *input, size_t input_size, uint32_t seed);

#endif
