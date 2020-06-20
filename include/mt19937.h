#ifndef MT19937_H
#define MT19937_H

#include "crypto_utility.h"

/* External RNG functions */
void mt_seed(int seed);
uint32_t mt_rand();

/* Alter the internal state manually */
void mt_set_state(uint32_t *new_MT);

/* Retrieve the internal state */
void mt_get_state(uint32_t *out_MT);

/* Get the state value used to generate a given output. */
uint32_t mt_get_state_value_from_output(uint32_t y);

/* Get the state values for a set of outputs that can be
 * passed to mt_set_state() to clone the RNG
 */
void mt_clone_state(uint32_t *cloned_state, uint32_t *outputs);

#endif
