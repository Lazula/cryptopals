#ifndef ARBITRARY_PRECISION_H
#define ARBITRARY_PRECISION_H

#include <gmp.h>

#if ! (	__GNU_MP_VERSION == 6 && __GNU_MP_VERSION_MINOR == 2 && __GNU_MP_PATCHLEVEL == 0)
#	error "This header is designed for use with GMP 6.2.0"
#endif

#include "hex_encoding.h"
#include "local_endian.h"
#include "crypto_utility.h"

/* define the pointer type */
typedef mpz_t apnum;
typedef mpz_t* apnum_ptr;

/* allocation/freeing and copying functions */
apnum_ptr new_apnum();
apnum_ptr clone_apnum(apnum_ptr in);
int copy_apnum(apnum_ptr out, apnum_ptr in);
int free_apnum(apnum_ptr a);

/* utility and printing */
int decode_apnum_from_hex(apnum_ptr out, char *in);
int apnum_to_hex_string(char **out, apnum_ptr in);
int print_apnum_as_hex(apnum_ptr in);
int _print_apnum_with_name(char *name, apnum_ptr p);
#define PRINT_APNUM_WITH_NAME(APNUM)		\
	_print_apnum_with_name(#APNUM, APNUM)
int _debug_print_apnum_with_name(char *tag, char *name, apnum_ptr p);
#define DEBUG_PRINT_APNUM_WITH_NAME(TAG, APNUM)			\
	_debug_print_apnum_with_name(#TAG, #APNUM, APNUM)

/* apnum <-> fixnum functions */
int uint8_to_apnum(apnum_ptr out, uint8_t in);
int uint32_to_apnum(apnum_ptr out, uint32_t in);
int apnum_to_uint32(uint32_t *out, apnum_ptr in);

/* basic arithmetic functions */
int apnum_add(apnum_ptr out, apnum_ptr a, apnum_ptr b);
int apnum_sub(apnum_ptr out, apnum_ptr a, apnum_ptr b);
int apnum_mul(apnum_ptr out, apnum_ptr a, apnum_ptr b);
int apnum_div(apnum_ptr quotient, apnum_ptr remainder, apnum_ptr dividend, apnum_ptr divisor);
int apnum_root(apnum_ptr out, apnum_ptr in, uint32_t n);

/* comparison */
int apnum_cmp(apnum_ptr a, apnum_ptr b);

/* modular arithmetic */
int apnum_mod(apnum_ptr out, apnum_ptr in, apnum_ptr mod);
int apnum_modexp(apnum_ptr out, apnum_ptr base, apnum_ptr exp, apnum_ptr mod);
int apnum_invmod(apnum_ptr out, apnum_ptr numerator, apnum_ptr denominator);

/* random generation */
void apnum_randinit();
int apnum_rand(apnum_ptr out, apnum_ptr mod);
int apnum_randprime(apnum_ptr out, apnum_ptr mod);

#endif
