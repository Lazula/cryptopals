#include <stdio.h>
#include <time.h>

#include "../arbitrary_precision.h"

static gmp_randstate_t apnum_randstate;

apnum_ptr new_apnum(){
	apnum_ptr a;

	a = malloc(sizeof(mpz_t));
	mpz_init(*a);

	return a;
}

/* allocate and return a new apnum_ptr copied from in */
apnum_ptr clone_apnum(apnum_ptr in){
	apnum_ptr out;

	if(!in) return NULL;

	out = new_apnum();

	if(!out) return out;

	copy_apnum(out, in);

	return out;
}

/* copy data from one apnum_ptr into another */
int copy_apnum(apnum_ptr out, apnum_ptr in){
	if(!out || !in) return -1;

	mpz_set(*out, *in);

	return 0;
}

int free_apnum(apnum_ptr a){
	if(!a) return 1;

	mpz_clear(*a);
	free(a);

	return 0;
}

int uint8_to_apnum(apnum_ptr out, uint8_t in){
	uint32_to_apnum(out, in);
	return 0;
}

int uint32_to_apnum(apnum_ptr out, uint32_t in){
	mpz_set_ui(*out, in);
	return 0;
}

int apnum_to_uint32(uint32_t *out, apnum_ptr in){
	if(mpz_sizeinbase(*in, 2) > 32) return 1;

	*out = (uint32_t) mpz_get_ui(*in);

	return 0;
}

int apnum_add(apnum_ptr out, apnum_ptr a, apnum_ptr b){
	if(!out || !a || !b) return 1;
	mpz_add(*out, *a, *b);
	return 0;
}

int apnum_sub(apnum_ptr out, apnum_ptr a, apnum_ptr b){
	if(!out || !a || !b) return 1;
	mpz_sub(*out, *a, *b);
	return 0;
}

int apnum_mul(apnum_ptr out, apnum_ptr a, apnum_ptr b){
	if(!out || !a || !b) return 1;
	mpz_mul(*out, *a, *b);
	return 0;
}

int apnum_div(apnum_ptr quotient, apnum_ptr remainder, apnum_ptr dividend, apnum_ptr divisor){
	if(!quotient || !remainder || !dividend || !divisor) return 1;
	mpz_fdiv_qr(*quotient, *remainder, *dividend, *divisor);
	return 0;
}

int apnum_mod(apnum_ptr out, apnum_ptr in, apnum_ptr mod){
	mpz_mod(*out, *in, *mod);
	return 0;
}

int apnum_modexp(apnum_ptr out, apnum_ptr base, apnum_ptr exp, apnum_ptr mod){
	if(mpz_odd_p(*mod)){
		/* The cryptograhically-specialized powm_sec can only be used
		 *  if mod is odd. */
		mpz_powm_sec(*out, *base, *exp, *mod);
	}else{
		mpz_powm(*out, *base, *exp, *mod);
	}
	return 0;
}

int apnum_invmod(apnum_ptr out, apnum_ptr numerator, apnum_ptr denominator){
	return mpz_invert(*out, *numerator, *denominator);
}

void apnum_randinit(){
	/* Not freeing the state is not considered a memory leak,
	 * as it may be used at any point before program termination,
	 * where it will be freed regardless. */
	
	gmp_randinit_mt(apnum_randstate);
	gmp_randseed_ui(apnum_randstate, time(NULL));
}

int apnum_rand(apnum_ptr out, apnum_ptr mod){
	mpz_urandomm(*out, apnum_randstate, *mod);
	return 0;
}

int apnum_randprime(apnum_ptr out, apnum_ptr mod){
	apnum_ptr temp;

	temp = new_apnum();

	mpz_urandomm(*temp, apnum_randstate, *mod);
	mpz_nextprime(*out, *temp);

	free_apnum(temp);
	return 0;
}

int apnum_cmp(apnum_ptr a, apnum_ptr b){
	return mpz_cmp(*a, *b);
}

/* Takes a big-endian number */
int decode_apnum_from_hex(apnum_ptr out, char *in){
	return mpz_init_set_str(*out, in, 16);
}

int apnum_to_hex_string(char **out, apnum_ptr in){
	if(!out || !in) return 1;

	*out = mpz_get_str(NULL, 16, *in);

	return 0;
}

int print_apnum_as_hex(apnum_ptr in){
	if(!in) return 1;

	gmp_printf("%Zx", *in);

	return 0;
}

int _print_apnum_with_name(char *name, apnum_ptr p){ 
	gmp_printf("%s = %Zx\n", name, *p);
	return 0;
}

int _debug_print_apnum_with_name(char *tag, char *name, apnum_ptr p){ 
	gmp_printf("[%s] %s = %Zx\n", tag, name, *p);
	return 0;
}
