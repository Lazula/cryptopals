#include "rsa.h"

#define DEBUG_GENERATE_RSA_KEYPAIR 0

rsa_keypair_ptr new_rsa_keypair(){
	rsa_keypair_ptr a;

	a = malloc(sizeof(struct rsa_keypair));

	if(!a) return NULL;

	a -> private_key = new_apnum();
	a -> public_key = new_apnum();
	a -> mod = new_apnum();

	return a;
}

int free_rsa_keypair(rsa_keypair_ptr a){
	if(!a) return -1;

	if(a -> private_key) free_apnum(a -> private_key);
	if(a -> public_key) free_apnum(a -> public_key);
	if(a -> mod) free(a -> mod);

	free(a);

	return 0;
}

int copy_rsa_keypair(rsa_keypair_ptr out, rsa_keypair_ptr in){
	if(!in || !out) return -1;

	copy_apnum(out -> private_key, in -> private_key);
	copy_apnum(out -> public_key, in -> public_key);
	copy_apnum(out -> mod, in -> mod);

	return 0;
}

int print_rsa_keypair(rsa_keypair_ptr in){
	if(!in) return -1;
	if(in -> private_key){
		printf("PRIV: ");
		print_apnum_as_hex(in -> private_key);
		printf("\n");
	}
	if(in -> private_key){
		printf("PUB: ");
		print_apnum_as_hex(in -> public_key);
		printf("\n");
	}
	if(in -> mod){
		printf("MOD: ");
		print_apnum_as_hex(in -> mod);
		printf("\n");
	}

	return 0;
}

int _rsa_generate_keypair(rsa_keypair_ptr pair, apnum_ptr mod){
	apnum_ptr p;
	apnum_ptr q;
	apnum_ptr n;
	apnum_ptr e;
	apnum_ptr et;
	apnum_ptr d;

	apnum_ptr temp1;
	apnum_ptr temp2;
	apnum_ptr const_one;

	if(!pair || !mod) return -1;

	p = new_apnum();
	q = new_apnum();
	n = new_apnum();
	e = new_apnum();
	et = new_apnum();
	d = new_apnum();

	temp1 = new_apnum();
	temp2 = new_apnum();
	const_one = new_apnum();

	uint8_to_apnum(const_one, 1);

	/* p, q = randprime < mod */
	apnum_randprime(p, mod);
	apnum_randprime(q, mod);
	#if DEBUG_GENERATE_RSA_KEYPAIR
	printf("p: "); print_apnum_as_hex(p); printf("\n");
	printf("q: "); print_apnum_as_hex(q); printf("\n");
	#endif

	/* n = p * q */
	apnum_mul(n, p, q);
	#if DEBUG_GENERATE_RSA_KEYPAIR
	printf("n: "); print_apnum_as_hex(n); printf("\n");
	#endif

	apnum_sub(temp1, p, const_one);
	apnum_sub(temp2, q, const_one);
	#if DEBUG_GENERATE_RSA_KEYPAIR
	printf("p-1: "); print_apnum_as_hex(temp1); printf("\n");
	printf("q-1: "); print_apnum_as_hex(temp2); printf("\n");
	#endif

	/* et = (p-1)*(q-1) */
	apnum_mul(et, temp1, temp2);
	#if DEBUG_GENERATE_RSA_KEYPAIR
	printf("et: "); print_apnum_as_hex(et); printf("\n");
	#endif

	/* e = 3 */
	uint8_to_apnum(e, 3);

	/* d = invmod(e, et) */
	apnum_invmod(d, e, et);
	#if DEBUG_GENERATE_RSA_KEYPAIR
	printf("d: "); print_apnum_as_hex(d); printf("\n\n");
	#endif

	copy_apnum(pair -> public_key, e);
	copy_apnum(pair -> private_key, d);
	copy_apnum(pair -> mod, n);

	free_apnum(p);
	free_apnum(q);
	free_apnum(n);
	free_apnum(e);
	free_apnum(et);
	free_apnum(d);
	free_apnum(temp1);
	free_apnum(temp2);
	free_apnum(const_one);

	return 0;
}

/* Used by dh_start_session or manual creation of a single keypair. */
int rsa_generate_keypair(rsa_keypair_ptr pair, apnum_ptr mod){
	apnum_ptr const_zero;

	const_zero = new_apnum();
	uint8_to_apnum(const_zero, 0);

	/* This is a hacky way to get around potential situations where d = 0 */
	do{
		_rsa_generate_keypair(pair, mod);
	}while(apnum_cmp(pair -> private_key, const_zero) == 0); /* while(d == 0) */

	free_apnum(const_zero);

	return 0;
}

/* Encrypt a number with RSA */
int rsa_encrypt(apnum_ptr out, apnum_ptr in, apnum_ptr public_key, apnum_ptr mod){
	return apnum_modexp(out, in, public_key, mod);
}

/* Encrypt a string with RSA */
int rsa_encrypt_str(char **out_ptr, char *in, apnum_ptr public_key, apnum_ptr mod){
	apnum_ptr input_as_apnum;
	apnum_ptr output_as_apnum;

	char *encoded_input = NULL;

	if(!out_ptr || !in || !public_key || !mod) return 1;
	if(*out_ptr) free(*out_ptr);

	input_as_apnum = new_apnum();
	output_as_apnum = new_apnum();

	hex_encode(&encoded_input, (unsigned char *) in, strlen(in));
	decode_apnum_from_hex(input_as_apnum, encoded_input);

	rsa_encrypt(output_as_apnum, input_as_apnum, public_key, mod);

	apnum_to_hex_string(out_ptr, output_as_apnum);

	free_apnum(input_as_apnum);
	free_apnum(output_as_apnum);

	free(encoded_input);

	return 0;
}

/* Decrypt a number with RSA */
int rsa_decrypt(apnum_ptr out, apnum_ptr in, apnum_ptr private_key, apnum_ptr mod){
	return apnum_modexp(out, in, private_key, mod);
}

/* Decrypt a string with RSA */
int rsa_decrypt_str(char **out_ptr, char *in, apnum_ptr private_key, apnum_ptr mod){
	apnum_ptr input_as_apnum;
	apnum_ptr output_as_apnum;

	char *encoded_output = NULL;

	unsigned char *decoded_output = NULL;
	size_t decoded_output_size;

	if(!out_ptr || !in || !private_key || !mod) return 1;
	if(*out_ptr) free(*out_ptr);

	input_as_apnum = new_apnum();
	output_as_apnum = new_apnum();

	decode_apnum_from_hex(input_as_apnum, in);

	rsa_decrypt(output_as_apnum, input_as_apnum, private_key, mod);

	apnum_to_hex_string(&encoded_output, output_as_apnum);
	hex_decode(&decoded_output, &decoded_output_size, encoded_output);

	*out_ptr = malloc(decoded_output_size+1);
	memcpy(*out_ptr, decoded_output, decoded_output_size);
	(*out_ptr)[decoded_output_size] = '\0';

	free_apnum(input_as_apnum);
	free_apnum(output_as_apnum);

	free(encoded_output);
	free(decoded_output);

	return 0;
}
