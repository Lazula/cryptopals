#ifndef RSA_H
#define RSA_H

#include <stdio.h>

#include "arbitrary_precision.h"

struct rsa_keypair {
	apnum_ptr private_key;
	apnum_ptr public_key;
	apnum_ptr mod;
};

typedef struct rsa_keypair* rsa_keypair_ptr;

rsa_keypair_ptr new_rsa_keypair();
int free_rsa_keypair(rsa_keypair_ptr a);
int copy_rsa_keypair(rsa_keypair_ptr out, rsa_keypair_ptr in);

int print_rsa_keypair(rsa_keypair_ptr in);

/* Generate an RSA keypair, using mod as the modulus for p and q. */
int rsa_generate_keypair(rsa_keypair_ptr pair, apnum_ptr mod);

/* Encrypt a number with RSA */
int rsa_encrypt(apnum_ptr out, apnum_ptr in, apnum_ptr public_key, apnum_ptr mod);

/* Encrypt a string with RSA */
int rsa_encrypt_str(char **out_ptr, char *in, apnum_ptr public_key, apnum_ptr mod);

/* Decrypt a number with RSA */
int rsa_decrypt(apnum_ptr out, apnum_ptr in, apnum_ptr private_key, apnum_ptr mod);

/* Decrypt a string with RSA */
int rsa_decrypt_str(char **out_ptr, char *in, apnum_ptr private_key, apnum_ptr mod);

#endif
