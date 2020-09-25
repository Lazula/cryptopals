#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include "arbitrary_precision.h"
#include "md4.h"
#include "sha1.h"

struct dh_keypair {
	apnum_ptr private_key;
	apnum_ptr public_key;
};

typedef struct dh_keypair* dh_keypair_ptr;

dh_keypair_ptr new_dh_keypair();
int free_dh_keypair(dh_keypair_ptr a);
int copy_dh_keypair(dh_keypair_ptr out, dh_keypair_ptr in);

int print_dh_keypair(dh_keypair_ptr in);

/* Used by dh_start_session or manual creation of a single keypair. */
int dh_generate_keypair(dh_keypair_ptr pair, apnum_ptr p, apnum_ptr g);

/* Start a DH session using the given p and g parameters. Generates each keypair with the same p and g. */
int dh_start_session(dh_keypair_ptr pair_a, dh_keypair_ptr pair_b, apnum_ptr p, apnum_ptr g);

/* Get the session key from your own private key and the other side's public key. */
int dh_get_session_key(apnum_ptr session_key, apnum_ptr private_key, apnum_ptr received_public_key, apnum_ptr p);

/* Get a 128-bit key from the session key. */
int dh_md4_session_key(unsigned char **hash_ptr, apnum_ptr session_key);

/* Get a 160-bit key from the session key, */
int dh_sha1_session_key(unsigned char **hash_ptr, apnum_ptr session_key);

#endif
