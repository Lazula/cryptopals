#include <stdio.h>

#include "../diffie_hellman.h"

dh_keypair_ptr new_dh_keypair(){
	dh_keypair_ptr a;

	a = malloc(sizeof(struct dh_keypair));

	if(!a) return NULL;

	a -> private_key = new_apnum();
	a -> public_key = new_apnum();

	return a;
}

int free_dh_keypair(dh_keypair_ptr a){
	if(!a) return -1;

	if(a -> private_key) free_apnum(a -> private_key);
	if(a -> public_key) free_apnum(a -> public_key);

	free(a);

	return 0;
}

int copy_dh_keypair(dh_keypair_ptr out, dh_keypair_ptr in){
	if(!in || !out) return -1;

	copy_apnum(out -> private_key, in -> private_key);
	copy_apnum(out -> public_key, in -> public_key);

	return 0;
}

int print_dh_keypair(dh_keypair_ptr in){
	if(!in) return -1;
	if(in -> private_key){
		printf("PRIV: ");
		print_apnum_as_hex(in -> private_key);
		printf("\n");
	}
	if(in -> public_key){
		printf("PUB: ");
		print_apnum_as_hex(in -> public_key);
		printf("\n");
	}

	return 0;
}

int dh_generate_keypair(dh_keypair_ptr pair, apnum_ptr p, apnum_ptr g){
	/* a = rand() % p */
	apnum_rand(pair -> private_key, p);

	/* A = (g^a) % p */
	apnum_modexp(pair -> public_key, g, pair -> private_key, p);

	return 0;
}

int dh_start_session(dh_keypair_ptr pair_a, dh_keypair_ptr pair_b, apnum_ptr p, apnum_ptr g){
	dh_generate_keypair(pair_a, p, g);
	dh_generate_keypair(pair_b, p, g);
	return 0;
}

int dh_get_session_key(apnum_ptr session_key, apnum_ptr private_key, apnum_ptr received_public_key, apnum_ptr p){
	return apnum_modexp(session_key, received_public_key, private_key, p);
}
