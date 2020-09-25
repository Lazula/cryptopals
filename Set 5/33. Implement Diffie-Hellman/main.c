#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/diffie_hellman.h"

#define DEBUG 0

int main(){
	dh_keypair_ptr pair_a;
	dh_keypair_ptr pair_b;

	apnum_ptr p;
	apnum_ptr g;

	apnum_ptr session_key;
	apnum_ptr session_key_a;
	apnum_ptr session_key_b;

	unsigned char *session_key_hash = NULL;

	apnum_randinit();

	pair_a = new_dh_keypair();
	pair_b = new_dh_keypair();

	p = new_apnum();
	g = new_apnum();

	session_key_a = new_apnum();
	session_key_b = new_apnum();

	decode_apnum_from_hex(
		p,
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff"
	);
	uint8_to_apnum(g, 2);

	#if DEBUG
	printf("p: "); print_apnum_as_hex(p); printf("\n");
	printf("g: "); print_apnum_as_hex(g); printf("\n");
	#endif

	dh_start_session(pair_a, pair_b, p, g);

	#if DEBUG
	printf("pair_a:\n"); print_dh_keypair(pair_a); printf("\n");
	printf("pair_b:\n"); print_dh_keypair(pair_b); printf("\n");
	#endif

	dh_get_session_key(session_key_a, pair_a -> private_key, pair_b -> public_key, p);
	dh_get_session_key(session_key_b, pair_b -> private_key, pair_a -> public_key, p);

	if(apnum_cmp(session_key_a, session_key_b) == 0){
		printf("Session keys match.\n");
		printf("session key: "); print_apnum_as_hex(session_key_a); printf("\n");
	}else{
		printf("Session keys do not match.\n");
		printf("session_key_a: "); print_apnum_as_hex(session_key_a); printf("\n");
		printf("session_key_b: "); print_apnum_as_hex(session_key_b); printf("\n");
	}

	session_key = session_key_a;

	dh_sha1_session_key(&session_key_hash, session_key);
	printf("Session key hash: "); hex_print(session_key_hash, MD4_DIGEST_SIZE); printf("\n");

	free(session_key_hash);

	free_apnum(p);
	free_apnum(g);

	free_apnum(session_key_a);
	free_apnum(session_key_b);

	free_dh_keypair(pair_a);
	free_dh_keypair(pair_b);

	return 0;
}
