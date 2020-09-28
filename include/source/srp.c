#include "srp.h"

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#endif

#define DEBUG_NO_RANDOM_SALT 0
#define DEBUG_NO_RANDOM_KEYS 0
#define DEBUG_GENERATE_SERVER_INFO 0
#define DEBUG_COMPUTE_U 0
#define DEBUG_SESSION_KEY 0

srp_paramset new_srp_paramset(){
	srp_paramset p;

	p = malloc(sizeof(struct _srp_paramset));
	p -> N = new_apnum();
	p -> g = new_apnum();
	p -> k = new_apnum();
	p -> I = NULL;
	p -> P = NULL;

	return p;
}

void free_srp_paramset(srp_paramset p){
	free_apnum(p -> N);
	free_apnum(p -> g);
	free_apnum(p -> k);
	free(p -> I);
	free(p -> P);
	free(p);
}

srp_server new_srp_server(){
	srp_server s;

	s = malloc(sizeof(struct _srp_server));
	s -> params = new_srp_paramset();
	s -> server_keys = new_dh_keypair();
	s -> client_pubkey = new_apnum();
	s -> salt = NULL;
	s -> v = new_apnum();
	s -> u = new_apnum();
	s -> S = new_apnum();
	s -> K = malloc(SHA256_DIGEST_SIZE);
	s -> client_K = malloc(SHA256_DIGEST_SIZE);
	s -> session_validated = 0;

	return s;
}

void free_srp_server(srp_server s){
	free_srp_paramset(s -> params);
	free_dh_keypair(s -> server_keys);
	free_apnum(s -> client_pubkey);
	free(s -> salt);
	free_apnum(s -> v);
	free_apnum(s -> u);
	free_apnum(s -> S);
	free(s -> K);
	free(s -> client_K);
	free(s);
}

srp_client new_srp_client(){
	srp_client c;

	c = malloc(sizeof(struct _srp_client));
	c -> params = new_srp_paramset();
	c -> client_keys = new_dh_keypair();
	c -> server_pubkey = new_apnum();
	c -> salt = NULL;
	c -> v = new_apnum();
	c -> u = new_apnum();
	c -> S = new_apnum();
	c -> K = malloc(SHA256_DIGEST_SIZE);
	c -> session_validated = 0;

	return c;
}

void free_srp_client(srp_client c){
	free_srp_paramset(c -> params);
	free_dh_keypair(c -> client_keys);
	free_apnum(c -> server_pubkey);
	free(c -> salt);
	free_apnum(c -> v);
	free_apnum(c -> u);
	free_apnum(c -> S);
	free(c -> K);
	free(c);
}

void set_srp_parameters(srp_paramset out, apnum_ptr N, apnum_ptr g, apnum_ptr k, char *I, char *P){
	copy_apnum(out -> N, N);
	copy_apnum(out -> g, g);
	copy_apnum(out -> k, k);
	out -> I = malloc(strlen(I)+1);
	strcpy(out -> I, I);
	out -> P = malloc(strlen(P)+1);
	strcpy(out -> P, P);
	
}

void copy_srp_paramset(srp_paramset out, srp_paramset in){
	copy_apnum(out -> N, in -> N);
	copy_apnum(out -> g, in -> g);
	copy_apnum(out -> k, in -> k);
	out -> I = malloc(strlen(in -> I)+1);
	strcpy(out -> I, in -> I);
	out -> P = malloc(strlen(in -> P)+1);
	strcpy(out -> P, in -> P);
}


/* Define each stage of negotiation separately. */

/* Set up pre-negotiated parameters. */
void srp_negotiate_parameters(srp_client client, srp_server server, srp_paramset shared_params){
	copy_srp_paramset(client -> params, shared_params);
	copy_srp_paramset(server -> params, shared_params);
}

/* Generate salt and v */
void srp_generate_server_info(srp_server server){
	apnum_ptr r;
	apnum_ptr x;
	unsigned char *xH_raw = NULL;
	char *xH = NULL;

	apnum_randinit();

	/* Generate salt */
	r = new_apnum();
	#if DEBUG_NO_RANDOM_SALT
	uint8_to_apnum(r, 0);
	#else
	apnum_rand(r, server -> params -> N);
	#endif
	apnum_to_hex_string(&(server -> salt), r);
	free_apnum(r);

	#if DEBUG_GENERATE_SERVER_INFO
	printf("server salt string: %s\n", server -> salt);
	#endif

	key_prefix_sha256(&xH_raw, (unsigned char *) server -> params -> P, strlen(server -> params -> P), \
			  (unsigned char *) server -> salt, strlen(server -> salt));
	sha256_hash_to_string(&xH, xH_raw);
	free(xH_raw);

	x = new_apnum();
	decode_apnum_from_hex(x, xH);
	free(xH);

	#if DEBUG_GENERATE_SERVER_INFO
	printf("server x: "); print_apnum_as_hex(x); printf("\n");
	#endif

	apnum_modexp(server -> v, server -> params -> g, x, server -> params -> N);

	#if DEBUG_GENERATE_SERVER_INFO
	printf("v: "); print_apnum_as_hex(server -> v); printf("\n");
	#endif

	free_apnum(x);
}

/* Send I and A */
int srp_client_send_username_and_pubkey(srp_client client, srp_server server){
	/* Simulate rejection of bad username */
	if(strcmp(client -> params -> I, server -> params -> I)){
		return 1;
	}

	#if DEBUG_NO_RANDOM_KEYS
	uint8_to_apnum(client -> client_keys -> private_key, 100);
	apnum_modexp(client -> client_keys -> public_key, client -> params -> g, client -> client_keys -> private_key, client -> params -> N);
	#else
	/* straightforward keypair generation */
	dh_generate_keypair(client -> client_keys, client -> params -> N, client -> params -> g);
	#endif

	/* send pubkey to server */
	copy_apnum(server -> client_pubkey, client -> client_keys -> public_key);

	return 0;
}

/* Send salt and B */
void srp_server_send_salt_and_pubkey(srp_client client, srp_server server){
	apnum_ptr temp;

	client -> salt = malloc(strlen(server -> salt)+1);
	strcpy(client -> salt, server -> salt);

	#if DEBUG_NO_RANDOM_KEYS
	uint8_to_apnum(server -> server_keys -> private_key, 100);
	apnum_modexp(server -> server_keys -> public_key, server -> params -> g, server -> server_keys -> private_key, server -> params -> N);
	#else
	/* generate private key as normal... */
	dh_generate_keypair(server -> server_keys, server -> params -> N, server -> params -> g);
	#endif
	/* but add kv to the public key */
	temp = new_apnum();
	apnum_mul(temp, server -> params -> k, server -> v);
	apnum_add(server -> server_keys -> public_key, server -> server_keys -> public_key, temp);
	free_apnum(temp);

	/* send pubkey to client */
	copy_apnum(client -> server_pubkey, server -> server_keys -> public_key);
}

/* Compute u */
void srp_compute_u_client(srp_client client){
	char *client_pubkey_str = NULL;
	char *server_pubkey_str = NULL;
	unsigned char *uH_raw = NULL;
	char *uH = NULL;

	apnum_to_hex_string(&client_pubkey_str, client -> client_keys -> public_key);
	apnum_to_hex_string(&server_pubkey_str, client -> server_pubkey);

	key_prefix_sha256(&uH_raw, (unsigned char *) client_pubkey_str, strlen(client_pubkey_str), \
			  (unsigned char *) server_pubkey_str, strlen(server_pubkey_str));
	free(client_pubkey_str);
	free(server_pubkey_str);

	sha256_hash_to_string(&uH, uH_raw);
	free(uH_raw);

	decode_apnum_from_hex(client -> u, uH);
	free(uH);

	#if DEBUG_COMPUTE_U
	printf("client u: "); print_apnum_as_hex(client -> u); printf("\n");
	#endif
}

void srp_compute_u_server(srp_server server){
	char *client_pubkey_str = NULL;
	char *server_pubkey_str = NULL;
	unsigned char *uH_raw = NULL;
	char *uH = NULL;

	apnum_to_hex_string(&server_pubkey_str, server -> server_keys -> public_key);
	apnum_to_hex_string(&client_pubkey_str, server -> client_pubkey);

	key_prefix_sha256(&uH_raw, (unsigned char *) client_pubkey_str, strlen(client_pubkey_str), \
			  (unsigned char *) server_pubkey_str, strlen(server_pubkey_str));
	free(client_pubkey_str);
	free(server_pubkey_str);

	sha256_hash_to_string(&uH, uH_raw);
	free(uH_raw);

	decode_apnum_from_hex(server -> u, uH);
	free(uH);

	#if DEBUG_COMPUTE_U
	printf("server u: "); print_apnum_as_hex(server -> u); printf("\n");
	#endif
}

/* Compute S/K */
void srp_compute_session_key_client(srp_client client){
	unsigned char *xH_raw = NULL;
	char *xH = NULL;
	apnum_ptr x;
	apnum_ptr temp1;
	apnum_ptr temp2;

	key_prefix_sha256(&xH_raw, (unsigned char *) client -> params -> P, strlen(client -> params -> P), \
			  (unsigned char *) client -> salt, strlen(client -> salt));
	sha256_hash_to_string(&xH, xH_raw);
	free(xH_raw);

	x = new_apnum();
	decode_apnum_from_hex(x, xH);
	free(xH);

	/* temp1 = B - k * pow(g, x) */
	temp1 = new_apnum();

	/* pow() result will be % N later, doing it now reduces memory usage */
	/* temp1 = pow(g, x, N) */
	apnum_modexp(temp1, client -> params -> g, x, client -> params -> N);
	/* temp1 = k * temp1 */
	apnum_mul(temp1, temp1, client -> params -> k);
	/* temp1 = B - temp1 */
	apnum_sub(temp1, client -> server_pubkey, temp1);

	/* temp2 = a + u * x */
	temp2 = new_apnum();
	/* temp2 = u * x */
	apnum_mul(temp2, client -> u, x);
	/* temp2 = a + temp2 */
	apnum_add(temp2, client -> client_keys -> private_key, temp2);

	/* S = pow(temp1, temp2, N) */
	apnum_modexp(client -> S, temp1, temp2, client -> params -> N);
	apnum_sha256((unsigned char **) &(client -> K), client -> S);

	#if DEBUG_SESSION_KEY
	printf("\nclient x = "); print_apnum_as_hex(x); printf("\n");
	printf("client u = "); print_apnum_as_hex(client -> u); printf("\n");
	printf("client session key (S): "); print_apnum_as_hex(client -> S); printf("\n");
	printf("client session key hash (K): "); hex_print(client -> K, SHA256_DIGEST_SIZE); printf("\n");
	#endif

	free_apnum(temp1);
	free_apnum(temp2);
	free_apnum(x);
}

void srp_compute_session_key_server(srp_server server){
	apnum_ptr temp;

	/* temp = A * pow(v, u) */
	temp = new_apnum();

	/* pow() result will be % N later, doing it now reduces memory usage */
	/* temp = pow(v, u, N) */
	apnum_modexp(temp, server -> v, server -> u, server -> params -> N);
	/* temp = A * temp1 */
	apnum_mul(temp, temp, server -> client_pubkey);

	/* S = pow(temp, b, N) */
	apnum_modexp(server -> S, temp, server -> server_keys -> private_key, server -> params -> N);
	apnum_sha256((unsigned char **) &(server -> K), server -> S);

	#if DEBUG_SESSION_KEY
	printf("server v: "); print_apnum_as_hex(server -> v); printf("\n");
	printf("server u: "); print_apnum_as_hex(server -> u); printf("\n");
	printf("server session key (S): "); print_apnum_as_hex(server -> S); printf("\n");
	printf("server session key hash (K): "); hex_print(server -> K, SHA256_DIGEST_SIZE); printf("\n");
	#endif

	free_apnum(temp);
}


void srp_client_send_session_key_hash(srp_client client, srp_server server){
	memcpy(server -> client_K, client -> K, SHA256_DIGEST_SIZE);
}

void srp_server_validate_session(srp_client client, srp_server server){
	if(!memcmp(server -> K, server -> client_K, SHA256_DIGEST_SIZE)){
		client -> session_validated = 1;
		server -> session_validated = 1;
	}else{
		client -> session_validated = 0;
		server -> session_validated = 0;
	}
}
