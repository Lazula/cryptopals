#ifndef SRP_H
#define SRP_H

#include "sha256.h"
#include "apnum_sha256.h"
#include "diffie_hellman.h"

/* Base parameters */
struct _srp_paramset {
	apnum_ptr N;
	apnum_ptr g;
	apnum_ptr k;
	char *I;
	char *P;
};
typedef struct _srp_paramset* srp_paramset;

/* Server state */
struct _srp_server {
	srp_paramset params;
	dh_keypair_ptr server_keys;
	apnum_ptr client_pubkey;

	char *salt;
	apnum_ptr v;
	apnum_ptr u;

	apnum_ptr S;
	unsigned char *K;
	unsigned char *client_K;
	unsigned char session_validated;
};
typedef struct _srp_server* srp_server;

/* Client state */
struct _srp_client {
	srp_paramset params;
	dh_keypair_ptr client_keys;
	apnum_ptr server_pubkey;

	char *salt;
	apnum_ptr v;
	apnum_ptr u;

	apnum_ptr S;
	unsigned char *K;
	unsigned char session_validated;
};
typedef struct _srp_client* srp_client;



srp_paramset new_srp_paramset();
void free_srp_paramset(srp_paramset p);
srp_server new_srp_server();
void free_srp_server(srp_server s);
srp_client new_srp_client();
void free_srp_client(srp_client c);

void copy_srp_paramset(srp_paramset out, srp_paramset in);
void set_srp_parameters(srp_paramset out, apnum_ptr N, apnum_ptr g, apnum_ptr k, char *I, char *P);

apnum_ptr srp_generate_x(char *password, char *salt);

/* Define each stage of negotiation separately. */

/* Set up pre-negotiated parameters. */
void srp_negotiate_parameters(srp_client client, srp_server server, srp_paramset shared_params);
/* Generate salt and v */
void srp_generate_server_info(srp_server server);
/* Send I and A */
int srp_client_send_username_and_pubkey(srp_client client, srp_server server);
/* Send salt and B */
void srp_server_send_salt_and_pubkey(srp_client client, srp_server server);
/* Compute u */
void srp_compute_u_client(srp_client client);
void srp_compute_u_server(srp_server server);
/* Compute S/K */
void srp_compute_session_key_client(srp_client client);
void srp_compute_session_key_server(srp_server server);

/* Send the session key hash to the server */
void srp_client_send_session_key_hash(srp_client client, srp_server server);
/* Validate the client if the session key hash was valid */
void srp_server_validate_session(srp_client client, srp_server server);

#endif
