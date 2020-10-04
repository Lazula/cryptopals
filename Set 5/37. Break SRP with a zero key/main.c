#include <stdio.h>

#include "srp.h"

#define DEBUG_PRINT_KEYS 0

int srp_client_send_username_and_fake_pubkey(srp_client client, srp_server server, apnum_ptr fake_public_key);
void srp_compute_fake_session_key_client(srp_client client, apnum_ptr fake_session_key);

void attack_zero_key();
void attack_N_key();
void attack_2N_key();

int main(){
	attack_zero_key();
	attack_N_key();
	attack_2N_key();

	return 0;
}

void attack_zero_key(){
	srp_paramset params;
	srp_client client;
	srp_server server;

	apnum_ptr N;
	apnum_ptr g;
	apnum_ptr k;

	apnum_ptr fake_pubkey;
	apnum_ptr fake_session_key;

	char *I = "email";
	char *P = "password";

	N = new_apnum();
	g = new_apnum();
	k = new_apnum();

	fake_pubkey = new_apnum();
	fake_session_key = new_apnum();

	decode_apnum_from_hex(
		N,
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
	uint8_to_apnum(k, 3);

	client = new_srp_client();
	server = new_srp_server();

	params = new_srp_paramset();
	set_srp_parameters(params, N, g, k, I, P);
	srp_negotiate_parameters(client, server, params);
	free_srp_paramset(params);

	/* Zero out the client's password to simulate a blind attack */
	memset(client -> params -> P, '\0', strlen(client -> params -> P));

	srp_generate_server_info(server);

	/* Attack starts here */
	uint8_to_apnum(fake_pubkey, 0);
	if(srp_client_send_username_and_fake_pubkey(client, server, fake_pubkey)){
		printf("Server rejected username.\n");
		return;
	}

	srp_server_send_salt_and_pubkey(client, server);

	#if DEBUG && DEBUG_PRINT_KEYS
	printf("server keys: "); print_dh_keypair(server -> server_keys);
	printf("client keys: "); print_dh_keypair(client -> client_keys);
	#endif

	srp_compute_u_client(client);
	srp_compute_u_server(server);

	uint8_to_apnum(fake_session_key, 0);
	srp_compute_fake_session_key_client(client, fake_session_key);
	srp_compute_session_key_server(server);

	srp_client_send_session_key_hash(client, server);
	srp_server_validate_session(client, server);

	if(client -> session_validated && server -> session_validated){
		printf("Validated SRP session with zero key.\n");
	}else{
		printf("Failed to validate SRP session.\n");
	}

	free_srp_client(client);
	free_srp_server(server);

	free_apnum(N);
	free_apnum(g);
	free_apnum(k);

	free_apnum(fake_pubkey);
	free_apnum(fake_session_key);
}

void attack_N_key(){
	srp_paramset params;
	srp_client client;
	srp_server server;

	apnum_ptr N;
	apnum_ptr g;
	apnum_ptr k;

	apnum_ptr fake_pubkey;
	apnum_ptr fake_session_key;

	char *I = "email";
	char *P = "password";

	N = new_apnum();
	g = new_apnum();
	k = new_apnum();

	fake_pubkey = new_apnum();
	fake_session_key = new_apnum();

	decode_apnum_from_hex(
		N,
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
	uint8_to_apnum(k, 3);

	client = new_srp_client();
	server = new_srp_server();

	params = new_srp_paramset();
	set_srp_parameters(params, N, g, k, I, P);
	srp_negotiate_parameters(client, server, params);
	free_srp_paramset(params);

	/* Zero out the client's password to simulate a blind attack */
	memset(client -> params -> P, '\0', strlen(client -> params -> P));

	srp_generate_server_info(server);

	/* Attack starts here */
	copy_apnum(fake_pubkey, client -> params -> N);
	if(srp_client_send_username_and_fake_pubkey(client, server, fake_pubkey)){
		printf("Server rejected username.\n");
		return;
	}

	srp_server_send_salt_and_pubkey(client, server);

	#if DEBUG && DEBUG_PRINT_KEYS
	printf("server keys: "); print_dh_keypair(server -> server_keys);
	printf("client keys: "); print_dh_keypair(client -> client_keys);
	#endif

	srp_compute_u_client(client);
	srp_compute_u_server(server);

	uint8_to_apnum(fake_session_key, 0);
	srp_compute_fake_session_key_client(client, fake_session_key);
	srp_compute_session_key_server(server);

	srp_client_send_session_key_hash(client, server);
	srp_server_validate_session(client, server);

	if(client -> session_validated && server -> session_validated){
		printf("Validated SRP session with N key.\n");
	}else{
		printf("Failed to validate SRP session.\n");
	}

	free_srp_client(client);
	free_srp_server(server);

	free_apnum(N);
	free_apnum(g);
	free_apnum(k);

	free_apnum(fake_pubkey);
	free_apnum(fake_session_key);
}

void attack_2N_key(){
	srp_paramset params;
	srp_client client;
	srp_server server;

	apnum_ptr N;
	apnum_ptr g;
	apnum_ptr k;

	apnum_ptr fake_pubkey;
	apnum_ptr fake_session_key;

	apnum_ptr const_two;

	char *I = "email";
	char *P = "password";

	N = new_apnum();
	g = new_apnum();
	k = new_apnum();

	fake_pubkey = new_apnum();
	fake_session_key = new_apnum();

	const_two = new_apnum();
	uint8_to_apnum(const_two, 2);

	decode_apnum_from_hex(
		N,
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
	uint8_to_apnum(k, 3);

	client = new_srp_client();
	server = new_srp_server();

	params = new_srp_paramset();
	set_srp_parameters(params, N, g, k, I, P);
	srp_negotiate_parameters(client, server, params);
	free_srp_paramset(params);

	/* Zero out the client's password to simulate a blind attack */
	memset(client -> params -> P, '\0', strlen(client -> params -> P));

	srp_generate_server_info(server);

	/* Attack starts here */
	copy_apnum(fake_pubkey, client -> params -> N);
	apnum_mul(fake_pubkey, fake_pubkey, const_two);
	if(srp_client_send_username_and_fake_pubkey(client, server, fake_pubkey)){
		printf("Server rejected username.\n");
		return;
	}

	srp_server_send_salt_and_pubkey(client, server);

	#if DEBUG && DEBUG_PRINT_KEYS
	printf("server keys: "); print_dh_keypair(server -> server_keys);
	printf("client keys: "); print_dh_keypair(client -> client_keys);
	#endif

	srp_compute_u_client(client);
	srp_compute_u_server(server);

	uint8_to_apnum(fake_session_key, 0);
	srp_compute_fake_session_key_client(client, fake_session_key);
	srp_compute_session_key_server(server);

	srp_client_send_session_key_hash(client, server);
	srp_server_validate_session(client, server);

	if(client -> session_validated && server -> session_validated){
		printf("Validated SRP session with 2N key.\n");
	}else{
		printf("Failed to validate SRP session.\n");
	}

	free_srp_client(client);
	free_srp_server(server);

	free_apnum(N);
	free_apnum(g);
	free_apnum(k);

	free_apnum(fake_pubkey);
	free_apnum(fake_session_key);

	free_apnum(const_two);
}


int srp_client_send_username_and_fake_pubkey(srp_client client, srp_server server, apnum_ptr fake_public_key){
	/* Simulate rejection of bad username */
	if(strcmp(client -> params -> I, server -> params -> I)){
		return 1;
	}

	/* Generate a private key as normal... */
	apnum_rand(client -> client_keys -> private_key, client -> params -> N);

	/* and set the public key to our fake value. */
	copy_apnum(client -> client_keys -> public_key, fake_public_key);

	/* send pubkey to server */
	copy_apnum(server -> client_pubkey, client -> client_keys -> public_key);

	return 0;
}

void srp_compute_fake_session_key_client(srp_client client, apnum_ptr fake_session_key){
	copy_apnum(client -> S, fake_session_key);
	apnum_sha256((unsigned char **) &(client -> K), client -> S);
}
