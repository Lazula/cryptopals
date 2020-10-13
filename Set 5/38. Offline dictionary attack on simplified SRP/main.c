#include <stdio.h>

#include "srp.h"

#define DEBUG 0

#define DEBUG_PRINT_KEYS 0
#define DEBUG_SESSION_KEY 0

#define DEBUG_DICTIONARY_CRACK 0

void simplified_srp_server_send_salt_and_pubkey(srp_client client, srp_server server);
void simplified_srp_compute_session_key_client(srp_client client);

void get_session_key_hash_from_password(unsigned char **session_key_hash_ptr, char *password, char *salt, srp_paramset params,
					apnum_ptr u, apnum_ptr client_pubkey, apnum_ptr server_privkey);
void dictionary_crack(char **found_password_ptr, unsigned char *client_K, char *salt, srp_paramset params,
		      apnum_ptr u, apnum_ptr client_pubkey, apnum_ptr server_privkey);

int main(){
	srp_paramset params;
	srp_client client;
	srp_server server;

	apnum_ptr N;
	apnum_ptr g;
	apnum_ptr k;

	char *I = "email";
	char *P = "password";

	char *found_password = NULL;

	N = new_apnum();
	g = new_apnum();
	k = new_apnum();

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

	srp_generate_server_info(server);

	if(srp_client_send_username_and_pubkey(client, server)){
		printf("Server rejected username.\n");
		return 0;
	}

	simplified_srp_server_send_salt_and_pubkey(client, server);

	#if DEBUG && DEBUG_PRINT_KEYS
	printf("server keys: "); print_dh_keypair(server -> server_keys);
	printf("client keys: "); print_dh_keypair(client -> client_keys);
	#endif

	simplified_srp_compute_session_key_client(client);
	srp_compute_session_key_server(server);

	srp_client_send_session_key_hash(client, server);

	/* We don't care about session validation */

	dictionary_crack(&found_password, server -> client_K, server -> salt, server -> params,
			 server -> u, server -> client_pubkey, server -> server_keys -> private_key);


	if(found_password){
		printf("Found password from client session key: \"%s\"\n", found_password);
		free(found_password);
	}else{
		printf("Failed to find password with wordlist.\n");
	}


	free_srp_client(client);
	free_srp_server(server);

	free_apnum(N);
	free_apnum(g);
	free_apnum(k);

	return 0;
}

/* basic wordlist cracker for srp session key */
void dictionary_crack(char **found_password_ptr, unsigned char *client_K, char *salt, srp_paramset params,
		      apnum_ptr u, apnum_ptr client_pubkey, apnum_ptr server_privkey){
	FILE *wordlist_file;
	char *linebreak;
	char *password;
	unsigned char *current_session_key_hash = NULL;

	if(!found_password_ptr || *found_password_ptr || !client_K || !salt || !u) return;

	#if DEBUG_DICTIONARY_CRACK
	printf("[DEBUG_DICTIONARY_CRACK] Attempting to crack client session key "); hex_print(client_K, SHA256_DIGEST_SIZE); printf("\n");
	#endif

	wordlist_file = fopen("wordlist.txt", "r");
	if(!wordlist_file) return;

	current_session_key_hash = malloc(SHA256_DIGEST_SIZE);

	password = malloc(1024);
	while(fgets(password, 1024, wordlist_file) != NULL){
		if((linebreak = strchr(password, '\n')) != NULL) *linebreak = '\0';

		/* calculate the server's session key */
		get_session_key_hash_from_password(&current_session_key_hash, password, salt, params,
						   u, client_pubkey, server_privkey);

		#if DEBUG_DICTIONARY_CRACK
		printf("[DEBUG_DICTIONARY_CRACK] Testing password \"%s\" with session key ", password);
		hex_print(current_session_key_hash, SHA256_DIGEST_SIZE); printf("\n");
		#endif

		if(!memcmp(client_K, current_session_key_hash, SHA256_DIGEST_SIZE)){
			*found_password_ptr = malloc(strlen(password)+1);
			strcpy(*found_password_ptr, password);
			free(password);
			free(current_session_key_hash);
			return;
		}
	}

	free(password);
	free(current_session_key_hash);

	fclose(wordlist_file);
}

void get_session_key_hash_from_password(unsigned char **session_key_hash_ptr, char *password, char *salt, srp_paramset params,
					apnum_ptr u, apnum_ptr client_pubkey, apnum_ptr server_privkey){
	apnum_ptr x;
	apnum_ptr v;
	apnum_ptr temp;
	apnum_ptr S;

	if(!session_key_hash_ptr || !(*session_key_hash_ptr)) return;

	x = srp_generate_x(password, salt);

	v = new_apnum();
	/* v = pow(g, x, n) */
	apnum_modexp(v, params -> g, x, params -> N);
	free_apnum(x);

	temp = new_apnum();
	/* temp = pow(v, u, n) */
	apnum_modexp(temp, v, u, params -> N);
	free_apnum(v);

	/* temp = A * temp */
	apnum_mul(temp, client_pubkey, temp);

	S = new_apnum();
	/* S = pow(temp, b, n) */
	apnum_modexp(S, temp, server_privkey, params -> N);
	free_apnum(temp);

	apnum_sha256(session_key_hash_ptr, S);

	free_apnum(S);
}

void simplified_srp_server_send_salt_and_pubkey(srp_client client, srp_server server){
	apnum_ptr u;
	apnum_ptr u_max;

	client -> salt = malloc(strlen(server -> salt)+1);
	strcpy(client -> salt, server -> salt);

	/* generate private key as normal. do not add kv in the simplified version */
	dh_generate_keypair(server -> server_keys, server -> params -> N, server -> params -> g);

	/* send pubkey to client */
	copy_apnum(client -> server_pubkey, server -> server_keys -> public_key);

	/* Generate u */
	u = new_apnum();

	u_max = new_apnum();
	/* use 128-bit max + 1 as the modulus */
	decode_apnum_from_hex(u_max, "100000000000000000000000000000000");
	apnum_rand(u, u_max);
	free_apnum(u_max);

	copy_apnum(client -> u, u);
	copy_apnum(server -> u, u);

	free_apnum(u);
}

void simplified_srp_compute_session_key_client(srp_client client){
	apnum_ptr x;
	apnum_ptr temp;

	x = srp_generate_x(client -> params -> P, client -> salt);

	#if DEBUG_SESSION_KEY
	printf("[DEBUG_SESSION_KEY] x = "); print_apnum_as_hex(x); printf("\n");
	printf("[DEBUG_SESSION_KEY] u = "); print_apnum_as_hex(client -> u); printf("\n");
	#endif

	/* temp = (a + ux) */
	temp = new_apnum();

	/* temp = ux */
	apnum_mul(temp, client -> u, x);
	#if DEBUG_SESSION_KEY
	printf("[DEBUG_SESSION_KEY] ux = "); print_apnum_as_hex(temp); printf("\n");
	#endif
	/* temp = temp + a */
	apnum_add(temp, temp, client -> client_keys -> private_key);
	#if DEBUG_SESSION_KEY
	printf("[DEBUG_SESSION_KEY] a + ux = "); print_apnum_as_hex(temp); printf("\n");
	#endif

	/* S = pow(B, temp, N) */
	apnum_modexp(client -> S, client -> server_pubkey, temp, client -> params -> N);
	apnum_sha256((unsigned char **) &(client -> K), client -> S);

	free_apnum(temp);

	#if DEBUG_SESSION_KEY
	printf("\nclient x = "); print_apnum_as_hex(x); printf("\n");
	printf("client u = "); print_apnum_as_hex(client -> u); printf("\n");
	printf("client session key (S): "); print_apnum_as_hex(client -> S); printf("\n");
	printf("client session key hash (K): "); hex_print(client -> K, SHA256_DIGEST_SIZE); printf("\n");
	#endif

	free_apnum(x);
}
