#include <stdio.h>

#include "srp.h"

#define DEBUG_PRINT_KEYS 0

int main(){
	srp_paramset params;
	srp_client client;
	srp_server server;

	apnum_ptr N;
	apnum_ptr g;
	apnum_ptr k;

	char *I = "email";
	char *P = "password";

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

	srp_server_send_salt_and_pubkey(client, server);

	#if DEBUG && DEBUG_PRINT_KEYS
	printf("server keys: "); print_dh_keypair(server -> server_keys);
	printf("client keys: "); print_dh_keypair(client -> client_keys);
	#endif

	srp_compute_u_client(client);
	srp_compute_u_server(server);

	srp_compute_session_key_client(client);
	srp_compute_session_key_server(server);

	srp_client_send_session_key_hash(client, server);
	srp_server_validate_session(client, server);

	if(client -> session_validated && server -> session_validated){
		printf("Validated SRP session.\n");
	}else{
		printf("Failed to validate SRP session.\n");
	}

	free_srp_client(client);
	free_srp_server(server);

	free_apnum(N);
	free_apnum(g);
	free_apnum(k);

	return 0;
}
