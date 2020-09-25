#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/diffie_hellman.h"
#include "../../include/aes.h"

#define DEBUG 0

/* Send parameters from a to b */
void send_parameters_a(apnum_ptr p, apnum_ptr A);
/* Send parameters from b to a */
void send_parameters_b(apnum_ptr B);
/* Send a message from a to b */
void send_message(unsigned char *session_key_hash, unsigned char *message, size_t message_size, unsigned char *iv);

/* The above functions call these to simulate a MITM. */

/* Intercept and modify paramters sent from a */
void intercept_parameters_a(apnum_ptr p, apnum_ptr A);
/* Intercept and modify parameters sent from b */
void intercept_parameters_b(apnum_ptr B);

/* Use recorded p and g to decrypt a message */
void intercept_and_print_message(unsigned char *encrypted_message, size_t encrypted_message_size, unsigned char *iv);

static apnum_ptr RECORDED_P;

int main(){
	dh_keypair_ptr pair_a;
	dh_keypair_ptr pair_b;

	apnum_ptr p;
	apnum_ptr g;

	apnum_ptr session_key;

	unsigned char *session_key_hash = NULL;
	unsigned char *iv = NULL;

	char *message = "Test message.";

	apnum_randinit();

	pair_a = new_dh_keypair();
	pair_b = new_dh_keypair();

	p = new_apnum();
	g = new_apnum();

	session_key = new_apnum();

	RECORDED_P = new_apnum();

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

	send_parameters_a(p, pair_a -> public_key);
	send_parameters_b(pair_b -> public_key);

	/* Only p needs to be recorded by the MITM in order to send as B;
	 * the session key for modexp(B, a, p) when B == p is always 0 */

	dh_get_session_key(session_key, pair_a -> private_key, pair_b -> public_key, p);
	dh_sha1_session_key(&session_key_hash, session_key);

	generate_random_aes_key(&iv, AES_KEY_128);
	send_message(session_key_hash, (unsigned char *) message, strlen(message), iv);

	free(session_key_hash);
	free(iv);

	free_apnum(p);
	free_apnum(g);
	free_apnum(session_key);

	free_dh_keypair(pair_a);
	free_dh_keypair(pair_b);

	return 0;
}

/* Send parameters from a to b */
void send_parameters_a(apnum_ptr p, apnum_ptr A){
	intercept_parameters_a(p, A);
}

/* Send parameters from b to a */
void send_parameters_b(apnum_ptr B){
	intercept_parameters_b(B);
}

/* Send a message from a to b */
void send_message(unsigned char *session_key_hash, unsigned char *message, size_t message_size, unsigned char *iv){
	unsigned char *encrypted_message = NULL;
	size_t encrypted_message_size;

	aes_encrypt(&encrypted_message, &encrypted_message_size, message, message_size, session_key_hash, iv, AES_CIPHER_CBC, AES_KEY_128);

	intercept_and_print_message(encrypted_message, encrypted_message_size, iv);

	free(encrypted_message);
}

/* Intercept and modify parameters sent from a */
void intercept_parameters_a(apnum_ptr p, apnum_ptr A){
	copy_apnum(RECORDED_P, p);

	/* Modify A to be equal to p */
	copy_apnum(A, p);
}

/* Intercept and modify parameters sent from b */
void intercept_parameters_b(apnum_ptr B){
	/* Modify B to be equal to p */
	copy_apnum(B, RECORDED_P);
	free_apnum(RECORDED_P);
}

void intercept_and_print_message(unsigned char *encrypted_message, size_t encrypted_message_size, unsigned char *iv){
	/* hash of 0 as apnum */
	static unsigned char *set_key = (unsigned char *) "\xb6\x58\x9f\xc6\xab\x0d\xc8\x2c\xf1\x20\x99\xd1\xc2\xd4\x0a\xb9";

	unsigned char *decrypted_message = NULL;
	size_t decrypted_message_size;

	char *decrypted_message_str;

	aes_decrypt(&decrypted_message, &decrypted_message_size, encrypted_message, encrypted_message_size, set_key, iv, AES_CIPHER_CBC, AES_KEY_128);

	decrypted_message_str = malloc(decrypted_message_size+1);
	memcpy(decrypted_message_str, decrypted_message, decrypted_message_size);
	decrypted_message_str[decrypted_message_size] = '\0';

	printf("%s\n", decrypted_message_str);

	free(decrypted_message);
	free(decrypted_message_str);
}
