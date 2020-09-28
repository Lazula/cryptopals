#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/sha1.h"
#include "../../include/diffie_hellman.h"
#include "../../include/aes.h"

#define DEBUG 0

struct dh_paramset {
	apnum_ptr p;
	apnum_ptr g;
	apnum_ptr o; /* Other side */
	apnum_ptr s;
};
typedef struct dh_paramset * dh_paramset_ptr;

dh_paramset_ptr new_dh_paramset(){
	dh_paramset_ptr ps;

	ps = malloc(sizeof(struct dh_paramset));

	ps -> p = new_apnum();
	ps -> g = new_apnum();
	ps -> o = new_apnum();
	ps -> s = new_apnum();

	return ps;
}

void free_dh_paramset(dh_paramset_ptr ps){
	free_apnum(ps -> p);
	free_apnum(ps -> g);
	free_apnum(ps -> o);
	free_apnum(ps -> s);
	free(ps);
}

/* Send a message from a to b */
void send_message(apnum_ptr session_key, unsigned char *message, size_t message_size, unsigned char *iv);
void intercept_and_print_message(unsigned char *encrypted_message, size_t encrypted_message_size, unsigned char *iv);

static apnum_ptr PREDICTED_SESSION_KEY;

int main(){
	dh_paramset_ptr a_params;
	dh_paramset_ptr b_params;

	dh_keypair_ptr pair_a;
	dh_keypair_ptr pair_b;

	unsigned char *iv = NULL;

	char *message = "Secret message.";

	apnum_randinit();

	a_params = new_dh_paramset();
	b_params = new_dh_paramset();

	pair_a = new_dh_keypair();
	pair_b = new_dh_keypair();

	PREDICTED_SESSION_KEY = new_apnum();

	decode_apnum_from_hex(
		a_params -> p,
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
		"fffffffffffff"
	);
	uint8_to_apnum(a_params -> g, 2);

	/* p and g are not tampered with. */
	copy_apnum(b_params -> p, a_params -> p);
	copy_apnum(b_params -> g, a_params -> g);

	/* Each side generates their keyset. */
	dh_generate_keypair(pair_a, a_params -> p, a_params -> g);
	dh_generate_keypair(pair_b, b_params -> p, b_params -> g);

	/* The MITM attack replaces each public key with p while in transit. */
	copy_apnum(a_params -> o, a_params -> p);
	copy_apnum(b_params -> o, a_params -> p);

	/* Each side generates their session key. */
	dh_get_session_key(a_params -> s, pair_a -> private_key, a_params -> o, a_params -> p);
	dh_get_session_key(a_params -> s, pair_b -> private_key, b_params -> o, b_params -> p);

	/* The attacker can predict that s is 0, since each public key is p.
	 * (p**X)%p is 0 for any value of X.
	 *
	 * This is shown in debug mode below.
	 */
	uint8_to_apnum(PREDICTED_SESSION_KEY, 0);

	#if DEBUG
	printf("[DEBUG] A's session key: "); print_apnum_as_hex(a_params -> s); printf("\n");
	printf("[DEBUG] B's session key: "); print_apnum_as_hex(b_params -> s); printf("\n");
	#endif

	generate_random_aes_key(&iv, AES_KEY_128);
	send_message(a_params -> s, (unsigned char *) message, strlen(message), iv);
	free(iv);

	free_dh_keypair(pair_a);
	free_dh_keypair(pair_b);

	free_dh_paramset(a_params);
	free_dh_paramset(b_params);

	return 0;
}

/* Send a message from a to b */
void send_message(apnum_ptr session_key, unsigned char *message, size_t message_size, unsigned char *iv){
	unsigned char *session_key_hash = NULL;

	unsigned char *encrypted_message = NULL;
	size_t encrypted_message_size;

	/* Hash the session key and encrypt */
	apnum_sha1(&session_key_hash, session_key);
	aes_encrypt(&encrypted_message, &encrypted_message_size, message, message_size, session_key_hash, iv, AES_CIPHER_CBC, AES_KEY_128);

	/* Only information visible on the wire is passed to the attacker. */
	intercept_and_print_message(encrypted_message, encrypted_message_size, iv);

	free(encrypted_message);
	free(session_key_hash);
}

void intercept_and_print_message(unsigned char *encrypted_message, size_t encrypted_message_size, unsigned char *iv){
	unsigned char *session_key_hash = NULL;

	unsigned char *decrypted_message = NULL;
	size_t decrypted_message_size;

	char *decrypted_message_str;

	/* Hash the predicted session key and decrypt. */
	apnum_sha1(&session_key_hash, PREDICTED_SESSION_KEY);
	aes_decrypt(&decrypted_message, &decrypted_message_size, encrypted_message, encrypted_message_size, session_key_hash, iv, AES_CIPHER_CBC, AES_KEY_128);
	free(session_key_hash);

	/* The message-in-transit lacks a terminating null byte. */
	decrypted_message_str = malloc(decrypted_message_size+1);
	memcpy(decrypted_message_str, decrypted_message, decrypted_message_size);
	decrypted_message_str[decrypted_message_size] = '\0';

	printf("Decrypted: \"%s\"\n", decrypted_message_str);

	free(decrypted_message);
	free(decrypted_message_str);
}
