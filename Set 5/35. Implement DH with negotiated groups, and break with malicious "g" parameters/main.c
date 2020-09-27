#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/diffie_hellman.h"
#include "../../include/aes.h"

#define DEBUG 0

struct dh_paramset {
	apnum_ptr p;
	apnum_ptr g;
	apnum_ptr s;
};
typedef struct dh_paramset * dh_paramset_ptr;

dh_paramset_ptr new_dh_paramset(){
	dh_paramset_ptr ps;

	ps = malloc(sizeof(struct dh_paramset));

	ps -> p = new_apnum();
	ps -> g = new_apnum();
	ps -> s = new_apnum();

	return ps;
}

void free_dh_paramset(dh_paramset_ptr ps){
	free_apnum(ps -> p);
	free_apnum(ps -> g);
	free_apnum(ps -> s);
	free(ps);
}

void attack_one();
void attack_two();
void attack_three();

/* Send a message from a to b */
void send_message(apnum_ptr session_key, unsigned char *message, size_t message_size, unsigned char *iv);
void intercept_and_print_message(unsigned char *encrypted_message, size_t encrypted_message_size, unsigned char *iv);

static apnum_ptr PREDICTED_SESSION_KEY;

int main(){
	apnum_randinit();

	attack_one();
	attack_two();
	attack_three();

	return 0;
}

void attack_one(){
	dh_paramset_ptr a_params;
	dh_paramset_ptr b_params;

	dh_keypair_ptr pair_a;
	dh_keypair_ptr pair_b;

	unsigned char *iv = NULL;

	char *message = "Secret message 1.";

	PREDICTED_SESSION_KEY = new_apnum();

	a_params = new_dh_paramset();
	b_params = new_dh_paramset();

	pair_a = new_dh_keypair();
	pair_b = new_dh_keypair();

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

	copy_apnum(b_params -> p, a_params -> p);
	/* The MITM attacker replaces g with 1 while in transit to B. */
	uint8_to_apnum(b_params -> g, 1);

	/* Each side generates their keyset */
	dh_generate_keypair(pair_a, a_params -> p, a_params -> g);
	dh_generate_keypair(pair_b, b_params -> p, b_params -> g);

	/* Public keys are not tampered with in transit but are known to the attacker. */

	/* Each side generates their session key. */
	dh_get_session_key(a_params -> s, pair_a -> private_key, pair_b -> public_key, a_params -> p);
	dh_get_session_key(b_params -> s, pair_b -> private_key, pair_a -> public_key, b_params -> p);

	#if DEBUG
	printf("pair_a:\n"); print_dh_keypair(pair_a);
	printf("pair_b:\n"); print_dh_keypair(pair_b);
	#endif

	/* The attacker can predict that s is 1, since B's public key is 1.
	 * Notably, the attacker can only intercept messages from A.
	 * The only key we can modify with this attack is B's public key, so when
	 * B calculates s it gets the expected "real" key value.
	 *
	 * This is shown in debug mode below.
	 */
	uint8_to_apnum(PREDICTED_SESSION_KEY, 1);

	#if DEBUG
	printf("[DEBUG] A's session key: "); print_apnum_as_hex(a_params -> s); printf("\n");
	printf("[DEBUG] B's session key: "); print_apnum_as_hex(b_params -> s); printf("\n");
	#endif

	generate_random_aes_key(&iv, AES_KEY_128);
	printf("First attack (g = 1): ");
	send_message(a_params -> s, (unsigned char *) message, strlen(message), iv);
	free(iv);

	free_dh_keypair(pair_a);
	free_dh_keypair(pair_b);

	free_dh_paramset(a_params);
	free_dh_paramset(b_params);

	free_apnum(PREDICTED_SESSION_KEY);
}

void attack_two(){
	dh_paramset_ptr a_params;
	dh_paramset_ptr b_params;

	dh_keypair_ptr pair_a;
	dh_keypair_ptr pair_b;

	unsigned char *iv = NULL;

	char *message = "Secret message 2.";

	PREDICTED_SESSION_KEY = new_apnum();

	a_params = new_dh_paramset();
	b_params = new_dh_paramset();

	pair_a = new_dh_keypair();
	pair_b = new_dh_keypair();

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

	copy_apnum(b_params -> p, a_params -> p);
	/* The MITM attacker replaces g with p while in transit to B. */
	copy_apnum(b_params -> g, a_params -> p);

	/* Each side generates their keyset */
	dh_generate_keypair(pair_a, a_params -> p, a_params -> g);
	dh_generate_keypair(pair_b, b_params -> p, b_params -> g);

	/* Public keys are not tampered with in transit but are known to the attacker. */

	/* Each side generates their session key */
	dh_get_session_key(a_params -> s, pair_a -> private_key, pair_b -> public_key, a_params -> p);
	dh_get_session_key(b_params -> s, pair_b -> private_key, pair_a -> public_key, b_params -> p);

	#if DEBUG
	printf("pair_a:\n"); print_dh_keypair(pair_a);
	printf("pair_b:\n"); print_dh_keypair(pair_b);
	#endif

	/* The attacker can predict that s is 0, since B's public key is 0.
	 * Notably, the attacker can only intercept messages from A.
	 * The only key we can modify with this attack is B's public key, so when
	 * B calculates s it gets the expected "real" key value.
	 *
	 * This is shown in debug mode below.
	 */
	uint8_to_apnum(PREDICTED_SESSION_KEY, 0);

	#if DEBUG
	printf("[DEBUG] A's session key: "); print_apnum_as_hex(a_params -> s); printf("\n");
	printf("[DEBUG] B's session key: "); print_apnum_as_hex(b_params -> s); printf("\n");
	#endif

	generate_random_aes_key(&iv, AES_KEY_128);
	printf("Second attack (g = p): ");
	send_message(a_params -> s, (unsigned char *) message, strlen(message), iv);
	free(iv);

	free_dh_keypair(pair_a);
	free_dh_keypair(pair_b);

	free_dh_paramset(a_params);
	free_dh_paramset(b_params);

	free_apnum(PREDICTED_SESSION_KEY);
}

void attack_three(){
	dh_paramset_ptr a_params;
	dh_paramset_ptr b_params;

	dh_keypair_ptr pair_a;
	dh_keypair_ptr pair_b;

	apnum_ptr const_one;

	unsigned char *iv = NULL;

	char *message = "Secret message 3.";

	PREDICTED_SESSION_KEY = new_apnum();

	const_one = new_apnum();
	uint8_to_apnum(const_one, 1);

	a_params = new_dh_paramset();
	b_params = new_dh_paramset();

	pair_a = new_dh_keypair();
	pair_b = new_dh_keypair();

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

	copy_apnum(b_params -> p, a_params -> p);
	/* The MITM attacker replaces g with p-1 while in transit to B. */
	copy_apnum(b_params -> g, a_params -> p);
	apnum_sub(b_params -> g, b_params -> g, const_one);

	/* Each side generates their keyset */
	dh_generate_keypair(pair_a, a_params -> p, a_params -> g);
	dh_generate_keypair(pair_b, b_params -> p, b_params -> g);

	/* Public keys are not tampered with in transit but are known to the attacker. */

	/* Each side generates their session key */
	dh_get_session_key(a_params -> s, pair_a -> private_key, pair_b -> public_key, a_params -> p);
	dh_get_session_key(b_params -> s, pair_b -> private_key, pair_a -> public_key, b_params -> p);

	#if DEBUG
	printf("pair_a:\n"); print_dh_keypair(pair_a);
	printf("pair_b:\n"); print_dh_keypair(pair_b);
	#endif

	/* The attacker can predict that s is 1, since B's public key is p-1.
	 * Notably, the attacker can only intercept messages from A.
	 * The only key we can modify with this attack is B's public key, so when
	 * B calculates s it gets the expected "real" key value.
	 *
	 * This is shown in debug mode below.
	 */
	uint8_to_apnum(PREDICTED_SESSION_KEY, 1);

	#if DEBUG
	printf("[DEBUG] A's session key: "); print_apnum_as_hex(a_params -> s); printf("\n");
	printf("[DEBUG] B's session key: "); print_apnum_as_hex(b_params -> s); printf("\n");
	#endif

	generate_random_aes_key(&iv, AES_KEY_128);
	printf("Third attack (g = p-1): ");
	send_message(a_params -> s, (unsigned char *) message, strlen(message), iv);
	free(iv);

	free_dh_keypair(pair_a);
	free_dh_keypair(pair_b);

	free_dh_paramset(a_params);
	free_dh_paramset(b_params);

	free_apnum(PREDICTED_SESSION_KEY);
	free_apnum(const_one);
}

/* Send a message from a to b */
void send_message(apnum_ptr session_key, unsigned char *message, size_t message_size, unsigned char *iv){
	unsigned char *session_key_hash = NULL;

	unsigned char *encrypted_message = NULL;
	size_t encrypted_message_size;

	/* Hash the session key and encrypt. */
	dh_sha1_session_key(&session_key_hash, session_key);
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
	dh_sha1_session_key(&session_key_hash, PREDICTED_SESSION_KEY);
	aes_decrypt(&decrypted_message, &decrypted_message_size, encrypted_message, encrypted_message_size, session_key_hash, iv, AES_CIPHER_CBC, AES_KEY_128);
	free(session_key_hash);

	/* The message-in-transit lacks a terminating null byte. */
	decrypted_message_str = malloc(decrypted_message_size+1);
	memcpy(decrypted_message_str, decrypted_message, decrypted_message_size);
	decrypted_message_str[decrypted_message_size] = '\0';

	printf("\"%s\"\n", decrypted_message_str);

	free(decrypted_message);
	free(decrypted_message_str);
}
