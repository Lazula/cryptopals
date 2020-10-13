#include <stdio.h>

#include "rsa.h"

void rsa_cube_root_decrypt(char **decrypted_plaintext_ptr, char *ciphertext_a_str, char *ciphertext_b_str, char *ciphertext_c_str,
			   apnum_ptr mod_a, apnum_ptr mod_b, apnum_ptr mod_c);

int main(){
	apnum_ptr N;

	rsa_keypair_ptr pair_a;
	rsa_keypair_ptr pair_b;
	rsa_keypair_ptr pair_c;

	char *plaintext_secret = "secret";

	char *ciphertext_a_str = NULL;
	char *ciphertext_b_str = NULL;
	char *ciphertext_c_str = NULL;

	char *decrypted_plaintext = NULL;

	apnum_randinit();

	N = new_apnum();

	/* 512-bit keys */
	decode_apnum_from_hex(
		N,
		"10000000000000000000000000000000"
		"00000000000000000000000000000000"
		"00000000000000000000000000000000"
		"000000000000000000000000000000000"
	);

	pair_a = new_rsa_keypair();
	pair_b = new_rsa_keypair();
	pair_c = new_rsa_keypair();

	rsa_generate_keypair(pair_a, N);
	rsa_generate_keypair(pair_b, N);
	rsa_generate_keypair(pair_c, N);
	free_apnum(N);

	rsa_encrypt_str(&ciphertext_a_str, plaintext_secret, pair_a -> public_key, pair_a -> mod);
	rsa_encrypt_str(&ciphertext_b_str, plaintext_secret, pair_b -> public_key, pair_b -> mod);
	rsa_encrypt_str(&ciphertext_c_str, plaintext_secret, pair_c -> public_key, pair_c -> mod);

	rsa_cube_root_decrypt(&decrypted_plaintext, ciphertext_a_str, ciphertext_b_str, ciphertext_c_str,
			      pair_a -> mod, pair_b -> mod, pair_c -> mod);

	printf("Decrypted plaintext with cube root attack: \"%s\"\n", decrypted_plaintext);

	free(decrypted_plaintext);

	free(ciphertext_a_str);
	free(ciphertext_b_str);
	free(ciphertext_c_str);

	free_rsa_keypair(pair_a);
	free_rsa_keypair(pair_b);
	free_rsa_keypair(pair_c);

	return 0;
}

void rsa_cube_root_decrypt(char **decrypted_plaintext_ptr, char *ciphertext_a_str, char *ciphertext_b_str, char *ciphertext_c_str,
			   apnum_ptr mod_a, apnum_ptr mod_b, apnum_ptr mod_c){
	apnum_ptr ciphertext_a;
	apnum_ptr ciphertext_b;
	apnum_ptr ciphertext_c;

	apnum_ptr mod_s_a;
	apnum_ptr mod_s_b;
	apnum_ptr mod_s_c;

	apnum_ptr temp_a;
	apnum_ptr temp_b;
	apnum_ptr temp_c;

	apnum_ptr mod_abc;
	apnum_ptr temp_abc;

	apnum_ptr result;

	char *encoded_plaintext = NULL;
	unsigned char *decoded_plaintext = NULL;
	size_t decoded_plaintext_size;

	ciphertext_a = new_apnum();
	ciphertext_b = new_apnum();
	ciphertext_c = new_apnum();

	mod_s_a = new_apnum();
	mod_s_b = new_apnum();
	mod_s_c = new_apnum();

	temp_a = new_apnum();
	temp_b = new_apnum();
	temp_c = new_apnum();

	temp_abc = new_apnum();
	mod_abc = new_apnum();

	result = new_apnum();

	decode_apnum_from_hex(ciphertext_a, ciphertext_a_str);
	decode_apnum_from_hex(ciphertext_b, ciphertext_b_str);
	decode_apnum_from_hex(ciphertext_c, ciphertext_c_str);

	apnum_mul(mod_s_a, mod_b, mod_c);
	apnum_mul(mod_s_b, mod_a, mod_c);
	apnum_mul(mod_s_c, mod_a, mod_b);

	/* temp_a = invmod(mod_s_a, mod_a) * mod_s_a * ciphertext_a */
	apnum_invmod(temp_a, mod_s_a, mod_a);
	apnum_mul(temp_a, temp_a, mod_s_a);
	apnum_mul(temp_a, temp_a, ciphertext_a);

	/* temp_b = invmod(mod_s_b, mod_b) * mod_s_b * ciphertext_b */
	apnum_invmod(temp_b, mod_s_b, mod_b);
	apnum_mul(temp_b, temp_b, mod_s_b);
	apnum_mul(temp_b, temp_b, ciphertext_b);

	/* temp_c = invmod(mod_s_c, mod_c) * mod_s_c * ciphertext_c */
	apnum_invmod(temp_c, mod_s_c, mod_c);
	apnum_mul(temp_c, temp_c, mod_s_c);
	apnum_mul(temp_c, temp_c, ciphertext_c);

	/* mod_abc = mod_a * mod_b * mod_c */
	apnum_mul(mod_abc, mod_a, mod_b);
	apnum_mul(mod_abc, mod_abc, mod_c);

	/* temp_abc = temp_a + temp_b + temp_c */
	apnum_add(temp_abc, temp_a, temp_b);
	apnum_add(temp_abc, temp_abc, temp_c);

	/* result = cuberoot(temp_abc % mod_abc) */
	apnum_mod(result, temp_abc, mod_abc);
	apnum_root(result, result, 3);

	apnum_to_hex_string(&encoded_plaintext, result);
	hex_decode(&decoded_plaintext, &decoded_plaintext_size, encoded_plaintext);

	*decrypted_plaintext_ptr = malloc(decoded_plaintext_size+1);
	memcpy(*decrypted_plaintext_ptr, decoded_plaintext, decoded_plaintext_size);
	(*decrypted_plaintext_ptr)[decoded_plaintext_size] = '\0';

	free_apnum(ciphertext_a);
	free_apnum(ciphertext_b);
	free_apnum(ciphertext_c);

	free_apnum(mod_s_a);
	free_apnum(mod_s_b);
	free_apnum(mod_s_c);

	free_apnum(temp_a);
	free_apnum(temp_b);
	free_apnum(temp_c);

	free_apnum(mod_abc);
	free_apnum(temp_abc);

	free_apnum(result);

	free(encoded_plaintext);
	free(decoded_plaintext);
}
