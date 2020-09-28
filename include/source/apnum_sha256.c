#include "arbitrary_precision.h"
#include "sha256.h"

int apnum_sha256(unsigned char **out, apnum_ptr in){
	char *apnum_str = NULL;

	apnum_to_hex_string(&apnum_str, in);
	sha256(out, (unsigned char *) apnum_str, strlen(apnum_str));

	free(apnum_str);
	return 0;
}
