#include "arbitrary_precision.h"
#include "md4.h"

int apnum_md4(unsigned char **out, apnum_ptr in){
	char *apnum_str = NULL;

	apnum_to_hex_string(&apnum_str, in);
	md4(out, (unsigned char *) apnum_str, strlen(apnum_str));

	free(apnum_str);
	return 0;
}
