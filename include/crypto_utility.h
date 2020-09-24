#ifndef CRYPTO_UTILITY_H
#define CRYPTO_UTILITY_H

#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* No, the C99 (this program is C89 regardless) uint8_t type is not guaranteed to exist in stdint.h
 * Yes, this code could be written in a way that works properly with CHAR_BIT != 8
 * No, I will not take the effort to do so, because so much other code in this project incidentally
 * relies on CHAR_BIT == 8.
 */
#if CHAR_BIT == 8
	typedef unsigned char uint8_t;
#else
#	error "No 8-bit type available. Cannot typedef uint8_t."
#endif

/* 32-bit maximum */
#if UINT_MAX == 4294967295
	typedef unsigned int uint32_t;
#elif ULONG_MAX == 4294967295
	typedef unsigned long uint32_t;
#else
#	error "No 32-bit type available. Cannot typedef uint32_t."
#endif

int pkcs7_pad(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, size_t block_size);
int pkcs7_unpad(unsigned char **output_ptr, size_t *output_size_ptr, unsigned char *input, size_t input_size, size_t block_size);

/* Define endian-dependency macros if we have endian support */
#ifdef LOCAL_ENDIAN_H
#	define UINT32_BYTESWAP(N) (		\
		  ((N & 0x000000FF) << 24)	\
		| ((N & 0x0000FF00) <<  8)	\
		| ((N & 0x00FF0000) >>  8)	\
		| ((N & 0xFF000000) >> 24)	\
	)
#	if LOCAL_ENDIANNESS == LOCAL_ENDIAN_LITTLE
#		define UINT32_HOST_TO_BIG_ENDIAN(N) UINT32_BYTESWAP(N)
#		define UINT32_BIG_TO_HOST_ENDIAN(N) UINT32_BYTESWAP(N)
		/* Host is already little-endian */
#		define UINT32_HOST_TO_LITTLE_ENDIAN(N) (N)
#		define UINT32_LITTLE_TO_HOST_ENDIAN(N) (N)
#	else /* LOCAL_ENDIANNESS == LOCAL_ENDIAN_BIG */
#		define UINT32_HOST_TO_LITTLE_ENDIAN(N) UINT32_BYTESWAP(N)
#		define UINT32_LITTLE_TO_HOST_ENDIAN(N) UINT32_BYTESWAP(N)
		/* Host is already big-endian */
#		define UINT32_HOST_TO_BIG_ENDIAN(N) (N)
#		define UINT32_BIG_TO_HOST_ENDIAN(N) (N)
#	endif
#	define UINT32_ROTATE_LEFT(N, R) ( ((N) << R) | ((N) >> (32-R)) )
#	define UINT32_ROTATE_RIGHT(N, R) ( ((N) >> R) | ((N) << (32-R)) )
#endif /* ifdef LOCAL_ENDIAN_H */

#endif
