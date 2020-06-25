#ifndef LOCAL_ENDIAN_H
#define LOCAL_ENDIAN_H

/* This is a header-only utility. There is no associated source (.c) file.
 * It must be included before other headers that may have endian-dependent
 * behavior. It is named local_endian.h to avoid potential name conflicts
 * with a standard endian.h header provided by the compiler.
 */

/* This is impossible to do both automatically
 * and cleanly while strictly adhering to the
 * C Standard, as it leaves all endianness
 * concerns implementation-defined.
 *
 * The README informs users that this file must
 * be altered to support big-endian machines.
 */

#define LOCAL_ENDIAN_LITTLE 0
#define LOCAL_ENDIAN_BIG 1

/* Change '1' to '0' on the following line to enable big endian support. */
#if 1
#  define LOCAL_ENDIANNESS LOCAL_ENDIAN_LITTLE
#else
#  define LOCAL_ENDIANNESS LOCAL_ENDIAN_BIG
#endif

#endif /* ifndef LOCAL_ENDIAN_H */
