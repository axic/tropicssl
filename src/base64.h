#ifndef _BASE64_H
#define _BASE64_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#define ERR_BASE64_BUFFER_TOO_SMALL     0x0002
#define ERR_BASE64_INVALID_CHARACTER    0x0004

/*
 * Encode buffer src of size slen into dst.
 *
 * Returns 0 if successful (dlen contains the # of bytes written) or
 *         ERR_BASE64_BUFFER_TOO_SMALL if *dlen is not large enough,
 *         in which case it is updated to contain the requested size.
 *
 * You may call this function with dst = NULL to determine how much
 * is needed for the destination buffer.
 */
int base64_encode( uchar *dst, uint *dlen, uchar *src, uint slen );

/*
 * Decode buffer src of size slen into dst.
 *
 * Returns 0 if successful (dlen contains the # of bytes written)
 *         ERR_BASE64_INVALID_CHARACTER if an invalid char is found
 *         ERR_BASE64_BUFFER_TOO_SMALL if *dlen is not large enough,
 *         in which case it is updated to contain the requested size.
 *
 * You may call this function with dst = NULL to determine how much
 * is needed for the destination buffer.
 */
int base64_decode( uchar *dst, uint *dlen, uchar *src, uint slen );

/*
 * Checkup routine
 */
int b64_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* base64.h */
