#ifndef _SHA2_H
#define _SHA2_H

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

typedef struct
{
    ulong total[2];
    ulong state[8];
    uchar buffer[64];
}
sha2_context;

/*
 * Core SHA-256 functions
 */
void sha2_starts( sha2_context *ctx );
void sha2_update( sha2_context *ctx, uchar *input, uint length );
void sha2_finish( sha2_context *ctx, uchar digest[32] );

/*
 * Output SHA-256(file contents), returns 0 if successful.
 */
int sha2_file( char *filename, uchar digest[32] );

/*
 * Output SHA-256(buf)
 */
void sha2_csum( uchar *buf, uint buflen, uchar digest[32] );

/*
 * Output HMAC-SHA-256(buf,key)
 */
void sha2_hmac( uchar *buf, uint buflen, uchar *key, uint keylen,
                  uchar digest[32] );

/*
 * Checkup routine
 */
int sha2_self_test( void );

/*
 * Output SHA-256(file contents), returns 0 if successful.
 */
int sha2_file( char *filename, uchar digest[32] );

/*
 * Output SHA-256(buf)
 */
void sha2_csum( uchar *buf, uint buflen, uchar digest[32] );

/*
 * Output HMAC-SHA-256(buf,key)
 */
void sha2_hmac( uchar *buf, uint buflen, uchar *key, uint keylen,
                uchar digest[32] );

/*
 * Checkup routine
 */
int sha2_self_test( void );

#endif /* sha2.h */
