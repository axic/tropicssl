#ifndef _MD4_H
#define _MD4_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

typedef struct
{
    ulong total[2];
    ulong state[4];
    uchar buffer[64];
}
md4_context;

/*
 * Core MD4 functions
 */
void md4_starts( md4_context *ctx );
void md4_update( md4_context *ctx, uchar *input, uint length );
void md4_finish( md4_context *ctx, uchar digest[16] );

/*
 * Output MD5(file contents), returns 0 if successful.
 */
int md4_file( char *filename, uchar digest[16] );

/*
 * Output MD4(buf)
 */
void md4_csum( uchar *buf, uint buflen, uchar digest[16] );

/*
 * Output HMAC-MD4(buf,key)
 */
void md4_hmac( uchar *buf, uint buflen, uchar *key, uint keylen,
                uchar digest[16] );

/*
 * Checkup routine
 */
int md4_self_test( void );

#ifdef __cplusplus
}
#endif

#endif /* md4.h */
